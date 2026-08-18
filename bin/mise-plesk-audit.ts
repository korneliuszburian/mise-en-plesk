#!/usr/bin/env node
import { getInventoryHostItem, readInventory, syncFromBitwarden } from "../src/ssh-inventory";
import { extractSecureNoteSshCredentials } from "../src/bitwarden";
import { createSshSession, scanPleskHost, DEFAULT_SSH_COMMAND_TIMEOUT_MS } from "../src/plesk-scan";
import type { ReadOnlyCommand } from "../src/ssh-transport";
import { auditWordPressInstallation, createBatchedWpRunners, type AuditResult, type WordPressAudit, type ScanProgress } from "../src/wp-audit";
import { writeAuditReport } from "../src/report";
import { createFileVulnerabilityCache, lookupVulnerabilities, type VulnerabilityCache } from "../src/vulnerabilities";
import { findingsFromAudits } from "../src/findings";
import { readFindingState, reconcileFindings, writeFindingState, type FindingScope, type FindingEvent } from "../src/finding-state";
import { appendScanCycleFindings, completeScanCycle, prepareScanCycle, readScanCycleState, writeScanCycleState } from "../src/scan-cycle";
import type { Finding } from "../src/findings";
import { notifyFindingEventsToWhatsApp } from "../src/whatsapp";
import { sendFindingEventsViaHermes, sendHermesText } from "../src/hermes";
import { createNotificationAdapters } from "../src/notification-adapters";
import { createNotificationDelivery, type NotificationDelivery } from "../src/notification-delivery";
import { runPreflight } from "../src/preflight";
import { createMonitorStaleFinding, readHeartbeat, writeHeartbeat } from "../src/monitor-health";
import { parseCliArguments } from "../src/cli-args";
import { readConfigFile, type MisePleskConfig } from "../src/config";
import { acquireLocalLock, type LocalLock } from "../src/local-lock";
import { createWhatsAppTestEvent, requireWhatsAppTestConfirmation } from "../src/notification-test";
import { formatScanOutput } from "../src/cli-output";
import { isCompleteScanPage, nextScanOffset } from "../src/scan-lifecycle";
import { shouldContinueScanChunks } from "../src/scan-budget";

const inventoryPath = process.env.MISE_PLESK_INVENTORY ?? "inventory.json";
const configPath = process.env.MISE_PLESK_CONFIG ?? "config.mise-en-plesk.json";

interface VulnerabilityLookupBudget {
  used: number;
}

function usage(): never {
  console.error("Scan options: [--max-sites=N] [--offset=N] [--max-chunks=N] [--all-chunks]");
  console.error("Usage: mise-plesk-audit doctor [--json] | monitor-health [--json] [--max-age-hours=N] | sync-ssh | whatsapp-test --confirm=<recipient> | hermes-test --confirm=<target> | scan <target|all> [--json] [--max-sites=N] [--offset=N] [--all-chunks]");
  process.exit(1);
}

function parseNonNegativeInteger(value: string, flag: string): number {
  if (!/^\d+$/.test(value)) throw new Error(`${flag} must be a non-negative integer.`);
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) throw new Error(`${flag} is too large.`);
  return parsed;
}

function readScanRange(flags: string[], config: MisePleskConfig): { json: boolean; maxSites?: number; offset: number; maxChunks: number; allChunks: boolean } {
  let json = false;
  let maxSites = config.maxSitesPerHost;
  let offset = 0;
  let maxChunks = config.maxScanChunksPerHost ?? 100;
  let allChunks = false;
  for (const flag of flags) {
    if (flag === "--json") {
      json = true;
      continue;
    }
    if (flag === "--all-chunks") {
      allChunks = true;
      continue;
    }
    const maxSitesMatch = /^--max-sites=(.+)$/.exec(flag);
    if (maxSitesMatch) {
      maxSites = parseNonNegativeInteger(maxSitesMatch[1], "--max-sites");
      continue;
    }
    const offsetMatch = /^--offset=(.+)$/.exec(flag);
    if (offsetMatch) {
      offset = parseNonNegativeInteger(offsetMatch[1], "--offset");
      continue;
    }
    const maxChunksMatch = /^--max-chunks=(.+)$/.exec(flag);
    if (maxChunksMatch) {
      maxChunks = parseNonNegativeInteger(maxChunksMatch[1], "--max-chunks");
      continue;
    }
    usage();
  }
  if (maxSites !== undefined && (!Number.isInteger(maxSites) || maxSites < 1)) {
    throw new Error("maxSitesPerHost/--max-sites must be a positive integer.");
  }
  if (offset > 0 && maxSites === undefined) {
    throw new Error("--offset requires --max-sites or maxSitesPerHost in config.");
  }
  if (allChunks && maxSites === undefined) {
    throw new Error("--all-chunks requires --max-sites or maxSitesPerHost in config.");
  }
  if (maxChunks < 1) throw new Error("maxScanChunksPerHost/--max-chunks must be a positive integer.");
  return { json, maxSites, offset, maxChunks, allChunks };
}

async function readConfig(): Promise<MisePleskConfig> {
  return readConfigFile(configPath);
}

async function readOptionalConfig(): Promise<MisePleskConfig> {
  try {
    return await readConfig();
  } catch (error: unknown) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") return {};
    throw error;
  }
}

function notificationOutboxPath(config: MisePleskConfig): string {
  return process.env.MISE_PLESK_NOTIFICATION_OUTBOX
    ?? config.notificationOutboxPath
    ?? ".mise-en-plesk/notification-outbox.json";
}

function notificationHistoryPath(config: MisePleskConfig): string {
  return process.env.MISE_PLESK_NOTIFICATION_HISTORY
    ?? config.notificationHistoryPath
    ?? ".mise-en-plesk/notification-history.json";
}

function createDelivery(config: MisePleskConfig): NotificationDelivery {
  const cooldownHours = config.notificationCooldownHours ?? 24;
  return createNotificationDelivery({
    outboxPath: notificationOutboxPath(config),
    historyPath: notificationHistoryPath(config),
    cooldownMs: cooldownHours * 60 * 60 * 1000,
    adapters: createNotificationAdapters(process.env),
    debug: (message) => console.error(message),
  });
}

async function persistFindingList(
  findingState: Awaited<ReturnType<typeof readFindingState>>,
  findings: Finding[],
  findingStatePath: string,
  scope: FindingScope,
  occurredAt: string,
  delivery: NotificationDelivery,
): Promise<{ state: Awaited<ReturnType<typeof readFindingState>>; events: FindingEvent[]; notificationSent: boolean; whatsappSent: boolean; hermesSent: boolean }> {
  const transition = reconcileFindings(findingState, findings, occurredAt, scope);
  await delivery.enqueue(transition.events);
  await writeFindingState(findingStatePath, transition.state);
  const notification = await delivery.flush();
  return {
    state: transition.state,
    events: transition.events,
    notificationSent: notification.webhookSent,
    whatsappSent: notification.whatsappSent,
    hermesSent: notification.hermesSent,
  };
}

async function scanHost(
  alias: string,
  inventory: Awaited<ReturnType<typeof readInventory>>,
  maxVulnerabilityLookups?: number,
  maxConcurrentSites = 4,
  maxSites?: number,
  offset = 0,
  vulnerabilityBudget: VulnerabilityLookupBudget = { used: 0 },
  useSudo = false,
  vulnerabilityCache?: VulnerabilityCache,
  commandTimeoutMs = DEFAULT_SSH_COMMAND_TIMEOUT_MS,
): Promise<{ report: AuditResult["hosts"][number]; scannedInstallationPaths: string[]; complete: boolean; offset: number }> {
  const host = inventory[alias];
  const item = process.env.BW_SESSION ? await getInventoryHostItem(host) : null;
  const credentials = item ? extractSecureNoteSshCredentials(item) : null;
  console.error(`[${alias}] scanning Plesk host ${host.host}`);
  let session: Awaited<ReturnType<typeof createSshSession>>;
  try {
    session = await createSshSession(host, credentials?.password, useSudo ? credentials?.password : undefined, commandTimeoutMs);
  } catch (error: unknown) {
    const detail = error instanceof Error ? error.message.replace(/\s+/g, " ").trim().slice(0, 240) : "SSH session could not be established";
    console.error(`[${alias}] host unreachable: ${detail}`);
    return {
      report: {
        host: alias,
        subscriptions: [],
        wordpress: [],
        health: { reachable: false, detail },
        warnings: [`SSH session could not be established: ${detail}`],
      },
      scannedInstallationPaths: [],
      complete: false,
      offset,
    };
  }
  try {
    const ssh = (command: ReadOnlyCommand) => session.run(command);
    const scan = await scanPleskHost(host, (_host, command) => ssh(command), {
      wordpressOffset: offset,
      wordpressLimit: maxSites,
      useSudo,
      collectHostFacts: offset === 0,
      includeAlternateWordPressDetection: true,
    });
    for (const warning of scan.warnings ?? []) console.error(`[${alias}] warning: ${warning}`);
    const effectiveSudo = useSudo && scan.pleskCliAvailable !== false;
    const selectedWordPress = maxSites === undefined ? scan.wordpress.slice(offset) : scan.wordpress;
    const scannedInstallationPaths = selectedWordPress.map((installation) => installation.path);
    const wordpress = [];
    for (let index = 0; index < selectedWordPress.length; index += maxConcurrentSites) {
      const batch = selectedWordPress.slice(index, index + maxConcurrentSites);
      wordpress.push(...await Promise.all(batch.map(async (installation) => {
        const batched = createBatchedWpRunners(installation, ssh, { useSudo: effectiveSudo });
        return auditWordPressInstallation(installation, batched.runner, {
          useSudo: effectiveSudo,
          enabled: process.env.MISE_PLESK_ENABLE_VULNS === "1",
          vulnerabilityResourceLookup: async (resource, identifier, options) => {
            if (process.env.MISE_PLESK_ENABLE_VULNS !== "1") return { status: "disabled" };
            try {
              const cached = await vulnerabilityCache?.get(resource, identifier);
              if (cached) return cached;
            } catch (error: unknown) {
              options?.debug?.(`vulnerability cache ignored: ${error instanceof Error ? error.message : "cache read failed"}`);
            }
            if (maxVulnerabilityLookups !== undefined && vulnerabilityBudget.used >= maxVulnerabilityLookups) return { status: "skipped" };
            vulnerabilityBudget.used += 1;
            return lookupVulnerabilities(resource, identifier, { ...options, enabled: true, cache: vulnerabilityCache });
          },
          suspiciousFileRunner: batched.suspiciousFileRunner,
        });
      })));
      console.error(`[${alias}] audited ${Math.min(index + batch.length, selectedWordPress.length)}/${selectedWordPress.length} selected WordPress installation(s)`);
    }
    console.error(`[${alias}] found ${scan.subscriptions.length} subscription(s), ${scan.wordpress.length} WordPress installation(s); selected ${selectedWordPress.length} at offset ${offset}`);
    return {
      report: {
        host: scan.host,
        subscriptions: scan.subscriptions,
        wordpress,
        ...(scan.health ? { health: scan.health } : {}),
        ...(scan.hostFacts ? { hostFacts: scan.hostFacts } : {}),
        ...(scan.warnings ? { warnings: scan.warnings } : {}),
      },
      scannedInstallationPaths,
      complete: isCompleteScanPage(scan, maxSites, offset),
      offset,
    };
  } finally {
    try {
      await session.close();
    } catch (error: unknown) {
      const detail = error instanceof Error ? error.message.replace(/\s+/g, " ").trim().slice(0, 200) : "SSH session close failed";
      console.error(`[${alias}] SSH session close warning: ${detail}`);
    }
  }
}

async function main(): Promise<void> {
  const { command, target, flags } = parseCliArguments(process.argv.slice(2));
  const json = flags.includes("--json");
  let runLock: LocalLock | undefined;
  try {
    if ((command === "scan" || command === "monitor-health") && process.env.MISE_PLESK_RUN_LOCK_HELD !== "1") {
      runLock = await acquireLocalLock(process.env.MISE_PLESK_RUN_LOCK ?? ".mise-en-plesk/scan.lock");
    }
  if (command === "doctor") {
    const config = await readOptionalConfig();
    const result = await runPreflight({ inventoryPath, configPath, heartbeatPath: process.env.MISE_PLESK_HEARTBEAT ?? config.heartbeatPath });
    if (json) console.log(JSON.stringify(result, null, 2));
    else for (const item of result.checks) console.log(`${item.ok ? "OK" : "FAIL"} ${item.name}: ${item.detail}`);
    if (!result.ok) process.exitCode = 1;
    return;
  }
  if (command === "sync-ssh") {
    const inventory = await syncFromBitwarden("mise-en-plesk", inventoryPath);
    console.log(`Synced ${Object.keys(inventory).length} host(s) to ${inventoryPath}.`);
    return;
  }
  if (command === "whatsapp-test") {
    const recipient = process.env.MISE_PLESK_WHATSAPP_RECIPIENT;
    requireWhatsAppTestConfirmation(flags, recipient);
    const result = await notifyFindingEventsToWhatsApp([createWhatsAppTestEvent()], {
      accessToken: process.env.MISE_PLESK_WHATSAPP_ACCESS_TOKEN,
      phoneNumberId: process.env.MISE_PLESK_WHATSAPP_PHONE_NUMBER_ID,
      recipient,
      templateName: process.env.MISE_PLESK_WHATSAPP_TEMPLATE_NAME,
      templateLanguage: process.env.MISE_PLESK_WHATSAPP_TEMPLATE_LANGUAGE,
      graphVersion: process.env.MISE_PLESK_WHATSAPP_GRAPH_VERSION,
      debug: (message) => console.error(message),
    });
    if (!result.sent) throw new Error("WhatsApp test delivery failed or is not configured.");
    console.log("WhatsApp test message delivered.");
    return;
  }
  if (command === "hermes-test") {
    const target = process.env.MISE_PLESK_HERMES_WHATSAPP_TARGET;
    if (!target) throw new Error("MISE_PLESK_HERMES_WHATSAPP_TARGET is not configured.");
    if (!flags.includes(`--confirm=${target}`)) throw new Error("Refusing Hermes delivery: pass --confirm=<exact configured target>.");
    await sendHermesText("mise-en-plesk Hermes alert channel test (read-only scanner)", {
      target,
      binary: process.env.MISE_PLESK_HERMES_BIN,
    });
    console.log("Hermes test message delivered.");
    return;
  }
  if (command === "monitor-health") {
    const config = await readOptionalConfig();
    let jsonOutput = false;
    let maxAgeHours = config.monitorMaxAgeHours ?? 2;
    for (const flag of flags) {
      if (flag === "--json") {
        jsonOutput = true;
        continue;
      }
      const maxAgeMatch = /^--max-age-hours=(.+)$/.exec(flag);
      if (!maxAgeMatch) usage();
      const parsed = Number(maxAgeMatch[1]);
      if (!Number.isFinite(parsed) || parsed <= 0) throw new Error("--max-age-hours must be a positive number.");
      maxAgeHours = parsed;
    }
    const heartbeatPath = process.env.MISE_PLESK_HEARTBEAT ?? config.heartbeatPath ?? ".mise-en-plesk/heartbeat.json";
    const now = new Date();
    const heartbeat = await readHeartbeat(heartbeatPath);
    const staleFinding = createMonitorStaleFinding(heartbeat, now, maxAgeHours * 60 * 60 * 1000);
    const findingStatePath = process.env.MISE_PLESK_FINDINGS ?? config.findingsStatePath ?? ".mise-en-plesk/findings.json";
    const previousState = await readFindingState(findingStatePath);
    const delivery = createDelivery(config);
    const transition = reconcileFindings(
      previousState,
      staleFinding ? [staleFinding] : [],
      now.toISOString(),
      { installationPaths: new Set(["__monitor__"]) },
    );
    await delivery.enqueue(transition.events);
    await writeFindingState(findingStatePath, transition.state);
    const notification = await delivery.flush();
    const result = { heartbeatPath, heartbeat, stale: Boolean(staleFinding), findingEvents: transition.events };
    if (jsonOutput) console.log(JSON.stringify(result, null, 2));
    else console.log(staleFinding ? `Monitor is stale: ${heartbeatPath}` : `Monitor is healthy: ${heartbeat?.completedAt ?? "unknown"}`);
    if (notification.webhookSent) console.error("Sent pending monitor webhook alert(s).");
    if (notification.whatsappSent) console.error("Sent pending monitor WhatsApp alert(s).");
    if (notification.hermesSent) console.error("Sent pending monitor Hermes alert(s).");
    return;
  }
  if (command === "scan" && target) {
    const preflight = await runPreflight({ inventoryPath, configPath, env: process.env });
    const blockingFailures = preflight.checks
      .filter((check) => check.blocking && !check.ok)
      .map((check) => `${check.name}: ${check.detail}`);
    if (blockingFailures.length) throw new Error(`Preflight failed: ${blockingFailures.join("; ")}`);
    const config = await readConfig();
    const scanRange = readScanRange(flags, config);
    const heartbeatPath = process.env.MISE_PLESK_HEARTBEAT ?? config.heartbeatPath ?? ".mise-en-plesk/heartbeat.json";
    const startedAt = new Date().toISOString();
    await writeHeartbeat(heartbeatPath, { version: 1, target, startedAt });
    const inventory = await readInventory(inventoryPath);
    const aliases = target === "all" ? config.hosts ?? [] : [target];
    if (!aliases.length) throw new Error(`No hosts configured in ${configPath}.`);
    for (const alias of aliases) {
      if (!inventory[alias]) throw new Error(`Unknown inventory target: ${alias}`);
    }
    const maxLookups = config.maxVulnerabilityLookupsPerHost;
    if (maxLookups !== undefined && (!Number.isInteger(maxLookups) || maxLookups < 0)) {
      throw new Error("maxVulnerabilityLookupsPerHost must be a non-negative integer.");
    }
    if (config.vulnerabilityCacheTtlHours !== undefined && (!Number.isFinite(config.vulnerabilityCacheTtlHours) || config.vulnerabilityCacheTtlHours <= 0)) {
      throw new Error("vulnerabilityCacheTtlHours must be a positive number.");
    }
    const vulnerabilityCache = createFileVulnerabilityCache(
      process.env.MISE_PLESK_VULN_CACHE ?? config.vulnerabilityCachePath ?? ".mise-en-plesk/vulnerabilities.json",
      (config.vulnerabilityCacheTtlHours ?? 12) * 60 * 60 * 1000,
    );
    const maxConcurrentSites = config.maxConcurrentSitesPerHost ?? 4;
    if (!Number.isInteger(maxConcurrentSites) || maxConcurrentSites < 1) {
      throw new Error("maxConcurrentSitesPerHost must be a positive integer.");
    }
    const executions: Array<Awaited<ReturnType<typeof scanHost>>> = [];
    const findingStatePath = process.env.MISE_PLESK_FINDINGS ?? config.findingsStatePath ?? ".mise-en-plesk/findings.json";
    const scanCycleStatePath = process.env.MISE_PLESK_SCAN_CYCLES ?? config.scanCycleStatePath ?? ".mise-en-plesk/scan-cycles.json";
    let findingState = await readFindingState(findingStatePath);
    let scanCycleState = await readScanCycleState(scanCycleStatePath);
    const delivery = createDelivery(config);
    const findingEvents: FindingEvent[] = [];
    let alertSent = false;
    let whatsappSent = false;
    let hermesSent = false;
    for (const alias of aliases) {
      let offset = scanRange.offset;
      const vulnerabilityBudget = { used: 0 };
      const useSudo = config.sudoHosts?.includes(alias) ?? false;
      const hostWordPress: WordPressAudit[] = [];
      const hostExecutions: Array<Awaited<ReturnType<typeof scanHost>>> = [];
      let chunksProcessed = 0;
      scanCycleState = prepareScanCycle(scanCycleState, alias, scanRange.offset, startedAt);
      await writeScanCycleState(scanCycleStatePath, scanCycleState);
      while (true) {
        const execution = await scanHost(alias, inventory, maxLookups, maxConcurrentSites, scanRange.maxSites, offset, vulnerabilityBudget, useSudo, vulnerabilityCache, config.sshCommandTimeoutMs ?? DEFAULT_SSH_COMMAND_TIMEOUT_MS);
        executions.push(execution);
        hostExecutions.push(execution);
        chunksProcessed += 1;
        hostWordPress.push(...execution.report.wordpress);
        const batchFindings = findingsFromAudits([execution.report]);
        scanCycleState = appendScanCycleFindings(scanCycleState, alias, batchFindings);
        await writeScanCycleState(scanCycleStatePath, scanCycleState);
        const batchTransition = await persistFindingList(
          findingState,
          batchFindings,
          findingStatePath,
          { installationPaths: new Set(execution.scannedInstallationPaths) },
          new Date().toISOString(),
          delivery,
        );
        findingState = batchTransition.state;
        findingEvents.push(...batchTransition.events);
        alertSent ||= batchTransition.notificationSent;
        whatsappSent ||= batchTransition.whatsappSent;
        hermesSent ||= batchTransition.hermesSent;
        if (!shouldContinueScanChunks(scanRange.allChunks, execution.complete, chunksProcessed, scanRange.maxChunks)) {
          if (scanRange.allChunks && !execution.complete && chunksProcessed >= scanRange.maxChunks) {
            console.error(`[${alias}] scan chunk budget reached (${scanRange.maxChunks}); leaving cycle incomplete.`);
          }
          break;
        }
        offset = nextScanOffset(offset, execution.scannedInstallationPaths.length);
      }
      const finalExecution = hostExecutions.at(-1);
      if (finalExecution?.complete) {
        const completedCycle = completeScanCycle(scanCycleState, alias);
        scanCycleState = completedCycle.state;
        await writeScanCycleState(scanCycleStatePath, scanCycleState);
        if (completedCycle.findings) {
          const completeTransition = await persistFindingList(
            findingState,
            completedCycle.findings,
            findingStatePath,
            { completeHosts: new Set([finalExecution.report.host]) },
            new Date().toISOString(),
            delivery,
          );
          findingState = completeTransition.state;
          findingEvents.push(...completeTransition.events);
          alertSent ||= completeTransition.notificationSent;
          whatsappSent ||= completeTransition.whatsappSent;
          hermesSent ||= completeTransition.hermesSent;
        }
      }
    }
    const hostsByAlias = new Map<string, AuditResult["hosts"][number]>();
    for (const execution of executions) {
      const existing = hostsByAlias.get(execution.report.host);
      if (existing) {
        existing.wordpress.push(...execution.report.wordpress);
        if (execution.report.subscriptions) existing.subscriptions = [...new Set([...(existing.subscriptions ?? []), ...execution.report.subscriptions])];
        if (!existing.hostFacts && execution.report.hostFacts) existing.hostFacts = execution.report.hostFacts;
        if (execution.report.health) existing.health = execution.report.health;
        if (execution.report.warnings?.length) existing.warnings = [...new Set([...(existing.warnings ?? []), ...execution.report.warnings])];
      }
      else hostsByAlias.set(execution.report.host, { ...execution.report, subscriptions: execution.report.subscriptions ? [...execution.report.subscriptions] : undefined, wordpress: [...execution.report.wordpress] });
    }
    const hosts = [...hostsByAlias.values()];
    const preliminaryResult: AuditResult = {
      generatedAt: new Date().toISOString(),
      hosts,
      scanProgress: executions.map((execution): ScanProgress => ({
        host: execution.report.host,
        offset: execution.offset,
        scanned: execution.scannedInstallationPaths.length,
        complete: execution.complete,
      })),
    };
    const currentFindings = findingsFromAudits(preliminaryResult.hosts);
    const result: AuditResult = { ...preliminaryResult, findings: currentFindings, findingEvents };
    const reportPath = await writeAuditReport(result, process.env.MISE_PLESK_REPORTS ?? config.reportsDirectory ?? "reports", json, process.env.MISE_PLESK_REPORT_SUFFIX ?? "");
    await writeHeartbeat(heartbeatPath, { version: 1, target, startedAt, completedAt: new Date().toISOString(), reportPath });
    console.log(formatScanOutput(result, { reportPath, json, alertSent, whatsappSent, hermesSent }));
    return;
  }
    usage();
  } finally {
    await runLock?.release();
  }
}

main().catch(async (error: unknown) => {
  if (process.argv[2] === "scan") {
    try {
      const heartbeatPath = process.env.MISE_PLESK_HEARTBEAT ?? ".mise-en-plesk/heartbeat.json";
      const heartbeat = await readHeartbeat(heartbeatPath);
      if (heartbeat) await writeHeartbeat(heartbeatPath, { ...heartbeat, failedAt: new Date().toISOString() });
    } catch {
      // Preserve the original scan failure; heartbeat diagnostics are best effort.
    }
  }
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
});
