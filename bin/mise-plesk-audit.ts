#!/usr/bin/env node
import { getInventoryHostItem, readInventory, syncFromBitwarden } from "../src/ssh-inventory";
import { extractSecureNoteSshCredentials } from "../src/bitwarden";
import { createSshSession, scanPleskHost, DEFAULT_SSH_COMMAND_TIMEOUT_MS } from "../src/plesk-scan";
import type { ReadOnlyCommand } from "../src/ssh-transport";
import { auditWordPressInstallation, createBatchedWpRunners, type AuditResult, type WordPressAudit, type ScanProgress } from "../src/wp-audit";
import { writeAuditReport } from "../src/report";
import { createBoundedVulnerabilityLookup, createFileVulnerabilityCache, type VulnerabilityCache } from "../src/vulnerabilities";
import { findingsFromAudits } from "../src/findings";
import { readFindingState, reconcileFindings, writeFindingState, type FindingScope, type FindingEvent } from "../src/finding-state";
import { appendScanCycleFindings, completeScanCycle, prepareScanCycle, readScanCycleState, writeScanCycleState } from "../src/scan-cycle";
import type { Finding } from "../src/findings";
import { notifyFindingEventsToWhatsApp } from "../src/whatsapp";
import { sendFindingEventsViaHermes, sendHermesText } from "../src/hermes";
import { createNotificationAdapters } from "../src/notification-adapters";
import { createNotificationDelivery, type NotificationDelivery } from "../src/notification-delivery";
import { runPreflight } from "../src/preflight";
import { createMonitorStaleFinding, readHeartbeat, reconcileDeferredHosts, writeHeartbeat } from "../src/monitor-health";
import { parseCliArguments } from "../src/cli-args";
import { readConfigFile, type MisePleskConfig } from "../src/config";
import { acquireLocalLock, type LocalLock } from "../src/local-lock";
import { createWhatsAppTestEvent, requireWhatsAppTestConfirmation } from "../src/notification-test";
import { formatScanOutput } from "../src/cli-output";
import { isCompleteScanCycle, isCompleteScanPage, nextScanOffset } from "../src/scan-lifecycle";
import { shouldContinueScanChunks } from "../src/scan-budget";
import { readRemoteCapabilities } from "../src/remote-preflight";
import {
  createPleskWpToolkitRunner,
  enrichAuditWithPleskWpToolkit,
  parsePleskWpToolkitInventory,
  parseWpCliCapability,
  type PleskWpToolkitInventory,
  type WpCliCapability,
} from "../src/plesk-wp-toolkit";
import { auditStaticWordPressInstallation } from "../src/static-wp-audit";
import { enrichAuditWithSiteDiagnostics } from "../src/site-diagnostics";

const inventoryPath = process.env.MISE_PLESK_INVENTORY ?? "inventory.json";
const configPath = process.env.MISE_PLESK_CONFIG ?? "config.mise-en-plesk.json";

interface VulnerabilityLookupBudget {
  used: number;
}

interface HostWordPressCapabilities {
  initialized?: boolean;
  wpCli?: WpCliCapability;
  toolkit?: PleskWpToolkitInventory;
  warnings?: string[];
}

function usage(): never {
  console.error("Scan options: [--max-sites=N] [--offset=N] [--max-chunks=N] [--all-chunks]");
  console.error("Usage: mise-plesk-audit doctor [--json] | remote-preflight <target> [--json] | monitor-health [--json] [--max-age-hours=N] | sync-ssh | whatsapp-test --confirm=<recipient> | hermes-test --confirm=<target> | scan <target|all> [--json] [--max-sites=N] [--offset=N] [--all-chunks]");
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
): Promise<{ state: Awaited<ReturnType<typeof readFindingState>>; events: FindingEvent[]; notificationAccepted: boolean; whatsappAccepted: boolean; hermesAccepted: boolean }> {
  const transition = reconcileFindings(findingState, findings, occurredAt, scope);
  await delivery.enqueue(transition.events);
  await writeFindingState(findingStatePath, transition.state);
  const notification = await delivery.flush();
  return {
    state: transition.state,
    events: transition.events,
    notificationAccepted: notification.webhookAccepted,
    whatsappAccepted: notification.whatsappAccepted,
    hermesAccepted: notification.hermesAccepted,
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
  hostCapabilities: HostWordPressCapabilities = {},
  publicSiteChecks = true,
  publicSiteCheckTimeoutMs = 10_000,
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
    const capabilityWarnings = [...(scan.warnings ?? [])];
    if (!hostCapabilities.initialized) {
      let wpCli: WpCliCapability = { available: false, detail: "WP-CLI capability probe unavailable" };
      try {
        wpCli = parseWpCliCapability(await ssh({ kind: "wp-cli-capability", useSudo: effectiveSudo }));
      } catch (error: unknown) {
        capabilityWarnings.push(`WP-CLI capability probe failed: ${error instanceof Error ? error.message : "unknown error"}`);
      }
      let toolkit: PleskWpToolkitInventory = { sites: new Map(), warnings: [] };
      if (scan.pleskCliAvailable !== false) {
        try {
          toolkit = parsePleskWpToolkitInventory(await ssh({ kind: "plesk-wp-toolkit-inventory", useSudo: effectiveSudo }));
          capabilityWarnings.push(...toolkit.warnings);
        } catch (error: unknown) {
          capabilityWarnings.push(`Plesk WP Toolkit inventory unavailable: ${error instanceof Error ? error.message : "unknown error"}`);
        }
      }
      hostCapabilities.initialized = true;
      hostCapabilities.wpCli = wpCli;
      hostCapabilities.toolkit = toolkit;
      hostCapabilities.warnings = capabilityWarnings.slice(scan.warnings?.length ?? 0);
    } else {
      capabilityWarnings.push(...(hostCapabilities.warnings ?? []));
    }
    const wpCliCapability = hostCapabilities.wpCli ?? { available: false, detail: "WP-CLI capability probe unavailable" };
    const toolkitInventory = hostCapabilities.toolkit ?? { sites: new Map(), warnings: [] };
    if (!wpCliCapability.available && toolkitInventory.sites.size) {
      capabilityWarnings.push(`Host WP-CLI unavailable (${wpCliCapability.detail ?? "unknown reason"}); using the Plesk WP Toolkit bridge with metadata fallback.`);
    }
    for (const warning of capabilityWarnings.slice(scan.warnings?.length ?? 0)) console.error(`[${alias}] warning: ${warning}`);
    const selectedWordPress = maxSites === undefined ? scan.wordpress.slice(offset) : scan.wordpress;
    const scannedInstallationPaths = selectedWordPress.map((installation) => installation.path);
    const wordpress = [];
    const vulnerabilityResourceLookup = createBoundedVulnerabilityLookup({
      enabled: process.env.MISE_PLESK_ENABLE_VULNS === "1",
      maxLookups: maxVulnerabilityLookups,
      budget: vulnerabilityBudget,
      cache: vulnerabilityCache,
    });
    for (let index = 0; index < selectedWordPress.length; index += maxConcurrentSites) {
      const batch = selectedWordPress.slice(index, index + maxConcurrentSites);
      wordpress.push(...await Promise.all(batch.map(async (installation) => {
        const toolkitSite = toolkitInventory.sites.get(installation.path.replace(/\/+$/, ""));
        let audit: WordPressAudit;
        if (!toolkitSite && !wpCliCapability.available) {
          audit = await auditStaticWordPressInstallation(installation, ssh, {
            useSudo: effectiveSudo,
            enabled: process.env.MISE_PLESK_ENABLE_VULNS === "1",
            vulnerabilityResourceLookup,
            sourceLimitations: [
              `Host WP-CLI unavailable: ${wpCliCapability.detail ?? "unknown reason"}`,
              "Plesk WP Toolkit has no matching installation registration",
            ],
          });
        } else {
          const batched = toolkitSite
            ? createBatchedWpRunners(installation, ssh, {
              useSudo: effectiveSudo,
              runtime: { kind: "plesk-wp-toolkit", instanceId: toolkitSite.id },
            })
            : wpCliCapability.available ? createBatchedWpRunners(installation, ssh, { useSudo: effectiveSudo }) : undefined;
          const toolkit = toolkitSite ? createPleskWpToolkitRunner(toolkitSite, batched?.runner) : undefined;
          const runner = toolkit?.runner ?? batched?.runner ?? (async () => {
            throw new Error(wpCliCapability.detail || "wp: command not found");
          });
          audit = await auditWordPressInstallation(installation, runner, {
            useSudo: effectiveSudo,
            enabled: process.env.MISE_PLESK_ENABLE_VULNS === "1",
            vulnerabilityResourceLookup,
            suspiciousFileRunner: batched?.suspiciousFileRunner ?? (async () => ssh({
              kind: "suspicious-uploads",
              installationPath: installation.path,
              useSudo: effectiveSudo,
            })),
          });
          if (!toolkitSite && audit.health.status && audit.health.status !== "unreachable") {
            audit = await auditStaticWordPressInstallation(installation, ssh, {
              useSudo: effectiveSudo,
              enabled: process.env.MISE_PLESK_ENABLE_VULNS === "1",
              vulnerabilityResourceLookup,
              observedHealth: audit.health,
              sourceLimitations: [
                `WP-CLI audit failed for this installation: ${audit.health.detail ?? audit.health.status}`,
                "Plesk WP Toolkit has no matching installation registration",
              ],
            });
          } else if (toolkit && toolkitSite) {
            audit = { ...enrichAuditWithPleskWpToolkit(audit, toolkitSite, toolkit.diagnostics()), wpCliTransport: "plesk-wp-toolkit" as const };
          } else if (wpCliCapability.available) {
            audit = { ...audit, auditSource: "wp-cli" as const };
          } else {
            audit = {
              ...audit,
              auditSource: "none" as const,
              limitations: [
                `Host WP-CLI unavailable: ${wpCliCapability.detail ?? "unknown reason"}`,
                "Plesk WP Toolkit has no matching installation registration",
              ],
            };
          }
        }
        return enrichAuditWithSiteDiagnostics(audit, ssh, {
          enabled: publicSiteChecks,
          timeoutMs: publicSiteCheckTimeoutMs,
          useSudo: effectiveSudo,
          pleskCliAvailable: scan.pleskCliAvailable,
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
        ...(capabilityWarnings.length ? { warnings: capabilityWarnings } : {}),
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
    if (result.outcome !== "accepted") {
      throw new Error(`WhatsApp test submission was not accepted (outcome: ${result.outcome}).`);
    }
    console.log(`WhatsApp test message accepted by Meta (${result.providerReceipts.map((receipt) => receipt.providerMessageId).join(", ")}).`);
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
    console.log("Hermes test message accepted by Hermes.");
    return;
  }
  if (command === "remote-preflight" && target) {
    if (flags.some((flag) => flag !== "--json")) usage();
    const preflight = await runPreflight({ inventoryPath, configPath, env: process.env });
    const blockingFailures = preflight.checks
      .filter((check) => check.blocking && !check.ok)
      .map((check) => `${check.name}: ${check.detail}`);
    if (blockingFailures.length) throw new Error(`Preflight failed: ${blockingFailures.join("; ")}`);
    const inventory = await readInventory(inventoryPath);
    const host = inventory[target];
    if (!host) throw new Error(`Unknown inventory target: ${target}`);
    const item = await getInventoryHostItem(host);
    const credentials = extractSecureNoteSshCredentials(item);
    const session = await createSshSession(host, credentials?.password, undefined, DEFAULT_SSH_COMMAND_TIMEOUT_MS);
    try {
      const capabilities = await readRemoteCapabilities(host, (_host, readOnlyCommand) => session.run(readOnlyCommand));
      if (json) console.log(JSON.stringify({ target, host: host.host, capabilities }, null, 2));
      else {
        console.log(`${target}: ${capabilities.username ?? "unknown user"} (uid ${capabilities.uid ?? "unknown"})`);
        console.log(`kernel: ${capabilities.kernel ?? "unknown"}`);
        for (const [name, path] of Object.entries(capabilities.commands)) console.log(`${name}: ${path ?? "not found"}`);
      }
    } finally {
      await session.close();
    }
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
    if (notification.webhookAccepted) console.error("Provider accepted pending monitor webhook alert(s).");
    if (notification.whatsappAccepted) console.error("Provider accepted pending monitor WhatsApp alert(s).");
    if (notification.hermesAccepted) console.error("Provider accepted pending monitor Hermes alert(s).");
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
    const previousHeartbeat = await readHeartbeat(heartbeatPath);
    await writeHeartbeat(heartbeatPath, {
      version: 1,
      target,
      startedAt,
      ...(previousHeartbeat?.deferredSince ? { deferredSince: previousHeartbeat.deferredSince } : {}),
    });
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
    let alertAccepted = false;
    let whatsappAccepted = false;
    let hermesAccepted = false;
    for (const alias of aliases) {
      let offset = scanRange.offset;
      const vulnerabilityBudget = { used: 0 };
      const hostCapabilities: HostWordPressCapabilities = {};
      const useSudo = config.sudoHosts?.includes(alias) ?? false;
      const hostWordPress: WordPressAudit[] = [];
      const hostExecutions: Array<Awaited<ReturnType<typeof scanHost>>> = [];
      let chunksProcessed = 0;
      scanCycleState = prepareScanCycle(scanCycleState, alias, scanRange.offset, startedAt);
      await writeScanCycleState(scanCycleStatePath, scanCycleState);
      while (true) {
        const execution = await scanHost(
          alias,
          inventory,
          maxLookups,
          maxConcurrentSites,
          scanRange.maxSites,
          offset,
          vulnerabilityBudget,
          useSudo,
          vulnerabilityCache,
          config.sshCommandTimeoutMs ?? DEFAULT_SSH_COMMAND_TIMEOUT_MS,
          hostCapabilities,
          (config.publicSiteChecks ?? true) && process.env.MISE_PLESK_DISABLE_PUBLIC_SITE_CHECKS !== "1",
          config.publicSiteCheckTimeoutMs ?? 10_000,
        );
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
        alertAccepted ||= batchTransition.notificationAccepted;
        whatsappAccepted ||= batchTransition.whatsappAccepted;
        hermesAccepted ||= batchTransition.hermesAccepted;
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
          alertAccepted ||= completeTransition.notificationAccepted;
          whatsappAccepted ||= completeTransition.whatsappAccepted;
          hermesAccepted ||= completeTransition.hermesAccepted;
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
    const scanComplete = isCompleteScanCycle(
      scanRange.offset,
      aliases.map((alias) => executions.filter((execution) => execution.report.host === alias).at(-1)?.complete === true),
    );
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
    const completedAt = new Date().toISOString();
    const deferredSince = reconcileDeferredHosts(
      previousHeartbeat?.deferredSince,
      aliases.map((alias) => {
        const finalExecution = executions.filter((execution) => execution.report.host === alias).at(-1);
        return {
          host: alias,
          progressed: Boolean(finalExecution && (finalExecution.complete || finalExecution.scannedInstallationPaths.length > 0)),
        };
      }),
      completedAt,
    );
    await writeHeartbeat(heartbeatPath, {
      version: 1,
      target,
      startedAt,
      completedAt,
      scanComplete,
      reportPath,
      ...(Object.keys(deferredSince).length ? { deferredSince } : {}),
    });
    console.log(formatScanOutput(result, { reportPath, json, alertAccepted, whatsappAccepted, hermesAccepted }));
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
