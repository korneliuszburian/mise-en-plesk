#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { getInventoryHostItem, readInventory, syncFromBitwarden } from "../src/ssh-inventory";
import { extractSecureNoteSshCredentials } from "../src/bitwarden";
import { createSshSession, scanPleskHost } from "../src/plesk-scan";
import { auditWordPressInstallation, createBatchedWpRunners, type AuditResult, type WordPressAudit } from "../src/wp-audit";
import { writeAuditReport } from "../src/report";
import { createFileVulnerabilityCache, lookupVulnerabilities, type VulnerabilityCache } from "../src/vulnerabilities";
import { findingsFromAudits } from "../src/findings";
import { readFindingState, reconcileFindings, writeFindingState, type FindingScope, type FindingEvent } from "../src/finding-state";
import { notifyFindingEvents } from "../src/notifications";
import { notifyFindingEventsToWhatsApp } from "../src/whatsapp";
import {
  enqueueNotificationEvents,
  compactNotificationOutbox,
  markNotificationChannelSent,
  pendingNotificationEvents,
  readNotificationOutbox,
  writeNotificationOutbox,
} from "../src/notification-outbox";
import { runPreflight } from "../src/preflight";
import { createMonitorStaleFinding, readHeartbeat, writeHeartbeat } from "../src/monitor-health";
import { parseCliArguments } from "../src/cli-args";

const inventoryPath = process.env.MISE_PLESK_INVENTORY ?? "inventory.json";
const configPath = process.env.MISE_PLESK_CONFIG ?? "config.mise-en-plesk.json";

interface MisePleskConfig {
  reportsDirectory?: string;
  hosts?: string[];
  sudoHosts?: string[];
  maxVulnerabilityLookupsPerHost?: number;
  vulnerabilityCachePath?: string;
  vulnerabilityCacheTtlHours?: number;
  maxConcurrentSitesPerHost?: number;
  maxSitesPerHost?: number;
  findingsStatePath?: string;
  notificationOutboxPath?: string;
  heartbeatPath?: string;
  monitorMaxAgeHours?: number;
}

interface VulnerabilityLookupBudget {
  used: number;
}

function usage(): never {
  console.error("Usage: mise-plesk-audit doctor [--json] | monitor-health [--json] [--max-age-hours=N] | sync-ssh | scan <target|all> [--json] [--max-sites=N] [--offset=N] [--all-chunks]");
  process.exit(1);
}

function parseNonNegativeInteger(value: string, flag: string): number {
  if (!/^\d+$/.test(value)) throw new Error(`${flag} must be a non-negative integer.`);
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) throw new Error(`${flag} is too large.`);
  return parsed;
}

function readScanRange(flags: string[], config: MisePleskConfig): { json: boolean; maxSites?: number; offset: number; allChunks: boolean } {
  let json = false;
  let maxSites = config.maxSitesPerHost;
  let offset = 0;
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
  return { json, maxSites, offset, allChunks };
}

async function readConfig(): Promise<MisePleskConfig> {
  const value: unknown = JSON.parse(await readFile(configPath, "utf8"));
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`Config must be a JSON object: ${configPath}`);
  }
  const config = value as MisePleskConfig;
  if (config.hosts && (!Array.isArray(config.hosts) || config.hosts.some((host) => typeof host !== "string"))) {
    throw new Error(`Config hosts must be an array of aliases: ${configPath}`);
  }
  if (config.sudoHosts && (!Array.isArray(config.sudoHosts) || config.sudoHosts.some((host) => typeof host !== "string"))) {
    throw new Error(`Config sudoHosts must be an array of aliases: ${configPath}`);
  }
  if (config.monitorMaxAgeHours !== undefined && (!Number.isFinite(config.monitorMaxAgeHours) || config.monitorMaxAgeHours <= 0)) {
    throw new Error(`Config monitorMaxAgeHours must be a positive number: ${configPath}`);
  }
  return config;
}

async function readOptionalConfig(): Promise<MisePleskConfig> {
  try {
    return await readConfig();
  } catch (error: unknown) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") return {};
    throw error;
  }
}

async function deliverNotifications(
  events: FindingEvent[],
  config: MisePleskConfig,
): Promise<{ webhookSent: boolean; whatsappSent: boolean }> {
  const outboxPath = process.env.MISE_PLESK_NOTIFICATION_OUTBOX
    ?? config.notificationOutboxPath
    ?? ".mise-en-plesk/notification-outbox.json";
  let outbox = await readNotificationOutbox(outboxPath);
  outbox = enqueueNotificationEvents(outbox, events);
  await writeNotificationOutbox(outboxPath, outbox);

  const pendingWebhook = pendingNotificationEvents(outbox, "webhook");
  const notification = await notifyFindingEvents(pendingWebhook, {
    webhookUrl: process.env.MISE_PLESK_ALERT_WEBHOOK_URL,
    debug: (message) => console.error(message),
  });
  if (notification.sent) outbox = markNotificationChannelSent(outbox, "webhook", pendingWebhook);

  const pendingWhatsApp = pendingNotificationEvents(outbox, "whatsapp");
  const whatsapp = await notifyFindingEventsToWhatsApp(pendingWhatsApp, {
    accessToken: process.env.MISE_PLESK_WHATSAPP_ACCESS_TOKEN,
    phoneNumberId: process.env.MISE_PLESK_WHATSAPP_PHONE_NUMBER_ID,
    recipient: process.env.MISE_PLESK_WHATSAPP_RECIPIENT,
    templateName: process.env.MISE_PLESK_WHATSAPP_TEMPLATE_NAME,
    templateLanguage: process.env.MISE_PLESK_WHATSAPP_TEMPLATE_LANGUAGE,
    graphVersion: process.env.MISE_PLESK_WHATSAPP_GRAPH_VERSION,
    debug: (message) => console.error(message),
  });
  if (whatsapp.sent) outbox = markNotificationChannelSent(outbox, "whatsapp", pendingWhatsApp);
  await writeNotificationOutbox(outboxPath, compactNotificationOutbox(outbox));
  return { webhookSent: notification.sent, whatsappSent: whatsapp.sent };
}

async function persistFindingBatch(
  hosts: AuditResult["hosts"],
  findingState: Awaited<ReturnType<typeof readFindingState>>,
  findingStatePath: string,
  scope: FindingScope,
  occurredAt: string,
  config: MisePleskConfig,
): Promise<{ state: Awaited<ReturnType<typeof readFindingState>>; events: FindingEvent[]; notificationSent: boolean; whatsappSent: boolean }> {
  const transition = reconcileFindings(findingState, findingsFromAudits(hosts), occurredAt, scope);
  await writeFindingState(findingStatePath, transition.state);
  const delivery = await deliverNotifications(transition.events, config);
  return {
    state: transition.state,
    events: transition.events,
    notificationSent: delivery.webhookSent,
    whatsappSent: delivery.whatsappSent,
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
): Promise<{ report: AuditResult["hosts"][number]; scannedInstallationPaths: string[]; complete: boolean }> {
  const host = inventory[alias];
  const item = process.env.BW_SESSION ? await getInventoryHostItem(host) : null;
  const credentials = item ? extractSecureNoteSshCredentials(item) : null;
  console.error(`[${alias}] scanning Plesk host ${host.host}`);
  const session = await createSshSession(host, credentials?.password, useSudo ? credentials?.password : undefined);
  try {
    const ssh = (command: string) => session.run(command);
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
        wordpress,
        ...(scan.hostFacts ? { hostFacts: scan.hostFacts } : {}),
        ...(scan.warnings ? { warnings: scan.warnings } : {}),
      },
      scannedInstallationPaths,
      complete: maxSites === undefined
        ? offset === 0
        : scan.wordpressHasMore === false && (offset === 0 || selectedWordPress.length > 0),
    };
  } finally {
    await session.close();
  }
}

async function main(): Promise<void> {
  const { command, target, flags } = parseCliArguments(process.argv.slice(2));
  const json = flags.includes("--json");
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
    const transition = reconcileFindings(
      previousState,
      staleFinding ? [staleFinding] : [],
      now.toISOString(),
      { installationPaths: new Set(["__monitor__"]) },
    );
    await writeFindingState(findingStatePath, transition.state);
    const notification = await deliverNotifications(transition.events, config);
    const result = { heartbeatPath, heartbeat, stale: Boolean(staleFinding), findingEvents: transition.events };
    if (jsonOutput) console.log(JSON.stringify(result, null, 2));
    else console.log(staleFinding ? `Monitor is stale: ${heartbeatPath}` : `Monitor is healthy: ${heartbeat?.completedAt ?? "unknown"}`);
    if (notification.webhookSent) console.error("Sent pending monitor webhook alert(s).");
    if (notification.whatsappSent) console.error("Sent pending monitor WhatsApp alert(s).");
    return;
  }
  if (command === "scan" && target) {
    const config = target === "all" ? await readConfig() : await readOptionalConfig();
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
    const executions = [];
    const findingStatePath = process.env.MISE_PLESK_FINDINGS ?? config.findingsStatePath ?? ".mise-en-plesk/findings.json";
    let findingState = await readFindingState(findingStatePath);
    const findingEvents: FindingEvent[] = [];
    let alertSent = false;
    let whatsappSent = false;
    for (const alias of aliases) {
      let offset = scanRange.offset;
      const vulnerabilityBudget = { used: 0 };
      const useSudo = config.sudoHosts?.includes(alias) ?? false;
      const hostWordPress: WordPressAudit[] = [];
      while (true) {
        const execution = await scanHost(alias, inventory, maxLookups, maxConcurrentSites, scanRange.maxSites, offset, vulnerabilityBudget, useSudo, vulnerabilityCache);
        executions.push(execution);
        hostWordPress.push(...execution.report.wordpress);
        const batchTransition = await persistFindingBatch(
          [execution.report],
          findingState,
          findingStatePath,
          { installationPaths: new Set(execution.scannedInstallationPaths) },
          new Date().toISOString(),
          config,
        );
        findingState = batchTransition.state;
        findingEvents.push(...batchTransition.events);
        alertSent ||= batchTransition.notificationSent;
        whatsappSent ||= batchTransition.whatsappSent;
        if (!scanRange.allChunks || execution.complete) break;
        if (!execution.scannedInstallationPaths.length) throw new Error(`[${alias}] bounded scan made no progress at offset ${offset}.`);
        offset += execution.scannedInstallationPaths.length;
      }
      if (scanRange.offset === 0 && executions.at(-1)?.complete) {
        const finalExecution = executions.at(-1)!;
        const completeTransition = await persistFindingBatch(
          [{ ...finalExecution.report, wordpress: hostWordPress }],
          findingState,
          findingStatePath,
          { completeHosts: new Set([finalExecution.report.host]) },
          new Date().toISOString(),
          config,
        );
        findingState = completeTransition.state;
        findingEvents.push(...completeTransition.events);
        alertSent ||= completeTransition.notificationSent;
        whatsappSent ||= completeTransition.whatsappSent;
      }
    }
    const hostsByAlias = new Map<string, AuditResult["hosts"][number]>();
    for (const execution of executions) {
      const existing = hostsByAlias.get(execution.report.host);
      if (existing) {
        existing.wordpress.push(...execution.report.wordpress);
        if (!existing.hostFacts && execution.report.hostFacts) existing.hostFacts = execution.report.hostFacts;
        if (execution.report.warnings?.length) existing.warnings = [...new Set([...(existing.warnings ?? []), ...execution.report.warnings])];
      }
      else hostsByAlias.set(execution.report.host, { ...execution.report, wordpress: [...execution.report.wordpress] });
    }
    const hosts = [...hostsByAlias.values()];
    const preliminaryResult: AuditResult = {
      generatedAt: new Date().toISOString(),
      hosts,
    };
    const currentFindings = findingsFromAudits(preliminaryResult.hosts);
    const result: AuditResult = { ...preliminaryResult, findings: currentFindings, findingEvents };
    const reportPath = await writeAuditReport(result, process.env.MISE_PLESK_REPORTS ?? config.reportsDirectory ?? "reports", json);
    await writeHeartbeat(heartbeatPath, { version: 1, target, startedAt, completedAt: new Date().toISOString(), reportPath });
    const eventSummary = findingEvents.length
      ? ` ${findingEvents.length} finding state change(s): ${findingEvents.map((event) => event.type).join(", ")}.`
      : " No finding state changes.";
    console.log(`Read-only scan complete. Report written to ${reportPath}.`);
    console.log(`Open findings: ${currentFindings.length}.${eventSummary}`);
    if (alertSent) console.log("Sent pending P1 alert(s).");
    if (whatsappSent) console.log("Sent pending P1 WhatsApp alert(s).");
    return;
  }
  usage();
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
