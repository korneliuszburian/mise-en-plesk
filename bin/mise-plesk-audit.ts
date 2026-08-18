#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { getInventoryHostItem, readInventory, syncFromBitwarden } from "../src/ssh-inventory";
import { extractSecureNoteSshCredentials } from "../src/bitwarden";
import { createSshSession, scanPleskHost } from "../src/plesk-scan";
import { auditWordPressInstallation, createBatchedWpRunners, type AuditResult } from "../src/wp-audit";
import { writeAuditReport } from "../src/report";
import { lookupPluginVulnerabilities } from "../src/vulnerabilities";
import { findingsFromAudits } from "../src/findings";
import { readFindingState, reconcileFindings, writeFindingState, type FindingScope } from "../src/finding-state";
import { notifyFindingEvents } from "../src/notifications";
import { notifyFindingEventsToWhatsApp } from "../src/whatsapp";
import { runPreflight } from "../src/preflight";

const inventoryPath = process.env.MISE_PLESK_INVENTORY ?? "inventory.json";
const configPath = process.env.MISE_PLESK_CONFIG ?? "config.mise-en-plesk.json";

interface MisePleskConfig {
  reportsDirectory?: string;
  hosts?: string[];
  maxVulnerabilityLookupsPerHost?: number;
  maxConcurrentSitesPerHost?: number;
  maxSitesPerHost?: number;
  findingsStatePath?: string;
}

function usage(): never {
  console.error("Usage: mise-plesk-audit doctor [--json] | sync-ssh | scan <target|all> [--json] [--max-sites=N] [--offset=N]");
  process.exit(1);
}

function parseNonNegativeInteger(value: string, flag: string): number {
  if (!/^\d+$/.test(value)) throw new Error(`${flag} must be a non-negative integer.`);
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) throw new Error(`${flag} is too large.`);
  return parsed;
}

function readScanRange(flags: string[], config: MisePleskConfig): { json: boolean; maxSites?: number; offset: number } {
  let json = false;
  let maxSites = config.maxSitesPerHost;
  let offset = 0;
  for (const flag of flags) {
    if (flag === "--json") {
      json = true;
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
  return { json, maxSites, offset };
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

async function scanHost(
  alias: string,
  inventory: Awaited<ReturnType<typeof readInventory>>,
  maxVulnerabilityLookups?: number,
  maxConcurrentSites = 4,
  maxSites?: number,
  offset = 0,
): Promise<{ report: AuditResult["hosts"][number]; scannedInstallationPaths: string[]; complete: boolean }> {
  const host = inventory[alias];
  const item = process.env.BW_SESSION ? await getInventoryHostItem(host) : null;
  const credentials = item ? extractSecureNoteSshCredentials(item) : null;
  console.error(`[${alias}] scanning Plesk host ${host.host}`);
  const session = await createSshSession(host, credentials?.password);
  try {
    const ssh = (command: string) => session.run(command);
    const scan = await scanPleskHost(host, (_host, command) => ssh(command));
    const selectedWordPress = maxSites === undefined
      ? scan.wordpress.slice(offset)
      : scan.wordpress.slice(offset, offset + maxSites);
    const scannedInstallationPaths = selectedWordPress.map((installation) => installation.path);
    let vulnerabilityLookups = 0;
    const wordpress = [];
    for (let index = 0; index < selectedWordPress.length; index += maxConcurrentSites) {
      const batch = selectedWordPress.slice(index, index + maxConcurrentSites);
      wordpress.push(...await Promise.all(batch.map(async (installation) => {
        const batched = createBatchedWpRunners(installation, ssh);
        return auditWordPressInstallation(installation, batched.runner, {
          enabled: process.env.MISE_PLESK_ENABLE_VULNS === "1",
          vulnerabilityLookup: async (slug, options) => {
            if (process.env.MISE_PLESK_ENABLE_VULNS !== "1") return null;
            if (maxVulnerabilityLookups !== undefined && vulnerabilityLookups >= maxVulnerabilityLookups) return null;
            vulnerabilityLookups += 1;
            return lookupPluginVulnerabilities(slug, options);
          },
          suspiciousFileRunner: batched.suspiciousFileRunner,
        });
      })));
      console.error(`[${alias}] audited ${Math.min(index + batch.length, selectedWordPress.length)}/${selectedWordPress.length} selected WordPress installation(s)`);
    }
    console.error(`[${alias}] found ${scan.subscriptions.length} subscription(s), ${scan.wordpress.length} WordPress installation(s); selected ${selectedWordPress.length} at offset ${offset}`);
    return {
      report: { host: scan.host, wordpress },
      scannedInstallationPaths,
      complete: maxSites === undefined ? offset === 0 : offset < scan.wordpress.length && offset + selectedWordPress.length >= scan.wordpress.length,
    };
  } finally {
    await session.close();
  }
}

async function main(): Promise<void> {
  const [command, target, ...flags] = process.argv.slice(2);
  const json = flags.includes("--json");
  if (command === "doctor") {
    const result = await runPreflight({ inventoryPath, configPath });
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
  if (command === "scan" && target) {
    const config = target === "all" ? await readConfig() : await readOptionalConfig();
    const scanRange = readScanRange(flags, config);
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
    const maxConcurrentSites = config.maxConcurrentSitesPerHost ?? 4;
    if (!Number.isInteger(maxConcurrentSites) || maxConcurrentSites < 1) {
      throw new Error("maxConcurrentSitesPerHost must be a positive integer.");
    }
    const executions = [];
    for (const alias of aliases) executions.push(await scanHost(alias, inventory, maxLookups, maxConcurrentSites, scanRange.maxSites, scanRange.offset));
    const hosts = executions.map((execution) => execution.report);
    const preliminaryResult: AuditResult = {
      generatedAt: new Date().toISOString(),
      hosts,
    };
    const currentFindings = findingsFromAudits(preliminaryResult.hosts);
    const findingStatePath = process.env.MISE_PLESK_FINDINGS ?? config.findingsStatePath ?? ".mise-en-plesk/findings.json";
    const findingState = await readFindingState(findingStatePath);
    const findingScope: FindingScope = {
      completeHosts: new Set(executions.filter((execution) => execution.complete).map((execution) => execution.report.host)),
      installationPaths: new Set(executions.flatMap((execution) => execution.scannedInstallationPaths)),
    };
    const transition = reconcileFindings(
      findingState,
      currentFindings,
      preliminaryResult.generatedAt,
      findingScope,
    );
    await writeFindingState(findingStatePath, transition.state);
    const notification = await notifyFindingEvents(transition.events, {
      webhookUrl: process.env.MISE_PLESK_ALERT_WEBHOOK_URL,
      debug: (message) => console.error(message),
    });
    const whatsapp = await notifyFindingEventsToWhatsApp(transition.events, {
      accessToken: process.env.MISE_PLESK_WHATSAPP_ACCESS_TOKEN,
      phoneNumberId: process.env.MISE_PLESK_WHATSAPP_PHONE_NUMBER_ID,
      recipient: process.env.MISE_PLESK_WHATSAPP_RECIPIENT,
      templateName: process.env.MISE_PLESK_WHATSAPP_TEMPLATE_NAME,
      templateLanguage: process.env.MISE_PLESK_WHATSAPP_TEMPLATE_LANGUAGE,
      graphVersion: process.env.MISE_PLESK_WHATSAPP_GRAPH_VERSION,
      debug: (message) => console.error(message),
    });
    const result: AuditResult = { ...preliminaryResult, findings: currentFindings, findingEvents: transition.events };
    const reportPath = await writeAuditReport(result, process.env.MISE_PLESK_REPORTS ?? config.reportsDirectory ?? "reports", json);
    const eventSummary = transition.events.length
      ? ` ${transition.events.length} finding state change(s): ${transition.events.map((event) => event.type).join(", ")}.`
      : " No finding state changes.";
    console.log(`Read-only scan complete. Report written to ${reportPath}.`);
    console.log(`Open findings: ${currentFindings.length}.${eventSummary}`);
    if (notification.sent) console.log(`Sent ${notification.eligibleEvents} P1 alert(s).`);
    if (whatsapp.sent) console.log(`Sent ${whatsapp.eligibleEvents} P1 WhatsApp alert(s).`);
    return;
  }
  usage();
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
});
