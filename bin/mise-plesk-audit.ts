#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { getInventoryHostItem, readInventory, syncFromBitwarden } from "../src/ssh-inventory";
import { extractSecureNoteSshCredentials } from "../src/bitwarden";
import { runSshCommand, scanPleskHost } from "../src/plesk-scan";
import { auditWordPressInstallation, type AuditResult } from "../src/wp-audit";
import { writeAuditReport } from "../src/report";
import { lookupPluginVulnerabilities } from "../src/vulnerabilities";

const inventoryPath = process.env.MISE_PLESK_INVENTORY ?? "inventory.json";
const configPath = process.env.MISE_PLESK_CONFIG ?? "config.mise-en-plesk.json";

interface MisePleskConfig {
  reportsDirectory?: string;
  hosts?: string[];
  maxVulnerabilityLookupsPerHost?: number;
}

function usage(): never {
  console.error("Usage: mise-plesk-audit sync-ssh | scan <target|all> [--json]");
  process.exit(1);
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
): Promise<AuditResult["hosts"][number]> {
  const host = inventory[alias];
  const item = process.env.BW_SESSION ? await getInventoryHostItem(host) : null;
  const credentials = item ? extractSecureNoteSshCredentials(item) : null;
  console.error(`[${alias}] scanning Plesk host ${host.host}`);
  const ssh = (command: string) => runSshCommand(host, command, credentials?.password);
  const scan = await scanPleskHost(host, (_host, command) => ssh(command));
  let vulnerabilityLookups = 0;
  const wordpress = await Promise.all(scan.wordpress.map((installation) => auditWordPressInstallation(installation, undefined, {
    enabled: process.env.MISE_PLESK_ENABLE_VULNS === "1",
    vulnerabilityLookup: async (slug, options) => {
      if (process.env.MISE_PLESK_ENABLE_VULNS !== "1") return null;
      if (maxVulnerabilityLookups !== undefined && vulnerabilityLookups >= maxVulnerabilityLookups) return null;
      vulnerabilityLookups += 1;
      return lookupPluginVulnerabilities(slug, options);
    },
    suspiciousFileRunner: (_installation, command) => ssh(command),
  })));
  console.error(`[${alias}] found ${scan.subscriptions.length} subscription(s), ${scan.wordpress.length} WordPress installation(s)`);
  return { host: scan.host, wordpress };
}

async function main(): Promise<void> {
  const [command, target, ...flags] = process.argv.slice(2);
  const json = flags.includes("--json");
  if (flags.some((flag) => flag !== "--json")) usage();
  if (command === "sync-ssh") {
    const inventory = await syncFromBitwarden("mise-en-plesk", inventoryPath);
    console.log(`Synced ${Object.keys(inventory).length} host(s) to ${inventoryPath}.`);
    return;
  }
  if (command === "scan" && target) {
    const config = target === "all" ? await readConfig() : await readOptionalConfig();
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
    const hosts = [];
    for (const alias of aliases) hosts.push(await scanHost(alias, inventory, maxLookups));
    const result: AuditResult = {
      generatedAt: new Date().toISOString(),
      hosts,
    };
    const reportPath = await writeAuditReport(result, process.env.MISE_PLESK_REPORTS ?? config.reportsDirectory ?? "reports", json);
    console.log(`Read-only scan complete. Report written to ${reportPath}.`);
    return;
  }
  usage();
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
});
