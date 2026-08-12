import type { WordPressInstallation } from "./plesk-scan";
import { lookupPluginVulnerabilities, type PluginVulnerabilitySummary, type VulnerabilityLookupOptions } from "./vulnerabilities";

export interface PluginInfo {
  name: string;
  version: string;
  active: boolean;
  hasUpdate: boolean;
  wporgStatus?: string;
  wporgLastUpdated?: string;
  vulnerabilities: PluginVulnerabilitySummary["vulnerabilities"];
}

export interface WordPressAudit {
  installation: WordPressInstallation;
  coreVersion: string;
  plugins: PluginInfo[];
  vulnerabilities: PluginVulnerabilitySummary[];
  suspiciousFiles: string[];
  health: { reachable: boolean; lastUpdate?: string };
  priorities: string[];
}

export interface AuditResult {
  generatedAt: string;
  hosts: Array<{ host: string; wordpress: WordPressAudit[] }>;
}

export type WpCommandRunner = (installation: WordPressInstallation, command: string) => Promise<string>;
export type SuspiciousFileRunner = (installation: WordPressInstallation, command: string) => Promise<string>;

export interface WordPressAuditOptions extends VulnerabilityLookupOptions {
  abandonmentDays?: number;
  now?: Date;
  vulnerabilityLookup?: typeof lookupPluginVulnerabilities;
  suspiciousFileRunner?: SuspiciousFileRunner;
}

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", "'\\''")}'`;
}

const defaultWpRunner: WpCommandRunner = async (installation, command) => {
  const { execFile } = await import("node:child_process");
  const { promisify } = await import("node:util");
  const result = await promisify(execFile)("wp", [
    ...command.split(/\s+/),
    `--path=${installation.path}`,
    "--allow-root",
  ]);
  return result.stdout;
};

export async function auditWordPressInstallation(
  installation: WordPressInstallation,
  runner: WpCommandRunner = defaultWpRunner,
  options: WordPressAuditOptions = {},
): Promise<WordPressAudit> {
  try {
    const coreVersion = (await runner(installation, "core version")).trim();
    const pluginOutput = await runner(installation, "plugin list --format=json --fields=name,status,update,version,update_version,wporg_status,wporg_last_updated");
    const rawPlugins: unknown = JSON.parse(pluginOutput);
    if (!Array.isArray(rawPlugins)) throw new Error(`wp plugin list returned invalid JSON for ${installation.path}`);
    const plugins = await Promise.all(rawPlugins.map(async (plugin) => {
      if (!plugin || typeof plugin !== "object") throw new Error("wp plugin list contained an invalid item");
      const value = plugin as Record<string, unknown>;
      const name = String(value.name ?? "");
      const vulnerabilitySummary = await (options.vulnerabilityLookup ?? lookupPluginVulnerabilities)(name, options);
      return {
        name,
        version: String(value.version ?? ""),
        active: value.status === "active",
        hasUpdate: value.update === "available" || Boolean(value.update_version),
        wporgStatus: typeof value.wporg_status === "string" ? value.wporg_status : undefined,
        wporgLastUpdated: typeof value.wporg_last_updated === "string" ? value.wporg_last_updated : undefined,
        vulnerabilities: vulnerabilitySummary?.vulnerabilities ?? [],
      };
    }));
    await runner(installation, "core verify-checksums");
    let suspiciousFiles: string[] = [];
    if (options.suspiciousFileRunner) {
      try {
        suspiciousFiles = parseSuspiciousFiles(await options.suspiciousFileRunner(
          installation,
          `find ${shellQuote(`${installation.path}/wp-content/uploads`)} -type f -name '*.php' -print`,
        ));
      } catch {
        suspiciousFiles = [];
      }
    }
    const vulnerabilities = plugins.flatMap((plugin) => {
      const summary = plugin.vulnerabilities;
      return summary.length ? [{ slug: plugin.name, vulnerabilities: summary }] : [];
    });
    return applyHeuristics({ installation, coreVersion, plugins, vulnerabilities, suspiciousFiles, health: { reachable: true } }, options);
  } catch {
    return applyHeuristics({
      installation,
      coreVersion: "unknown",
      plugins: [],
      vulnerabilities: [],
      suspiciousFiles: [],
      health: { reachable: false },
    }, options);
  }
}

export function parseSuspiciousFiles(output: string): string[] {
  return output.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
}

export function applyHeuristics(
  audit: Omit<WordPressAudit, "priorities">,
  options: Pick<WordPressAuditOptions, "abandonmentDays" | "now"> = {},
): WordPressAudit {
  const priorities: string[] = [];
  if (/^(4|5)\./.test(audit.coreVersion)) priorities.push("core is very old");
  if (!audit.health.reachable) priorities.push("installation is unreachable");
  const now = (options.now ?? new Date()).getTime();
  const abandonmentDays = options.abandonmentDays ?? 365;
  const abandonmentMs = abandonmentDays * 24 * 60 * 60 * 1000;
  const abandonmentMonths = Math.round(abandonmentDays / 30);
  for (const plugin of audit.plugins) {
    if (plugin.hasUpdate) priorities.push(`plugin ${plugin.name} has an update available`);
    const lastUpdated = plugin.wporgLastUpdated ? Date.parse(plugin.wporgLastUpdated) : Number.NaN;
    const abandoned = plugin.wporgStatus !== undefined && plugin.wporgStatus !== "active"
      || !Number.isNaN(lastUpdated) && now - lastUpdated > abandonmentMs;
    if (abandoned) priorities.push(`plugin ${plugin.name} appears abandoned (no wp.org updates in > ${abandonmentMonths} months)`);
    if (plugin.vulnerabilities.length) {
      const severe = plugin.vulnerabilities.find((item) => ["high", "critical"].includes(item.severity?.toLowerCase() ?? ""));
      priorities.push(`plugin ${plugin.name} has known vulnerabilities (via WPVulnerability)${severe?.severity ? `: ${severe.severity}` : ""}`);
    }
  }
  if (audit.suspiciousFiles.length) priorities.push("PHP files found in uploads (possible backdoors)");
  return { ...audit, priorities };
}
