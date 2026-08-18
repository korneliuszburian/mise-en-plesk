import type { WordPressInstallation } from "./plesk-scan";
import { lookupPluginVulnerabilities, type PluginVulnerabilitySummary, type VulnerabilityLookupOptions } from "./vulnerabilities";
import type { Finding } from "./findings";
import type { FindingEvent } from "./finding-state";

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
  health: {
    reachable: boolean;
    lastUpdate?: string;
    status?: "runtime-incompatible" | "wp-cli-error" | "unreachable";
    detail?: string;
  };
  priorities: string[];
}

export interface AuditResult {
  generatedAt: string;
  hosts: Array<{ host: string; wordpress: WordPressAudit[] }>;
  findings?: Finding[];
  findingEvents?: FindingEvent[];
}

export type WpCommandRunner = (installation: WordPressInstallation, command: string) => Promise<string>;
export type SuspiciousFileRunner = (installation: WordPressInstallation, command: string) => Promise<string>;

interface BatchSection {
  output: string;
  status: number;
}

export function buildWpAuditBatchCommand(installation: WordPressInstallation): string {
  const commands = {
    core: buildWpCliCommand(installation, "core version"),
    plugins: buildWpCliCommand(installation, "plugin list --format=json --fields=name,status,update,version,update_version,wporg_status,wporg_last_updated"),
    checksums: buildWpCliCommand(installation, "core verify-checksums"),
    uploads: `find ${shellQuote(`${installation.path}/wp-content/uploads`)} -type f -name '*.php' -print`,
  };
  return Object.entries(commands).map(([name, command]) => [
    `printf '%s\\n' '__MISE_${name.toUpperCase()}_BEGIN__'`,
    `value=$(${command} 2>&1)`,
    "status=$?",
    "printf '%s\\n' \"$value\"",
    `printf '%s\\n' "__MISE_${name.toUpperCase()}_STATUS_\${status}__"`,
    `printf '%s\\n' '__MISE_${name.toUpperCase()}_END__'`,
  ].join("; ")).join("; ");
}

function parseBatchSections(output: string): Map<string, BatchSection> {
  const sections = new Map<string, BatchSection>();
  for (const name of ["CORE", "PLUGINS", "CHECKSUMS", "UPLOADS"]) {
    const match = output.match(new RegExp(`__MISE_${name}_BEGIN__\\n([\\s\\S]*?)\\n__MISE_${name}_STATUS_(\\d+)__\\n__MISE_${name}_END__`));
    if (match) sections.set(name.toLowerCase(), { output: match[1], status: Number(match[2]) });
  }
  return sections;
}

export function createBatchedWpRunners(
  installation: WordPressInstallation,
  remoteRunner: (command: string) => Promise<string>,
): { runner: WpCommandRunner; suspiciousFileRunner: SuspiciousFileRunner } {
  let sectionsPromise: Promise<Map<string, BatchSection>> | undefined;
  const sections = async (): Promise<Map<string, BatchSection>> => {
    sectionsPromise ??= remoteRunner(buildWpAuditBatchCommand(installation)).then(parseBatchSections);
    return sectionsPromise;
  };
  const read = async (name: string): Promise<string> => {
    const section = (await sections()).get(name);
    if (!section) throw new Error(`WP audit batch did not return ${name} output.`);
    if (section.status !== 0) throw new Error(section.output || `WP ${name} command failed.`);
    return section.output;
  };
  return {
    runner: async (_installation, command) => {
      if (command === "core version") return read("core");
      if (command.startsWith("plugin list")) return read("plugins");
      if (command === "core verify-checksums") return read("checksums");
      throw new Error(`Unsupported batched WP command: ${command}`);
    },
    suspiciousFileRunner: async () => read("uploads"),
  };
}

export interface WordPressAuditOptions extends VulnerabilityLookupOptions {
  abandonmentDays?: number;
  now?: Date;
  vulnerabilityLookup?: typeof lookupPluginVulnerabilities;
  suspiciousFileRunner?: SuspiciousFileRunner;
}

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", "'\\''")}'`;
}

export function buildWpCliCommand(installation: WordPressInstallation, command: string): string {
  return `wp ${command} --path=${shellQuote(installation.path)} --allow-root`;
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
  let coreVersion = "unknown";
  try {
    coreVersion = (await runner(installation, "core version")).trim();
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
  } catch (error: unknown) {
    const health = classifyAuditError(error);
    return applyHeuristics({
      installation,
      coreVersion,
      plugins: [],
      vulnerabilities: [],
      suspiciousFiles: [],
      health,
    }, options);
  }
}

function classifyAuditError(error: unknown): WordPressAudit["health"] {
  const detail = error instanceof Error ? error.message : String(error);
  const shortDetail = detail.replace(/\s+/g, " ").trim().slice(0, 240);
  if (/PHP version.*requires at least|requires PHP/i.test(detail)) {
    return { reachable: true, status: "runtime-incompatible", detail: shortDetail };
  }
  if (/connection refused|connection reset|connection closed|permission denied|timed out|could not resolve|kex_exchange|wp unavailable|no route to host/i.test(detail)) {
    return { reachable: false, status: "unreachable", detail: shortDetail };
  }
  return { reachable: true, status: "wp-cli-error", detail: shortDetail };
}

export function parseSuspiciousFiles(output: string): string[] {
  return output.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
}

export function applyHeuristics(
  audit: Omit<WordPressAudit, "priorities">,
  options: Pick<WordPressAuditOptions, "abandonmentDays" | "now"> = {},
): WordPressAudit {
  const priorities: string[] = [];
  if (isVeryOldCore(audit.coreVersion)) priorities.push("core is very old");
  if (!audit.health.reachable) priorities.push("installation is unreachable");
  if (audit.health.status === "runtime-incompatible") {
    priorities.push("WordPress runtime is incompatible with the installed PHP version");
  } else if (audit.health.status === "wp-cli-error") {
    priorities.push("WP-CLI audit failed; manual review required");
  }
  const now = options.now ?? new Date();
  const abandonmentDays = options.abandonmentDays ?? 365;
  const abandonmentMonths = Math.round(abandonmentDays / 30);
  for (const plugin of audit.plugins) {
    if (plugin.hasUpdate) priorities.push(`plugin ${plugin.name} has an update available`);
    if (isPluginAbandoned(plugin, now, abandonmentDays)) priorities.push(`plugin ${plugin.name} appears abandoned (no wp.org updates in > ${abandonmentMonths} months)`);
    if (plugin.vulnerabilities.length) {
      const severe = plugin.vulnerabilities.find((item) => ["high", "critical"].includes(item.severity?.toLowerCase() ?? ""));
      priorities.push(`plugin ${plugin.name} has known vulnerabilities (via WPVulnerability)${severe?.severity ? `: ${severe.severity}` : ""}`);
    }
  }
  if (audit.suspiciousFiles.length) priorities.push("PHP files found in uploads (possible backdoors)");
  return { ...audit, priorities };
}

export function isVeryOldCore(coreVersion: string): boolean {
  return /^(4|5)\./.test(coreVersion);
}

export function isPluginAbandoned(
  plugin: Pick<PluginInfo, "wporgStatus" | "wporgLastUpdated">,
  now = new Date(),
  abandonmentDays = 365,
): boolean {
  const lastUpdated = plugin.wporgLastUpdated ? Date.parse(plugin.wporgLastUpdated) : Number.NaN;
  return (plugin.wporgStatus !== undefined && plugin.wporgStatus !== "active")
    || !Number.isNaN(lastUpdated) && now.getTime() - lastUpdated > abandonmentDays * 24 * 60 * 60 * 1000;
}
