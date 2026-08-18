import type { WordPressInstallation } from "./plesk-scan";
import {
  lookupPluginVulnerabilities,
  lookupVulnerabilities,
  type PluginVulnerability,
  type PluginVulnerabilitySummary,
  type VulnerabilityLookupOptions,
  type VulnerabilityLookupStatus,
  type VulnerabilityResource,
} from "./vulnerabilities";
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

export interface ThemeInfo {
  name: string;
  version: string;
  active: boolean;
  hasUpdate: boolean;
  vulnerabilities?: PluginVulnerability[];
}

export type ChecksumStatus = "verified" | "failed";

export interface WordPressAudit {
  installation: WordPressInstallation;
  coreVersion: string;
  coreUpdateAvailable?: boolean;
  plugins: PluginInfo[];
  themes?: ThemeInfo[];
  vulnerabilities: PluginVulnerabilitySummary[];
  coreVulnerabilities?: PluginVulnerability[];
  vulnerabilityStatus?: "disabled" | "complete" | "partial" | "unavailable";
  vulnerabilityCheckedAt?: string;
  suspiciousFiles: string[];
  integrity?: {
    coreChecksums: ChecksumStatus;
    pluginChecksums: ChecksumStatus;
  };
  health: {
    reachable: boolean;
    lastUpdate?: string;
    status?: "runtime-incompatible" | "wp-cli-error" | "wp-cli-missing" | "wp-cli-permission-denied" | "wp-cli-broken" | "unreachable";
    detail?: string;
  };
  priorities: string[];
}

export interface AuditResult {
  generatedAt: string;
  hosts: Array<{ host: string; wordpress: WordPressAudit[]; warnings?: string[] }>;
  findings?: Finding[];
  findingEvents?: FindingEvent[];
}

export type WpCommandRunner = (installation: WordPressInstallation, command: string) => Promise<string>;
export type SuspiciousFileRunner = (installation: WordPressInstallation, command: string) => Promise<string>;

interface BatchSection {
  output: string;
  status: number;
}

export function buildWpAuditBatchCommand(installation: WordPressInstallation, options: { useSudo?: boolean } = {}): string {
  const prefix = options.useSudo ? "sudo -S -p '' -- " : "";
  const commands = {
    core: buildWpCliCommand(installation, "core version", options),
    coreUpdate: buildWpCliCommand(installation, "core check-update --minor --format=json", options),
    plugins: buildWpCliCommand(installation, "plugin list --format=json --fields=name,status,update,version,update_version,wporg_status,wporg_last_updated", options),
    pluginChecksums: buildWpCliCommand(installation, "plugin verify-checksums --all --strict", options),
    themes: buildWpCliCommand(installation, "theme list --format=json --fields=name,status,version,update,update_version,auto_update", options),
    checksums: buildWpCliCommand(installation, "core verify-checksums", options),
    uploads: `${prefix}find ${shellQuote(`${installation.path}/wp-content/uploads`)} -type f -name '*.php' -print`,
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
  for (const name of ["CORE", "CORE_UPDATE", "PLUGINS", "PLUGIN_CHECKSUMS", "THEMES", "CHECKSUMS", "UPLOADS"]) {
    const match = output.match(new RegExp(`__MISE_${name}_BEGIN__\\n([\\s\\S]*?)\\n__MISE_${name}_STATUS_(\\d+)__\\n__MISE_${name}_END__`));
    if (match) sections.set(name.toLowerCase(), { output: match[1], status: Number(match[2]) });
  }
  return sections;
}

export function createBatchedWpRunners(
  installation: WordPressInstallation,
  remoteRunner: (command: string) => Promise<string>,
  options: { useSudo?: boolean } = {},
): { runner: WpCommandRunner; suspiciousFileRunner: SuspiciousFileRunner } {
  let sectionsPromise: Promise<Map<string, BatchSection>> | undefined;
  const sections = async (): Promise<Map<string, BatchSection>> => {
    sectionsPromise ??= remoteRunner(buildWpAuditBatchCommand(installation, options)).then(parseBatchSections);
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
      if (command === "core check-update --minor --format=json") return read("core_update");
      if (command.startsWith("plugin list")) return read("plugins");
      if (command.startsWith("plugin verify-checksums")) return read("plugin_checksums");
      if (command.startsWith("theme list")) return read("themes");
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
  vulnerabilityResourceLookup?: typeof lookupVulnerabilities;
  suspiciousFileRunner?: SuspiciousFileRunner;
}

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", "'\\''")}'`;
}

export function buildWpCliCommand(installation: WordPressInstallation, command: string, options: { useSudo?: boolean } = {}): string {
  return `${options.useSudo ? "sudo -S -p '' -- " : ""}wp ${command} --path=${shellQuote(installation.path)} --allow-root`;
}

export function pluginSlug(name: string): string {
  const [slug] = name.split("/", 1);
  return slug || name;
}

function vulnerabilityApiEnabled(options: VulnerabilityLookupOptions): boolean {
  return options.enabled ?? process.env.MISE_PLESK_ENABLE_VULNS === "1";
}

function summarizeVulnerabilityStatus(statuses: VulnerabilityLookupStatus[]): WordPressAudit["vulnerabilityStatus"] {
  if (!statuses.length || statuses.every((status) => status === "disabled")) return "disabled";
  if (statuses.some((status) => status === "unavailable")) return "unavailable";
  if (statuses.some((status) => status === "skipped")) return "partial";
  return "complete";
}

export async function auditWordPressInstallation(
  installation: WordPressInstallation,
  runner: WpCommandRunner,
  options: WordPressAuditOptions = {},
): Promise<WordPressAudit> {
  let coreVersion = "unknown";
  try {
    coreVersion = (await runner(installation, "core version")).trim();
    const vulnerabilityStatuses: VulnerabilityLookupStatus[] = [];
    const vulnerabilityCheckedAt: string[] = [];
    const lookupResource = options.vulnerabilityResourceLookup ?? lookupVulnerabilities;
    const resourceResult = async (resource: VulnerabilityResource, identifier: string) => {
      const result = await lookupResource(resource, identifier, options);
      vulnerabilityStatuses.push(result.status);
      if (result.checkedAt) vulnerabilityCheckedAt.push(result.checkedAt);
      return result;
    };
    let coreUpdateAvailable: boolean | undefined;
    try {
      coreUpdateAvailable = parseCoreUpdateAvailable(await runner(installation, "core check-update --minor --format=json"));
    } catch {
      coreUpdateAvailable = undefined;
    }
    const pluginOutput = await runner(installation, "plugin list --format=json --fields=name,status,update,version,update_version,wporg_status,wporg_last_updated");
    const rawPlugins: unknown = JSON.parse(pluginOutput);
    if (!Array.isArray(rawPlugins)) throw new Error(`wp plugin list returned invalid JSON for ${installation.path}`);
    const plugins = await Promise.all(rawPlugins.map(async (plugin) => {
      if (!plugin || typeof plugin !== "object") throw new Error("wp plugin list contained an invalid item");
      const value = plugin as Record<string, unknown>;
      const name = String(value.name ?? "");
      let vulnerabilitySummary: PluginVulnerabilitySummary | null = null;
      if (options.vulnerabilityLookup) {
        vulnerabilitySummary = await options.vulnerabilityLookup(pluginSlug(name), options);
        vulnerabilityStatuses.push(vulnerabilitySummary ? "known" : vulnerabilityApiEnabled(options) ? "unavailable" : "disabled");
      } else {
        const result = await resourceResult("plugin", pluginSlug(name));
        vulnerabilitySummary = result.summary ? { slug: pluginSlug(name), vulnerabilities: result.summary.vulnerabilities } : null;
      }
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
    let coreChecksums: ChecksumStatus = "verified";
    try {
      await runner(installation, "core verify-checksums");
    } catch {
      coreChecksums = "failed";
    }
    let pluginChecksums: ChecksumStatus = "verified";
    try {
      await runner(installation, "plugin verify-checksums --all --strict");
    } catch {
      pluginChecksums = "failed";
    }
    let themes: ThemeInfo[] | undefined;
    try {
      const rawThemes: unknown = JSON.parse(await runner(installation, "theme list --format=json --fields=name,status,version,update,update_version,auto_update"));
      if (!Array.isArray(rawThemes)) throw new Error("wp theme list returned invalid JSON");
      themes = await Promise.all(rawThemes.map(async (theme) => {
        if (!theme || typeof theme !== "object") throw new Error("wp theme list contained an invalid item");
        const value = theme as Record<string, unknown>;
        const name = String(value.name ?? "");
        const vulnerabilityResult = await resourceResult("theme", name);
        return {
          name,
          version: String(value.version ?? ""),
          active: value.status === "active",
          hasUpdate: value.update === "available" || Boolean(value.update_version),
          ...(vulnerabilityResult.summary?.vulnerabilities.length ? { vulnerabilities: vulnerabilityResult.summary.vulnerabilities } : {}),
        };
      }));
    } catch {
      themes = undefined;
    }
    const coreVulnerabilityResult = await resourceResult("core", coreVersion);
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
      return summary.length ? [{ slug: pluginSlug(plugin.name), vulnerabilities: summary }] : [];
    });
    const vulnerabilityStatus = summarizeVulnerabilityStatus(vulnerabilityStatuses);
    return applyHeuristics({
      installation,
      coreVersion,
      coreUpdateAvailable,
      plugins,
      themes,
      vulnerabilities,
      ...(coreVulnerabilityResult.summary?.vulnerabilities.length ? { coreVulnerabilities: coreVulnerabilityResult.summary.vulnerabilities } : {}),
      ...(vulnerabilityStatus !== "disabled" ? { vulnerabilityStatus } : {}),
      ...(vulnerabilityCheckedAt.length ? { vulnerabilityCheckedAt: vulnerabilityCheckedAt.sort().at(-1) } : {}),
      suspiciousFiles,
      integrity: { coreChecksums, pluginChecksums },
      health: { reachable: true },
    }, options);
  } catch (error: unknown) {
    const health = classifyAuditError(error);
    return applyHeuristics({
      installation,
      coreVersion,
      plugins: [],
      themes: [],
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
  if (/sudo:|must be run as root/i.test(detail)) {
    return { reachable: true, status: "wp-cli-permission-denied", detail: shortDetail };
  }
  if (/connection refused|connection reset|connection closed|permission denied|timed out|could not resolve|kex_exchange|wp unavailable|no route to host/i.test(detail)) {
    return { reachable: false, status: "unreachable", detail: shortDetail };
  }
  if (/command not found|no such file or directory/i.test(detail)) {
    return { reachable: true, status: "wp-cli-missing", detail: shortDetail };
  }
  if (/404.*not found|parse error|syntax error|fatal error|unexpected token/i.test(detail)) {
    return { reachable: true, status: "wp-cli-broken", detail: shortDetail };
  }
  return { reachable: true, status: "wp-cli-error", detail: shortDetail };
}

function isWpCliFailure(status?: WordPressAudit["health"]["status"]): boolean {
  return status === "wp-cli-error"
    || status === "wp-cli-missing"
    || status === "wp-cli-permission-denied"
    || status === "wp-cli-broken";
}

export function parseSuspiciousFiles(output: string): string[] {
  return output.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
}

export function parseCoreUpdateAvailable(output: string): boolean {
  const value: unknown = JSON.parse(output);
  if (Array.isArray(value)) return value.length > 0;
  if (value && typeof value === "object") return true;
  throw new Error("wp core check-update returned invalid JSON");
}

export function applyHeuristics(
  audit: Omit<WordPressAudit, "priorities">,
  options: Pick<WordPressAuditOptions, "abandonmentDays" | "now"> = {},
): WordPressAudit {
  const priorities: string[] = [];
  if (isVeryOldCore(audit.coreVersion)) priorities.push("core is very old");
  if (audit.coreUpdateAvailable) priorities.push("WordPress core update available");
  if (!audit.health.reachable) priorities.push("installation is unreachable");
  if (audit.health.status === "runtime-incompatible") {
    priorities.push("WordPress runtime is incompatible with the installed PHP version");
  } else if (isWpCliFailure(audit.health.status)) {
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
  for (const theme of audit.themes ?? []) {
    if (theme.hasUpdate) priorities.push(`theme ${theme.name} has an update available`);
    if (theme.vulnerabilities?.length) priorities.push(`theme ${theme.name} has known vulnerabilities (via WPVulnerability)`);
  }
  if (audit.coreVulnerabilities?.length) priorities.push("WordPress core has known vulnerabilities (via WPVulnerability)");
  if (audit.integrity?.coreChecksums === "failed") priorities.push("WordPress core checksum verification failed");
  if (audit.integrity?.pluginChecksums === "failed") priorities.push("WordPress plugin checksum verification needs manual review");
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
