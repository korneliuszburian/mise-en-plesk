import { AuditCapabilityUnavailableError, type WordPressAudit, type WpCommandRunner } from "./wp-audit";
import { READ_ONLY_WP_COMMANDS } from "./ssh-transport";

export interface PleskWpToolkitExtension {
  name: string;
  version: string;
  active: boolean;
  hasUpdate: boolean;
}

export interface PleskWpToolkitSite {
  id: number;
  fullPath: string;
  version: string;
  outdatedWp: boolean;
  unsupportedPhp: boolean;
  broken: boolean;
  infected: boolean;
  alive?: boolean;
  stateText?: string;
  plugins: PleskWpToolkitExtension[];
  themes: PleskWpToolkitExtension[];
}

export interface PleskWpToolkitInventory {
  sites: Map<string, PleskWpToolkitSite>;
  warnings: string[];
}

export interface PleskWpToolkitDiagnostics {
  source: "wp-cli" | "plesk-wp-toolkit" | "hybrid";
  limitations: string[];
}

export interface WpCliCapability {
  available: boolean;
  version?: string;
  detail?: string;
}

export function parseWpCliCapability(output: string): WpCliCapability {
  const match = output.match(/__MISE_WP_CLI_BEGIN__\r?\n([\s\S]*?)\r?\n__MISE_WP_CLI_STATUS_(\d+)__\r?\n__MISE_WP_CLI_END__/);
  if (!match) throw new Error("WP-CLI returned an invalid capability envelope");
  const detail = match[1].trim().replace(/\s+/g, " ").slice(0, 240);
  const version = detail.match(/WP-CLI\s+(\d+(?:\.\d+)+)/i)?.[1];
  const available = Number(match[2]) === 0 && version !== undefined;
  return { available, ...(version ? { version } : {}), ...(detail ? { detail } : {}) };
}

function record(value: unknown, context: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${context} must be a JSON object`);
  return value as Record<string, unknown>;
}

function bool(value: unknown): boolean {
  return value === true;
}

function optionalBool(value: unknown): boolean | undefined {
  return typeof value === "boolean" ? value : undefined;
}

function canonicalPath(value: unknown): string {
  if (typeof value !== "string" || !value.startsWith("/var/www/vhosts/") || /[\u0000-\u001f\u007f]/.test(value)) {
    throw new Error("WP Toolkit site has invalid fullPath");
  }
  return value.length > 1 ? value.replace(/\/+$/, "") : value;
}

function extensions(value: unknown, context: string): PleskWpToolkitExtension[] {
  if (value === undefined || value === null || Array.isArray(value) && value.length === 0) return [];
  const source = record(value, context);
  return Object.values(source).map((item) => {
    const extension = record(item, `${context} entry`);
    const name = typeof extension.name === "string" ? extension.name : "";
    if (!name) throw new Error(`${context} entry has invalid name`);
    return {
      name,
      version: typeof extension.version === "string" ? extension.version : "",
      active: extension.status === "active",
      hasUpdate: typeof extension.update_version === "string" && extension.update_version.length > 0,
    };
  });
}

export function parsePleskWpToolkitInventory(output: string): PleskWpToolkitInventory {
  const value: unknown = JSON.parse(output);
  if (!Array.isArray(value)) throw new Error("WP Toolkit inventory must be a JSON array");
  const grouped = new Map<string, PleskWpToolkitSite[]>();
  for (const item of value) {
    const site = record(item, "WP Toolkit site");
    const fullPath = canonicalPath(site.fullPath);
    if (!Number.isSafeInteger(site.id) || Number(site.id) < 1) throw new Error(`WP Toolkit site ${fullPath} has invalid id`);
    const normalized: PleskWpToolkitSite = {
      id: Number(site.id),
      fullPath,
      version: typeof site.version === "string" ? site.version : "unknown",
      outdatedWp: bool(site.outdatedWp),
      unsupportedPhp: bool(site.unsupportedPhp),
      broken: bool(site.broken),
      infected: bool(site.infected),
      alive: optionalBool(site.alive),
      stateText: typeof site.stateText === "string" ? site.stateText : undefined,
      plugins: extensions(site.plugins, `WP Toolkit plugins for ${fullPath}`),
      themes: extensions(site.themes, `WP Toolkit themes for ${fullPath}`),
    };
    grouped.set(fullPath, [...(grouped.get(fullPath) ?? []), normalized]);
  }
  const sites = new Map<string, PleskWpToolkitSite>();
  const warnings: string[] = [];
  for (const [fullPath, candidates] of grouped) {
    const ranked = [...candidates].sort((left, right) => toolkitSiteScore(right) - toolkitSiteScore(left) || left.id - right.id);
    const selected = ranked[0];
    if (candidates.length === 1) {
      sites.set(fullPath, selected);
      continue;
    }
    const ids = candidates.map((site) => site.id).sort((left, right) => left - right);
    warnings.push(`WP Toolkit returned duplicate registrations for ${fullPath} (IDs ${ids.join(", ")}); merged conservatively.`);
    sites.set(fullPath, {
      ...selected,
      outdatedWp: candidates.some((site) => site.outdatedWp),
      unsupportedPhp: candidates.some((site) => site.unsupportedPhp),
      broken: candidates.some((site) => site.broken),
      infected: candidates.some((site) => site.infected),
      alive: candidates.some((site) => site.alive === false)
        ? false
        : candidates.some((site) => site.alive === true) ? true : undefined,
      plugins: mergeExtensions(selected.plugins, candidates.flatMap((site) => site.plugins)),
      themes: mergeExtensions(selected.themes, candidates.flatMap((site) => site.themes)),
    });
  }
  return { sites, warnings };
}

function toolkitSiteScore(site: PleskWpToolkitSite): number {
  return (site.alive === true ? 1_000 : 0)
    + (site.broken ? 0 : 500)
    + (site.version === "unknown" ? 0 : 100)
    + site.plugins.length
    + site.themes.length;
}

function mergeExtensions(preferred: PleskWpToolkitExtension[], all: PleskWpToolkitExtension[]): PleskWpToolkitExtension[] {
  const merged = new Map(preferred.map((extension) => [extension.name, extension]));
  for (const extension of all) {
    const existing = merged.get(extension.name);
    if (!existing) merged.set(extension.name, extension);
    else if (extension.hasUpdate && !existing.hasUpdate) merged.set(extension.name, { ...existing, hasUpdate: true });
  }
  return [...merged.values()];
}

function pluginJson(site: PleskWpToolkitSite): string {
  return JSON.stringify(site.plugins.map((plugin) => ({
    name: plugin.name,
    status: plugin.active ? "active" : "inactive",
    update: plugin.hasUpdate ? "available" : "none",
    version: plugin.version,
    update_version: plugin.hasUpdate ? "available" : "",
  })));
}

function themeJson(site: PleskWpToolkitSite): string {
  return JSON.stringify(site.themes.map((theme) => ({
    name: theme.name,
    status: theme.active ? "active" : "inactive",
    update: theme.hasUpdate ? "available" : "none",
    version: theme.version,
    update_version: theme.hasUpdate ? "available" : "",
    auto_update: "off",
  })));
}

export function createPleskWpToolkitRunner(
  site: PleskWpToolkitSite,
  primary?: WpCommandRunner,
): { runner: WpCommandRunner; diagnostics(): PleskWpToolkitDiagnostics } {
  let primarySucceeded = false;
  let toolkitUsed = false;
  const unavailable = new Set<string>();
  const primaryFailures = new Set<string>();

  const fallback = (command: string): string => {
    toolkitUsed = true;
    if (command === READ_ONLY_WP_COMMANDS[0]) return site.version;
    if (command === READ_ONLY_WP_COMMANDS[1]) return site.outdatedWp ? "[{}]" : "[]";
    if (command === READ_ONLY_WP_COMMANDS[3]) {
      unavailable.add("WordPress.org plugin freshness metadata unavailable");
      return pluginJson(site);
    }
    if (command === READ_ONLY_WP_COMMANDS[5]) return themeJson(site);
    if (command === READ_ONLY_WP_COMMANDS[2]) {
      unavailable.add("core checksum verification unavailable");
      throw new AuditCapabilityUnavailableError("Plesk WP Toolkit does not expose core checksum verification in inventory mode");
    }
    if (command === READ_ONLY_WP_COMMANDS[4]) {
      unavailable.add("plugin checksum verification unavailable");
      throw new AuditCapabilityUnavailableError("Plesk WP Toolkit does not expose plugin checksum verification in inventory mode");
    }
    throw new AuditCapabilityUnavailableError(`Plesk WP Toolkit cannot provide: ${command}`);
  };

  return {
    runner: async (installation, command) => {
      if (primary) {
        try {
          const output = await primary(installation, command);
          primarySucceeded = true;
          return output;
        } catch (error: unknown) {
          const detail = (error instanceof Error ? error.message : String(error)).replace(/\s+/g, " ").trim().slice(0, 160);
          if (command === READ_ONLY_WP_COMMANDS[2] || command === READ_ONLY_WP_COMMANDS[4]) {
            if (!isWpCliCapabilityFailure(detail)) throw error;
            const limitation = command === READ_ONLY_WP_COMMANDS[2]
              ? "core checksum verification unavailable"
              : "plugin checksum verification unavailable";
            unavailable.add(limitation);
            if (detail) primaryFailures.add(`WP-CLI fallback used: ${detail}`);
            throw new AuditCapabilityUnavailableError(detail || limitation);
          }
          if (detail) primaryFailures.add(`WP-CLI fallback used: ${detail}`);
          return fallback(command);
        }
      }
      return fallback(command);
    },
    diagnostics: () => ({
      source: toolkitUsed ? primarySucceeded ? "hybrid" : "plesk-wp-toolkit" : "wp-cli",
      limitations: [...primaryFailures, ...unavailable],
    }),
  };
}

function isWpCliCapabilityFailure(detail: string): boolean {
  return /PHP version.*requires at least|requires PHP|command not found|no such file|\b404(?::)?\s*not found|permission denied|sudo:|parse error|syntax error|fatal error/i.test(detail);
}

export function enrichAuditWithPleskWpToolkit(
  audit: WordPressAudit,
  site: PleskWpToolkitSite,
  diagnostics: PleskWpToolkitDiagnostics,
): WordPressAudit {
  const toolkitSignals = {
    infected: site.infected,
    broken: site.broken,
    alive: site.alive,
    unsupportedPhp: site.unsupportedPhp,
    ...(site.stateText ? { stateText: site.stateText } : {}),
  };
  const toolkitPriorities = [
    ...(site.infected ? ["Plesk WP Toolkit reports the installation as infected"] : []),
    ...(site.broken ? ["Plesk WP Toolkit reports the installation as broken"] : []),
    ...(site.unsupportedPhp ? ["Plesk WP Toolkit reports an unsupported PHP runtime"] : []),
    ...(site.alive === false ? ["Plesk WP Toolkit reports the installation as not alive"] : []),
  ].filter((priority) => !audit.priorities.includes(priority));
  return {
    ...audit,
    auditSource: diagnostics.source,
    ...(diagnostics.limitations.length ? { limitations: diagnostics.limitations } : {}),
    toolkitSignals,
    priorities: [...audit.priorities, ...toolkitPriorities],
  };
}
