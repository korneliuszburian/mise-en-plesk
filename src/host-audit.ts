import { extractSecureNoteSshCredentials } from "./bitwarden";
import { getInventoryHostItem, type Inventory } from "./ssh-inventory";
import {
  createSshSession,
  DEFAULT_SSH_COMMAND_TIMEOUT_MS,
  scanPleskHost,
} from "./plesk-scan";
import type { ReadOnlyCommand } from "./ssh-transport";
import {
  auditWordPressInstallation,
  createBatchedWpRunners,
  type AuditResult,
  type WordPressAudit,
} from "./wp-audit";
import {
  createBoundedVulnerabilityLookup,
  type VulnerabilityCache,
} from "./vulnerabilities";
import { isCompleteScanPage } from "./scan-lifecycle";
import {
  createPleskWpToolkitRunner,
  enrichAuditWithPleskWpToolkit,
  parsePleskWpToolkitInventory,
  parseWpCliCapability,
  type PleskWpToolkitInventory,
  type WpCliCapability,
} from "./plesk-wp-toolkit";
import { auditStaticWordPressInstallation } from "./static-wp-audit";
import { enrichAuditWithSiteDiagnostics } from "./site-diagnostics";

export interface VulnerabilityLookupBudget {
  used: number;
}

interface HostWordPressCapabilities {
  initialized?: boolean;
  wpCli?: WpCliCapability;
  toolkit?: PleskWpToolkitInventory;
  warnings?: string[];
}

const hostAuditContextState = Symbol("hostAuditContextState");

export interface HostAuditContext {
  readonly [hostAuditContextState]: HostWordPressCapabilities;
}

export function createHostAuditContext(): HostAuditContext {
  return { [hostAuditContextState]: {} };
}

export interface HostAuditOptions {
  maxVulnerabilityLookups?: number;
  enableVulnerabilityLookups?: boolean;
  maxConcurrentSites?: number;
  maxSites?: number;
  offset?: number;
  vulnerabilityBudget?: VulnerabilityLookupBudget;
  useSudo?: boolean;
  vulnerabilityCache?: VulnerabilityCache;
  commandTimeoutMs?: number;
  context?: HostAuditContext;
  publicSiteChecks?: boolean;
  publicSiteCheckTimeoutMs?: number;
}

export interface HostAuditPage {
  report: AuditResult["hosts"][number];
  scannedInstallationPaths: string[];
  complete: boolean;
  offset: number;
}

export async function auditHost(
  alias: string,
  inventory: Inventory,
  options: HostAuditOptions = {},
): Promise<HostAuditPage> {
  const {
    maxVulnerabilityLookups,
    enableVulnerabilityLookups = false,
    maxConcurrentSites = 4,
    maxSites,
    offset = 0,
    vulnerabilityBudget = { used: 0 },
    useSudo = false,
    vulnerabilityCache,
    commandTimeoutMs = DEFAULT_SSH_COMMAND_TIMEOUT_MS,
    context = createHostAuditContext(),
    publicSiteChecks = true,
    publicSiteCheckTimeoutMs = 10_000,
  } = options;
  const hostCapabilities = context[hostAuditContextState];
  const host = inventory[alias];
  if (!host) throw new Error(`Unknown inventory target: ${alias}`);
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
    const wordpress: WordPressAudit[] = [];
    const vulnerabilityResourceLookup = createBoundedVulnerabilityLookup({
      enabled: enableVulnerabilityLookups,
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
            enabled: enableVulnerabilityLookups,
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
            enabled: enableVulnerabilityLookups,
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
              enabled: enableVulnerabilityLookups,
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
