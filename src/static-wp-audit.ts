import { randomBytes } from "node:crypto";
import { posix } from "node:path";
import type { WordPressInstallation } from "./plesk-scan";
import { applyHeuristics, summarizeVulnerabilityStatus, type PluginInfo, type ThemeInfo, type WordPressAudit } from "./wp-audit";
import {
  lookupVulnerabilities,
  type VulnerabilityLookupOptions,
  type VulnerabilityLookupStatus,
  type VulnerabilityResource,
  type VulnerabilityResourceSummary,
} from "./vulnerabilities";
import {
  renderReadOnlyCommand,
  STATIC_WP_AUDIT_SECTIONS,
  type ReadOnlyCommand,
  type StaticWpAuditSection,
} from "./ssh-transport";
import { parseFramedBatch, type FramedBatchSection } from "./framed-batch";

export interface StaticWpAuditOptions extends VulnerabilityLookupOptions {
  useSudo?: boolean;
  vulnerabilityResourceLookup?: typeof lookupVulnerabilities;
  sourceLimitations?: string[];
  observedHealth?: WordPressAudit["health"];
}

export type StaticWpAuditRunner = (command: ReadOnlyCommand) => Promise<string>;

function bedrockDocumentRoot(installation: WordPressInstallation): string {
  return installation.pathEvidence?.some((evidence) => evidence.signal === "wp-includes/version.php" && evidence.rootKind === "core-root")
    && posix.basename(installation.path) === "wp"
    ? posix.dirname(installation.path)
    : installation.path;
}

export function buildStaticAuditBatchCommand(installation: WordPressInstallation, options: StaticWpAuditOptions = {}): string {
  return renderReadOnlyCommand({
    kind: "static-wp-audit-batch",
    installationPath: installation.path,
    bedrockDocumentRoot: bedrockDocumentRoot(installation),
    useSudo: options.useSudo,
    markerNonce: randomBytes(16).toString("hex"),
  });
}

function parseStaticSections(output: string, nonce: string): Map<StaticWpAuditSection, FramedBatchSection> {
  return parseFramedBatch(output, nonce, STATIC_WP_AUDIT_SECTIONS, "static WordPress audit");
}

function parseVersion(section: FramedBatchSection | undefined): string | undefined {
  if (!section || section.status !== 0) return undefined;
  return section.output.match(/\$wp_version\s*=\s*['"]([^'"]+)['"]\s*;/)?.[1];
}

interface StaticRead<T> {
  availability: "available" | "unavailable";
  value: T;
}

function names(section: FramedBatchSection | undefined): StaticRead<string[]> {
  if (!section || section.status !== 0) return { availability: "unavailable", value: [] };
  const value = [...new Set(section.output.split(/\r?\n/)
    .map((value) => value.trim())
    .filter((value) => value !== "index.php" && /^[A-Za-z0-9._-]+$/.test(value)))].sort();
  return { availability: "available", value };
}

function suspiciousFiles(section: FramedBatchSection | undefined, uploadsRoot: string): StaticRead<string[]> {
  if (!section || section.status !== 0) return { availability: "unavailable", value: [] };
  const prefix = `${uploadsRoot}/`;
  const value = [...new Set(section.output.split(/\r?\n/).map((value) => value.trim()).filter((value) => value.startsWith(prefix) && value.endsWith(".php")))].sort();
  return { availability: "available", value };
}

function containsExactPath(section: FramedBatchSection | undefined, expected: string): boolean {
  return section?.status === 0 && section.output.split(/\r?\n/).some((value) => value.trim() === expected);
}

function safeStaticFailureDetail(error: unknown): string {
  const detail = error instanceof Error ? error.message : String(error);
  if (/timed out|timeout/i.test(detail)) return "static filesystem probe timed out";
  if (/output exceeded/i.test(detail)) return "static filesystem probe exceeded the scanner output limit";
  if (/permission denied|sudo:/i.test(detail)) return "static filesystem probe permission denied";
  if (/invalid .* framing/i.test(detail)) return "static filesystem probe returned invalid framing";
  return "static filesystem probe failed";
}

export async function auditStaticWordPressInstallation(
  installation: WordPressInstallation,
  runner: StaticWpAuditRunner,
  options: StaticWpAuditOptions = {},
): Promise<WordPressAudit> {
  const markerNonce = randomBytes(16).toString("hex");
  let sections: Map<StaticWpAuditSection, FramedBatchSection>;
  try {
    const output = await runner({
      kind: "static-wp-audit-batch",
      installationPath: installation.path,
      bedrockDocumentRoot: bedrockDocumentRoot(installation),
      useSudo: options.useSudo,
      markerNonce,
    });
    sections = parseStaticSections(output, markerNonce);
  } catch (error: unknown) {
    return unavailableStaticAudit(installation, safeStaticFailureDetail(error), [], options.sourceLimitations);
  }
  const classicVersion = parseVersion(sections.get("classic_version"));
  const bedrockVersion = parseVersion(sections.get("bedrock_version"));
  const documentRoot = bedrockDocumentRoot(installation);
  const projectRoot = posix.dirname(documentRoot);
  const bedrockMarkers = containsExactPath(sections.get("bedrock_composer"), `${projectRoot}/composer.json`)
    && containsExactPath(sections.get("bedrock_config"), `${projectRoot}/config/application.php`);
  const bedrockConfirmed = bedrockVersion !== undefined && bedrockMarkers;
  if (!classicVersion && !bedrockConfirmed || classicVersion !== undefined && bedrockConfirmed) {
    const classicSuspicious = suspiciousFiles(sections.get("classic_uploads"), `${installation.path}/wp-content/uploads`);
    const bedrockSuspicious = suspiciousFiles(sections.get("bedrock_uploads"), `${installation.path}/app/uploads`);
    const detail = classicVersion && bedrockConfirmed
      ? "classic and Bedrock layout signals are ambiguous"
      : bedrockVersion && !bedrockMarkers
        ? "Bedrock core path found without canonical project markers"
        : "no readable classic or Bedrock core version file";
    return unavailableStaticAudit(installation, detail, [...classicSuspicious.value, ...bedrockSuspicious.value], options.sourceLimitations);
  }
  const bedrock = bedrockConfirmed;
  const contentRoot = bedrock ? `${documentRoot}/app` : `${installation.path}/wp-content`;
  const coreRoot = bedrock ? `${documentRoot}/wp` : installation.path;
  const pluginRead = names(sections.get(bedrock ? "bedrock_plugins" : "classic_plugins"));
  const themeRead = names(sections.get(bedrock ? "bedrock_themes" : "classic_themes"));
  const uploadsRead = suspiciousFiles(sections.get(bedrock ? "bedrock_uploads" : "classic_uploads"), `${contentRoot}/uploads`);
  const lookup = options.vulnerabilityResourceLookup ?? lookupVulnerabilities;
  const vulnerabilityStatuses: VulnerabilityLookupStatus[] = [];
  const checkedAt: string[] = [];
  const lookupResource = async (resource: VulnerabilityResource, identifier: string) => {
    const result = await lookup(resource, identifier, options);
    vulnerabilityStatuses.push(result.status);
    if (result.checkedAt) checkedAt.push(result.checkedAt);
    return result;
  };
  const unscopedVulnerabilityIntelligence: VulnerabilityResourceSummary[] = [];
  const plugins: PluginInfo[] = await Promise.all(pluginRead.value.map(async (name) => {
    const identifier = name.endsWith(".php") ? name.slice(0, -4) : name;
    const result = await lookupResource("plugin", identifier);
    if (result.summary?.vulnerabilities.length) unscopedVulnerabilityIntelligence.push(result.summary);
    return {
      name,
      version: "unknown",
      active: undefined,
      hasUpdate: undefined,
      vulnerabilities: [],
    };
  }));
  const themes: ThemeInfo[] = await Promise.all(themeRead.value.map(async (name) => {
    const result = await lookupResource("theme", name);
    if (result.summary?.vulnerabilities.length) unscopedVulnerabilityIntelligence.push(result.summary);
    return {
      name,
      version: "unknown",
      active: undefined,
      hasUpdate: undefined,
    };
  }));
  const coreVersion = bedrockVersion ?? classicVersion!;
  const coreResult = await lookupResource("core", coreVersion);
  const vulnerabilityStatus = summarizeVulnerabilityStatus(vulnerabilityStatuses);
  const limitations = [
    ...(options.sourceLimitations ?? []),
    "plugin versions, activation state, and update status unavailable from static filesystem audit",
    "theme versions, activation state, and update status unavailable from static filesystem audit",
    "core and plugin checksum verification unavailable from static filesystem audit",
    "WordPress runtime health unavailable because application PHP was not executed",
    ...(pluginRead.availability === "unavailable" ? ["plugin filesystem inventory unavailable"] : []),
    ...(themeRead.availability === "unavailable" ? ["theme filesystem inventory unavailable"] : []),
    ...(uploadsRead.availability === "unavailable" ? ["uploads PHP scan unavailable"] : []),
    ...(unscopedVulnerabilityIntelligence.length ? ["plugin/theme vulnerability records are unscoped intelligence because installed versions are unavailable"] : []),
  ];
  return applyHeuristics({
    installation,
    coreVersion,
    plugins,
    themes,
    vulnerabilities: [],
    ...(coreResult.summary?.vulnerabilities.length ? { coreVulnerabilities: coreResult.summary.vulnerabilities } : {}),
    ...(vulnerabilityStatus !== "disabled" ? { vulnerabilityStatus } : {}),
    ...(checkedAt.length ? { vulnerabilityCheckedAt: checkedAt.sort().at(-1) } : {}),
    ...(unscopedVulnerabilityIntelligence.length ? { unscopedVulnerabilityIntelligence } : {}),
    suspiciousFiles: uploadsRead.value,
    auditSource: "static-filesystem",
    layout: {
      kind: bedrock ? "bedrock" : "classic",
      projectRoot: bedrock ? projectRoot : installation.path,
      documentRoot: bedrock ? documentRoot : installation.path,
      coreRoot,
      contentRoot,
    },
    staticCapabilities: {
      pluginInventory: pluginRead.availability,
      themeInventory: themeRead.availability,
      suspiciousUploads: uploadsRead.availability,
      updateStatus: "unavailable",
    },
    limitations,
    integrity: { coreChecksums: "unavailable", pluginChecksums: "unavailable" },
    health: options.observedHealth ?? { reachable: true },
  });
}

function unavailableStaticAudit(installation: WordPressInstallation, detail: string, suspicious: string[] = [], sourceLimitations: string[] = []): WordPressAudit {
  return applyHeuristics({
    installation,
    coreVersion: "unknown",
    plugins: [],
    themes: [],
    vulnerabilities: [],
    suspiciousFiles: suspicious,
    auditSource: "none",
    staticCapabilities: { pluginInventory: "unavailable", themeInventory: "unavailable", suspiciousUploads: "unavailable", updateStatus: "unavailable" },
    limitations: [...sourceLimitations, "Static filesystem audit could not identify a supported WordPress layout"],
    health: { reachable: true, status: "audit-unavailable", detail },
  });
}
