import { createHash } from "node:crypto";
import { classifySuspiciousUploadFiles, hasIncompleteStaticCapabilities, isPluginAbandoned, isVeryOldCore, isWpCliFailure, type WordPressAudit } from "./wp-audit";

export type FindingCode =
  | "host-unreachable"
  | "unreachable"
  | "runtime-incompatible"
  | "wp-cli-error"
  | "wp-cli-missing"
  | "wp-cli-permission-denied"
  | "wp-cli-broken"
  | "audit-unavailable"
  | "audit-incomplete"
  | "core-outdated"
  | "core-update"
  | "plugin-update"
  | "plugin-abandoned"
  | "plugin-vulnerable"
  | "theme-update"
  | "core-checksum-failed"
  | "plugin-checksum-failed"
  | "plugin-checksum-unavailable"
  | "suspicious-upload-php"
  | "monitor-stale"
  | "core-vulnerable"
  | "theme-vulnerable"
  | "plesk-toolkit-infected"
  | "plesk-toolkit-broken"
  | "plesk-toolkit-unsupported-php"
  | "plesk-toolkit-not-alive"
  | "tls-certificate-invalid"
  | "public-http-error"
  | "plesk-site-suspended";

export type FindingSeverity = "P1" | "P2" | "info";

const findingCodes = new Set<FindingCode>([
  "host-unreachable", "unreachable", "runtime-incompatible", "wp-cli-error", "wp-cli-missing", "wp-cli-permission-denied", "wp-cli-broken", "audit-unavailable", "audit-incomplete", "core-outdated", "core-update",
  "plugin-update", "plugin-abandoned", "plugin-vulnerable", "theme-update",
  "core-checksum-failed", "plugin-checksum-failed", "plugin-checksum-unavailable", "suspicious-upload-php",
  "monitor-stale", "core-vulnerable", "theme-vulnerable", "plesk-toolkit-infected",
  "plesk-toolkit-broken", "plesk-toolkit-unsupported-php", "plesk-toolkit-not-alive",
  "tls-certificate-invalid", "public-http-error",
  "plesk-site-suspended",
]);

export function isFindingCode(value: unknown): value is FindingCode {
  return typeof value === "string" && findingCodes.has(value as FindingCode);
}

export interface Finding {
  id: string;
  code: FindingCode;
  severity: FindingSeverity;
  host: string;
  installationPath: string;
  domain?: string;
  plugin?: string;
  vulnerabilityId?: string;
  message: string;
  evidence?: string;
}

type AuditedHost = { host: string; wordpress: WordPressAudit[]; health?: { reachable: boolean; detail?: string } };

function stableId(parts: string[]): string {
  const input = parts.map((part) => part.trim()).join("\u001f");
  return `finding-${createHash("sha256").update(input).digest("hex").slice(0, 20)}`;
}

function makeFinding(
  host: string,
  audit: WordPressAudit,
  code: FindingCode,
  severity: FindingSeverity,
  message: string,
  identity: string,
  extra: Partial<Pick<Finding, "plugin" | "vulnerabilityId" | "evidence">> = {},
  stableIdentityCode: FindingCode = code,
): Finding {
  return {
    id: stableId([host, audit.installation.path, stableIdentityCode, identity]),
    code,
    severity,
    host,
    installationPath: audit.installation.path,
    domain: audit.installation.domain,
    message,
    ...extra,
  };
}

function vulnerabilitySeverity(value?: string): FindingSeverity {
  const severity = value?.toLowerCase();
  if (severity === "critical" || severity === "high") return "P1";
  if (severity === "medium" || severity === "moderate" || severity === "low") return "P2";
  return "P2";
}

export function findingsFromAudits(hosts: AuditedHost[], now = new Date()): Finding[] {
  const findings: Finding[] = [];
  for (const { host, wordpress, health } of hosts) {
    if (health && !health.reachable) {
      findings.push({
        id: stableId([host, "__host__", "host-unreachable"]),
        code: "host-unreachable",
        severity: "P1",
        host,
        installationPath: "__host__",
        message: "Plesk host is unreachable; scan could not start",
        evidence: health.detail,
      });
    }
    for (const audit of wordpress) {
      const publicSeverity: FindingSeverity = audit.installation.classification?.kind === "staging" || audit.installation.classification?.kind === "backup" ? "P2" : "P1";
      if (audit.publicSiteHealth?.tls.status === "invalid") {
        findings.push(makeFinding(host, audit, "tls-certificate-invalid", publicSeverity, "Public TLS certificate is invalid", "public-tls", {
          evidence: audit.publicSiteHealth.tls.error,
        }));
      }
      const publicHttp = audit.publicSiteHealth?.http;
      if (!audit.pleskSiteInfo?.suspended && publicHttp && (!publicHttp.reachable || publicHttp.status === undefined || publicHttp.status >= 500)) {
        findings.push(makeFinding(host, audit, "public-http-error", publicSeverity, "Public website is unavailable", "public-http", {
          evidence: publicHttp.status === undefined ? publicHttp.error : `HTTP ${publicHttp.status}`,
        }));
      }
      if (audit.pleskSiteInfo?.suspended) {
        findings.push(makeFinding(host, audit, "plesk-site-suspended", publicSeverity, "Plesk website is administratively suspended", "plesk-site-status", {
          evidence: audit.pleskSiteInfo.status,
        }));
      }
      if (!audit.health.reachable) {
        findings.push(makeFinding(host, audit, "unreachable", "P1", "installation is unreachable", "installation", { evidence: audit.health.detail }));
      }
      if (audit.health.status === "runtime-incompatible") {
        findings.push(makeFinding(host, audit, "runtime-incompatible", "P1", "WordPress runtime is incompatible with the installed PHP version", "runtime", { evidence: audit.health.detail }));
      }
      if (isWpCliFailure(audit.health.status)) {
        findings.push(makeFinding(
          host,
          audit,
          audit.health.status,
          "P1",
          "WP-CLI audit failed; manual review required",
          "wp-cli",
          { evidence: audit.health.detail },
          "wp-cli-error",
        ));
      }
      if (audit.health.status === "audit-unavailable") {
        findings.push(makeFinding(host, audit, "audit-unavailable", "P1", "WordPress audit data unavailable; manual review required", "audit-source", { evidence: audit.health.detail }));
      }
      if (audit.health.status !== "audit-unavailable" && hasIncompleteStaticCapabilities(audit.staticCapabilities)) {
        findings.push(makeFinding(host, audit, "audit-incomplete", "P1", "Static filesystem audit incomplete; manual review required", "static-capabilities"));
      }
      if (isVeryOldCore(audit.coreVersion)) {
        findings.push(makeFinding(host, audit, "core-outdated", "P1", "core is very old", "core"));
      }
      if (audit.coreUpdateAvailable) {
        findings.push(makeFinding(host, audit, "core-update", "P2", "WordPress core update available", "core-update"));
      }
      for (const vulnerability of audit.coreVulnerabilities ?? []) {
        findings.push(makeFinding(
          host,
          audit,
          "core-vulnerable",
          vulnerabilitySeverity(vulnerability.severity),
          `WordPress core has known vulnerabilities (via WPVulnerability)${vulnerability.severity ? `: ${vulnerability.severity}` : ""}`,
          `core:vulnerability:${vulnerability.id}`,
          { vulnerabilityId: vulnerability.id, evidence: vulnerability.title },
        ));
      }
      for (const plugin of audit.plugins) {
        if (plugin.hasUpdate) {
          findings.push(makeFinding(host, audit, "plugin-update", "P2", `plugin ${plugin.name} has an update available`, `plugin:${plugin.name}:update`, { plugin: plugin.name }));
        }
        if (isPluginAbandoned(plugin, now)) {
          findings.push(makeFinding(host, audit, "plugin-abandoned", "P2", `plugin ${plugin.name} appears abandoned (no wp.org updates in > 12 months)`, `plugin:${plugin.name}:abandoned`, { plugin: plugin.name }));
        }
        for (const vulnerability of plugin.vulnerabilities) {
          findings.push(makeFinding(
            host,
            audit,
            "plugin-vulnerable",
            vulnerabilitySeverity(vulnerability.severity),
            `plugin ${plugin.name} has known vulnerabilities (via WPVulnerability)${vulnerability.severity ? `: ${vulnerability.severity}` : ""}`,
            `plugin:${plugin.name}:vulnerability:${vulnerability.id}`,
            { plugin: plugin.name, vulnerabilityId: vulnerability.id, evidence: vulnerability.title },
          ));
        }
      }
      for (const theme of audit.themes ?? []) {
        if (theme.hasUpdate) {
          findings.push(makeFinding(host, audit, "theme-update", "P2", `theme ${theme.name} has an update available`, `theme:${theme.name}:update`, { evidence: theme.version }));
        }
        for (const vulnerability of theme.vulnerabilities ?? []) {
          findings.push(makeFinding(
            host,
            audit,
            "theme-vulnerable",
            vulnerabilitySeverity(vulnerability.severity),
            `theme ${theme.name} has known vulnerabilities (via WPVulnerability)${vulnerability.severity ? `: ${vulnerability.severity}` : ""}`,
            `theme:${theme.name}:vulnerability:${vulnerability.id}`,
            { vulnerabilityId: vulnerability.id, evidence: vulnerability.title },
          ));
        }
      }
      if (audit.integrity?.coreChecksums === "failed") {
        findings.push(makeFinding(host, audit, "core-checksum-failed", "P1", "WordPress core checksum verification failed", "core-checksums", { evidence: audit.integrity.coreDetail }));
      }
      if (audit.integrity?.pluginChecksums === "failed") {
        findings.push(makeFinding(host, audit, "plugin-checksum-failed", "P2", "WordPress plugin checksum verification needs manual review", "plugin-checksums", { evidence: audit.integrity.pluginDetail }));
      }
      if (audit.integrity?.pluginChecksums === "unavailable" && /permission denied/i.test(audit.integrity.pluginDetail ?? "")) {
        findings.push(makeFinding(host, audit, "plugin-checksum-unavailable", "P2", "WordPress plugin checksum audit is incomplete", "plugin-checksums-unavailable", { evidence: audit.integrity.pluginDetail }));
      }
      const suspiciousFiles = classifySuspiciousUploadFiles(audit.suspiciousFiles);
      if (suspiciousFiles.nonIndexPhpFiles.length) {
        findings.push(makeFinding(host, audit, "suspicious-upload-php", "P1", "PHP files found in uploads (possible backdoors)", "uploads-php", { evidence: suspiciousFiles.nonIndexPhpFiles.join("\n") }));
      } else if (suspiciousFiles.indexNamedPhpFiles.length) {
        findings.push(makeFinding(host, audit, "suspicious-upload-php", "P2", "index.php files found in uploads; manual review required", "uploads-php", { evidence: suspiciousFiles.indexNamedPhpFiles.join("\n") }));
      }
      if (audit.toolkitSignals?.infected) {
        findings.push(makeFinding(host, audit, "plesk-toolkit-infected", "P1", "Plesk WP Toolkit reports the installation as infected", "toolkit-infected", { evidence: audit.toolkitSignals.stateText }));
      }
      if (audit.toolkitSignals?.broken) {
        findings.push(makeFinding(host, audit, "plesk-toolkit-broken", "P1", "Plesk WP Toolkit reports the installation as broken", "toolkit-broken", { evidence: audit.toolkitSignals.stateText }));
      }
      if (audit.toolkitSignals?.unsupportedPhp) {
        findings.push(makeFinding(host, audit, "plesk-toolkit-unsupported-php", "P1", "Plesk WP Toolkit reports an unsupported PHP runtime", "toolkit-unsupported-php", { evidence: audit.toolkitSignals.stateText }));
      }
      if (audit.toolkitSignals?.alive === false) {
        findings.push(makeFinding(host, audit, "plesk-toolkit-not-alive", "P1", "Plesk WP Toolkit reports the installation as not alive", "toolkit-not-alive", { evidence: audit.toolkitSignals.stateText }));
      }
    }
  }
  return findings;
}
