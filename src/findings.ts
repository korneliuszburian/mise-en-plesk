import { createHash } from "node:crypto";
import { isPluginAbandoned, isVeryOldCore, type WordPressAudit } from "./wp-audit";

export type FindingCode =
  | "unreachable"
  | "runtime-incompatible"
  | "wp-cli-error"
  | "core-outdated"
  | "core-update"
  | "plugin-update"
  | "plugin-abandoned"
  | "plugin-vulnerable"
  | "theme-update"
  | "core-checksum-failed"
  | "plugin-checksum-failed"
  | "suspicious-upload-php"
  | "monitor-stale";

export type FindingSeverity = "P1" | "P2" | "info";

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

type AuditedHost = { host: string; wordpress: WordPressAudit[] };

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
): Finding {
  return {
    id: stableId([host, audit.installation.path, code, identity]),
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
  for (const { host, wordpress } of hosts) {
    for (const audit of wordpress) {
      if (!audit.health.reachable) {
        findings.push(makeFinding(host, audit, "unreachable", "P1", "installation is unreachable", "installation", { evidence: audit.health.detail }));
      }
      if (audit.health.status === "runtime-incompatible") {
        findings.push(makeFinding(host, audit, "runtime-incompatible", "P1", "WordPress runtime is incompatible with the installed PHP version", "runtime", { evidence: audit.health.detail }));
      }
      if (audit.health.status === "wp-cli-error" || audit.health.status === "wp-cli-missing" || audit.health.status === "wp-cli-permission-denied" || audit.health.status === "wp-cli-broken") {
        findings.push(makeFinding(host, audit, "wp-cli-error", "P1", "WP-CLI audit failed; manual review required", "wp-cli", { evidence: audit.health.detail }));
      }
      if (isVeryOldCore(audit.coreVersion)) {
        findings.push(makeFinding(host, audit, "core-outdated", "P1", "core is very old", "core"));
      }
      if (audit.coreUpdateAvailable) {
        findings.push(makeFinding(host, audit, "core-update", "P2", "WordPress core update available", "core-update"));
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
      }
      if (audit.integrity?.coreChecksums === "failed") {
        findings.push(makeFinding(host, audit, "core-checksum-failed", "P1", "WordPress core checksum verification failed", "core-checksums"));
      }
      if (audit.integrity?.pluginChecksums === "failed") {
        findings.push(makeFinding(host, audit, "plugin-checksum-failed", "P2", "WordPress plugin checksum verification needs manual review", "plugin-checksums"));
      }
      if (audit.suspiciousFiles.length) {
        findings.push(makeFinding(host, audit, "suspicious-upload-php", "P1", "PHP files found in uploads (possible backdoors)", "uploads-php", { evidence: audit.suspiciousFiles.join("\n") }));
      }
    }
  }
  return findings;
}
