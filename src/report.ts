import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { AuditResult } from "./wp-audit";
import { classifySuspiciousUploadFiles } from "./wp-audit";

export function auditMarkdown(result: AuditResult): string {
  const lines = [`# Plesk WordPress audit`, ``, `Generated: ${result.generatedAt}`, ``];
  for (const host of result.hosts) {
    lines.push(`## ${host.host}`, ``);
    if (host.health) {
      lines.push(`- Host reachable: ${host.health.reachable ? "yes" : "no"}`);
      if (host.health.detail) lines.push(`- Host health detail: ${host.health.detail}`);
      lines.push("");
    }
    if (host.subscriptions) lines.push(`- Plesk subscriptions: ${host.subscriptions.length}`, ``);
    for (const warning of host.warnings ?? []) lines.push(`> Warning: ${warning}`, ``);
    if (host.hostFacts) {
      lines.push(`- Plesk: ${host.hostFacts.pleskVersion ?? "unknown"}`, `- PHP: ${host.hostFacts.phpVersion ?? "unknown"}`);
      if (host.hostFacts.disk) lines.push(`- Disk: ${host.hostFacts.disk.usedPercent}% used, ${host.hostFacts.disk.availableKb} KiB available on ${host.hostFacts.disk.filesystem}`);
      lines.push("");
    }
    for (const site of host.wordpress) {
      lines.push(`### ${site.installation.domain ?? site.installation.path}`, ``, `- Core: ${site.coreVersion}`, `- Reachable: ${site.health.reachable ? "yes" : "no"}`);
      if (site.installation.classification) {
        lines.push(`- Site classification: ${site.installation.classification.kind} (${site.installation.classification.reason})`);
      }
      if (site.installation.detectionSignals?.length) lines.push(`- Detection signals: ${site.installation.detectionSignals.join(", ")}`);
      if (site.health.status) lines.push(`- Health status: ${site.health.status}`);
      if (site.health.detail) lines.push(`- Health detail: ${site.health.detail}`);
      if (site.publicSiteHealth) {
        const publicHttp = site.publicSiteHealth.http;
        lines.push(`- Public HTTPS: ${publicHttp.reachable ? `HTTP ${publicHttp.status ?? "unknown"}` : `unreachable (${publicHttp.error ?? "unknown error"})`}`);
        const publicTls = site.publicSiteHealth.tls;
        lines.push(`- Public TLS: ${publicTls.status === "valid" ? "valid" : `${publicTls.status} (${publicTls.error ?? "unknown error"})`}`);
        if (site.publicSiteHealth.tls.validTo) lines.push(`- TLS valid until: ${site.publicSiteHealth.tls.validTo}`);
      }
      if (site.pleskSiteInfo) {
        lines.push(`- Plesk site status: ${site.pleskSiteInfo.status}`);
        if (site.pleskSiteInfo.certificate) lines.push(`- Plesk configured certificate: ${site.pleskSiteInfo.certificate}`);
      }
      if (site.auditSource) lines.push(`- Audit source: ${site.auditSource}`);
      if (site.wpCliTransport) lines.push(`- WP-CLI transport: ${site.wpCliTransport}`);
      if (site.layout) {
        lines.push(`- Filesystem layout: ${site.layout.kind}`);
        lines.push(`- Core root: ${site.layout.coreRoot}`);
        lines.push(`- Content root: ${site.layout.contentRoot}`);
      }
      if (site.staticCapabilities) {
        lines.push(`- Static coverage: plugins ${site.staticCapabilities.pluginInventory}, themes ${site.staticCapabilities.themeInventory}, uploads ${site.staticCapabilities.suspiciousUploads}, update status ${site.staticCapabilities.updateStatus}`);
      }
      if (site.unscopedVulnerabilityIntelligence?.length) {
        lines.push(`- Unscoped vulnerability intelligence: ${site.unscopedVulnerabilityIntelligence.length} resource(s); installed-version applicability is unknown`);
      }
      for (const limitation of site.limitations ?? []) lines.push(`- Audit limitation: ${limitation}`);
      if (site.toolkitSignals) {
        const alive = site.toolkitSignals.alive === undefined ? "unknown" : site.toolkitSignals.alive ? "yes" : "no";
        lines.push(`- WP Toolkit: ${site.toolkitSignals.stateText ?? "unknown state"}; alive=${alive}; infected=${site.toolkitSignals.infected ? "yes" : "no"}; broken=${site.toolkitSignals.broken ? "yes" : "no"}; unsupported PHP=${site.toolkitSignals.unsupportedPhp ? "yes" : "no"}`);
      }
      if (site.coreUpdateAvailable !== undefined) lines.push(`- Core update available: ${site.coreUpdateAvailable ? "yes" : "no"}`);
      const themeUpdateCount = (site.themes ?? []).filter((theme) => theme.hasUpdate === true).length;
      const themeVulnerabilityCount = (site.themes ?? []).filter((theme) => theme.vulnerabilities?.length).length;
      if (site.themes) lines.push(site.staticCapabilities?.updateStatus === "unavailable"
        ? `- Theme risk: update status unavailable, ${themeVulnerabilityCount} with version-scoped known vulnerabilities`
        : `- Theme risk: ${themeUpdateCount} with updates, ${themeVulnerabilityCount} with known vulnerabilities`);
      if (site.coreVulnerabilities?.length) lines.push(`- Core vulnerability risk: ${site.coreVulnerabilities.length} known vulnerability record(s)`);
      if (site.vulnerabilityStatus) lines.push(`- Vulnerability lookup status: ${site.vulnerabilityStatus}`);
      if (site.vulnerabilityCheckedAt) lines.push(`- Vulnerability data checked: ${site.vulnerabilityCheckedAt}`);
      if (site.integrity) {
        lines.push(`- Integrity: core checksums ${site.integrity.coreChecksums}, plugin checksums ${site.integrity.pluginChecksums}`);
        if (site.integrity.coreDetail) lines.push(`- Core checksum detail: ${site.integrity.coreDetail}`);
        if (site.integrity.pluginDetail) lines.push(`- Plugin checksum detail: ${site.integrity.pluginDetail}`);
      }
      const updateCount = site.plugins.filter((plugin) => plugin.hasUpdate === true).length;
      const abandonedCount = site.plugins.filter((plugin) => plugin.wporgStatus !== undefined && plugin.wporgStatus !== "active" || plugin.wporgLastUpdated !== undefined && Date.parse(plugin.wporgLastUpdated) < Date.now() - 365 * 24 * 60 * 60 * 1000).length;
      const vulnerablePluginCount = site.plugins.filter((plugin) => plugin.vulnerabilities.length > 0).length;
      lines.push(site.staticCapabilities?.updateStatus === "unavailable"
        ? `- Plugin risk: update and abandonment status unavailable, ${vulnerablePluginCount} with version-scoped known vulnerabilities`
        : `- Plugin risk: ${updateCount} with updates, ${abandonedCount} abandoned, ${vulnerablePluginCount} with known vulnerabilities`);
      const suspiciousFiles = classifySuspiciousUploadFiles(site.suspiciousFiles);
      if (suspiciousFiles.nonIndexPhpFiles.length) {
        lines.push(`- Suspicious uploads: ${suspiciousFiles.nonIndexPhpFiles.length} non-index PHP file(s); details are available in JSON`);
        for (const file of suspiciousFiles.nonIndexPhpFiles.slice(0, 5)) lines.push(`  - ${file}`);
      }
      if (suspiciousFiles.indexNamedPhpFiles.length) lines.push(`- Upload index.php files: ${suspiciousFiles.indexNamedPhpFiles.length}; retained for lower-priority manual review`);
      if (site.priorities.length) lines.push(`- Priorities: ${site.priorities.join(", ")}`);
      lines.push("");
    }
  }
  return `${lines.join("\n")}\n`;
}

export async function writeAuditReport(result: AuditResult, directory = "reports", json = false, filenameSuffix = ""): Promise<string> {
  await mkdir(directory, { recursive: true });
  const generatedAt = new Date(result.generatedAt);
  if (!Number.isFinite(generatedAt.getTime())) throw new Error("AuditResult.generatedAt must be a valid date");
  const date = generatedAt.toISOString().slice(0, 10).replaceAll("-", "");
  const uniqueSuffix = filenameSuffix || `-${generatedAt.toISOString().replace(/[-:.]/g, "")}`;
  const path = join(directory, `plesk-wp-audit-${date}${uniqueSuffix}.${json ? "json" : "md"}`);
  await writeFile(path, json ? `${JSON.stringify(result, null, 2)}\n` : auditMarkdown(result), { encoding: "utf8", flag: "wx" });
  return path;
}
