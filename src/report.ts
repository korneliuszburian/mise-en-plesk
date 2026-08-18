import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { AuditResult } from "./wp-audit";

export function auditMarkdown(result: AuditResult): string {
  const lines = [`# Plesk WordPress audit`, ``, `Generated: ${result.generatedAt}`, ``];
  for (const host of result.hosts) {
    lines.push(`## ${host.host}`, ``);
    for (const warning of host.warnings ?? []) lines.push(`> Warning: ${warning}`, ``);
    for (const site of host.wordpress) {
      lines.push(`### ${site.installation.domain ?? site.installation.path}`, ``, `- Core: ${site.coreVersion}`, `- Reachable: ${site.health.reachable ? "yes" : "no"}`);
      if (site.health.status) lines.push(`- Health status: ${site.health.status}`);
      if (site.health.detail) lines.push(`- Health detail: ${site.health.detail}`);
      if (site.coreUpdateAvailable !== undefined) lines.push(`- Core update available: ${site.coreUpdateAvailable ? "yes" : "no"}`);
      const themeUpdateCount = (site.themes ?? []).filter((theme) => theme.hasUpdate).length;
      if (site.themes) lines.push(`- Theme risk: ${themeUpdateCount} with updates`);
      if (site.integrity) lines.push(`- Integrity: core checksums ${site.integrity.coreChecksums}, plugin checksums ${site.integrity.pluginChecksums}`);
      const updateCount = site.plugins.filter((plugin) => plugin.hasUpdate).length;
      const abandonedCount = site.plugins.filter((plugin) => plugin.wporgStatus !== undefined && plugin.wporgStatus !== "active" || plugin.wporgLastUpdated !== undefined && Date.parse(plugin.wporgLastUpdated) < Date.now() - 365 * 24 * 60 * 60 * 1000).length;
      const vulnerablePluginCount = site.plugins.filter((plugin) => plugin.vulnerabilities.length > 0).length;
      lines.push(`- Plugin risk: ${updateCount} with updates, ${abandonedCount} abandoned, ${vulnerablePluginCount} with known vulnerabilities`);
      if (site.suspiciousFiles.length) {
        lines.push(`- Suspicious uploads: ${site.suspiciousFiles.length} PHP file(s); details are available in JSON`);
        for (const file of site.suspiciousFiles.slice(0, 5)) lines.push(`  - ${file}`);
      }
      if (site.priorities.length) lines.push(`- Priorities: ${site.priorities.join(", ")}`);
      lines.push("");
    }
  }
  return `${lines.join("\n")}\n`;
}

export async function writeAuditReport(result: AuditResult, directory = "reports", json = false): Promise<string> {
  await mkdir(directory, { recursive: true });
  const date = new Date().toISOString().slice(0, 10).replaceAll("-", "");
  const path = join(directory, `plesk-wp-audit-${date}.${json ? "json" : "md"}`);
  await writeFile(path, json ? `${JSON.stringify(result, null, 2)}\n` : auditMarkdown(result), "utf8");
  return path;
}
