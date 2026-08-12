import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { AuditResult } from "./wp-audit";

export function auditMarkdown(result: AuditResult): string {
  const lines = [`# Plesk WordPress audit`, ``, `Generated: ${result.generatedAt}`, ``];
  for (const host of result.hosts) {
    lines.push(`## ${host.host}`, ``);
    for (const site of host.wordpress) {
      lines.push(`### ${site.installation.domain ?? site.installation.path}`, ``, `- Core: ${site.coreVersion}`, `- Reachable: ${site.health.reachable ? "yes" : "no"}`);
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
