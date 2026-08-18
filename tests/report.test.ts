import { readFile, mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { auditMarkdown, writeAuditReport } from "../src/report";
import type { AuditResult } from "../src/wp-audit";

const result: AuditResult = {
  generatedAt: "2026-08-12T00:00:00.000Z",
  hosts: [{
    host: "master",
    wordpress: [{
      installation: {
        path: "/var/www/vhosts/example.test/httpdocs",
        domain: "example.test",
        classification: { kind: "production", reason: "standard Plesk httpdocs path without staging or backup markers" },
      },
      coreVersion: "5.9.0",
      plugins: [{ name: "sample", version: "1.0", active: true, hasUpdate: true, vulnerabilities: [] }],
      vulnerabilities: [],
      suspiciousFiles: ["/var/www/vhosts/example.test/httpdocs/wp-content/uploads/shell.php"],
      health: { reachable: true },
      priorities: ["core is very old"],
    }],
  }],
};

describe("audit reports", () => {
  it("renders useful Markdown sections and priorities", () => {
    expect(auditMarkdown(result)).toContain("## master");
    expect(auditMarkdown(result)).toContain("Site classification: production");
    expect(auditMarkdown(result)).toContain("Plugin risk: 1 with updates, 0 abandoned, 0 with known vulnerabilities");
    expect(auditMarkdown(result)).toContain("- Priorities: core is very old");
  });

  it("writes machine-readable JSON when requested", async () => {
    const directory = await mkdtemp(join(tmpdir(), "mise-en-plesk-report-"));
    const path = await writeAuditReport(result, directory, true);

    await expect(readFile(path, "utf8")).resolves.toContain('"generatedAt": "2026-08-12T00:00:00.000Z"');
    expect(path).toMatch(/plesk-wp-audit-\d{8}\.json$/);
  });

  it("renders host capability warnings", () => {
    const markdown = auditMarkdown({
      ...result,
      hosts: [{ ...result.hosts[0], warnings: ["Plesk CLI unavailable; filesystem discovery only"] }],
    });

    expect(markdown).toContain("> Warning: Plesk CLI unavailable; filesystem discovery only");
  });
});
