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
      installation: { path: "/var/www/vhosts/example.test/httpdocs", domain: "example.test" },
      coreVersion: "5.9.0",
      plugins: [],
      health: { reachable: true },
      priorities: ["core is very old"],
    }],
  }],
};

describe("audit reports", () => {
  it("renders useful Markdown sections and priorities", () => {
    expect(auditMarkdown(result)).toContain("## master");
    expect(auditMarkdown(result)).toContain("- Priorities: core is very old");
  });

  it("writes machine-readable JSON when requested", async () => {
    const directory = await mkdtemp(join(tmpdir(), "mise-en-plesk-report-"));
    const path = await writeAuditReport(result, directory, true);

    await expect(readFile(path, "utf8")).resolves.toContain('"generatedAt": "2026-08-12T00:00:00.000Z"');
    expect(path).toMatch(/plesk-wp-audit-\d{8}\.json$/);
  });
});
