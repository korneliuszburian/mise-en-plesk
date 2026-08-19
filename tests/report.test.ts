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

  it("explains WP Toolkit fallback provenance and limitations", () => {
    const markdown = auditMarkdown({
      ...result,
      hosts: [{
        ...result.hosts[0],
        wordpress: [{
          ...result.hosts[0].wordpress[0],
          auditSource: "plesk-wp-toolkit",
          wpCliTransport: "plesk-wp-toolkit",
          limitations: ["core checksum verification unavailable"],
          toolkitSignals: { infected: false, broken: false, alive: true, unsupportedPhp: false, stateText: "Working" },
        }],
      }],
    });

    expect(markdown).toContain("- Audit source: plesk-wp-toolkit");
    expect(markdown).toContain("- WP-CLI transport: plesk-wp-toolkit");
    expect(markdown).toContain("- Audit limitation: core checksum verification unavailable");
    expect(markdown).toContain("- WP Toolkit: Working; alive=yes; infected=no; broken=no; unsupported PHP=no");
  });

  it("renders actionable checksum failure details", () => {
    const markdown = auditMarkdown({
      ...result,
      hosts: [{
        ...result.hosts[0],
        wordpress: [{
          ...result.hosts[0].wordpress[0],
          integrity: { coreChecksums: "failed", pluginChecksums: "failed", coreDetail: "WP-CLI reported checksum mismatches", pluginDetail: "WP-CLI reported checksum mismatches" },
        }],
      }],
    });

    expect(markdown).toContain("- Core checksum detail: WP-CLI reported checksum mismatches");
    expect(markdown).toContain("- Plugin checksum detail: WP-CLI reported checksum mismatches");
  });

  it("writes machine-readable JSON when requested", async () => {
    const directory = await mkdtemp(join(tmpdir(), "mise-en-plesk-report-"));
    const path = await writeAuditReport(result, directory, true);

    await expect(readFile(path, "utf8")).resolves.toContain('"generatedAt": "2026-08-12T00:00:00.000Z"');
    expect(path).toMatch(/plesk-wp-audit-\d{8}\.json$/);
  });

  it("supports a suffix for rotated per-host reports", async () => {
    const directory = await mkdtemp(join(tmpdir(), "mise-en-plesk-report-suffix-"));
    const path = await writeAuditReport(result, directory, true, "-dev-ssh");
    expect(path).toMatch(/plesk-wp-audit-\d{8}-dev-ssh\.json$/);
  });

  it("renders host capability warnings", () => {
    const markdown = auditMarkdown({
      ...result,
      hosts: [{ ...result.hosts[0], warnings: ["Plesk CLI unavailable; filesystem discovery only"] }],
    });

    expect(markdown).toContain("> Warning: Plesk CLI unavailable; filesystem discovery only");
  });

  it("renders read-only host facts", () => {
    const markdown = auditMarkdown({
      ...result,
      hosts: [{
        ...result.hosts[0],
        hostFacts: { pleskVersion: "Plesk Obsidian 18.0.67", phpVersion: "8.2.29", disk: { filesystem: "/dev/vda1", availableKb: 35000, usedPercent: 65 } },
      }],
    });

    expect(markdown).toContain("- Plesk: Plesk Obsidian 18.0.67");
    expect(markdown).toContain("- Disk: 65% used, 35000 KiB available on /dev/vda1");
  });

  it("renders the discovered Plesk subscription count", () => {
    const markdown = auditMarkdown({
      ...result,
      hosts: [{ host: "master-ssh", subscriptions: ["example.test", "shop.test"], wordpress: [] }],
    });
    expect(markdown).toContain("- Plesk subscriptions: 2");
  });

  it("renders a host-level unreachable result without inventing a WordPress site", () => {
    const markdown = auditMarkdown({
      generatedAt: "2026-08-18T00:00:00.000Z",
      hosts: [{
        host: "master-ssh",
        subscriptions: [],
        wordpress: [],
        health: { reachable: false, detail: "Command failed (timeout)" },
      }],
    });

    expect(markdown).toContain("- Host reachable: no");
    expect(markdown).toContain("- Host health detail: Command failed (timeout)");
    expect(markdown).not.toContain("### unknown");
  });
});
