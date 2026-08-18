import { describe, expect, it } from "vitest";
import { findingsFromAudits } from "../src/findings";
import type { WordPressAudit } from "../src/wp-audit";

const baseAudit = (overrides: Partial<WordPressAudit> = {}): WordPressAudit => ({
  installation: { path: "/var/www/vhosts/example.test/httpdocs", domain: "example.test" },
  coreVersion: "6.6.1",
  plugins: [],
  vulnerabilities: [],
  suspiciousFiles: [],
  health: { reachable: true },
  priorities: [],
  ...overrides,
});

describe("structured findings", () => {
  it("maps audit signals to stable, typed findings", () => {
    const findings = findingsFromAudits([{
      host: "master-ssh",
      wordpress: [baseAudit({
        coreVersion: "5.9.0",
        coreUpdateAvailable: true,
        themes: [{ name: "old-theme", version: "1.0", active: true, hasUpdate: true }],
        integrity: { coreChecksums: "failed", pluginChecksums: "failed" },
        plugins: [{
          name: "old-plugin",
          version: "1.0",
          active: true,
          hasUpdate: true,
          wporgStatus: "closed",
          wporgLastUpdated: "2024-01-01",
          vulnerabilities: [{
            id: "CVE-2026-0001",
            title: "Example issue",
            severity: "high",
            cve: ["CVE-2026-0001"],
            source: "WPVulnerability",
          }],
        }],
        suspiciousFiles: ["/uploads/shell.php"],
      })],
    }], new Date("2026-08-12T00:00:00Z"));

    expect(findings.map((finding) => finding.code)).toEqual([
      "core-outdated",
      "core-update",
      "plugin-update",
      "plugin-abandoned",
      "plugin-vulnerable",
      "theme-update",
      "core-checksum-failed",
      "plugin-checksum-failed",
      "suspicious-upload-php",
    ]);
    expect(findings[2]).toMatchObject({
      severity: "P2",
      host: "master-ssh",
      installationPath: "/var/www/vhosts/example.test/httpdocs",
      plugin: "old-plugin",
      message: "plugin old-plugin has an update available",
    });
    expect(findings[4]).toMatchObject({ severity: "P1", vulnerabilityId: "CVE-2026-0001" });
    expect(findings[2].id).toBe(findingsFromAudits([{
      host: "master-ssh",
      wordpress: [baseAudit({ plugins: [{
        name: "old-plugin", version: "1.0", active: true, hasUpdate: true,
        wporgStatus: "closed", wporgLastUpdated: "2024-01-01", vulnerabilities: [],
      }] })],
    }], new Date("2026-08-12T00:00:00Z"))[0].id);
  });

  it("creates health findings for unreachable and failed installations", () => {
    const findings = findingsFromAudits([{
      host: "dev-ssh",
      wordpress: [
        baseAudit({ health: { reachable: false, status: "unreachable", detail: "connection refused" } }),
        baseAudit({ installation: { path: "/srv/broken" }, health: { reachable: true, status: "wp-cli-error", detail: "parse error" } }),
      ],
    }]);

    expect(findings).toEqual(expect.arrayContaining([
      expect.objectContaining({ code: "unreachable", severity: "P1", message: "installation is unreachable" }),
      expect.objectContaining({ code: "wp-cli-error", severity: "P1", message: "WP-CLI audit failed; manual review required" }),
    ]));
  });
});
