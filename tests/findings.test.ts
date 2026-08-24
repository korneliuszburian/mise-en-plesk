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
        coreVulnerabilities: [{ id: "CVE-2026-0005", title: "Core issue", severity: "critical", cve: [], source: "WPVulnerability" }],
        themes: [{ name: "old-theme", version: "1.0", active: true, hasUpdate: true, vulnerabilities: [{ id: "CVE-2026-0006", title: "Theme issue", severity: "high", cve: [], source: "WPVulnerability" }] }],
        integrity: { coreChecksums: "failed", pluginChecksums: "failed", coreDetail: "WP-CLI reported checksum mismatches", pluginDetail: "WP-CLI reported checksum mismatches" },
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
      "core-vulnerable",
      "plugin-update",
      "plugin-abandoned",
      "plugin-vulnerable",
      "theme-update",
      "theme-vulnerable",
      "core-checksum-failed",
      "plugin-checksum-failed",
      "suspicious-upload-php",
    ]);
    expect(findings.find((finding) => finding.code === "plugin-update")).toMatchObject({
      severity: "P2",
      host: "master-ssh",
      installationPath: "/var/www/vhosts/example.test/httpdocs",
      plugin: "old-plugin",
      message: "plugin old-plugin has an update available",
    });
    expect(findings.find((finding) => finding.code === "plugin-vulnerable")).toMatchObject({ severity: "P1", vulnerabilityId: "CVE-2026-0001" });
    expect(findings.find((finding) => finding.code === "core-checksum-failed")?.evidence).toBe("WP-CLI reported checksum mismatches");
    expect(findings.find((finding) => finding.code === "plugin-checksum-failed")?.evidence).toBe("WP-CLI reported checksum mismatches");
    expect(findings.find((finding) => finding.code === "plugin-update")?.id).toBe(findingsFromAudits([{
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

  it("treats the Plesk WP Toolkit infected signal as P1 evidence", () => {
    const findings = findingsFromAudits([{
      host: "dev-ssh",
      wordpress: [baseAudit({
        toolkitSignals: { infected: true, broken: false, alive: true, unsupportedPhp: false, stateText: "Infected" },
      })],
    }]);

    expect(findings).toEqual([expect.objectContaining({
      code: "plesk-toolkit-infected",
      severity: "P1",
      evidence: "Infected",
    })]);
  });

  it("keeps uploads index-named files as a P2 manual-review finding", () => {
    const findings = findingsFromAudits([{
      host: "dev-ssh",
      wordpress: [baseAudit({ suspiciousFiles: ["/uploads/index.php", "/uploads/2026/index.php"] })],
    }]);

    expect(findings).toEqual([expect.objectContaining({
      code: "suspicious-upload-php",
      severity: "P2",
      message: "index.php files found in uploads; manual review required",
      evidence: "/uploads/index.php\n/uploads/2026/index.php",
    })]);
  });

  it("reports public HTTP and TLS failures separately from Toolkit reachability", () => {
    const findings = findingsFromAudits([{
      host: "dev-ssh",
      wordpress: [baseAudit({
        installation: { path: "/var/www/vhosts/solozaszkola.dev.proudsite.pl/httpdocs", domain: "solozaszkola.dev.proudsite.pl" },
        health: { reachable: true },
        publicSiteHealth: {
          url: "https://solozaszkola.dev.proudsite.pl/",
          checkedAt: "2026-08-24T15:13:29.000Z",
          tls: { status: "invalid", error: "certificate has expired", validTo: "2026-06-21T11:40:54.000Z" },
          http: { reachable: true, status: 503, finalUrl: "https://solozaszkola.dev.proudsite.pl/" },
        },
      })],
    }]);

    expect(findings).toEqual(expect.arrayContaining([
      expect.objectContaining({ code: "tls-certificate-invalid", severity: "P1" }),
      expect.objectContaining({ code: "public-http-error", severity: "P1", evidence: "HTTP 503" }),
    ]));
  });

  it("downgrades a known staging suspension to P2 while keeping its cause explicit", () => {
    const findings = findingsFromAudits([{
      host: "dev-ssh",
      wordpress: [baseAudit({
        installation: {
          path: "/var/www/vhosts/solozaszkola.dev.proudsite.pl/httpdocs",
          domain: "solozaszkola.dev.proudsite.pl",
          classification: { kind: "staging", reason: "staging marker found in the domain or path" },
        },
        health: { reachable: true },
        pleskSiteInfo: { domain: "solozaszkola.dev.proudsite.pl", status: "The domain was suspended by the administrator.", suspended: true },
        publicSiteHealth: {
          url: "https://solozaszkola.dev.proudsite.pl/",
          checkedAt: "2026-08-24T15:13:29.000Z",
          tls: { status: "invalid", error: "certificate has expired" },
          http: { reachable: true, status: 503, finalUrl: "https://solozaszkola.dev.proudsite.pl/" },
        },
      })],
    }]);

    expect(findings).toEqual(expect.arrayContaining([
      expect.objectContaining({ code: "plesk-site-suspended", severity: "P2" }),
      expect.objectContaining({ code: "tls-certificate-invalid", severity: "P2" }),
    ]));
    expect(findings.some((finding) => finding.code === "public-http-error")).toBe(false);
  });

  it("keeps permission-denied plugin checksums as an explicit incomplete audit", () => {
    const findings = findingsFromAudits([{
      host: "dev-ssh",
      wordpress: [baseAudit({
        integrity: {
          coreChecksums: "verified",
          pluginChecksums: "unavailable",
          pluginDetail: "WP-CLI execution permission denied",
        },
      })],
    }]);

    expect(findings).toContainEqual(expect.objectContaining({
      code: "plugin-checksum-unavailable",
      severity: "P2",
      evidence: "WP-CLI execution permission denied",
    }));
  });

  it("preserves broken, unsupported PHP, and not-alive Toolkit signals", () => {
    const findings = findingsFromAudits([{
      host: "dev-ssh",
      wordpress: [baseAudit({
        toolkitSignals: { infected: false, broken: true, alive: false, unsupportedPhp: true, stateText: "Broken" },
      })],
    }]);

    expect(findings.map((finding) => finding.code)).toEqual([
      "plesk-toolkit-broken",
      "plesk-toolkit-unsupported-php",
      "plesk-toolkit-not-alive",
    ]);
    expect(findings.every((finding) => finding.severity === "P1")).toBe(true);
  });

  it("does not invent a not-alive finding when Toolkit omits alive", () => {
    const findings = findingsFromAudits([{
      host: "dev-ssh",
      wordpress: [baseAudit({
        toolkitSignals: { infected: false, broken: false, unsupportedPhp: false, stateText: "Unknown" },
      })],
    }]);

    expect(findings).toEqual([]);
  });

  it("preserves the precise WP-CLI health status in finding codes", () => {
    const statuses = ["wp-cli-missing", "wp-cli-permission-denied", "wp-cli-broken"] as const;
    const findings = findingsFromAudits([{
      host: "dev-ssh",
      wordpress: statuses.map((status, index) => baseAudit({
        installation: { path: `/srv/site-${index}` },
        health: { reachable: true, status, detail: `${status} detail` },
      })),
    }]);

    expect(findings.map((finding) => finding.code)).toEqual([...statuses]);
    expect(findings.map((finding) => finding.evidence)).toEqual(statuses.map((status) => `${status} detail`));
  });

  it("keeps the legacy WP-CLI finding identity during status refinement", () => {
    const legacy = findingsFromAudits([{
      host: "dev-ssh",
      wordpress: [baseAudit({ health: { reachable: true, status: "wp-cli-error", detail: "old detail" } })],
    }])[0];
    const refined = findingsFromAudits([{
      host: "dev-ssh",
      wordpress: [baseAudit({ health: { reachable: true, status: "wp-cli-missing", detail: "new detail" } })],
    }])[0];

    expect(refined).toMatchObject({ code: "wp-cli-missing", evidence: "new detail" });
    expect(refined.id).toBe(legacy.id);
  });

  it("creates a P1 finding for a discovered installation with no usable audit source", () => {
    const findings = findingsFromAudits([{
      host: "dev-ssh",
      wordpress: [baseAudit({
        auditSource: "none",
        health: { reachable: true, status: "audit-unavailable", detail: "no readable supported layout" },
      })],
    }]);

    expect(findings).toEqual([expect.objectContaining({
      code: "audit-unavailable",
      severity: "P1",
      evidence: "no readable supported layout",
    })]);
  });

  it("creates a stable P1 finding when the SSH host cannot be reached", () => {
    const hosts = [{
      host: "master-ssh",
      health: { reachable: false, detail: "Command failed (timeout)" },
      wordpress: [],
    }];

    const findings = findingsFromAudits(hosts);
    expect(findings).toEqual([expect.objectContaining({
      code: "host-unreachable",
      severity: "P1",
      installationPath: "__host__",
      message: "Plesk host is unreachable; scan could not start",
      evidence: "Command failed (timeout)",
    })]);
    expect(findingsFromAudits(hosts)[0].id).toBe(findings[0].id);
  });
});
