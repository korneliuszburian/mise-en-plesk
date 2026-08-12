import { describe, expect, it } from "vitest";
import { applyHeuristics, auditWordPressInstallation, type WpCommandRunner } from "../src/wp-audit";

describe("WordPress audit", () => {
  it("collects core, plugin, and checksum health through wp CLI", async () => {
    const calls: string[] = [];
    const runner: WpCommandRunner = async (_instance, command) => {
      calls.push(command);
      if (command.includes("core version")) return "6.6.1\n";
      if (command.includes("plugin list")) {
        return JSON.stringify([
          { name: "akismet", version: "5.3", status: "active", update: "none" },
          { name: "old-plugin", version: "1.0", status: "inactive", update: "none" },
        ]);
      }
      return "Success: WordPress installation verifies against checksums.";
    };

    await expect(auditWordPressInstallation({ path: "/var/www/vhosts/example.test/httpdocs", domain: "example.test" }, runner)).resolves.toEqual({
      installation: { path: "/var/www/vhosts/example.test/httpdocs", domain: "example.test" },
      coreVersion: "6.6.1",
      plugins: [
        { name: "akismet", version: "5.3", active: true, hasUpdate: false, vulnerabilities: [] },
        { name: "old-plugin", version: "1.0", active: false, hasUpdate: false, vulnerabilities: [] },
      ],
      vulnerabilities: [],
      suspiciousFiles: [],
      health: { reachable: true },
      priorities: [],
    });
    expect(calls).toContain("plugin list --format=json --fields=name,status,update,version,update_version,wporg_status,wporg_last_updated");
  });

  it("keeps the host audit alive when one WordPress install is unreachable", async () => {
    const runner: WpCommandRunner = async () => {
      throw new Error("wp unavailable");
    };

    await expect(
      auditWordPressInstallation({ path: "/var/www/vhosts/down.test/httpdocs", domain: "down.test" }, runner),
    ).resolves.toMatchObject({
      coreVersion: "unknown",
      plugins: [],
      vulnerabilities: [],
      suspiciousFiles: [],
      health: { reachable: false },
      priorities: ["installation is unreachable"],
    });
  });

  it("flags plugin updates and stale or inactive wp.org plugins", () => {
    const audit = applyHeuristics({
      installation: { path: "/srv/site" },
      coreVersion: "6.6.1",
      plugins: [
        { name: "update-me", version: "1.0", active: true, hasUpdate: true, vulnerabilities: [] },
        { name: "stale", version: "1.0", active: false, hasUpdate: false, wporgStatus: "closed", wporgLastUpdated: "2024-01-01", vulnerabilities: [] },
      ],
      vulnerabilities: [],
      suspiciousFiles: [],
      health: { reachable: true },
    }, { now: new Date("2026-08-12T00:00:00Z") });

    expect(audit.priorities).toEqual([
      "plugin update-me has an update available",
      "plugin stale appears abandoned (no wp.org updates in > 12 months)",
    ]);
  });

  it("includes suspicious uploads and prioritizes them", async () => {
    const runner: WpCommandRunner = async (_installation, command) => {
      if (command.includes("core version")) return "6.6.1";
      if (command.includes("plugin list")) return "[]";
      return "ok";
    };
    const audit = await auditWordPressInstallation({ path: "/var/www/vhosts/site.test/httpdocs" }, runner, {
      suspiciousFileRunner: async (_installation, command) => {
        expect(command).toContain("find '/var/www/vhosts/site.test/httpdocs/wp-content/uploads'");
        return "/var/www/vhosts/site.test/httpdocs/wp-content/uploads/shell.php\n";
      },
    });

    expect(audit.suspiciousFiles).toEqual(["/var/www/vhosts/site.test/httpdocs/wp-content/uploads/shell.php"]);
    expect(audit.priorities).toContain("PHP files found in uploads (possible backdoors)");
  });

  it("attaches vulnerability summaries from an injected lookup", async () => {
    const runner: WpCommandRunner = async (_installation, command) => {
      if (command.includes("core version")) return "6.6.1";
      if (command.includes("plugin list")) return JSON.stringify([{ name: "sample-plugin", version: "1.0", status: "active", update: "none" }]);
      return "ok";
    };
    const audit = await auditWordPressInstallation({ path: "/srv/site" }, runner, {
      vulnerabilityLookup: async () => ({
        slug: "sample-plugin",
        vulnerabilities: [{ id: "CVE-2026-0001", title: "Example issue", severity: "high", cve: ["CVE-2026-0001"], source: "WPVulnerability" }],
      }),
    });

    expect(audit.plugins[0].vulnerabilities[0].cve).toEqual(["CVE-2026-0001"]);
    expect(audit.vulnerabilities[0].slug).toBe("sample-plugin");
    expect(audit.priorities).toContain("plugin sample-plugin has known vulnerabilities (via WPVulnerability): high");
  });
});
