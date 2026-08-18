import { describe, expect, it } from "vitest";
import { applyHeuristics, auditWordPressInstallation, buildWpAuditBatchCommand, buildWpCliCommand, createBatchedWpRunners, pluginSlug, type WpCommandRunner } from "../src/wp-audit";

describe("WordPress audit", () => {
  it("normalizes WP-CLI plugin filenames to vulnerability API slugs", () => {
    expect(pluginSlug("akismet/akismet.php")).toBe("akismet");
    expect(pluginSlug("hello.php")).toBe("hello.php");
  });
  it("builds a read-only WP-CLI command for a remote SSH shell", () => {
    expect(buildWpCliCommand({ path: "/var/www/vhosts/example.test/httpdocs" }, "core version"))
      .toBe("wp core version --path='/var/www/vhosts/example.test/httpdocs' --allow-root");
  });

  it("builds one read-only batch for all per-installation checks", () => {
    const command = buildWpAuditBatchCommand({ path: "/srv/site" });

    expect(command).toContain("__MISE_CORE_BEGIN__");
    expect(command).toContain("core check-update --minor --format=json");
    expect(command).toContain("__MISE_PLUGINS_BEGIN__");
    expect(command).toContain("plugin verify-checksums --all --strict");
    expect(command).toContain("theme list --format=json");
    expect(command).toContain("__MISE_CORE_STATUS_${status}__");
    expect(command).toContain("wp core verify-checksums");
    expect(command).toContain("find '/srv/site/wp-content/uploads'");
  });

  it("reuses one batch result for WP and uploads checks", async () => {
    let calls = 0;
    const batched = createBatchedWpRunners({ path: "/srv/site" }, async () => {
      calls += 1;
      return [
        "__MISE_CORE_BEGIN__", "6.6.1", "__MISE_CORE_STATUS_0__", "__MISE_CORE_END__",
        "__MISE_CORE_UPDATE_BEGIN__", "[]", "__MISE_CORE_UPDATE_STATUS_0__", "__MISE_CORE_UPDATE_END__",
        "__MISE_PLUGINS_BEGIN__", "[]", "__MISE_PLUGINS_STATUS_0__", "__MISE_PLUGINS_END__",
        "__MISE_PLUGIN_CHECKSUMS_BEGIN__", "Success", "__MISE_PLUGIN_CHECKSUMS_STATUS_0__", "__MISE_PLUGIN_CHECKSUMS_END__",
        "__MISE_THEMES_BEGIN__", "[]", "__MISE_THEMES_STATUS_0__", "__MISE_THEMES_END__",
        "__MISE_CHECKSUMS_BEGIN__", "ok", "__MISE_CHECKSUMS_STATUS_0__", "__MISE_CHECKSUMS_END__",
        "__MISE_UPLOADS_BEGIN__", "/srv/site/wp-content/uploads/shell.php", "__MISE_UPLOADS_STATUS_0__", "__MISE_UPLOADS_END__",
      ].join("\n");
    });

    await expect(batched.runner({ path: "/srv/site" }, "core version")).resolves.toBe("6.6.1");
    await expect(batched.suspiciousFileRunner({ path: "/srv/site" }, "ignored")).resolves.toContain("shell.php");
    expect(calls).toBe(1);
  });

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
      if (command.includes("core check-update")) return "[]";
      if (command.includes("theme list")) return JSON.stringify([{ name: "twentytwentyfour", version: "1.0", status: "active", update: "none" }]);
      if (command.includes("plugin verify-checksums")) return "Success: Plugin verified.";
      return "Success: WordPress installation verifies against checksums.";
    };

    await expect(auditWordPressInstallation({ path: "/var/www/vhosts/example.test/httpdocs", domain: "example.test" }, runner)).resolves.toEqual({
      installation: { path: "/var/www/vhosts/example.test/httpdocs", domain: "example.test" },
      coreVersion: "6.6.1",
      coreUpdateAvailable: false,
      plugins: [
        { name: "akismet", version: "5.3", active: true, hasUpdate: false, vulnerabilities: [] },
        { name: "old-plugin", version: "1.0", active: false, hasUpdate: false, vulnerabilities: [] },
      ],
      themes: [{ name: "twentytwentyfour", version: "1.0", active: true, hasUpdate: false }],
      vulnerabilities: [],
      suspiciousFiles: [],
      integrity: { coreChecksums: "verified", pluginChecksums: "verified" },
      health: { reachable: true },
      priorities: [],
    });
    expect(calls).toContain("plugin list --format=json --fields=name,status,update,version,update_version,wporg_status,wporg_last_updated");
    expect(calls).toContain("core check-update --minor --format=json");
    expect(calls.some((call) => call.startsWith("theme list --format=json"))).toBe(true);
    expect(calls).toContain("plugin verify-checksums --all --strict");
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

  it("treats PHP/plugin failures as reachable WP-CLI errors", async () => {
    const runner: WpCommandRunner = async (_installation, command) => {
      if (command === "core version") return "6.6.1";
      throw new Error("PHP Parse error: syntax error, unexpected ')' in plugin.php");
    };

    const result = await auditWordPressInstallation({ path: "/var/www/vhosts/broken.test/httpdocs" }, runner);

    expect(result).toMatchObject({
      coreVersion: "6.6.1",
      health: { reachable: true, status: "wp-cli-error" },
    });
    expect(result.priorities).toContain("WP-CLI audit failed; manual review required");
  });

  it("distinguishes a reachable site with an incompatible PHP runtime", async () => {
    const runner: WpCommandRunner = async (_installation, command) => {
      if (command === "core version") return "7.0.3";
      throw new Error("Your server is running PHP version 7.2.24 but WordPress 7.0.3 requires at least 7.4.");
    };

    const result = await auditWordPressInstallation({ path: "/var/www/vhosts/old.test/httpdocs" }, runner);

    expect(result.health).toMatchObject({ reachable: true, status: "runtime-incompatible" });
    expect(result.priorities).toContain("WordPress runtime is incompatible with the installed PHP version");
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
    let requestedSlug = "";
    const audit = await auditWordPressInstallation({ path: "/srv/site" }, async (_installation, command) => {
      if (command.includes("core version")) return "6.6.1";
      if (command.includes("plugin list")) return JSON.stringify([{ name: "sample-plugin/sample-plugin.php", version: "1.0", status: "active", update: "none" }]);
      return "ok";
    }, {
      vulnerabilityLookup: async (slug) => {
        requestedSlug = slug;
        return {
        slug: "sample-plugin",
        vulnerabilities: [{ id: "CVE-2026-0001", title: "Example issue", severity: "high", cve: ["CVE-2026-0001"], source: "WPVulnerability" }],
        };
      },
    });

    expect(requestedSlug).toBe("sample-plugin");
    expect(audit.plugins[0].vulnerabilities[0].cve).toEqual(["CVE-2026-0001"]);
    expect(audit.vulnerabilities[0].slug).toBe("sample-plugin");
    expect(audit.priorities).toContain("plugin sample-plugin/sample-plugin.php has known vulnerabilities (via WPVulnerability): high");
  });
});
