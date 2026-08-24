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
    expect(() => buildWpCliCommand({ path: "/var/www/vhosts/example.test/httpdocs" }, "plugin update --all")).toThrow("Unsupported read-only WP command");
  });

  it("prefixes every fixed audit command with non-interactive sudo when enabled", () => {
    const command = buildWpAuditBatchCommand({ path: "/var/www/vhosts/example.test/httpdocs" }, { useSudo: true });

    expect(command.startsWith("sudo -S -p '' -v; ")).toBe(true);
    expect(command.match(/sudo -S/g)).toHaveLength(1);
    expect(command).toContain("sudo -n -- wp core version");
    expect(command).toContain("sudo -n -- find '/var/www/vhosts/example.test/httpdocs/wp-content/uploads'");
  });

  it("builds one read-only batch for all per-installation checks", () => {
    const command = buildWpAuditBatchCommand({ path: "/var/www/vhosts/example.test/httpdocs" });

    expect(command).toMatch(/__MISE_[a-f0-9]{32}_CORE_BEGIN__/);
    expect(command).toContain("core check-update --format=json");
    expect(command).toMatch(/__MISE_[a-f0-9]{32}_PLUGINS_BEGIN__/);
    expect(command).toMatch(/__MISE_[a-f0-9]{32}_CORE_UPDATE_BEGIN__/);
    expect(command).toMatch(/__MISE_[a-f0-9]{32}_PLUGIN_CHECKSUMS_BEGIN__/);
    expect(command).toContain("plugin verify-checksums --all --strict");
    expect(command).toContain("theme list --format=json");
    expect(command).toMatch(/__MISE_[a-f0-9]{32}_CORE_STATUS_\$\{status\}__/);
    expect(command).not.toContain("value=$(wp");
    expect(command).toContain("wp core verify-checksums");
    expect(command).toContain("find '/var/www/vhosts/example.test/httpdocs/wp-content/uploads'");
  });

  it("builds a batch through a registered WP Toolkit instance", () => {
    const command = buildWpAuditBatchCommand(
      { path: "/var/www/vhosts/example.test/httpdocs" },
      { useSudo: true, runtime: { kind: "plesk-wp-toolkit", instanceId: 7 } },
    );

    expect(command).toContain("plesk ext wp-toolkit --wp-cli -instance-id 7 -- plugin list");
    expect(command).toContain("plesk ext wp-toolkit --wp-cli -instance-id 7 -- core verify-checksums");
  });

  it("reuses one batch result for WP and uploads checks", async () => {
    let calls = 0;
    const batched = createBatchedWpRunners({ path: "/var/www/vhosts/example.test/httpdocs" }, async (command) => {
      calls += 1;
      const nonce = command.kind === "wp-audit-batch" ? command.markerNonce! : "";
      const marker = (section: string, phase: string) => `__MISE_${nonce}_${section}_${phase}__`;
      return [
        marker("CORE", "BEGIN"), "6.6.1", marker("CORE", "STATUS_0"), marker("CORE", "END"),
        marker("CORE_UPDATE", "BEGIN"), "[]", marker("CORE_UPDATE", "STATUS_0"), marker("CORE_UPDATE", "END"),
        marker("PLUGINS", "BEGIN"), "[]", marker("PLUGINS", "STATUS_0"), marker("PLUGINS", "END"),
        marker("PLUGIN_CHECKSUMS", "BEGIN"), "Success", marker("PLUGIN_CHECKSUMS", "STATUS_0"), marker("PLUGIN_CHECKSUMS", "END"),
        marker("THEMES", "BEGIN"), "[]", marker("THEMES", "STATUS_0"), marker("THEMES", "END"),
        marker("CHECKSUMS", "BEGIN"), "ok", marker("CHECKSUMS", "STATUS_0"), marker("CHECKSUMS", "END"),
        marker("UPLOADS", "BEGIN"), "/var/www/vhosts/example.test/httpdocs/wp-content/uploads/shell.php", marker("UPLOADS", "STATUS_0"), marker("UPLOADS", "END"),
      ].join("\n");
    });

    await expect(batched.runner({ path: "/var/www/vhosts/example.test/httpdocs" }, "core version")).resolves.toBe("6.6.1");
    await expect(batched.runner({ path: "/var/www/vhosts/example.test/httpdocs" }, "core check-update --format=json")).resolves.toBe("[]");
    await expect(batched.runner({ path: "/var/www/vhosts/example.test/httpdocs" }, "plugin verify-checksums --all --strict")).resolves.toBe("Success");
    await expect(batched.suspiciousFileRunner({ path: "/var/www/vhosts/example.test/httpdocs" }, "ignored")).resolves.toContain("shell.php");
    expect(calls).toBe(1);
  });

  it("distinguishes checksum mismatches from unavailable batch capabilities", async () => {
    const batch = (nonce: string, pluginOutput: string, pluginStatus: number) => {
      const marker = (section: string, phase: string) => `__MISE_${nonce}_${section}_${phase}__`;
      return [
        marker("CORE", "BEGIN"), "6.6.1", marker("CORE", "STATUS_0"), marker("CORE", "END"),
        marker("CORE_UPDATE", "BEGIN"), "[]", marker("CORE_UPDATE", "STATUS_0"), marker("CORE_UPDATE", "END"),
        marker("PLUGINS", "BEGIN"), "[]", marker("PLUGINS", "STATUS_0"), marker("PLUGINS", "END"),
        marker("PLUGIN_CHECKSUMS", "BEGIN"), pluginOutput, marker("PLUGIN_CHECKSUMS", `STATUS_${pluginStatus}`), marker("PLUGIN_CHECKSUMS", "END"),
        marker("THEMES", "BEGIN"), "[]", marker("THEMES", "STATUS_0"), marker("THEMES", "END"),
        marker("CHECKSUMS", "BEGIN"), "ok", marker("CHECKSUMS", "STATUS_0"), marker("CHECKSUMS", "END"),
        marker("UPLOADS", "BEGIN"), "", marker("UPLOADS", "STATUS_0"), marker("UPLOADS", "END"),
      ].join("\n");
    };
    const unavailable = createBatchedWpRunners({ path: "/var/www/vhosts/example.test/httpdocs" }, async (command) => batch(command.kind === "wp-audit-batch" ? command.markerNonce! : "", "unknown option --strict token=secret", 3));
    const mismatch = createBatchedWpRunners({ path: "/var/www/vhosts/example.test/httpdocs" }, async (command) => batch(command.kind === "wp-audit-batch" ? command.markerNonce! : "", "Warning: checksum mismatch: modified file", 1));

    await expect(unavailable.runner({ path: "/var/www/vhosts/example.test/httpdocs" }, "plugin verify-checksums --all --strict"))
      .rejects.toMatchObject({ name: "AuditCapabilityUnavailableError", message: "WP-CLI command failed" });
    await expect(mismatch.runner({ path: "/var/www/vhosts/example.test/httpdocs" }, "plugin verify-checksums --all --strict"))
      .rejects.toThrow("WP-CLI reported checksum mismatches");
  });

  it("does not accept marker-like plugin output without the random batch nonce", async () => {
    const batched = createBatchedWpRunners({ path: "/var/www/vhosts/example.test/httpdocs" }, async (command) => {
      const nonce = command.kind === "wp-audit-batch" ? command.markerNonce! : "";
      return [
        `__MISE_${nonce}_CORE_BEGIN__`,
        "__MISE_CORE_STATUS_0__\n__MISE_CORE_END__",
        `__MISE_${nonce}_CORE_STATUS_7__`,
        `__MISE_${nonce}_CORE_END__`,
      ].join("\n");
    });

    await expect(batched.runner({ path: "/var/www/vhosts/example.test/httpdocs" }, "core version")).rejects.toThrow("invalid core_update framing");
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
    expect(calls).toContain("core check-update --format=json");
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

  it("treats PHP/plugin failures as reachable broken WP-CLI", async () => {
    const runner: WpCommandRunner = async (_installation, command) => {
      if (command === "core version") return "6.6.1";
      throw new Error("PHP Parse error: syntax error, unexpected ')' in plugin.php");
    };

    const result = await auditWordPressInstallation({ path: "/var/www/vhosts/broken.test/httpdocs" }, runner);

    expect(result).toMatchObject({
      coreVersion: "6.6.1",
      health: { reachable: true, status: "wp-cli-broken" },
    });
    expect(result.priorities).toContain("WP-CLI audit failed; manual review required");
  });

  it("classifies missing, permission-denied, and broken WP-CLI separately", async () => {
    const cases = [
      ["wp: command not found", "wp-cli-missing"],
      ["sudo: a password is required", "wp-cli-permission-denied"],
      ["/usr/local/bin/wp: 1: 404: not found", "wp-cli-missing"],
      ["/usr/local/bin/wp: 404 not found", "wp-cli-missing"],
    ] as const;

    for (const [message, status] of cases) {
      const result = await auditWordPressInstallation({ path: "/var/www/vhosts/example.test/httpdocs" }, async (_installation, command) => {
        if (command === "core version") return "6.6.1";
        throw new Error(message);
      });

      expect(result.health).toMatchObject({ reachable: true, status });
      expect(result.priorities).toContain("WP-CLI audit failed; manual review required");
    }
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

  it("treats a WP-CLI command timeout as a site audit failure, not an unreachable SSH host", async () => {
    const result = await auditWordPressInstallation({ path: "/var/www/vhosts/slow.test/httpdocs" }, async () => {
      throw new Error("Command failed (timeout)");
    });

    expect(result.health).toEqual({ reachable: true, status: "wp-cli-error", detail: "WP-CLI command timed out" });
  });

  it("still scans uploads when WP-CLI fails", async () => {
    const result = await auditWordPressInstallation(
      { path: "/var/www/vhosts/broken.test/httpdocs" },
      async () => { throw new Error("/usr/local/bin/wp: 1: 404: not found"); },
      {
        suspiciousFileRunner: async () => "/var/www/vhosts/broken.test/httpdocs/wp-content/uploads/backdoor.php\n",
      },
    );

    expect(result.health).toMatchObject({ reachable: true, status: "wp-cli-missing" });
    expect(result.suspiciousFiles).toEqual([
      "/var/www/vhosts/broken.test/httpdocs/wp-content/uploads/backdoor.php",
    ]);
    expect(result.priorities).toContain("PHP files found in uploads (possible backdoors)");
  });

  it("flags plugin updates and stale or inactive wp.org plugins", () => {
    const audit = applyHeuristics({
      installation: { path: "/var/www/vhosts/example.test/httpdocs" },
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

  it("keeps uploads index files as evidence without escalating them as possible backdoors", async () => {
    const audit = applyHeuristics({
      installation: { path: "/var/www/vhosts/site.test/httpdocs" },
      coreVersion: "6.9.4",
      plugins: [],
      vulnerabilities: [],
      suspiciousFiles: ["/var/www/vhosts/site.test/httpdocs/wp-content/uploads/2026/08/index.php"],
      health: { reachable: true },
    });

    expect(audit.suspiciousFiles).toHaveLength(1);
    expect(audit.priorities).not.toContain("PHP files found in uploads (possible backdoors)");
  });

  it("treats checksum timeouts as unavailable instead of checksum failures", async () => {
    const audit = await auditWordPressInstallation({ path: "/var/www/vhosts/slow.test/httpdocs" }, async (_installation, command) => {
      if (command === "core version") return "6.9.4";
      if (command.startsWith("core check-update")) return "[]";
      if (command.startsWith("plugin list")) return "[]";
      if (command.startsWith("theme list")) return "[]";
      if (command === "core verify-checksums") throw new Error("WP-CLI command timed out");
      if (command.startsWith("plugin verify-checksums")) return "Success";
      return "ok";
    });

    expect(audit.integrity).toMatchObject({
      coreChecksums: "unavailable",
      coreDetail: "WP-CLI command timed out",
      pluginChecksums: "verified",
    });
    expect(audit.priorities).not.toContain("WordPress core checksum verification failed");
  });

  it("attaches vulnerability summaries from an injected lookup", async () => {
    let requestedSlug = "";
    const audit = await auditWordPressInstallation({ path: "/var/www/vhosts/example.test/httpdocs" }, async (_installation, command) => {
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

  it("enriches core and themes through the typed vulnerability resource lookup", async () => {
    const requested: string[] = [];
    const audit = await auditWordPressInstallation({ path: "/var/www/vhosts/example.test/httpdocs" }, async (_installation, command) => {
      if (command === "core version") return "6.6.1";
      if (command.startsWith("plugin list")) return "[]";
      if (command.startsWith("theme list")) return JSON.stringify([{ name: "custom-theme", version: "1.0", status: "active", update: "none" }]);
      return "ok";
    }, {
      enabled: true,
      vulnerabilityResourceLookup: async (resource, identifier) => {
        requested.push(`${resource}:${identifier}`);
        if (resource === "core") return { status: "known", summary: { resource, identifier, vulnerabilities: [{ id: "CVE-2026-0005", title: "Core issue", cve: [], source: "WPVulnerability" }] } };
        if (resource === "theme") return { status: "known", summary: { resource, identifier, vulnerabilities: [{ id: "CVE-2026-0006", title: "Theme issue", cve: [], source: "WPVulnerability" }] } };
        return { status: "empty" };
      },
    });

    expect(requested).toEqual(["theme:custom-theme", "core:6.6.1"]);
    expect(audit.vulnerabilityStatus).toBe("complete");
    expect(audit.coreVulnerabilities?.[0].id).toBe("CVE-2026-0005");
    expect(audit.themes?.[0].vulnerabilities?.[0].id).toBe("CVE-2026-0006");
    expect(audit.priorities).toEqual([
      "theme custom-theme has known vulnerabilities (via WPVulnerability)",
      "WordPress core has known vulnerabilities (via WPVulnerability)",
    ]);
  });
});
