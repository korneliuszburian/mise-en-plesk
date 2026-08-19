import { describe, expect, it } from "vitest";
import { assertReadOnlyRenderedCommand, STATIC_WP_AUDIT_SECTIONS, type ReadOnlyCommand } from "../src/ssh-transport";
import { auditStaticWordPressInstallation, buildStaticAuditBatchCommand } from "../src/static-wp-audit";

function staticEnvelope(command: Extract<ReadOnlyCommand, { kind: "static-wp-audit-batch" }>, values: Record<string, { output: string; status: number }>): string {
  const nonce = command.markerNonce;
  return STATIC_WP_AUDIT_SECTIONS.flatMap((sectionName) => {
    const section = sectionName.toUpperCase();
    const value = values[section] ?? { output: "", status: 1 };
    return [
    `__MISE_${nonce}_${section}_BEGIN__`,
    value.output,
    `__MISE_${nonce}_${section}_STATUS_${value.status}__`,
    `__MISE_${nonce}_${section}_END__`,
    ];
  }).join("\n");
}

describe("static WordPress filesystem audit", () => {
  it("renders one nonce-framed read-only probe without executing application PHP", () => {
    const rendered = buildStaticAuditBatchCommand({ path: "/var/www/vhosts/example.test/httpdocs/web" }, { useSudo: true });

    expect(rendered).toMatch(/__MISE_[a-f0-9]{32}_CLASSIC_VERSION_BEGIN__/);
    expect(rendered).toContain("/web/wp/wp-includes/version.php");
    expect(rendered).toContain("/web/app/plugins");
    expect(rendered).toContain("/web/app/uploads");
    expect(rendered).not.toMatch(/(?:^|;\s*)(?:sudo -n -- )?php\s/);
    expect(rendered.match(/sudo -S/g)).toHaveLength(1);
    expect(() => assertReadOnlyRenderedCommand(rendered)).not.toThrow();
  });

  it("audits an unregistered Bedrock installation from bounded filesystem metadata", async () => {
    const installation = { path: "/var/www/vhosts/example.test/httpdocs/web", domain: "example.test" };
    const audit = await auditStaticWordPressInstallation(installation, async (command) => {
      if (command.kind !== "static-wp-audit-batch") throw new Error("unexpected command");
      return staticEnvelope(command, {
        CLASSIC_VERSION: { output: "", status: 2 },
        BEDROCK_VERSION: { output: "$wp_version = '6.8.3';", status: 0 },
        BEDROCK_COMPOSER: { output: "/var/www/vhosts/example.test/httpdocs/composer.json", status: 0 },
        BEDROCK_CONFIG: { output: "/var/www/vhosts/example.test/httpdocs/config/application.php", status: 0 },
        CLASSIC_PLUGINS: { output: "", status: 1 },
        BEDROCK_PLUGINS: { output: "akismet\nindex.php\nwordfence\nhello.php", status: 0 },
        CLASSIC_THEMES: { output: "", status: 1 },
        BEDROCK_THEMES: { output: "sage", status: 0 },
        CLASSIC_UPLOADS: { output: "", status: 1 },
        BEDROCK_UPLOADS: { output: "/var/www/vhosts/example.test/httpdocs/web/app/uploads/backdoor.php", status: 0 },
      });
    });

    expect(audit).toMatchObject({
      coreVersion: "6.8.3",
      auditSource: "static-filesystem",
      layout: {
        kind: "bedrock",
        documentRoot: "/var/www/vhosts/example.test/httpdocs/web",
        coreRoot: "/var/www/vhosts/example.test/httpdocs/web/wp",
        contentRoot: "/var/www/vhosts/example.test/httpdocs/web/app",
      },
      plugins: [
        { name: "akismet", version: "unknown", active: undefined, vulnerabilities: [] },
        { name: "hello.php", version: "unknown", active: undefined, vulnerabilities: [] },
        { name: "wordfence", version: "unknown", active: undefined, vulnerabilities: [] },
      ],
      themes: [{ name: "sage", version: "unknown", active: undefined }],
      integrity: { coreChecksums: "unavailable", pluginChecksums: "unavailable" },
      suspiciousFiles: ["/var/www/vhosts/example.test/httpdocs/web/app/uploads/backdoor.php"],
      health: { reachable: true },
    });
    expect(audit.limitations).toContain("plugin versions, activation state, and update status unavailable from static filesystem audit");
    expect(audit.priorities).toContain("PHP files found in uploads (possible backdoors)");
  });

  it("normalizes a version.php-only canonical Bedrock core candidate to its document root", async () => {
    const installation = {
      path: "/var/www/vhosts/example.test/httpdocs/web/wp",
      detectionSignals: ["wp-includes/version.php" as const],
      pathEvidence: [{
        signal: "wp-includes/version.php" as const,
        detectedPath: "/var/www/vhosts/example.test/httpdocs/web/wp/wp-includes/version.php",
        rootKind: "core-root" as const,
      }],
    };
    const audit = await auditStaticWordPressInstallation(installation, async (command) => {
      if (command.kind !== "static-wp-audit-batch") throw new Error("unexpected command");
      expect(command.bedrockDocumentRoot).toBe("/var/www/vhosts/example.test/httpdocs/web");
      return staticEnvelope(command, {
        CLASSIC_VERSION: { output: "$wp_version = '6.8.3';", status: 0 },
        BEDROCK_VERSION: { output: "$wp_version = '6.8.3';", status: 0 },
        BEDROCK_COMPOSER: { output: "/var/www/vhosts/example.test/httpdocs/composer.json", status: 0 },
        BEDROCK_CONFIG: { output: "/var/www/vhosts/example.test/httpdocs/config/application.php", status: 0 },
        BEDROCK_PLUGINS: { output: "akismet", status: 0 },
        BEDROCK_THEMES: { output: "sage", status: 0 },
        BEDROCK_UPLOADS: { output: "", status: 0 },
      });
    });

    expect(audit).toMatchObject({
      auditSource: "static-filesystem",
      layout: {
        kind: "bedrock",
        projectRoot: "/var/www/vhosts/example.test/httpdocs",
        documentRoot: "/var/www/vhosts/example.test/httpdocs/web",
        coreRoot: "/var/www/vhosts/example.test/httpdocs/web/wp",
        contentRoot: "/var/www/vhosts/example.test/httpdocs/web/app",
      },
    });
  });

  it("applies opt-in vulnerability intelligence to statically discovered plugin slugs", async () => {
    const audit = await auditStaticWordPressInstallation({ path: "/var/www/vhosts/example.test/httpdocs" }, async (command) => {
      if (command.kind !== "static-wp-audit-batch") throw new Error("unexpected command");
      return staticEnvelope(command, {
        CLASSIC_VERSION: { output: "$wp_version = '6.8.3';", status: 0 },
        BEDROCK_VERSION: { output: "", status: 2 },
        CLASSIC_PLUGINS: { output: "vulnerable-plugin", status: 0 },
        BEDROCK_PLUGINS: { output: "", status: 1 },
        CLASSIC_THEMES: { output: "theme", status: 0 },
        BEDROCK_THEMES: { output: "", status: 1 },
        CLASSIC_UPLOADS: { output: "", status: 0 },
        BEDROCK_UPLOADS: { output: "", status: 1 },
      });
    }, {
      enabled: true,
      vulnerabilityResourceLookup: async (resource, identifier) => resource === "plugin" ? {
        status: "known",
        checkedAt: "2026-08-19T00:00:00.000Z",
        summary: {
          resource,
          identifier,
          vulnerabilities: [{ id: "CVE-2026-1", title: "RCE", severity: "critical", cve: ["CVE-2026-1"], source: "WPVulnerability" }],
        },
      } : { status: "empty", checkedAt: "2026-08-19T00:00:00.000Z" },
    });

    expect(audit.plugins[0]?.vulnerabilities).toHaveLength(0);
    expect(audit.unscopedVulnerabilityIntelligence).toHaveLength(1);
    expect(audit.vulnerabilityStatus).toBe("complete");
    expect(audit.priorities).not.toContain("plugin vulnerable-plugin has known vulnerabilities (via WPVulnerability): critical");
    expect(audit.limitations).toContain("plugin/theme vulnerability records are unscoped intelligence because installed versions are unavailable");
  });

  it("rejects Bedrock-shaped core files without canonical project markers", async () => {
    const audit = await auditStaticWordPressInstallation({
      path: "/var/www/vhosts/example.test/httpdocs/web/wp",
      detectionSignals: ["wp-includes/version.php"],
      pathEvidence: [{ signal: "wp-includes/version.php", detectedPath: "/var/www/vhosts/example.test/httpdocs/web/wp/wp-includes/version.php", rootKind: "core-root" }],
    }, async (command) => {
      if (command.kind !== "static-wp-audit-batch") throw new Error("unexpected command");
      return staticEnvelope(command, {
        CLASSIC_VERSION: { output: "$wp_version = '6.8.3';", status: 0 },
        BEDROCK_VERSION: { output: "$wp_version = '6.8.3';", status: 0 },
        BEDROCK_COMPOSER: { output: "", status: 1 },
        BEDROCK_CONFIG: { output: "", status: 1 },
        BEDROCK_UPLOADS: { output: "/var/www/vhosts/example.test/httpdocs/web/app/uploads/shell.php", status: 0 },
      });
    });

    expect(audit).toMatchObject({ auditSource: "none", health: { status: "audit-unavailable", detail: "Bedrock core path found without canonical project markers" } });
    expect(audit.suspiciousFiles).toEqual(["/var/www/vhosts/example.test/httpdocs/web/app/uploads/shell.php"]);
  });

  it("fails closed on ambiguous classic and Bedrock layout signals", async () => {
    const audit = await auditStaticWordPressInstallation({ path: "/var/www/vhosts/example.test/httpdocs/web" }, async (command) => {
      if (command.kind !== "static-wp-audit-batch") throw new Error("unexpected command");
      return staticEnvelope(command, {
        CLASSIC_VERSION: { output: "$wp_version = '6.8.3';", status: 0 },
        BEDROCK_VERSION: { output: "$wp_version = '6.8.3';", status: 0 },
        BEDROCK_COMPOSER: { output: "/var/www/vhosts/example.test/httpdocs/composer.json", status: 0 },
        BEDROCK_CONFIG: { output: "/var/www/vhosts/example.test/httpdocs/config/application.php", status: 0 },
      });
    });

    expect(audit).toMatchObject({ auditSource: "none", health: { status: "audit-unavailable", detail: "classic and Bedrock layout signals are ambiguous" } });
  });

  it("keeps failed filesystem sections unavailable instead of reporting empty success", async () => {
    const audit = await auditStaticWordPressInstallation({ path: "/var/www/vhosts/example.test/httpdocs" }, async (command) => {
      if (command.kind !== "static-wp-audit-batch") throw new Error("unexpected command");
      return staticEnvelope(command, {
        CLASSIC_VERSION: { output: "$wp_version = '6.8.3';", status: 0 },
        CLASSIC_PLUGINS: { output: "permission denied", status: 1 },
        CLASSIC_THEMES: { output: "permission denied", status: 1 },
        CLASSIC_UPLOADS: { output: "permission denied", status: 1 },
      });
    });

    expect(audit.staticCapabilities).toEqual({ pluginInventory: "unavailable", themeInventory: "unavailable", suspiciousUploads: "unavailable", updateStatus: "unavailable" });
    expect(audit.priorities).toContain("Static filesystem audit incomplete; manual review required");
  });

  it("keeps an explicit source gap when no supported core layout is readable", async () => {
    const audit = await auditStaticWordPressInstallation({ path: "/var/www/vhosts/example.test/httpdocs-copy" }, async (command) => {
      if (command.kind !== "static-wp-audit-batch") throw new Error("unexpected command");
      return staticEnvelope(command, Object.fromEntries([
        ...["CLASSIC_VERSION", "BEDROCK_VERSION", "CLASSIC_PLUGINS", "BEDROCK_PLUGINS", "CLASSIC_THEMES", "BEDROCK_THEMES"].map((section) => [section, { output: "", status: 1 }]),
        ["CLASSIC_UPLOADS", { output: "/var/www/vhosts/example.test/httpdocs-copy/wp-content/uploads/shell.php", status: 0 }],
        ["BEDROCK_UPLOADS", { output: "", status: 1 }],
      ]));
    });

    expect(audit).toMatchObject({
      auditSource: "none",
      coreVersion: "unknown",
      health: { reachable: true, status: "audit-unavailable", detail: "no readable classic or Bedrock core version file" },
      suspiciousFiles: ["/var/www/vhosts/example.test/httpdocs-copy/wp-content/uploads/shell.php"],
    });
    expect(audit.priorities).toContain("WordPress audit data unavailable; manual review required");
  });

  it("fails closed when section framing is duplicated", async () => {
    const audit = await auditStaticWordPressInstallation({ path: "/var/www/vhosts/example.test/httpdocs" }, async (command) => {
      if (command.kind !== "static-wp-audit-batch") throw new Error("unexpected command");
      const envelope = staticEnvelope(command, { CLASSIC_VERSION: { output: "$wp_version = '6.8.3';", status: 0 } });
      return `${envelope}\n${envelope}`;
    });

    expect(audit).toMatchObject({
      auditSource: "none",
      health: { status: "audit-unavailable", detail: "static filesystem probe returned invalid framing" },
    });
  });

  it("classifies runner output limits without exposing raw errors", async () => {
    const audit = await auditStaticWordPressInstallation({ path: "/var/www/vhosts/example.test/httpdocs" }, async () => {
      throw new Error("stdout maxBuffer length exceeded; output exceeded configured limit /secret/path");
    });

    expect(audit.health.detail).toBe("static filesystem probe exceeded the scanner output limit");
  });
});
