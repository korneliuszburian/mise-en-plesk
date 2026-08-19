import { describe, expect, it } from "vitest";
import { createPleskWpToolkitRunner, enrichAuditWithPleskWpToolkit, parsePleskWpToolkitInventory, parseWpCliCapability } from "../src/plesk-wp-toolkit";
import { auditWordPressInstallation } from "../src/wp-audit";

const toolkitPayload = JSON.stringify([{
  id: 5,
  fullPath: "/var/www/vhosts/example.test/httpdocs/",
  version: "7.0",
  outdatedWp: true,
  unsupportedPhp: false,
  broken: false,
  infected: true,
  alive: true,
  stateText: "Working",
  plugins: {
    akismet: { name: "akismet", status: "active", version: "5.3", update_version: "5.4", autoUpdates: true },
  },
  themes: {
    twentytwentyfive: { name: "twentytwentyfive", status: "inactive", version: "1.2", update_version: "", autoUpdates: false },
  },
}]);

describe("Plesk WP Toolkit audit fallback", () => {
  it("parses the fixed WP-CLI capability envelope", () => {
    expect(parseWpCliCapability("__MISE_WP_CLI_BEGIN__\nWP-CLI 2.12.0\n__MISE_WP_CLI_STATUS_0__\n__MISE_WP_CLI_END__\n"))
      .toEqual({ available: true, version: "2.12.0", detail: "WP-CLI 2.12.0" });
    expect(parseWpCliCapability("__MISE_WP_CLI_BEGIN__\n/usr/local/bin/wp: 1: 404: not found\n__MISE_WP_CLI_STATUS_127__\n__MISE_WP_CLI_END__\n"))
      .toEqual({ available: false, detail: "/usr/local/bin/wp: 1: 404: not found" });
    expect(parseWpCliCapability("__MISE_WP_CLI_BEGIN__\nnot really WP-CLI\n__MISE_WP_CLI_STATUS_0__\n__MISE_WP_CLI_END__\n"))
      .toEqual({ available: false, detail: "not really WP-CLI" });
    expect(() => parseWpCliCapability("garbage")).toThrow("invalid capability envelope");
  });

  it("normalizes the structured Toolkit inventory by canonical installation path", () => {
    const inventory = parsePleskWpToolkitInventory(toolkitPayload);

    expect(inventory.sites.get("/var/www/vhosts/example.test/httpdocs")).toMatchObject({
      id: 5,
      version: "7.0",
      outdatedWp: true,
      infected: true,
      plugins: [{ name: "akismet", active: true, version: "5.3", hasUpdate: true }],
      themes: [{ name: "twentytwentyfive", active: false, version: "1.2", hasUpdate: false }],
    });
  });

  it("accepts the empty array and null extension shapes returned by WP Toolkit", () => {
    const inventory = parsePleskWpToolkitInventory(JSON.stringify([
      { id: 1, fullPath: "/var/www/vhosts/empty.test/httpdocs", version: "6.8", plugins: [], themes: {} },
      { id: 2, fullPath: "/var/www/vhosts/broken.test/httpdocs", version: "6.7", plugins: null, themes: null },
    ]));

    expect(inventory.sites.get("/var/www/vhosts/empty.test/httpdocs")).toMatchObject({ plugins: [], themes: [] });
    expect(inventory.sites.get("/var/www/vhosts/broken.test/httpdocs")).toMatchObject({ plugins: [], themes: [] });
  });

  it("keeps duplicate Toolkit registrations deterministic and conservative", () => {
    const inventory = parsePleskWpToolkitInventory(JSON.stringify([
      { id: 435, fullPath: "/var/www/vhosts/duplicate.test/httpdocs", version: "7.0", alive: true, infected: false, plugins: {}, themes: {} },
      { id: 135, fullPath: "/var/www/vhosts/duplicate.test/httpdocs/", version: "7.0", alive: true, infected: true, plugins: {}, themes: {} },
    ]));

    expect(inventory.sites.get("/var/www/vhosts/duplicate.test/httpdocs")).toMatchObject({ id: 135, infected: true });
    expect(inventory.warnings).toEqual([
      "WP Toolkit returned duplicate registrations for /var/www/vhosts/duplicate.test/httpdocs (IDs 135, 435); merged conservatively.",
    ]);
  });

  it("produces a useful audit when the host WP-CLI is broken", async () => {
    const site = parsePleskWpToolkitInventory(toolkitPayload).sites.get("/var/www/vhosts/example.test/httpdocs");
    expect(site).toBeDefined();
    const fallback = createPleskWpToolkitRunner(site!);

    const rawAudit = await auditWordPressInstallation(
      { path: "/var/www/vhosts/example.test/httpdocs", domain: "example.test" },
      fallback.runner,
      { suspiciousFileRunner: async () => "/var/www/vhosts/example.test/httpdocs/wp-content/uploads/shell.php\n" },
    );
    const diagnostics = fallback.diagnostics();
    const audit = enrichAuditWithPleskWpToolkit(rawAudit, site!, diagnostics);

    expect(audit).toMatchObject({
      coreVersion: "7.0",
      coreUpdateAvailable: true,
      plugins: [{ name: "akismet", version: "5.3", active: true, hasUpdate: true }],
      themes: [{ name: "twentytwentyfive", version: "1.2", active: false, hasUpdate: false }],
      integrity: { coreChecksums: "unavailable", pluginChecksums: "unavailable" },
      health: { reachable: true },
      suspiciousFiles: ["/var/www/vhosts/example.test/httpdocs/wp-content/uploads/shell.php"],
    });
    expect(audit.priorities).not.toContain("WP-CLI audit failed; manual review required");
    expect(audit.priorities).toContain("Plesk WP Toolkit reports the installation as infected");
    expect(diagnostics).toEqual({
      source: "plesk-wp-toolkit",
      limitations: [
        "WordPress.org plugin freshness metadata unavailable",
        "core checksum verification unavailable",
        "plugin checksum verification unavailable",
      ],
    });
  });

  it("does not downgrade real WP-CLI checksum failures to unavailable", async () => {
    const site = parsePleskWpToolkitInventory(toolkitPayload).sites.get("/var/www/vhosts/example.test/httpdocs");
    const fallback = createPleskWpToolkitRunner(site!, async (_installation, command) => {
      if (command.includes("verify-checksums")) throw new Error("checksum mismatch: modified file");
      throw new Error("metadata command failed");
    });

    const audit = await auditWordPressInstallation({ path: site!.fullPath }, fallback.runner);

    expect(audit.integrity).toEqual({ coreChecksums: "failed", pluginChecksums: "failed" });
    expect(audit.priorities).toContain("WordPress core checksum verification failed");
    expect(audit.priorities).toContain("WordPress plugin checksum verification needs manual review");
  });

  it("marks checksum verification unavailable when the WP-CLI runtime cannot execute it", async () => {
    const site = parsePleskWpToolkitInventory(toolkitPayload).sites.get("/var/www/vhosts/example.test/httpdocs");
    const fallback = createPleskWpToolkitRunner(site!, async (_installation, command) => {
      if (command.includes("verify-checksums")) {
        throw new Error("PHP version 7.2 but WordPress requires at least PHP 7.4");
      }
      throw new Error("metadata command failed");
    });

    const audit = await auditWordPressInstallation({ path: site!.fullPath }, fallback.runner);

    expect(audit.integrity).toEqual({ coreChecksums: "unavailable", pluginChecksums: "unavailable" });
    expect(audit.priorities).not.toContain("WordPress core checksum verification failed");
    expect(audit.priorities).not.toContain("WordPress plugin checksum verification needs manual review");
  });

  it("rejects malformed Toolkit output instead of inventing site data", () => {
    expect(() => parsePleskWpToolkitInventory("{}"))
      .toThrow("WP Toolkit inventory must be a JSON array");
    expect(() => parsePleskWpToolkitInventory('[{"id":1,"fullPath":"../site"}]'))
      .toThrow("invalid fullPath");
    expect(() => parsePleskWpToolkitInventory('[{"id":1,"fullPath":"/var/www/vhosts/site.test/httpdocs\\n"}]'))
      .toThrow("invalid fullPath");
  });
});
