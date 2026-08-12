import { describe, expect, it } from "vitest";
import { auditWordPressInstallation, type WpCommandRunner } from "../src/wp-audit";

describe("WordPress audit", () => {
  it("collects core, plugin, and checksum health through wp CLI", async () => {
    const runner: WpCommandRunner = async (_instance, command) => {
      if (command.includes("core version")) return "6.6.1\n";
      if (command.includes("plugin list")) {
        return JSON.stringify([
          { name: "akismet", version: "5.3", status: "active" },
          { name: "old-plugin", version: "1.0", status: "inactive" },
        ]);
      }
      return "Success: WordPress installation verifies against checksums.";
    };

    await expect(auditWordPressInstallation({ path: "/var/www/vhosts/example.test/httpdocs", domain: "example.test" }, runner)).resolves.toEqual({
      installation: { path: "/var/www/vhosts/example.test/httpdocs", domain: "example.test" },
      coreVersion: "6.6.1",
      plugins: [
        { name: "akismet", version: "5.3", active: true },
        { name: "old-plugin", version: "1.0", active: false },
      ],
      health: { reachable: true },
      priorities: [],
    });
  });
});
