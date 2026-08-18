import { describe, expect, it } from "vitest";
import { runPreflight } from "../src/preflight";

describe("local preflight", () => {
  it("reports missing runtime prerequisites without throwing", async () => {
    const result = await runPreflight({
      inventoryPath: "/tmp/mise-en-plesk-no-inventory.json",
      configPath: "/tmp/mise-en-plesk-no-config.json",
      env: {},
      commandRunner: async (command) => {
        if (command === "ssh") return "OpenSSH";
        throw new Error("not installed");
      },
    });

    expect(result.ok).toBe(false);
    expect(result.checks).toEqual(expect.arrayContaining([
      expect.objectContaining({ name: "ssh", ok: true }),
      expect.objectContaining({ name: "bw", ok: false }),
      expect.objectContaining({ name: "sshpass", ok: false, blocking: false }),
      expect.objectContaining({ name: "BW_SESSION", ok: false }),
      expect.objectContaining({ name: "inventory", ok: false }),
    ]));
  });

  it("keeps alerting informational rather than a scan blocker", async () => {
    const result = await runPreflight({
      inventoryPath: "/tmp/mise-en-plesk-no-inventory.json",
      configPath: "/tmp/mise-en-plesk-no-config.json",
      env: { BW_SESSION: "short-lived" },
      commandRunner: async () => "available",
    });

    expect(result.checks.find((item) => item.name === "alerting")).toMatchObject({ ok: false });
    expect(result.ok).toBe(false);
  });
});
