import { describe, expect, it } from "vitest";
import { runPreflight, versionArguments } from "../src/preflight";

describe("local preflight", () => {
  it("uses OpenSSH's single-dash version flag", () => {
    expect(versionArguments("ssh")).toEqual(["-V"]);
    expect(versionArguments("sshpass")).toEqual(["-V"]);
    expect(versionArguments("bw")).toEqual(["--version"]);
  });

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
    expect(result.checks.find((item) => item.name === "whatsapp")).toMatchObject({ ok: true, detail: expect.stringContaining("disabled") });
    expect(result.ok).toBe(false);
  });

  it("reports partial WhatsApp configuration without exposing values", async () => {
    const result = await runPreflight({
      inventoryPath: "/tmp/mise-en-plesk-no-inventory.json",
      configPath: "/tmp/mise-en-plesk-no-config.json",
      env: { MISE_PLESK_WHATSAPP_ACCESS_TOKEN: "do-not-print", MISE_PLESK_WHATSAPP_PHONE_NUMBER_ID: "123" },
      commandRunner: async () => "available",
    });
    const whatsapp = result.checks.find((item) => item.name === "whatsapp");
    expect(whatsapp).toMatchObject({ ok: false, blocking: false });
    expect(whatsapp?.detail).toContain("MISE_PLESK_WHATSAPP_RECIPIENT");
    expect(whatsapp?.detail).not.toContain("do-not-print");
  });
});
