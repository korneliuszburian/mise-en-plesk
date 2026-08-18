import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { runPreflight, versionArguments } from "../src/preflight";
import { writeHeartbeat } from "../src/monitor-health";

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

  it("makes sshpass blocking when inventory requires Secure Note password auth", async () => {
    const directory = await mkdtemp(join(tmpdir(), "mise-en-plesk-preflight-password-"));
    const inventoryPath = join(directory, "inventory.json");
    await writeFile(inventoryPath, JSON.stringify({
      dev: {
        alias: "dev",
        id: "dev-id",
        name: "dev ssh",
        host: "dev.example.test",
        port: 22,
        user: "deploy",
        identitySource: "bitwarden:dev-id",
        credentialMode: "secure-note-password",
      },
    }));
    const result = await runPreflight({
      inventoryPath,
      configPath: "/tmp/mise-en-plesk-no-config.json",
      env: { BW_SESSION: "short-lived" },
      commandRunner: async (command) => {
        if (command === "sshpass") throw new Error("not installed");
        return "available";
      },
    });

    expect(result.checks).toContainEqual(expect.objectContaining({
      name: "sshpass",
      ok: false,
      blocking: true,
      detail: expect.stringContaining("Secure Note password"),
    }));
    expect(result.ok).toBe(false);
  });

  it("reports a stale monitor heartbeat without making doctor fail", async () => {
    const directory = await mkdtemp(join(tmpdir(), "mise-en-plesk-preflight-"));
    const heartbeatPath = join(directory, "heartbeat.json");
    await writeHeartbeat(heartbeatPath, {
      version: 1,
      target: "all",
      startedAt: "2026-08-18T07:00:00.000Z",
      completedAt: "2026-08-18T08:00:00.000Z",
    });
    const result = await runPreflight({
      inventoryPath: "/tmp/mise-en-plesk-no-inventory.json",
      configPath: "/tmp/mise-en-plesk-no-config.json",
      heartbeatPath,
      heartbeatMaxAgeMs: 60 * 60 * 1000,
      now: new Date("2026-08-18T10:00:00.000Z"),
      env: { BW_SESSION: "short-lived" },
      commandRunner: async () => "available",
    });

    expect(result.checks).toContainEqual(expect.objectContaining({ name: "monitor-heartbeat", ok: false, blocking: false }));
    expect(result.ok).toBe(false);
  });

  it("rejects malformed config values during preflight", async () => {
    const directory = await mkdtemp(join(tmpdir(), "mise-en-plesk-config-"));
    const configPath = join(directory, "config.json");
    await writeFile(configPath, JSON.stringify({ hosts: ["master ssh"], maxConcurrentSitesPerHost: 0 }));
    const result = await runPreflight({
      inventoryPath: "/tmp/mise-en-plesk-no-inventory.json",
      configPath,
      env: { BW_SESSION: "short-lived" },
      commandRunner: async () => "available",
    });
    expect(result.checks).toContainEqual(expect.objectContaining({ name: "config", ok: false, detail: expect.stringContaining("aliases") }));
  });

  it("checks the Hermes executable only when a target is configured", async () => {
    const commands: string[] = [];
    const result = await runPreflight({
      inventoryPath: "/tmp/mise-en-plesk-no-inventory.json",
      configPath: "/tmp/mise-en-plesk-no-config.json",
      env: { BW_SESSION: "short-lived", MISE_PLESK_HERMES_WHATSAPP_TARGET: "whatsapp:123@s.whatsapp.net" },
      commandRunner: async (command) => {
        commands.push(command);
        return command === "hermes" ? "Hermes Agent 0.1" : "available";
      },
    });

    expect(commands).toContain("hermes");
    expect(result.checks.find((item) => item.name === "hermes")).toMatchObject({ ok: true, blocking: false });
  });

  it("rejects an invalid Hermes target without checking the executable", async () => {
    const commands: string[] = [];
    const result = await runPreflight({
      inventoryPath: "/tmp/mise-en-plesk-no-inventory.json",
      configPath: "/tmp/mise-en-plesk-no-config.json",
      env: { BW_SESSION: "short-lived", MISE_PLESK_HERMES_WHATSAPP_TARGET: "telegram:123" },
      commandRunner: async (command) => { commands.push(command); return "available"; },
    });

    expect(commands).not.toContain("hermes");
    expect(result.checks.find((item) => item.name === "hermes")).toMatchObject({ ok: false, blocking: false, detail: expect.stringContaining("invalid target") });
  });
});
