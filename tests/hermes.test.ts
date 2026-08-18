import { describe, expect, it } from "vitest";
import { isHermesWhatsAppTarget, sendFindingEventsViaHermes, sendHermesText } from "../src/hermes";
import type { FindingEvent } from "../src/finding-state";

const event: FindingEvent = {
  type: "opened",
  occurredAt: "2026-08-18T12:00:00.000Z",
  finding: {
    id: "finding-1",
    severity: "P1",
    code: "suspicious-upload-php",
    host: "dev",
    domain: "example.test",
    installationPath: "/var/www/vhosts/example.test/httpdocs",
    message: "PHP files found in uploads",
    status: "open",
    firstSeen: "2026-08-18T12:00:00.000Z",
    lastSeen: "2026-08-18T12:00:00.000Z",
  },
};

describe("Hermes notifications", () => {
  it("accepts only explicit WhatsApp targets", () => {
    expect(isHermesWhatsAppTarget("whatsapp:123@s.whatsapp.net")).toBe(true);
    expect(isHermesWhatsAppTarget("telegram:123")).toBe(false);
    expect(isHermesWhatsAppTarget("whatsapp:123 target")).toBe(false);
  });

  it("does not run a process when the target is disabled", async () => {
    let called = false;
    const result = await sendFindingEventsViaHermes([event], {
      commandRunner: async () => { called = true; },
    });
    expect(result.sent).toBe(false);
    expect(called).toBe(false);
  });

  it("invokes hermes send with the configured target", async () => {
    const calls: Array<{ binary: string; args: string[]; timeout: number }> = [];
    const result = await sendFindingEventsViaHermes([event], {
      target: "whatsapp:123456789@s.whatsapp.net",
      commandRunner: async (binary, args, timeout) => { calls.push({ binary, args, timeout }); },
    });
    expect(result.sent).toBe(true);
    expect(result.sentEvents).toEqual([event]);
    expect(calls).toEqual([{
      binary: "hermes",
      args: ["send", "--to", "whatsapp:123456789@s.whatsapp.net", "[P1] opened on dev/example.test: PHP files found in uploads"],
      timeout: 15000,
    }]);
  });

  it("returns partial delivery without throwing when Hermes fails", async () => {
    const result = await sendFindingEventsViaHermes([event], {
      target: "whatsapp:123@s.whatsapp.net",
      commandRunner: async () => { throw new Error("hermes unavailable"); },
    });
    expect(result.sent).toBe(false);
    expect(result.sentEvents).toEqual([]);
  });

  it("supports a guarded one-shot text delivery", async () => {
    const calls: string[][] = [];
    await sendHermesText("test", {
      target: "whatsapp:123@s.whatsapp.net",
      commandRunner: async (_binary, args) => { calls.push(args); },
    });
    expect(calls).toEqual([["send", "--to", "whatsapp:123@s.whatsapp.net", "test"]]);
  });
});
