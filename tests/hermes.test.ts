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
    expect(result.outcome).toBe("failed");
    expect(called).toBe(false);
  });

  it("invokes hermes send with the configured target", async () => {
    const calls: Array<{ binary: string; args: string[]; timeout: number }> = [];
    const result = await sendFindingEventsViaHermes([event], {
      target: "whatsapp:123456789@s.whatsapp.net",
      commandRunner: async (binary, args, timeout) => { calls.push({ binary, args, timeout }); },
    });
    expect(result.outcome).toBe("accepted");
    expect(result.acceptedEvents).toEqual([event]);
    expect(calls).toEqual([{
      binary: "hermes",
      args: ["send", "--to", "whatsapp:123456789@s.whatsapp.net", "[P1] opened on dev/example.test: PHP files found in uploads [event finding-1.0]"],
      timeout: 15000,
    }]);
  });

  it("returns partial delivery without throwing when Hermes fails", async () => {
    const result = await sendFindingEventsViaHermes([event], {
      target: "whatsapp:123@s.whatsapp.net",
      commandRunner: async () => { throw new Error("hermes unavailable"); },
    });
    expect(result.outcome).toBe("unknown");
    expect(result.acceptedEvents).toEqual([]);
  });

  it("retries a failed Hermes command with bounded backoff", async () => {
    let calls = 0;
    const result = await sendFindingEventsViaHermes([event], {
      target: "whatsapp:123@s.whatsapp.net",
      maxAttempts: 2,
      retryDelayMs: 0,
      commandRunner: async () => {
        calls += 1;
        if (calls === 1) throw new Error("temporary failure");
      },
    });
    expect(result.outcome).toBe("accepted");
    expect(calls).toBe(2);
  });

  it("acknowledges only successful chunks when a later chunk fails", async () => {
    const secondEvent = {
      ...event,
      finding: { ...event.finding, id: "finding-2", domain: "second.test" },
    } satisfies FindingEvent;
    let calls = 0;
    const result = await sendFindingEventsViaHermes([event, secondEvent], {
      target: "whatsapp:123@s.whatsapp.net",
      maxMessageLength: 10,
      maxAttempts: 1,
      commandRunner: async () => {
        calls += 1;
        if (calls === 2) throw new Error("second chunk failed");
      },
    });
    expect(calls).toBe(2);
    expect(result.outcome).toBe("unknown");
    expect(result.acceptedEvents).toEqual([event]);
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
