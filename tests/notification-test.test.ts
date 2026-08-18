import { describe, expect, it } from "vitest";
import { createWhatsAppTestEvent, requireWhatsAppTestConfirmation } from "../src/notification-test";

describe("WhatsApp test event", () => {
  it("creates an eligible P1 event without site or credential data", () => {
    const event = createWhatsAppTestEvent(new Date("2026-08-18T10:00:00.000Z"));

    expect(event).toMatchObject({
      type: "opened",
      occurredAt: "2026-08-18T10:00:00.000Z",
      finding: {
        id: "notification-test",
        code: "monitor-stale",
        severity: "P1",
        message: "mise-en-plesk WhatsApp delivery test",
      },
    });
  });

  it("requires the exact runtime recipient before an outbound test", () => {
    expect(() => requireWhatsAppTestConfirmation(["--confirm=48123123123"], "48123123123")).not.toThrow();
    expect(() => requireWhatsAppTestConfirmation(["--confirm"], "48123123123")).toThrow("--confirm=<configured recipient>");
    expect(() => requireWhatsAppTestConfirmation(["--confirm=48999999999"], "48123123123")).toThrow("--confirm=<configured recipient>");
    expect(() => requireWhatsAppTestConfirmation(["--confirm=48123123123", "--json"], "48123123123")).toThrow("--confirm=<configured recipient>");
    expect(() => requireWhatsAppTestConfirmation(["--confirm=48123123123"], undefined)).toThrow("recipient is not configured");
  });
});
