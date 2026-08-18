import { describe, expect, it } from "vitest";
import { notifyFindingEventsToWhatsApp } from "../src/whatsapp";
import type { FindingEvent } from "../src/finding-state";

const findingEvent: FindingEvent = {
  type: "opened",
  occurredAt: "2026-08-18T00:00:00.000Z",
  finding: {
    id: "finding-1", code: "plugin-vulnerable", severity: "P1", host: "master-ssh",
    installationPath: "/srv/site", domain: "example.test", message: "critical plugin vulnerability",
    status: "open", firstSeen: "2026-08-18T00:00:00.000Z", lastSeen: "2026-08-18T00:00:00.000Z",
  },
};

describe("WhatsApp Cloud API notifier", () => {
  it("does not call the API when configuration is incomplete", async () => {
    let calls = 0;
    await expect(notifyFindingEventsToWhatsApp([findingEvent], { fetchImpl: async () => { calls += 1; throw new Error("must not call"); } })).resolves.toEqual({ sent: false, eligibleEvents: 1 });
    expect(calls).toBe(0);
  });

  it("sends an approved template message through the Graph API", async () => {
    let url = "";
    let init: RequestInit | undefined;
    const result = await notifyFindingEventsToWhatsApp([findingEvent], {
      accessToken: "runtime-token",
      phoneNumberId: "12345",
      recipient: "48123123123",
      templateName: "plesk_security_alert",
      templateLanguage: "pl",
      graphVersion: "v23.0",
      fetchImpl: async (requestUrl, requestInit) => {
        url = String(requestUrl);
        init = requestInit;
        return new Response(null, { status: 200 });
      },
    });

    expect(result).toEqual({ sent: true, eligibleEvents: 1 });
    expect(url).toBe("https://graph.facebook.com/v23.0/12345/messages");
    expect(init?.headers).toMatchObject({ authorization: "Bearer runtime-token" });
    expect(JSON.parse(String(init?.body))).toMatchObject({
      messaging_product: "whatsapp",
      type: "template",
      template: { name: "plesk_security_alert", language: { code: "pl" } },
    });
  });
});
