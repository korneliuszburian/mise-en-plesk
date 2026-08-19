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
    await expect(notifyFindingEventsToWhatsApp([findingEvent], { fetchImpl: async () => { calls += 1; throw new Error("must not call"); } })).resolves.toEqual({ outcome: "failed", eligibleEvents: 1, acceptedEvents: [], providerReceipts: [] });
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
        return Response.json({ messages: [{ id: "wamid.accepted-1" }] });
      },
    });

    expect(result).toEqual({
      outcome: "accepted",
      eligibleEvents: 1,
      acceptedEvents: [findingEvent],
      providerReceipts: [{ providerMessageId: "wamid.accepted-1", eventReferences: ["finding-1.0"] }],
    });
    expect(url).toBe("https://graph.facebook.com/v23.0/12345/messages");
    expect(init?.headers).toMatchObject({ authorization: "Bearer runtime-token" });
    expect(JSON.parse(String(init?.body))).toMatchObject({
      messaging_product: "whatsapp",
      type: "template",
      template: { name: "plesk_security_alert", language: { code: "pl" } },
    });
  });

  it("retries transient Graph API failures", async () => {
    let calls = 0;
    const result = await notifyFindingEventsToWhatsApp([findingEvent], {
      accessToken: "runtime-token",
      phoneNumberId: "12345",
      recipient: "48123123123",
      templateName: "plesk_security_alert",
      graphVersion: "v23.0",
      retryDelayMs: 0,
      fetchImpl: async () => {
        calls += 1;
        return calls === 1 ? new Response(null, { status: 429 }) : Response.json({ messages: [{ id: "wamid.retry-1" }] });
      },
    });

    expect(result).toEqual({
      outcome: "accepted",
      eligibleEvents: 1,
      acceptedEvents: [findingEvent],
      providerReceipts: [{ providerMessageId: "wamid.retry-1", eventReferences: ["finding-1.0"] }],
    });
    expect(calls).toBe(2);
  });

  it("chunks long alert batches and reports only provider-accepted events", async () => {
    const second = {
      ...findingEvent,
      finding: { ...findingEvent.finding, id: "finding-2", message: "second critical vulnerability" },
    } satisfies FindingEvent;
    let calls = 0;
    const messageLengths: number[] = [];
    const result = await notifyFindingEventsToWhatsApp([findingEvent, second], {
      accessToken: "runtime-token",
      phoneNumberId: "12345",
      recipient: "48123123123",
      templateName: "plesk_security_alert",
      graphVersion: "v23.0",
      maxMessageLength: 40,
      retryDelayMs: 0,
      fetchImpl: async (_url, init) => {
        calls += 1;
        const body = JSON.parse(String(init?.body)) as { template: { components: Array<{ parameters: Array<{ text: string }> }> } };
        messageLengths.push(body.template.components[0].parameters[0].text.length);
        return calls === 1 ? Response.json({ messages: [{ id: "wamid.chunk-1" }] }) : new Response(null, { status: 400 });
      },
    });

    expect(result.outcome).toBe("failed");
    expect(result.eligibleEvents).toBe(2);
    expect(result.acceptedEvents).toEqual([findingEvent]);
    expect(result.providerReceipts).toEqual([{
      providerMessageId: "wamid.chunk-1",
      eventReferences: ["finding-1.0"],
    }]);
    expect(calls).toBe(2);
    expect(messageLengths).toEqual([40, 40]);
  });

  it("does not acknowledge a 2xx response without a provider message id", async () => {
    const result = await notifyFindingEventsToWhatsApp([findingEvent], {
      accessToken: "runtime-token",
      phoneNumberId: "12345",
      recipient: "48123123123",
      templateName: "plesk_security_alert",
      graphVersion: "v23.0",
      maxAttempts: 1,
      fetchImpl: async () => Response.json({ messages: [] }),
    });

    expect(result).toEqual({ outcome: "unknown", eligibleEvents: 1, acceptedEvents: [], providerReceipts: [] });
  });

  it("returns unknown without retrying an ambiguous network failure", async () => {
    let calls = 0;
    const result = await notifyFindingEventsToWhatsApp([findingEvent], {
      accessToken: "runtime-token",
      phoneNumberId: "12345",
      recipient: "48123123123",
      templateName: "plesk_security_alert",
      graphVersion: "v23.0",
      maxAttempts: 3,
      fetchImpl: async () => {
        calls += 1;
        throw new Error("connection reset after write");
      },
    });

    expect(calls).toBe(1);
    expect(result.outcome).toBe("unknown");
  });
});
