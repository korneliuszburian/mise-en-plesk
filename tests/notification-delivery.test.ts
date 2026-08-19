import { mkdtemp, readFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { describe, expect, it } from "vitest";
import type { FindingEvent } from "../src/finding-state";
import { readNotificationOutbox } from "../src/notification-outbox";
import { readNotificationHistory } from "../src/notification-history";
import { createNotificationDelivery } from "../src/notification-delivery";
import type { NotificationChannelAdapter } from "../src/notifier";

const event = (id: string, type: FindingEvent["type"] = "opened"): FindingEvent => ({
  type,
  occurredAt: "2026-08-18T00:00:00.000Z",
  finding: {
    id,
    code: "plugin-vulnerable",
    severity: "P1",
    host: "master-ssh",
    installationPath: `/srv/${id}`,
    plugin: "example-plugin",
    message: "critical plugin vulnerability",
    status: type === "resolved" ? "resolved" : "open",
    firstSeen: "2026-08-18T00:00:00.000Z",
    lastSeen: "2026-08-18T00:00:00.000Z",
    ...(type === "resolved" ? { resolvedAt: "2026-08-18T00:00:00.000Z" } : {}),
  },
});

async function paths() {
  const directory = await mkdtemp(join(tmpdir(), "mise-en-plesk-delivery-"));
  return { outboxPath: join(directory, "outbox.json"), historyPath: join(directory, "history.json") };
}

function adapter(channel: NotificationChannelAdapter["channel"], send: NotificationChannelAdapter["notifier"]["send"], configured = true): NotificationChannelAdapter {
  return { channel, configured, notifier: { send } };
}

describe("notification delivery module", () => {
  it("does not retain or replay events for channels disabled when they were enqueued", async () => {
    const filePaths = await paths();
    const sent: FindingEvent[] = [];
    const delivery = createNotificationDelivery({
      ...filePaths,
      cooldownMs: 24 * 60 * 60 * 1000,
      adapters: [
        adapter("webhook", async (events) => { sent.push(...events); return { outcome: "accepted", acceptedEvents: events }; }),
        adapter("hermes", async () => ({ outcome: "failed", acceptedEvents: [] }), false),
      ],
      now: () => new Date("2026-08-18T01:00:00.000Z"),
    });

    await delivery.enqueue([event("one")]);
    await delivery.flush();

    expect(sent.map((item) => item.finding.id)).toEqual(["one"]);
    const outbox = await readNotificationOutbox(filePaths.outboxPath);
    expect(outbox.entries).toHaveLength(0);

    const laterHermesEvents: FindingEvent[] = [];
    const laterDelivery = createNotificationDelivery({
      ...filePaths,
      cooldownMs: 0,
      adapters: [adapter("hermes", async (events) => {
        laterHermesEvents.push(...events);
        return { outcome: "accepted", acceptedEvents: events };
      })],
    });
    await laterDelivery.flush();
    expect(laterHermesEvents).toEqual([]);
  });

  it("delivers recovery transitions despite the normal cooldown", async () => {
    const filePaths = await paths();
    const sentTypes: FindingEvent["type"][] = [];
    const delivery = createNotificationDelivery({
      ...filePaths,
      cooldownMs: 24 * 60 * 60 * 1000,
      adapters: [adapter("hermes", async (events) => {
        sentTypes.push(...events.map((item) => item.type));
        return { outcome: "accepted", acceptedEvents: events };
      })],
      now: () => new Date("2026-08-18T01:00:00.000Z"),
    });

    await delivery.enqueue([event("one")]);
    const first = await delivery.flush();
    await delivery.enqueue([event("one", "resolved")]);
    const second = await delivery.flush();
    await delivery.enqueue([event("one", "reopened")]);
    const third = await delivery.flush();

    expect(sentTypes).toEqual(["opened", "resolved", "reopened"]);
    expect(first.channels.hermes).toMatchObject({ acknowledged: 1, pending: 0, failed: false });
    expect(second.hermesAccepted).toBe(true);
    expect(third.hermesAccepted).toBe(true);
  });

  it("keeps partial acknowledgements and provider failures pending", async () => {
    const filePaths = await paths();
    const first = event("one");
    const second = event("two");
    const delivery = createNotificationDelivery({
      ...filePaths,
      cooldownMs: 0,
      adapters: [
        adapter("hermes", async () => ({ outcome: "failed", acceptedEvents: [first] })),
        adapter("whatsapp", async () => { throw new Error("provider unavailable"); }),
      ],
      debug: (message) => expect(message).toContain("whatsapp notification failed"),
    });

    await delivery.enqueue([first, second]);
    await delivery.flush();

    const outbox = await readNotificationOutbox(filePaths.outboxPath);
    expect(outbox.entries).toHaveLength(2);
    expect(outbox.entries.find((entry) => entry.event.finding.id === "one"))
      .toMatchObject({ deliveries: { hermes: "accepted", whatsapp: "pending" } });
    expect(outbox.entries.find((entry) => entry.event.finding.id === "two"))
      .toMatchObject({ deliveries: { hermes: "pending", whatsapp: "pending" } });
  });

  it("does not claim delivery when a provider acknowledges nothing", async () => {
    const filePaths = await paths();
    const delivery = createNotificationDelivery({
      ...filePaths,
      cooldownMs: 0,
      adapters: [adapter("hermes", async () => ({ outcome: "accepted", acceptedEvents: [] }))],
    });

    await delivery.enqueue([event("one")]);
    const result = await delivery.flush();

    expect(result.hermesAccepted).toBe(false);
    expect(result.channels.hermes).toMatchObject({ acknowledged: 0, pending: 1, failed: true });
  });

  it("pauses automatic retry after an ambiguous provider outcome", async () => {
    const filePaths = await paths();
    let attempts = 0;
    const delivery = createNotificationDelivery({
      ...filePaths,
      cooldownMs: 0,
      adapters: [adapter("whatsapp", async () => {
        attempts += 1;
        return { outcome: "unknown", acceptedEvents: [] };
      })],
    });

    await delivery.enqueue([event("one")]);
    const first = await delivery.flush();
    const second = await delivery.flush();

    expect(attempts).toBe(1);
    expect(first.channels.whatsapp).toMatchObject({ unknown: 1, pending: 0, failed: false });
    expect(second.channels.whatsapp).toMatchObject({ attempted: 0, pending: 0 });
    const outbox = await readNotificationOutbox(filePaths.outboxPath);
    expect(outbox.entries[0]).toMatchObject({ deliveries: { whatsapp: "unknown" } });
  });

  it("persists provider message ids after acceptance", async () => {
    const filePaths = await paths();
    const delivery = createNotificationDelivery({
      ...filePaths,
      cooldownMs: 0,
      adapters: [adapter("whatsapp", async (events) => ({
        outcome: "accepted",
        acceptedEvents: events,
        providerReceipts: [{ providerMessageId: "wamid.accepted-1", eventReferences: ["one.0"] }],
      }))],
    });

    await delivery.enqueue([event("one")]);
    await delivery.flush();

    const history = await readNotificationHistory(filePaths.historyPath);
    expect(history.providerReceipts).toEqual([{
      channel: "whatsapp",
      providerMessageId: "wamid.accepted-1",
      eventReferences: ["one.0"],
      acceptedAt: expect.any(String),
    }]);
  });

  it("checkpoints an earlier channel before a later channel fails", async () => {
    const filePaths = await paths();
    const delivery = createNotificationDelivery({
      ...filePaths,
      cooldownMs: 0,
      adapters: [
        adapter("webhook", async (events) => ({ outcome: "accepted", acceptedEvents: events })),
        adapter("hermes", async () => { throw new Error("hermes unavailable"); }),
      ],
    });
    await delivery.enqueue([event("one")]);
    await delivery.flush();

    const raw = JSON.parse(await readFile(filePaths.outboxPath, "utf8")) as { entries: Array<{ deliveries: Record<string, string> }> };
    expect(raw.entries[0]).toMatchObject({ deliveries: { webhook: "accepted", hermes: "pending" } });
  });
});
