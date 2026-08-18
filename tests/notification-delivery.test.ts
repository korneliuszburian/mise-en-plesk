import { mkdtemp, readFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { describe, expect, it } from "vitest";
import type { FindingEvent } from "../src/finding-state";
import { readNotificationOutbox } from "../src/notification-outbox";
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
  it("keeps disabled channels pending while delivering through configured adapters", async () => {
    const filePaths = await paths();
    const sent: FindingEvent[] = [];
    const delivery = createNotificationDelivery({
      ...filePaths,
      cooldownMs: 24 * 60 * 60 * 1000,
      adapters: [
        adapter("webhook", async (events) => { sent.push(...events); return { sent: true, sentEvents: events }; }),
        adapter("hermes", async () => ({ sent: false, sentEvents: [] }), false),
      ],
      now: () => new Date("2026-08-18T01:00:00.000Z"),
    });

    await delivery.enqueue([event("one")]);
    await delivery.flush();

    expect(sent.map((item) => item.finding.id)).toEqual(["one"]);
    const outbox = await readNotificationOutbox(filePaths.outboxPath);
    expect(outbox.entries).toHaveLength(1);
    expect(outbox.entries[0]).toMatchObject({ webhookSent: true, hermesSent: false });
  });

  it("keeps partial acknowledgements and provider failures pending", async () => {
    const filePaths = await paths();
    const first = event("one");
    const second = event("two");
    const delivery = createNotificationDelivery({
      ...filePaths,
      cooldownMs: 0,
      adapters: [
        adapter("hermes", async () => ({ sent: false, sentEvents: [first] })),
        adapter("whatsapp", async () => { throw new Error("provider unavailable"); }),
      ],
      debug: (message) => expect(message).toContain("whatsapp notification failed"),
    });

    await delivery.enqueue([first, second]);
    await delivery.flush();

    const outbox = await readNotificationOutbox(filePaths.outboxPath);
    expect(outbox.entries).toHaveLength(2);
    expect(outbox.entries.find((entry) => entry.event.finding.id === "one")).toMatchObject({ hermesSent: true, whatsappSent: false });
    expect(outbox.entries.find((entry) => entry.event.finding.id === "two")).toMatchObject({ hermesSent: false, whatsappSent: false });
  });

  it("checkpoints an earlier channel before a later channel fails", async () => {
    const filePaths = await paths();
    const delivery = createNotificationDelivery({
      ...filePaths,
      cooldownMs: 0,
      adapters: [
        adapter("webhook", async (events) => ({ sent: true, sentEvents: events })),
        adapter("hermes", async () => { throw new Error("hermes unavailable"); }),
      ],
    });
    await delivery.enqueue([event("one")]);
    await delivery.flush();

    const raw = JSON.parse(await readFile(filePaths.outboxPath, "utf8")) as { entries: Array<{ webhookSent: boolean; hermesSent: boolean }> };
    expect(raw.entries[0]).toMatchObject({ webhookSent: true, hermesSent: false });
  });
});
