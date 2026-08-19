import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { FindingEvent } from "../src/finding-state";
import {
  emptyNotificationOutbox,
  enqueueNotificationEvents,
  compactNotificationOutbox,
  markNotificationChannelOutcome,
  pendingNotificationEvents,
  readNotificationOutbox,
  writeNotificationOutbox,
} from "../src/notification-outbox";

const event = (type: "opened" | "resolved" = "opened"): FindingEvent => ({
  type,
  occurredAt: "2026-08-18T00:00:00.000Z",
  finding: {
    id: "finding-1", code: "plugin-vulnerable", severity: "P1", host: "master-ssh",
    installationPath: "/srv/site", domain: "example.test", message: "critical risk",
    status: "open", firstSeen: "2026-08-18T00:00:00.000Z", lastSeen: "2026-08-18T00:00:00.000Z",
  },
});

describe("notification outbox", () => {
  it("deduplicates actionable events and keeps failed delivery pending", () => {
    const queued = enqueueNotificationEvents(emptyNotificationOutbox(), [event(), event()]);
    expect(queued.entries).toHaveLength(1);
    expect(pendingNotificationEvents(queued, "webhook")).toHaveLength(1);

    const delivered = markNotificationChannelOutcome(queued, "webhook", [event()]);
    expect(pendingNotificationEvents(delivered, "webhook")).toHaveLength(0);
    expect(pendingNotificationEvents(delivered, "whatsapp")).toHaveLength(1);

    const fullyDelivered = markNotificationChannelOutcome(markNotificationChannelOutcome(delivered, "whatsapp", [event()]), "hermes", [event()]);
    expect(compactNotificationOutbox(fullyDelivered).entries).toHaveLength(0);
  });

  it("queues a P1 resolved transition for recovery delivery", () => {
    const queued = enqueueNotificationEvents(emptyNotificationOutbox(), [event("resolved")]);
    expect(queued.entries).toHaveLength(1);
    expect(pendingNotificationEvents(queued, "hermes")).toHaveLength(1);
  });

  it("deduplicates a replayed transition after a crash with a new timestamp", () => {
    const replay = { ...event(), occurredAt: "2026-08-18T00:01:00.000Z" };

    const queued = enqueueNotificationEvents(emptyNotificationOutbox(), [event()]);
    const replayed = enqueueNotificationEvents(queued, [replay]);

    expect(replayed.entries).toHaveLength(1);
    expect(replayed.entries[0]?.event.occurredAt).toBe(event().occurredAt);
  });

  it("keeps distinct lifecycle cycles for the same finding", () => {
    const firstResolution = {
      ...event("resolved"),
      finding: { ...event("resolved").finding, transitionSequence: 2 },
    };
    const secondResolution = {
      ...event("resolved"),
      occurredAt: "2026-08-20T00:00:00.000Z",
      finding: { ...event("resolved").finding, transitionSequence: 4 },
    };

    const queued = enqueueNotificationEvents(emptyNotificationOutbox(), [firstResolution, secondResolution]);
    expect(queued.entries).toHaveLength(2);
  });

  it("allows disabled channels to be discarded without retaining an alert backlog", () => {
    const queued = enqueueNotificationEvents(emptyNotificationOutbox(), [event()]);
    const skippedWebhook = markNotificationChannelOutcome(queued, "webhook", [event()]);
    const skippedBoth = markNotificationChannelOutcome(markNotificationChannelOutcome(skippedWebhook, "whatsapp", [event()]), "hermes", [event()]);

    expect(compactNotificationOutbox(skippedBoth).entries).toHaveLength(0);
  });

  it("round-trips atomically as local mode-600 bookkeeping", async () => {
    const directory = await mkdtemp(join(tmpdir(), "mise-en-plesk-outbox-"));
    const path = join(directory, "outbox.json");
    const outbox = enqueueNotificationEvents(emptyNotificationOutbox(), [event()]);
    await writeNotificationOutbox(path, outbox);
    await expect(readNotificationOutbox(path)).resolves.toEqual(outbox);
  });

  it("rejects an outbox entry without a valid finding event", async () => {
    const directory = await mkdtemp(join(tmpdir(), "mise-en-plesk-outbox-invalid-"));
    const path = join(directory, "outbox.json");
    await writeFile(path, JSON.stringify({ version: 1, entries: [{ id: "broken", webhookSent: false, whatsappSent: false, event: {} }] }));
    await expect(readNotificationOutbox(path)).rejects.toThrow("Invalid notification outbox");
  });

  it("retires ambiguous legacy entries instead of replaying them to newly enabled channels", async () => {
    const directory = await mkdtemp(join(tmpdir(), "mise-en-plesk-outbox-legacy-"));
    const path = join(directory, "outbox.json");
    await writeFile(path, JSON.stringify({
      version: 1,
      entries: [{
        id: "opened:finding-1",
        event: event(),
        createdAt: event().occurredAt,
        webhookSent: false,
        whatsappSent: false,
      }],
    }));

    await expect(readNotificationOutbox(path)).resolves.toEqual({ version: 2, entries: [] });
  });

  it("rejects a malformed Hermes delivery flag", async () => {
    const directory = await mkdtemp(join(tmpdir(), "mise-en-plesk-outbox-hermes-invalid-"));
    const path = join(directory, "outbox.json");
    await writeFile(path, JSON.stringify({ version: 1, entries: [{
      id: "opened:finding-1",
      event: event(),
      createdAt: event().occurredAt,
      webhookSent: false,
      whatsappSent: false,
      hermesSent: "yes",
    }] }));

    await expect(readNotificationOutbox(path)).rejects.toThrow("Invalid notification outbox");
  });
});
