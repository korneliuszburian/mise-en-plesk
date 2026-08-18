import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { FindingEvent } from "../src/finding-state";
import {
  emptyNotificationOutbox,
  enqueueNotificationEvents,
  compactNotificationOutbox,
  markNotificationChannelSent,
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
    const queued = enqueueNotificationEvents(emptyNotificationOutbox(), [event(), event("resolved")]);
    expect(queued.entries).toHaveLength(1);
    expect(pendingNotificationEvents(queued, "webhook")).toHaveLength(1);

    const delivered = markNotificationChannelSent(queued, "webhook", [event()]);
    expect(pendingNotificationEvents(delivered, "webhook")).toHaveLength(0);
    expect(pendingNotificationEvents(delivered, "whatsapp")).toHaveLength(1);

    const fullyDelivered = markNotificationChannelSent(delivered, "whatsapp", [event()]);
    expect(compactNotificationOutbox(fullyDelivered).entries).toHaveLength(0);
  });

  it("round-trips atomically as local mode-600 bookkeeping", async () => {
    const directory = await mkdtemp(join(tmpdir(), "mise-en-plesk-outbox-"));
    const path = join(directory, "outbox.json");
    const outbox = enqueueNotificationEvents(emptyNotificationOutbox(), [event()]);
    await writeNotificationOutbox(path, outbox);
    await expect(readNotificationOutbox(path)).resolves.toEqual(outbox);
  });
});
