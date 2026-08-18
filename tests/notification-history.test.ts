import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { describe, expect, it } from "vitest";
import type { FindingEvent } from "../src/finding-state";
import { emptyNotificationHistory, markNotificationsSent, partitionByCooldown, readNotificationHistory, writeNotificationHistory } from "../src/notification-history";

const event: FindingEvent = {
  type: "opened",
  occurredAt: "2026-08-18T00:00:00.000Z",
  finding: {
    id: "finding-1", code: "plugin-vulnerable", severity: "P1", host: "dev-ssh",
    installationPath: "/srv/site", domain: "example.test", message: "critical risk",
    status: "open", firstSeen: "2026-08-18T00:00:00.000Z", lastSeen: "2026-08-18T00:00:00.000Z",
  },
};

describe("notification cooldown history", () => {
  it("suppresses the same finding per channel during cooldown", () => {
    const sent = markNotificationsSent(emptyNotificationHistory(), "hermes", [event], new Date("2026-08-18T00:00:00.000Z"));
    expect(partitionByCooldown([event], "hermes", sent, new Date("2026-08-18T01:00:00.000Z"), 24 * 60 * 60 * 1000).suppressed).toEqual([event]);
    expect(partitionByCooldown([event], "whatsapp", sent, new Date("2026-08-18T01:00:00.000Z"), 24 * 60 * 60 * 1000).deliverable).toEqual([event]);
  });

  it("allows delivery after cooldown expires", () => {
    const sent = markNotificationsSent(emptyNotificationHistory(), "hermes", [event], new Date("2026-08-18T00:00:00.000Z"));
    expect(partitionByCooldown([event], "hermes", sent, new Date("2026-08-19T00:00:01.000Z"), 24 * 60 * 60 * 1000).deliverable).toEqual([event]);
  });

  it("round-trips mode-600 history atomically", async () => {
    const directory = await mkdtemp(join(tmpdir(), "mise-en-plesk-history-"));
    const path = join(directory, "history.json");
    const history = markNotificationsSent(emptyNotificationHistory(), "webhook", [event], new Date("2026-08-18T00:00:00.000Z"));
    await writeNotificationHistory(path, history);
    await expect(readNotificationHistory(path)).resolves.toEqual(history);
    expect(JSON.parse(await readFile(path, "utf8"))).toEqual(history);
  });

  it("rejects malformed history", async () => {
    const directory = await mkdtemp(join(tmpdir(), "mise-en-plesk-history-invalid-"));
    const path = join(directory, "history.json");
    await writeFile(path, JSON.stringify({ version: 1, sentAt: { "hermes:finding-1": "not-a-date" } }));
    await expect(readNotificationHistory(path)).rejects.toThrow("Invalid notification history");
  });
});
