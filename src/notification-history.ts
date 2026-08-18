import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import type { FindingEvent } from "./finding-state";
import type { NotificationChannel } from "./notification-outbox";

export interface NotificationHistory {
  version: 1;
  sentAt: Record<string, string>;
}

export function emptyNotificationHistory(): NotificationHistory {
  return { version: 1, sentAt: {} };
}

function historyKey(channel: NotificationChannel, event: FindingEvent): string {
  return `${channel}:${event.finding.id}`;
}

export function partitionByCooldown(
  events: FindingEvent[],
  channel: NotificationChannel,
  history: NotificationHistory,
  now: Date,
  cooldownMs: number,
): { deliverable: FindingEvent[]; suppressed: FindingEvent[] } {
  if (cooldownMs <= 0) return { deliverable: events, suppressed: [] };
  const deliverable: FindingEvent[] = [];
  const suppressed: FindingEvent[] = [];
  for (const event of events) {
    if (event.type === "resolved" || event.type === "reopened") {
      deliverable.push(event);
      continue;
    }
    const lastSent = Date.parse(history.sentAt[historyKey(channel, event)] ?? "");
    if (Number.isFinite(lastSent) && now.getTime() - lastSent < cooldownMs) suppressed.push(event);
    else deliverable.push(event);
  }
  return { deliverable, suppressed };
}

export function markNotificationsSent(
  history: NotificationHistory,
  channel: NotificationChannel,
  events: FindingEvent[],
  now: Date,
): NotificationHistory {
  const sentAt = { ...history.sentAt };
  const timestamp = now.toISOString();
  for (const event of events) sentAt[historyKey(channel, event)] = timestamp;
  return { version: 1, sentAt };
}

export async function readNotificationHistory(path: string): Promise<NotificationHistory> {
  try {
    const parsed: unknown = JSON.parse(await readFile(path, "utf8"));
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error(`Invalid notification history: ${path}`);
    const value = parsed as Partial<NotificationHistory>;
    if (value.version !== 1 || !value.sentAt || typeof value.sentAt !== "object" || Array.isArray(value.sentAt)
      || !Object.values(value.sentAt).every((timestamp) => typeof timestamp === "string" && Number.isFinite(Date.parse(timestamp)))) {
      throw new Error(`Invalid notification history: ${path}`);
    }
    return value as NotificationHistory;
  } catch (error: unknown) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") return emptyNotificationHistory();
    throw error;
  }
}

export async function writeNotificationHistory(path: string, history: NotificationHistory): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  const temporaryPath = `${path}.tmp-${process.pid}`;
  await writeFile(temporaryPath, `${JSON.stringify(history, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
  await rename(temporaryPath, path);
}
