import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import type { FindingEvent } from "./finding-state";

export interface NotificationOutboxEntry {
  id: string;
  event: FindingEvent;
  createdAt: string;
  webhookSent: boolean;
  whatsappSent: boolean;
}

export interface NotificationOutbox {
  version: 1;
  entries: NotificationOutboxEntry[];
}

export function emptyNotificationOutbox(): NotificationOutbox {
  return { version: 1, entries: [] };
}

function eventId(event: FindingEvent): string {
  return `${event.type}:${event.finding.id}:${event.occurredAt}`;
}

function actionable(event: FindingEvent): boolean {
  return (event.type === "opened" || event.type === "reopened") && event.finding.severity === "P1";
}

export function enqueueNotificationEvents(
  outbox: NotificationOutbox,
  events: FindingEvent[],
): NotificationOutbox {
  const entries = outbox.entries.filter((entry) => !(entry.webhookSent && entry.whatsappSent));
  const known = new Set(entries.map((entry) => entry.id));
  for (const event of events) {
    if (!actionable(event)) continue;
    const id = eventId(event);
    if (known.has(id)) continue;
    entries.push({ id, event, createdAt: event.occurredAt, webhookSent: false, whatsappSent: false });
    known.add(id);
  }
  return { version: 1, entries };
}

export function compactNotificationOutbox(outbox: NotificationOutbox): NotificationOutbox {
  return {
    version: 1,
    entries: outbox.entries.filter((entry) => !(entry.webhookSent && entry.whatsappSent)),
  };
}

export function pendingNotificationEvents(
  outbox: NotificationOutbox,
  channel: "webhook" | "whatsapp",
): FindingEvent[] {
  return outbox.entries
    .filter((entry) => channel === "webhook" ? !entry.webhookSent : !entry.whatsappSent)
    .map((entry) => entry.event);
}

export function markNotificationChannelSent(
  outbox: NotificationOutbox,
  channel: "webhook" | "whatsapp",
  events: FindingEvent[],
): NotificationOutbox {
  const sent = new Set(events.map(eventId));
  return {
    version: 1,
    entries: outbox.entries.map((entry) => {
      if (!sent.has(entry.id)) return entry;
      return channel === "webhook" ? { ...entry, webhookSent: true } : { ...entry, whatsappSent: true };
    }),
  };
}

export async function readNotificationOutbox(path: string): Promise<NotificationOutbox> {
  try {
    const parsed: unknown = JSON.parse(await readFile(path, "utf8"));
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error(`Invalid notification outbox: ${path}`);
    const value = parsed as Partial<NotificationOutbox>;
    if (value.version !== 1 || !Array.isArray(value.entries)) throw new Error(`Invalid notification outbox: ${path}`);
    return value as NotificationOutbox;
  } catch (error: unknown) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") return emptyNotificationOutbox();
    throw error;
  }
}

export async function writeNotificationOutbox(path: string, outbox: NotificationOutbox): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  const temporaryPath = `${path}.tmp-${process.pid}`;
  await writeFile(temporaryPath, `${JSON.stringify(outbox, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
  await rename(temporaryPath, path);
}
