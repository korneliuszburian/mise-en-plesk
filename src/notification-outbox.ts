import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { isFindingEvent, type FindingEvent } from "./finding-state";

export interface NotificationOutboxEntry {
  id: string;
  event: FindingEvent;
  createdAt: string;
  webhookSent: boolean;
  whatsappSent: boolean;
  hermesSent: boolean;
}

export interface NotificationOutbox {
  version: 1;
  entries: NotificationOutboxEntry[];
}

export function emptyNotificationOutbox(): NotificationOutbox {
  return { version: 1, entries: [] };
}

function eventId(event: FindingEvent): string {
  return `${event.type}:${event.finding.id}`;
}

function legacyEventId(event: FindingEvent): string {
  return `${event.type}:${event.finding.id}:${event.occurredAt}`;
}

function actionable(event: FindingEvent): boolean {
  return (event.type === "opened" || event.type === "reopened") && event.finding.severity === "P1";
}

export function enqueueNotificationEvents(
  outbox: NotificationOutbox,
  events: FindingEvent[],
): NotificationOutbox {
  const entries = outbox.entries.filter((entry) => !(entry.webhookSent && entry.whatsappSent && entry.hermesSent));
  const known = new Set(entries.flatMap((entry) => [entry.id, eventId(entry.event), legacyEventId(entry.event)]));
  for (const event of events) {
    if (!actionable(event)) continue;
    const id = eventId(event);
    if (known.has(id) || known.has(legacyEventId(event))) continue;
    entries.push({ id, event, createdAt: event.occurredAt, webhookSent: false, whatsappSent: false, hermesSent: false });
    known.add(id);
  }
  return { version: 1, entries };
}

export function compactNotificationOutbox(outbox: NotificationOutbox): NotificationOutbox {
  return {
    version: 1,
    entries: outbox.entries.filter((entry) => !(entry.webhookSent && entry.whatsappSent && entry.hermesSent)),
  };
}

export function pendingNotificationEvents(
  outbox: NotificationOutbox,
  channel: "webhook" | "whatsapp" | "hermes",
): FindingEvent[] {
  return outbox.entries
    .filter((entry) => channel === "webhook" ? !entry.webhookSent : channel === "whatsapp" ? !entry.whatsappSent : !entry.hermesSent)
    .map((entry) => entry.event);
}

export function markNotificationChannelSent(
  outbox: NotificationOutbox,
  channel: "webhook" | "whatsapp" | "hermes",
  events: FindingEvent[],
): NotificationOutbox {
  const sent = new Set(events.flatMap((event) => [eventId(event), legacyEventId(event)]));
  return {
    version: 1,
    entries: outbox.entries.map((entry) => {
      if (!sent.has(entry.id) && !sent.has(eventId(entry.event)) && !sent.has(legacyEventId(entry.event))) return entry;
      return channel === "webhook"
        ? { ...entry, webhookSent: true }
        : channel === "whatsapp"
          ? { ...entry, whatsappSent: true }
          : { ...entry, hermesSent: true };
    }),
  };
}

export async function readNotificationOutbox(path: string): Promise<NotificationOutbox> {
  try {
    const parsed: unknown = JSON.parse(await readFile(path, "utf8"));
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error(`Invalid notification outbox: ${path}`);
    const value = parsed as Partial<NotificationOutbox>;
    if (value.version !== 1 || !Array.isArray(value.entries) || !value.entries.every((entry) => {
      if (!entry || typeof entry !== "object" || Array.isArray(entry)) return false;
      const item = entry as Partial<NotificationOutboxEntry>;
      return typeof item.id === "string" && item.id.length > 0
        && typeof item.createdAt === "string"
        && typeof item.webhookSent === "boolean"
        && typeof item.whatsappSent === "boolean"
        && (item.hermesSent === undefined || typeof item.hermesSent === "boolean")
        && isFindingEvent(item.event);
    })) throw new Error(`Invalid notification outbox: ${path}`);
    return {
      version: 1,
      entries: (value as NotificationOutbox).entries.map((entry) => ({ ...entry, hermesSent: entry.hermesSent ?? true })),
    };
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
