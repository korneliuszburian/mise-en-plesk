import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { isFindingEvent, type FindingEvent } from "./finding-state";

export type NotificationChannel = "webhook" | "whatsapp" | "hermes";
export type NotificationDeliveryStatus = "pending" | "accepted" | "suppressed" | "unknown";

const ALL_CHANNELS: readonly NotificationChannel[] = ["webhook", "whatsapp", "hermes"];

export interface NotificationOutboxEntry {
  id: string;
  event: FindingEvent;
  createdAt: string;
  deliveries: Partial<Record<NotificationChannel, NotificationDeliveryStatus>>;
}

export interface NotificationOutbox {
  version: 2;
  entries: NotificationOutboxEntry[];
}

interface LegacyNotificationOutboxEntry {
  id: string;
  event: FindingEvent;
  createdAt: string;
  webhookSent: boolean;
  whatsappSent: boolean;
  hermesSent?: boolean;
}

export function emptyNotificationOutbox(): NotificationOutbox {
  return { version: 2, entries: [] };
}

function eventId(event: FindingEvent): string {
  const sequence = event.finding.transitionSequence;
  return sequence === undefined
    ? `${event.type}:${event.finding.id}`
    : `${event.type}:${event.finding.id}:${sequence}`;
}

function preSequenceEventId(event: FindingEvent): string {
  return `${event.type}:${event.finding.id}`;
}

function legacyEventId(event: FindingEvent): string {
  return `${event.type}:${event.finding.id}:${event.occurredAt}`;
}

function actionable(event: FindingEvent): boolean {
  return (event.type === "opened" || event.type === "reopened" || event.type === "resolved")
    && event.finding.severity === "P1";
}

function hasUnresolvedDelivery(entry: NotificationOutboxEntry): boolean {
  return Object.values(entry.deliveries).some((status) => status === "pending" || status === "unknown");
}

export function enqueueNotificationEvents(
  outbox: NotificationOutbox,
  events: FindingEvent[],
  requiredChannels: readonly NotificationChannel[] = ALL_CHANNELS,
): NotificationOutbox {
  const entries = outbox.entries.filter(hasUnresolvedDelivery);
  const known = new Set(entries.flatMap((entry) => [
    entry.id,
    eventId(entry.event),
    legacyEventId(entry.event),
    ...(entry.event.finding.transitionSequence === undefined ? [preSequenceEventId(entry.event)] : []),
  ]));
  for (const event of events) {
    if (!actionable(event) || requiredChannels.length === 0) continue;
    const id = eventId(event);
    if (known.has(id)
      || known.has(legacyEventId(event))
      || (event.finding.transitionSequence !== undefined && known.has(preSequenceEventId(event)))) continue;
    const deliveries = Object.fromEntries(requiredChannels.map((channel) => [channel, "pending"])) as
      Partial<Record<NotificationChannel, NotificationDeliveryStatus>>;
    entries.push({ id, event, createdAt: event.occurredAt, deliveries });
    known.add(id);
  }
  return { version: 2, entries };
}

export function compactNotificationOutbox(outbox: NotificationOutbox): NotificationOutbox {
  return { version: 2, entries: outbox.entries.filter(hasUnresolvedDelivery) };
}

export function pendingNotificationEvents(
  outbox: NotificationOutbox,
  channel: NotificationChannel,
): FindingEvent[] {
  return outbox.entries
    .filter((entry) => entry.deliveries[channel] === "pending")
    .map((entry) => entry.event);
}

export function markNotificationChannelOutcome(
  outbox: NotificationOutbox,
  channel: NotificationChannel,
  events: FindingEvent[],
  status: Exclude<NotificationDeliveryStatus, "pending"> = "accepted",
): NotificationOutbox {
  const acknowledged = new Set(events.flatMap((event) => [eventId(event), legacyEventId(event)]));
  return {
    version: 2,
    entries: outbox.entries.map((entry) => {
      if (!acknowledged.has(entry.id)
        && !acknowledged.has(eventId(entry.event))
        && !acknowledged.has(legacyEventId(entry.event))) return entry;
      if (entry.deliveries[channel] !== "pending") return entry;
      return { ...entry, deliveries: { ...entry.deliveries, [channel]: status } };
    }),
  };
}

function validDeliveries(value: unknown): value is NotificationOutboxEntry["deliveries"] {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  return Object.entries(value).every(([channel, status]) =>
    ALL_CHANNELS.includes(channel as NotificationChannel)
    && (status === "pending" || status === "accepted" || status === "suppressed" || status === "unknown"));
}

function validEntry(value: unknown): value is NotificationOutboxEntry {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const entry = value as Partial<NotificationOutboxEntry>;
  return typeof entry.id === "string" && entry.id.length > 0
    && typeof entry.createdAt === "string"
    && isFindingEvent(entry.event)
    && validDeliveries(entry.deliveries);
}

function validLegacyEntry(value: unknown): value is LegacyNotificationOutboxEntry {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const entry = value as Partial<LegacyNotificationOutboxEntry>;
  return typeof entry.id === "string" && entry.id.length > 0
    && typeof entry.createdAt === "string"
    && typeof entry.webhookSent === "boolean"
    && typeof entry.whatsappSent === "boolean"
    && (entry.hermesSent === undefined || typeof entry.hermesSent === "boolean")
    && isFindingEvent(entry.event);
}

function migrateLegacyOutbox(_entries: LegacyNotificationOutboxEntry[]): NotificationOutbox {
  // Version 1 did not record which channels were enabled when an event was
  // enqueued. Retiring those ambiguous entries is safer than replaying stale
  // incidents when a provider is enabled later.
  return emptyNotificationOutbox();
}

export async function readNotificationOutbox(path: string): Promise<NotificationOutbox> {
  try {
    const parsed: unknown = JSON.parse(await readFile(path, "utf8"));
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error(`Invalid notification outbox: ${path}`);
    }
    const value = parsed as { version?: unknown; entries?: unknown };
    if (!Array.isArray(value.entries)) throw new Error(`Invalid notification outbox: ${path}`);
    if (value.version === 2 && value.entries.every(validEntry)) return value as NotificationOutbox;
    if (value.version === 1 && value.entries.every(validLegacyEntry)) {
      return migrateLegacyOutbox(value.entries);
    }
    throw new Error(`Invalid notification outbox: ${path}`);
  } catch (error: unknown) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") {
      return emptyNotificationOutbox();
    }
    throw error;
  }
}

export async function writeNotificationOutbox(path: string, outbox: NotificationOutbox): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  const temporaryPath = `${path}.tmp-${process.pid}`;
  await writeFile(temporaryPath, `${JSON.stringify(outbox, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
  await rename(temporaryPath, path);
}
