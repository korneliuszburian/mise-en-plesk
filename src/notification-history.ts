import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import type { FindingEvent } from "./finding-state";
import type { NotificationChannel } from "./notification-outbox";
import type { ProviderSubmissionReceipt } from "./notifier";

export interface ProviderReceipt {
  channel: NotificationChannel;
  providerMessageId: string;
  eventReferences: string[];
  acceptedAt: string;
}

export interface NotificationHistory {
  version: 2;
  acceptedAt: Record<string, string>;
  providerReceipts: ProviderReceipt[];
}

const MAX_PROVIDER_RECEIPTS = 1000;

export function emptyNotificationHistory(): NotificationHistory {
  return { version: 2, acceptedAt: {}, providerReceipts: [] };
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
    const lastAccepted = Date.parse(history.acceptedAt[historyKey(channel, event)] ?? "");
    if (Number.isFinite(lastAccepted) && now.getTime() - lastAccepted < cooldownMs) suppressed.push(event);
    else deliverable.push(event);
  }
  return { deliverable, suppressed };
}

export function markNotificationsAccepted(
  history: NotificationHistory,
  channel: NotificationChannel,
  events: FindingEvent[],
  now: Date,
  receipts: readonly ProviderSubmissionReceipt[] = [],
): NotificationHistory {
  const acceptedAt = { ...history.acceptedAt };
  const timestamp = now.toISOString();
  for (const event of events) acceptedAt[historyKey(channel, event)] = timestamp;
  const providerReceipts = [
    ...history.providerReceipts,
    ...receipts.map((receipt) => ({ channel, ...receipt, acceptedAt: timestamp })),
  ].slice(-MAX_PROVIDER_RECEIPTS);
  return { version: 2, acceptedAt, providerReceipts };
}

function validTimestampRecord(value: unknown): value is Record<string, string> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value)
    && Object.values(value as Record<string, unknown>)
      .every((timestamp) => typeof timestamp === "string" && Number.isFinite(Date.parse(timestamp)));
}

function validReceipt(value: unknown): value is ProviderReceipt {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const receipt = value as Partial<ProviderReceipt>;
  return (receipt.channel === "webhook" || receipt.channel === "whatsapp" || receipt.channel === "hermes")
    && typeof receipt.providerMessageId === "string" && receipt.providerMessageId.length > 0
    && Array.isArray(receipt.eventReferences)
    && receipt.eventReferences.length > 0
    && receipt.eventReferences.every((reference) => typeof reference === "string" && reference.length > 0)
    && typeof receipt.acceptedAt === "string" && Number.isFinite(Date.parse(receipt.acceptedAt));
}

export async function readNotificationHistory(path: string): Promise<NotificationHistory> {
  try {
    const parsed: unknown = JSON.parse(await readFile(path, "utf8"));
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error(`Invalid notification history: ${path}`);
    }
    const value = parsed as { version?: unknown; acceptedAt?: unknown; providerReceipts?: unknown; sentAt?: unknown };
    if (value.version === 2
      && validTimestampRecord(value.acceptedAt)
      && Array.isArray(value.providerReceipts)
      && value.providerReceipts.every(validReceipt)) return value as NotificationHistory;
    if (value.version === 1 && validTimestampRecord(value.sentAt)) {
      return { version: 2, acceptedAt: value.sentAt, providerReceipts: [] };
    }
    throw new Error(`Invalid notification history: ${path}`);
  } catch (error: unknown) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") {
      return emptyNotificationHistory();
    }
    throw error;
  }
}

export async function writeNotificationHistory(path: string, history: NotificationHistory): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  const temporaryPath = `${path}.tmp-${process.pid}`;
  await writeFile(temporaryPath, `${JSON.stringify(history, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
  await rename(temporaryPath, path);
}
