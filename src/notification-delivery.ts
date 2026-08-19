import type { FindingEvent } from "./finding-state";
import {
  compactNotificationOutbox,
  enqueueNotificationEvents,
  markNotificationChannelOutcome,
  pendingNotificationEvents,
  readNotificationOutbox,
  type NotificationChannel,
  writeNotificationOutbox,
} from "./notification-outbox";
import { markNotificationsAccepted, partitionByCooldown, readNotificationHistory, writeNotificationHistory } from "./notification-history";
import type { NotificationChannelAdapter } from "./notifier";

export interface NotificationDeliveryOptions {
  outboxPath: string;
  historyPath: string;
  cooldownMs: number;
  adapters: readonly NotificationChannelAdapter[];
  now?: () => Date;
  debug?: (message: string) => void;
}

export interface NotificationChannelDelivery {
  attempted: number;
  acknowledged: number;
  suppressed: number;
  pending: number;
  failed: boolean;
  unknown: number;
  error?: string;
  providerMessageIds?: string[];
}

export interface NotificationDeliveryResult {
  webhookAccepted: boolean;
  whatsappAccepted: boolean;
  hermesAccepted: boolean;
  channels: Record<NotificationChannel, NotificationChannelDelivery>;
}

export interface NotificationDelivery {
  enqueue(events: readonly FindingEvent[]): Promise<void>;
  flush(): Promise<NotificationDeliveryResult>;
}

function emptyResult(): NotificationDeliveryResult {
  const channel = (): NotificationChannelDelivery => ({ attempted: 0, acknowledged: 0, suppressed: 0, pending: 0, failed: false, unknown: 0 });
  return {
    webhookAccepted: false,
    whatsappAccepted: false,
    hermesAccepted: false,
    channels: { webhook: channel(), whatsapp: channel(), hermes: channel() },
  };
}

function markAccepted(result: NotificationDeliveryResult, channel: NotificationChannel): void {
  if (channel === "webhook") result.webhookAccepted = true;
  if (channel === "whatsapp") result.whatsappAccepted = true;
  if (channel === "hermes") result.hermesAccepted = true;
}

export function createNotificationDelivery(options: NotificationDeliveryOptions): NotificationDelivery {
  const now = options.now ?? (() => new Date());
  const debug = options.debug ?? (() => undefined);
  const configuredChannels = options.adapters
    .filter((adapter) => adapter.configured)
    .map((adapter) => adapter.channel);

  return {
    async enqueue(events) {
      if (!events.length) return;
      const outbox = enqueueNotificationEvents(
        await readNotificationOutbox(options.outboxPath),
        [...events],
        configuredChannels,
      );
      await writeNotificationOutbox(options.outboxPath, outbox);
    },

    async flush() {
      let outbox = await readNotificationOutbox(options.outboxPath);
      let history = await readNotificationHistory(options.historyPath);
      const result = emptyResult();

      for (const adapter of options.adapters) {
        const channelResult = result.channels[adapter.channel];
        if (!adapter.configured) {
          channelResult.pending = pendingNotificationEvents(outbox, adapter.channel).length;
          continue;
        }

        const pending = pendingNotificationEvents(outbox, adapter.channel);
        const partition = partitionByCooldown(pending, adapter.channel, history, now(), options.cooldownMs);
        channelResult.attempted = partition.deliverable.length;
        channelResult.suppressed = partition.suppressed.length;
        if (partition.suppressed.length) {
          outbox = markNotificationChannelOutcome(outbox, adapter.channel, partition.suppressed, "suppressed");
        }

        if (partition.deliverable.length) {
          try {
            const delivery = await adapter.notifier.send(partition.deliverable);
            channelResult.acknowledged = delivery.acceptedEvents.length;
            if (delivery.providerReceipts?.length) {
              channelResult.providerMessageIds = delivery.providerReceipts.map((receipt) => receipt.providerMessageId);
              debug(`${adapter.channel} provider accepted ${delivery.providerReceipts.length} message batch(es): ${channelResult.providerMessageIds.join(", ")}`);
            }
            if (delivery.acceptedEvents.length) {
              outbox = markNotificationChannelOutcome(outbox, adapter.channel, delivery.acceptedEvents);
              history = markNotificationsAccepted(
                history,
                adapter.channel,
                delivery.acceptedEvents,
                now(),
                delivery.providerReceipts,
              );
            }
            if (delivery.acceptedEvents.length) markAccepted(result, adapter.channel);
            if (delivery.outcome === "unknown") {
              const accepted = new Set(delivery.acceptedEvents);
              const unknownEvents = partition.deliverable.filter((event) => !accepted.has(event));
              if (unknownEvents.length) {
                outbox = markNotificationChannelOutcome(outbox, adapter.channel, unknownEvents, "unknown");
                channelResult.unknown = unknownEvents.length;
                channelResult.error = "provider outcome is unknown; automatic retry is paused";
              }
            }
            if (delivery.outcome === "accepted" && !delivery.acceptedEvents.length) {
              channelResult.failed = true;
              channelResult.error = "provider reported acceptance without acknowledged events";
            }
          } catch (error: unknown) {
            const detail = error instanceof Error ? error.message : "provider error";
            channelResult.failed = true;
            channelResult.error = detail;
            debug(`${adapter.channel} notification failed: ${detail}`);
          }
        }

        await writeNotificationOutbox(options.outboxPath, compactNotificationOutbox(outbox));
        await writeNotificationHistory(options.historyPath, history);
        outbox = await readNotificationOutbox(options.outboxPath);
        channelResult.pending = pendingNotificationEvents(outbox, adapter.channel).length;
      }

      if (!options.adapters.some((adapter) => adapter.configured)) {
        await writeNotificationOutbox(options.outboxPath, compactNotificationOutbox(outbox));
      }
      return result;
    },
  };
}
