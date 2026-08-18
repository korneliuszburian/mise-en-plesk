import type { FindingEvent } from "./finding-state";
import {
  compactNotificationOutbox,
  enqueueNotificationEvents,
  markNotificationChannelSent,
  pendingNotificationEvents,
  readNotificationOutbox,
  type NotificationChannel,
  writeNotificationOutbox,
} from "./notification-outbox";
import { markNotificationsSent, partitionByCooldown, readNotificationHistory, writeNotificationHistory } from "./notification-history";
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
  error?: string;
}

export interface NotificationDeliveryResult {
  webhookSent: boolean;
  whatsappSent: boolean;
  hermesSent: boolean;
  channels: Record<NotificationChannel, NotificationChannelDelivery>;
}

export interface NotificationDelivery {
  enqueue(events: readonly FindingEvent[]): Promise<void>;
  flush(): Promise<NotificationDeliveryResult>;
}

function emptyResult(): NotificationDeliveryResult {
  const channel = (): NotificationChannelDelivery => ({ attempted: 0, acknowledged: 0, suppressed: 0, pending: 0, failed: false });
  return {
    webhookSent: false,
    whatsappSent: false,
    hermesSent: false,
    channels: { webhook: channel(), whatsapp: channel(), hermes: channel() },
  };
}

function markDelivered(result: NotificationDeliveryResult, channel: NotificationChannel): void {
  if (channel === "webhook") result.webhookSent = true;
  if (channel === "whatsapp") result.whatsappSent = true;
  if (channel === "hermes") result.hermesSent = true;
}

export function createNotificationDelivery(options: NotificationDeliveryOptions): NotificationDelivery {
  const now = options.now ?? (() => new Date());
  const debug = options.debug ?? (() => undefined);

  return {
    async enqueue(events) {
      if (!events.length) return;
      const outbox = enqueueNotificationEvents(await readNotificationOutbox(options.outboxPath), [...events]);
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
        if (partition.suppressed.length) outbox = markNotificationChannelSent(outbox, adapter.channel, partition.suppressed);

        if (partition.deliverable.length) {
          try {
            const delivery = await adapter.notifier.send(partition.deliverable);
            channelResult.acknowledged = delivery.sentEvents.length;
            if (delivery.sentEvents.length) {
              outbox = markNotificationChannelSent(outbox, adapter.channel, delivery.sentEvents);
              history = markNotificationsSent(history, adapter.channel, delivery.sentEvents, now());
            }
            if (delivery.sentEvents.length) markDelivered(result, adapter.channel);
            if (delivery.sent && !delivery.sentEvents.length) {
              channelResult.failed = true;
              channelResult.error = "provider reported success without acknowledged events";
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
