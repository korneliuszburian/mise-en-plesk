import type { FindingEvent } from "./finding-state";
import type { NotificationChannel } from "./notification-outbox";

export interface NotifierResult {
  sent: boolean;
  sentEvents: FindingEvent[];
}

export interface Notifier {
  send(events: FindingEvent[]): Promise<NotifierResult>;
}

export interface NotificationChannelAdapter {
  channel: NotificationChannel;
  configured: boolean;
  notifier: Notifier;
}
