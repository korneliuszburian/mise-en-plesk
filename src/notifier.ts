import type { FindingEvent } from "./finding-state";
import type { NotificationChannel } from "./notification-outbox";

export interface NotifierResult {
  outcome: "accepted" | "failed" | "unknown";
  acceptedEvents: FindingEvent[];
  providerReceipts?: ProviderSubmissionReceipt[];
}

export interface ProviderSubmissionReceipt {
  providerMessageId: string;
  eventReferences: string[];
}

export interface Notifier {
  send(events: FindingEvent[]): Promise<NotifierResult>;
}

export interface NotificationChannelAdapter {
  channel: NotificationChannel;
  configured: boolean;
  notifier: Notifier;
}
