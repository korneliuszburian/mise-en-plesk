import type { FindingEvent } from "./finding-state";
import { fetchWithRetry, type RetryOptions } from "./retry";
import { chunkFindingEvents } from "./notification-format";

export interface WhatsAppOptions extends RetryOptions {
  accessToken?: string;
  phoneNumberId?: string;
  recipient?: string;
  templateName?: string;
  templateLanguage?: string;
  graphVersion?: string;
  timeoutMs?: number;
  maxMessageLength?: number;
  fetchImpl?: typeof fetch;
  debug?: (message: string) => void;
}

export interface WhatsAppResult {
  sent: boolean;
  eligibleEvents: number;
  sentEvents: FindingEvent[];
}

const DEFAULT_MAX_MESSAGE_LENGTH = 900;

function eligible(events: FindingEvent[]): FindingEvent[] {
  return events.filter((event) =>
    (event.type === "opened" || event.type === "reopened") && event.finding.severity === "P1");
}

export async function notifyFindingEventsToWhatsApp(
  events: FindingEvent[],
  options: WhatsAppOptions = {},
): Promise<WhatsAppResult> {
  const selected = eligible(events);
  const configured = options.accessToken && options.phoneNumberId && options.recipient && options.templateName && options.graphVersion;
  if (!configured || selected.length === 0) return { sent: false, eligibleEvents: selected.length, sentEvents: [] };

  const version = options.graphVersion!;
  const endpoint = `https://graph.facebook.com/${version}/${encodeURIComponent(options.phoneNumberId!)}/messages`;
  const maxMessageLength = Math.max(1, Math.floor(options.maxMessageLength ?? DEFAULT_MAX_MESSAGE_LENGTH));
  const sentEvents: FindingEvent[] = [];
  for (const chunk of chunkFindingEvents(selected, maxMessageLength)) {
    try {
      const response = await fetchWithRetry(options.fetchImpl ?? fetch, endpoint, {
        method: "POST",
        headers: {
          authorization: `Bearer ${options.accessToken}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          messaging_product: "whatsapp",
          to: options.recipient,
          type: "template",
          template: {
            name: options.templateName,
            language: { code: options.templateLanguage ?? "en_US" },
            components: [{ type: "body", parameters: [{ type: "text", text: chunk.text }] }],
          },
        }),
      }, options.timeoutMs ?? 5000, options);
      if (!response.ok) throw new Error(`WhatsApp API returned HTTP ${response.status}`);
      sentEvents.push(...chunk.events);
    } catch (error: unknown) {
      options.debug?.(`WhatsApp notification skipped: ${error instanceof Error ? error.message : "request failed"}`);
      return { sent: false, eligibleEvents: selected.length, sentEvents };
    }
  }
  return { sent: true, eligibleEvents: selected.length, sentEvents };
}
