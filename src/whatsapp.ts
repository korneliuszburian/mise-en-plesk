import type { FindingEvent } from "./finding-state";
import { fetchWithRetry, type RetryOptions } from "./retry";
import { chunkFindingEvents, notificationEventReference } from "./notification-format";
import type { ProviderSubmissionReceipt } from "./notifier";

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
  outcome: "accepted" | "failed" | "unknown";
  eligibleEvents: number;
  acceptedEvents: FindingEvent[];
  providerReceipts: ProviderSubmissionReceipt[];
}

const DEFAULT_MAX_MESSAGE_LENGTH = 900;

async function acceptedMessageIds(response: Response): Promise<string[]> {
  const payload: unknown = await response.json();
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) return [];
  const messages = (payload as { messages?: unknown }).messages;
  if (!Array.isArray(messages)) return [];
  return messages.flatMap((message) => {
    if (!message || typeof message !== "object" || Array.isArray(message)) return [];
    const id = (message as { id?: unknown }).id;
    return typeof id === "string" && id.trim().startsWith("wamid.") ? [id.trim()] : [];
  });
}

function eligible(events: FindingEvent[]): FindingEvent[] {
  return events.filter((event) =>
    (event.type === "opened" || event.type === "reopened" || event.type === "resolved") && event.finding.severity === "P1");
}

export async function notifyFindingEventsToWhatsApp(
  events: FindingEvent[],
  options: WhatsAppOptions = {},
): Promise<WhatsAppResult> {
  const selected = eligible(events);
  const configured = options.accessToken && options.phoneNumberId && options.recipient && options.templateName && options.graphVersion;
  if (!configured || selected.length === 0) {
    return { outcome: "failed", eligibleEvents: selected.length, acceptedEvents: [], providerReceipts: [] };
  }

  const version = options.graphVersion!;
  const endpoint = `https://graph.facebook.com/${version}/${encodeURIComponent(options.phoneNumberId!)}/messages`;
  const maxMessageLength = Math.max(1, Math.floor(options.maxMessageLength ?? DEFAULT_MAX_MESSAGE_LENGTH));
  const acceptedEvents: FindingEvent[] = [];
  const providerReceipts: ProviderSubmissionReceipt[] = [];
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
      }, options.timeoutMs ?? 5000, { ...options, retryNetworkErrors: false });
      if (!response.ok) throw new Error(`WhatsApp API returned HTTP ${response.status}`);
      const acceptedIds = await acceptedMessageIds(response);
      if (!acceptedIds.length) throw new Error("WhatsApp API response did not contain a provider message id");
      providerReceipts.push(...acceptedIds.map((providerMessageId) => ({
        providerMessageId,
        eventReferences: chunk.events.map(notificationEventReference),
      })));
      acceptedEvents.push(...chunk.events);
    } catch (error: unknown) {
      options.debug?.(`WhatsApp notification skipped: ${error instanceof Error ? error.message : "request failed"}`);
      const definitiveFailure = error instanceof Error && error.message.startsWith("WhatsApp API returned HTTP ");
      return {
        outcome: definitiveFailure ? "failed" : "unknown",
        eligibleEvents: selected.length,
        acceptedEvents,
        providerReceipts,
      };
    }
  }
  return { outcome: "accepted", eligibleEvents: selected.length, acceptedEvents, providerReceipts };
}
