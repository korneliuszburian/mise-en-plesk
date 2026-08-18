import type { FindingEvent } from "./finding-state";

export interface WhatsAppOptions {
  accessToken?: string;
  phoneNumberId?: string;
  recipient?: string;
  templateName?: string;
  templateLanguage?: string;
  graphVersion?: string;
  timeoutMs?: number;
  fetchImpl?: typeof fetch;
  debug?: (message: string) => void;
}

export interface WhatsAppResult {
  sent: boolean;
  eligibleEvents: number;
}

function eligible(events: FindingEvent[]): FindingEvent[] {
  return events.filter((event) =>
    (event.type === "opened" || event.type === "reopened") && event.finding.severity === "P1");
}

function messageText(events: FindingEvent[]): string {
  return events.map((event) => {
    const site = event.finding.domain ?? event.finding.installationPath;
    return `[${event.finding.severity}] ${event.type} on ${event.finding.host}/${site}: ${event.finding.message}`;
  }).join("\n");
}

export async function notifyFindingEventsToWhatsApp(
  events: FindingEvent[],
  options: WhatsAppOptions = {},
): Promise<WhatsAppResult> {
  const selected = eligible(events);
  const configured = options.accessToken && options.phoneNumberId && options.recipient && options.templateName && options.graphVersion;
  if (!configured || selected.length === 0) return { sent: false, eligibleEvents: selected.length };

  const version = options.graphVersion!;
  const endpoint = `https://graph.facebook.com/${version}/${encodeURIComponent(options.phoneNumberId!)}/messages`;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), options.timeoutMs ?? 5000);
  try {
    const response = await (options.fetchImpl ?? fetch)(endpoint, {
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
          components: [{ type: "body", parameters: [{ type: "text", text: messageText(selected) }] }],
        },
      }),
      signal: controller.signal,
    });
    if (!response.ok) throw new Error(`WhatsApp API returned HTTP ${response.status}`);
    return { sent: true, eligibleEvents: selected.length };
  } catch (error: unknown) {
    options.debug?.(`WhatsApp notification skipped: ${error instanceof Error ? error.message : "request failed"}`);
    return { sent: false, eligibleEvents: selected.length };
  } finally {
    clearTimeout(timeout);
  }
}
