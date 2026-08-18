import type { FindingEvent } from "./finding-state";
import { fetchWithRetry, type RetryOptions } from "./retry";
import { chunkFindingEvents } from "./notification-format";

export interface NotificationOptions extends RetryOptions {
  webhookUrl?: string;
  timeoutMs?: number;
  fetchImpl?: typeof fetch;
  debug?: (message: string) => void;
}

export interface NotificationResult {
  sent: boolean;
  eligibleEvents: number;
}

function actionableEvents(events: FindingEvent[]): FindingEvent[] {
  return events.filter((event) =>
    (event.type === "opened" || event.type === "reopened" || event.type === "resolved") && event.finding.severity === "P1");
}

export async function notifyFindingEvents(
  events: FindingEvent[],
  options: NotificationOptions = {},
): Promise<NotificationResult> {
  const eligible = actionableEvents(events);
  if (!options.webhookUrl || eligible.length === 0) return { sent: false, eligibleEvents: eligible.length };

  try {
    const response = await fetchWithRetry(options.fetchImpl ?? fetch, options.webhookUrl, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({
        source: "mise-en-plesk",
        kind: "wordpress-risk-alert",
        text: chunkFindingEvents(eligible, 1_000_000).map((chunk) => chunk.text).join("\n"),
        events: eligible.map((event) => ({
          type: event.type,
          occurredAt: event.occurredAt,
          finding: {
            id: event.finding.id,
            severity: event.finding.severity,
            code: event.finding.code,
            host: event.finding.host,
            domain: event.finding.domain,
            message: event.finding.message,
          },
        })),
      }),
    }, options.timeoutMs ?? 5000, options);
    if (!response.ok) throw new Error(`alert webhook returned HTTP ${response.status}`);
    return { sent: true, eligibleEvents: eligible.length };
  } catch (error: unknown) {
    options.debug?.(`alert notification skipped: ${error instanceof Error ? error.message : "request failed"}`);
    return { sent: false, eligibleEvents: eligible.length };
  }
}
