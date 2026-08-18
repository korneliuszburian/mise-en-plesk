import type { FindingEvent } from "./finding-state";

export interface NotificationOptions {
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
    (event.type === "opened" || event.type === "reopened") && event.finding.severity === "P1");
}

function eventText(event: FindingEvent): string {
  const site = event.finding.domain ?? event.finding.installationPath;
  return `[${event.finding.severity}] ${event.type} on ${event.finding.host}/${site}: ${event.finding.message}`;
}

export async function notifyFindingEvents(
  events: FindingEvent[],
  options: NotificationOptions = {},
): Promise<NotificationResult> {
  const eligible = actionableEvents(events);
  if (!options.webhookUrl || eligible.length === 0) return { sent: false, eligibleEvents: eligible.length };

  const fetchImpl = options.fetchImpl ?? fetch;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), options.timeoutMs ?? 5000);
  try {
    const response = await fetchImpl(options.webhookUrl, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({
        source: "mise-en-plesk",
        kind: "wordpress-risk-alert",
        text: eligible.map(eventText).join("\n"),
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
      signal: controller.signal,
    });
    if (!response.ok) throw new Error(`alert webhook returned HTTP ${response.status}`);
    return { sent: true, eligibleEvents: eligible.length };
  } catch (error: unknown) {
    options.debug?.(`alert notification skipped: ${error instanceof Error ? error.message : "request failed"}`);
    return { sent: false, eligibleEvents: eligible.length };
  } finally {
    clearTimeout(timeout);
  }
}
