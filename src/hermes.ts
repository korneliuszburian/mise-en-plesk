import { execFile } from "node:child_process";
import { promisify } from "node:util";
import type { FindingEvent } from "./finding-state";
import type { RetryOptions } from "./retry";

const execFileAsync = promisify(execFile);
const DEFAULT_MAX_MESSAGE_LENGTH = 900;

export interface HermesOptions extends RetryOptions {
  target?: string;
  binary?: string;
  timeoutMs?: number;
  maxMessageLength?: number;
  commandRunner?: (binary: string, args: string[], timeoutMs: number) => Promise<void>;
  debug?: (message: string) => void;
}

export interface HermesResult {
  sent: boolean;
  eligibleEvents: number;
  sentEvents: FindingEvent[];
}

function eligible(events: FindingEvent[]): FindingEvent[] {
  return events.filter((event) =>
    (event.type === "opened" || event.type === "reopened") && event.finding.severity === "P1");
}

function eventText(event: FindingEvent, maxLength: number): string {
  const site = event.finding.domain ?? event.finding.installationPath;
  const text = `[${event.finding.severity}] ${event.type} on ${event.finding.host}/${site}: ${event.finding.message}`;
  return text.length <= maxLength ? text : `${text.slice(0, Math.max(0, maxLength - 1))}…`;
}

function chunks(events: FindingEvent[], maxLength: number): FindingEvent[][] {
  const result: FindingEvent[][] = [];
  let current: FindingEvent[] = [];
  let length = 0;
  for (const event of events) {
    const eventLength = eventText(event, maxLength).length;
    if (current.length && length + 1 + eventLength > maxLength) {
      result.push(current);
      current = [];
      length = 0;
    }
    current.push(event);
    length += (current.length > 1 ? 1 : 0) + eventLength;
  }
  if (current.length) result.push(current);
  return result;
}

async function defaultCommandRunner(binary: string, args: string[], timeoutMs: number): Promise<void> {
  await execFileAsync(binary, args, { timeout: timeoutMs, maxBuffer: 1024 * 1024 });
}

export async function sendFindingEventsViaHermes(
  events: FindingEvent[],
  options: HermesOptions = {},
): Promise<HermesResult> {
  const selected = eligible(events);
  if (!options.target?.trim() || selected.length === 0) {
    return { sent: false, eligibleEvents: selected.length, sentEvents: [] };
  }

  const binary = options.binary?.trim() || "hermes";
  const timeoutMs = options.timeoutMs ?? 15_000;
  const maxLength = Math.max(1, Math.floor(options.maxMessageLength ?? DEFAULT_MAX_MESSAGE_LENGTH));
  const sentEvents: FindingEvent[] = [];
  for (const chunk of chunks(selected, maxLength)) {
    const message = chunk.map((event) => eventText(event, maxLength)).join("\n");
    try {
      await (options.commandRunner ?? defaultCommandRunner)(binary, ["send", "--to", options.target.trim(), message], timeoutMs);
      sentEvents.push(...chunk);
    } catch (error: unknown) {
      options.debug?.(`Hermes notification skipped: ${error instanceof Error ? error.message : "command failed"}`);
      return { sent: false, eligibleEvents: selected.length, sentEvents };
    }
  }
  return { sent: true, eligibleEvents: selected.length, sentEvents };
}

export async function sendHermesText(
  message: string,
  options: Pick<HermesOptions, "target" | "binary" | "timeoutMs" | "commandRunner">,
): Promise<void> {
  if (!options.target?.trim()) throw new Error("MISE_PLESK_HERMES_WHATSAPP_TARGET is not configured.");
  await (options.commandRunner ?? defaultCommandRunner)(
    options.binary?.trim() || "hermes",
    ["send", "--to", options.target.trim(), message],
    options.timeoutMs ?? 15_000,
  );
}
