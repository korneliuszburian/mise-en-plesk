import { execFile } from "node:child_process";
import { promisify } from "node:util";
import type { FindingEvent } from "./finding-state";
import type { RetryOptions } from "./retry";
import { chunkFindingEvents } from "./notification-format";

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
  outcome: "accepted" | "failed" | "unknown";
  eligibleEvents: number;
  acceptedEvents: FindingEvent[];
}

export function isHermesWhatsAppTarget(value: string | undefined): value is string {
  return typeof value === "string" && /^whatsapp:\S+$/.test(value.trim());
}

function requireHermesWhatsAppTarget(value: string | undefined): string {
  if (!isHermesWhatsAppTarget(value)) {
    throw new Error("Hermes WhatsApp target must match whatsapp:<chat-id> without whitespace.");
  }
  return value.trim();
}

function eligible(events: FindingEvent[]): FindingEvent[] {
  return events.filter((event) =>
    (event.type === "opened" || event.type === "reopened" || event.type === "resolved") && event.finding.severity === "P1");
}

async function defaultCommandRunner(binary: string, args: string[], timeoutMs: number): Promise<void> {
  await execFileAsync(binary, args, { timeout: timeoutMs, maxBuffer: 1024 * 1024 });
}

function sleep(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function runWithRetry(
  runner: (binary: string, args: string[], timeoutMs: number) => Promise<void>,
  binary: string,
  args: string[],
  timeoutMs: number,
  options: RetryOptions,
): Promise<void> {
  const maxAttempts = Math.max(1, Math.min(5, Math.floor(options.maxAttempts ?? 1)));
  const retryDelayMs = Math.max(0, options.retryDelayMs ?? 250);
  const sleepImpl = options.sleepImpl ?? sleep;
  let lastError: unknown;
  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    try {
      await runner(binary, args, timeoutMs);
      return;
    } catch (error: unknown) {
      lastError = error;
      if (attempt === maxAttempts) break;
      await sleepImpl(retryDelayMs * attempt);
    }
  }
  throw lastError instanceof Error ? lastError : new Error("Hermes command failed");
}

export async function sendFindingEventsViaHermes(
  events: FindingEvent[],
  options: HermesOptions = {},
): Promise<HermesResult> {
  const selected = eligible(events);
  if (!options.target?.trim() || selected.length === 0) {
    return { outcome: "failed", eligibleEvents: selected.length, acceptedEvents: [] };
  }
  let target: string;
  try {
    target = requireHermesWhatsAppTarget(options.target);
  } catch (error: unknown) {
    options.debug?.(`Hermes notification skipped: ${error instanceof Error ? error.message : "invalid target"}`);
    return { outcome: "failed", eligibleEvents: selected.length, acceptedEvents: [] };
  }

  const binary = options.binary?.trim() || "hermes";
  const timeoutMs = options.timeoutMs ?? 15_000;
  const maxLength = Math.max(1, Math.floor(options.maxMessageLength ?? DEFAULT_MAX_MESSAGE_LENGTH));
  const acceptedEvents: FindingEvent[] = [];
  for (const chunk of chunkFindingEvents(selected, maxLength)) {
    const message = chunk.text;
    try {
      await runWithRetry(
        options.commandRunner ?? defaultCommandRunner,
        binary,
        ["send", "--to", target, message],
        timeoutMs,
        options,
      );
      acceptedEvents.push(...chunk.events);
    } catch (error: unknown) {
      options.debug?.(`Hermes notification skipped: ${error instanceof Error ? error.message : "command failed"}`);
      return { outcome: "unknown", eligibleEvents: selected.length, acceptedEvents };
    }
  }
  return { outcome: "accepted", eligibleEvents: selected.length, acceptedEvents };
}

export async function sendHermesText(
  message: string,
  options: Pick<HermesOptions, "target" | "binary" | "timeoutMs" | "commandRunner" | "maxAttempts" | "retryDelayMs" | "sleepImpl">,
): Promise<void> {
  const target = requireHermesWhatsAppTarget(options.target);
  await runWithRetry(
    options.commandRunner ?? defaultCommandRunner,
    options.binary?.trim() || "hermes",
    ["send", "--to", target, message],
    options.timeoutMs ?? 15_000,
    options,
  );
}
