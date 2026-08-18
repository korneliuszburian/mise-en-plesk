import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { isFindingCode, type Finding } from "./findings";

export interface StoredFinding extends Finding {
  status: "open" | "resolved";
  firstSeen: string;
  lastSeen: string;
  resolvedAt?: string;
}

export interface FindingState {
  version: 1;
  findings: Record<string, StoredFinding>;
}

export interface FindingEvent {
  type: "opened" | "reopened" | "resolved";
  finding: StoredFinding;
  occurredAt: string;
}

export interface FindingScope {
  completeHosts?: ReadonlySet<string>;
  installationPaths?: ReadonlySet<string>;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function optionalString(value: unknown): boolean {
  return value === undefined || typeof value === "string";
}

function isStoredFindingValue(value: unknown): value is StoredFinding {
  if (!isRecord(value)) return false;
  return typeof value.id === "string" && value.id.length > 0
    && isFindingCode(value.code)
    && (value.severity === "P1" || value.severity === "P2" || value.severity === "info")
    && typeof value.host === "string" && value.host.length > 0
    && typeof value.installationPath === "string" && value.installationPath.length > 0
    && optionalString(value.domain) && optionalString(value.plugin) && optionalString(value.vulnerabilityId)
    && typeof value.message === "string" && value.message.length > 0
    && optionalString(value.evidence)
    && (value.status === "open" || value.status === "resolved")
    && typeof value.firstSeen === "string" && typeof value.lastSeen === "string"
    && optionalString(value.resolvedAt);
}

export function isFindingEvent(value: unknown): value is FindingEvent {
  if (!isRecord(value)) return false;
  return (value.type === "opened" || value.type === "reopened" || value.type === "resolved")
    && typeof value.occurredAt === "string"
    && isStoredFindingValue(value.finding);
}

type ReconciliationScope = ReadonlySet<string> | FindingScope;

function isFindingScope(scope: ReconciliationScope): scope is FindingScope {
  return !("has" in scope);
}

export function emptyFindingState(): FindingState {
  return { version: 1, findings: {} };
}

export function reconcileFindings(
  previous: FindingState,
  current: Finding[],
  now = new Date().toISOString(),
  scope?: ReconciliationScope,
): { state: FindingState; events: FindingEvent[] } {
  const next: FindingState = { version: 1, findings: { ...previous.findings } };
  const events: FindingEvent[] = [];
  const currentIds = new Set<string>();

  for (const finding of current) {
    currentIds.add(finding.id);
    const existing = previous.findings[finding.id];
    if (!existing) {
      const stored: StoredFinding = { ...finding, status: "open", firstSeen: now, lastSeen: now };
      next.findings[finding.id] = stored;
      events.push({ type: "opened", finding: stored, occurredAt: now });
      continue;
    }
    const reopened = existing.status === "resolved";
    const stored: StoredFinding = {
      ...existing,
      ...finding,
      status: "open",
      firstSeen: existing.firstSeen,
      lastSeen: now,
      resolvedAt: undefined,
    };
    next.findings[finding.id] = stored;
    if (reopened) events.push({ type: "reopened", finding: stored, occurredAt: now });
  }

  for (const existing of Object.values(previous.findings)) {
    const inScope = scope === undefined
      || (!isFindingScope(scope)
        ? scope.has(existing.host)
        : scope.completeHosts?.has(existing.host) === true
          || scope.installationPaths?.has(existing.installationPath) === true);
    if (existing.status === "open" && inScope && !currentIds.has(existing.id)) {
      const resolved: StoredFinding = { ...existing, status: "resolved", resolvedAt: now };
      next.findings[existing.id] = resolved;
      events.push({ type: "resolved", finding: resolved, occurredAt: now });
    }
  }
  return { state: next, events };
}

export async function readFindingState(path: string): Promise<FindingState> {
  try {
    const parsed: unknown = JSON.parse(await readFile(path, "utf8"));
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error(`Invalid finding state: ${path}`);
    const value = parsed as Partial<FindingState>;
    if (value.version !== 1 || !value.findings || typeof value.findings !== "object" || Array.isArray(value.findings)
      || !Object.values(value.findings).every(isStoredFindingValue)) {
      throw new Error(`Invalid finding state: ${path}`);
    }
    return value as FindingState;
  } catch (error: unknown) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") return emptyFindingState();
    throw error;
  }
}

export async function writeFindingState(path: string, state: FindingState): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  const temporaryPath = `${path}.tmp-${process.pid}`;
  await writeFile(temporaryPath, `${JSON.stringify(state, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
  await rename(temporaryPath, path);
}
