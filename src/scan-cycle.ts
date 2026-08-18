import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import type { Finding } from "./findings";
import { isFindingCode } from "./findings";

export interface ScanCycleHostState {
  startedAt: string;
  eligibleForCompletion: boolean;
  findings: Finding[];
}

export interface ScanCycleState {
  version: 1;
  hosts: Record<string, ScanCycleHostState>;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function isFinding(value: unknown): value is Finding {
  if (!isRecord(value)) return false;
  return typeof value.id === "string" && value.id.length > 0
    && isFindingCode(value.code)
    && (value.severity === "P1" || value.severity === "P2" || value.severity === "info")
    && typeof value.host === "string" && value.host.length > 0
    && typeof value.installationPath === "string" && value.installationPath.length > 0
    && (value.domain === undefined || typeof value.domain === "string")
    && (value.plugin === undefined || typeof value.plugin === "string")
    && (value.vulnerabilityId === undefined || typeof value.vulnerabilityId === "string")
    && typeof value.message === "string" && value.message.length > 0
    && (value.evidence === undefined || typeof value.evidence === "string");
}

function isHostState(value: unknown): value is ScanCycleHostState {
  return isRecord(value)
    && typeof value.startedAt === "string" && value.startedAt.length > 0
    && typeof value.eligibleForCompletion === "boolean"
    && Array.isArray(value.findings)
    && value.findings.every(isFinding);
}

export function emptyScanCycleState(): ScanCycleState {
  return { version: 1, hosts: {} };
}

export function validateScanCycleState(value: unknown, path = "scan cycle state"): ScanCycleState {
  if (!isRecord(value) || value.version !== 1 || !isRecord(value.hosts)
    || !Object.values(value.hosts).every(isHostState)) {
    throw new Error(`Invalid ${path}.`);
  }
  return value as unknown as ScanCycleState;
}

export function prepareScanCycle(
  state: ScanCycleState,
  host: string,
  offset: number,
  startedAt = new Date().toISOString(),
): ScanCycleState {
  if (offset === 0) {
    return { version: 1, hosts: { ...state.hosts, [host]: { startedAt, eligibleForCompletion: true, findings: [] } } };
  }
  if (state.hosts[host]) return state;
  return { version: 1, hosts: { ...state.hosts, [host]: { startedAt, eligibleForCompletion: false, findings: [] } } };
}

export function appendScanCycleFindings(
  state: ScanCycleState,
  host: string,
  findings: Finding[],
): ScanCycleState {
  const existing = state.hosts[host] ?? {
    startedAt: new Date().toISOString(),
    eligibleForCompletion: false,
    findings: [],
  };
  const byId = new Map(existing.findings.map((finding) => [finding.id, finding]));
  for (const finding of findings) byId.set(finding.id, finding);
  return {
    version: 1,
    hosts: {
      ...state.hosts,
      [host]: { ...existing, findings: [...byId.values()] },
    },
  };
}

export function completeScanCycle(
  state: ScanCycleState,
  host: string,
): { state: ScanCycleState; findings: Finding[] | null } {
  const cycle = state.hosts[host];
  if (!cycle?.eligibleForCompletion) return { state, findings: null };
  const hosts = { ...state.hosts };
  delete hosts[host];
  return { state: { version: 1, hosts }, findings: cycle.findings };
}

export async function readScanCycleState(path: string): Promise<ScanCycleState> {
  try {
    return validateScanCycleState(JSON.parse(await readFile(path, "utf8")) as unknown, path);
  } catch (error: unknown) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") return emptyScanCycleState();
    throw error;
  }
}

export async function writeScanCycleState(path: string, state: ScanCycleState): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  const temporaryPath = `${path}.tmp-${process.pid}`;
  await writeFile(temporaryPath, `${JSON.stringify(state, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
  await rename(temporaryPath, path);
}
