import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import type { Finding } from "./findings";

export interface MonitorHeartbeat {
  version: 1;
  target: string;
  startedAt: string;
  completedAt?: string;
  scanComplete?: boolean;
  deferredSince?: Record<string, string>;
  failedAt?: string;
  reportPath?: string;
}

export interface HostProgressObservation {
  host: string;
  progressed: boolean;
}

function isIsoDate(value: unknown): value is string {
  return typeof value === "string" && Number.isFinite(Date.parse(value));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

export function reconcileDeferredHosts(
  previous: Readonly<Record<string, string>> | undefined,
  observations: readonly HostProgressObservation[],
  observedAt = new Date().toISOString(),
): Record<string, string> {
  if (!isIsoDate(observedAt)) throw new Error("deferred host observation time is invalid");
  const deferredSince = { ...(previous ?? {}) };
  for (const observation of observations) {
    if (!observation.host) throw new Error("deferred host observation has no host");
    if (observation.progressed) delete deferredSince[observation.host];
    else deferredSince[observation.host] ??= observedAt;
  }
  return deferredSince;
}

export function isHeartbeatStale(
  heartbeat: MonitorHeartbeat | undefined,
  now = new Date(),
  maxAgeMs = 2 * 60 * 60 * 1000,
): boolean {
  if (!heartbeat?.completedAt || !isIsoDate(heartbeat.completedAt) || !isIsoDate(heartbeat.startedAt)) return true;
  if (Date.parse(heartbeat.startedAt) > Date.parse(heartbeat.completedAt)) return true;
  if (now.getTime() - Date.parse(heartbeat.completedAt) > maxAgeMs) return true;
  return Object.values(heartbeat.deferredSince ?? {})
    .some((deferredAt) => !isIsoDate(deferredAt) || now.getTime() - Date.parse(deferredAt) > maxAgeMs);
}

export function createMonitorStaleFinding(
  heartbeat: MonitorHeartbeat | undefined,
  now = new Date(),
  maxAgeMs = 2 * 60 * 60 * 1000,
): Finding | undefined {
  if (!isHeartbeatStale(heartbeat, now, maxAgeMs)) return undefined;
  const evidence = heartbeat
    ? `target=${heartbeat.target}; startedAt=${heartbeat.startedAt}; completedAt=${heartbeat.completedAt ?? "missing"}; failedAt=${heartbeat.failedAt ?? "missing"}; deferred=${Object.entries(heartbeat.deferredSince ?? {}).map(([host, since]) => `${host}@${since}`).join(",") || "none"}`
    : "no heartbeat has been recorded";
  return {
    id: "finding-monitor-stale",
    code: "monitor-stale",
    severity: "P1",
    host: "monitor",
    installationPath: "__monitor__",
    domain: "monitor",
    message: "mise-en-plesk monitor is stale; no recent completion or host progress",
    evidence,
  };
}

export async function readHeartbeat(path: string): Promise<MonitorHeartbeat | undefined> {
  try {
    const value: unknown = JSON.parse(await readFile(path, "utf8"));
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`Invalid monitor heartbeat: ${path}`);
    const heartbeat = value as Partial<MonitorHeartbeat>;
    if (heartbeat.version !== 1 || typeof heartbeat.target !== "string" || !isIsoDate(heartbeat.startedAt)) {
      throw new Error(`Invalid monitor heartbeat: ${path}`);
    }
    for (const timestamp of [heartbeat.completedAt, heartbeat.failedAt]) {
      if (timestamp !== undefined && !isIsoDate(timestamp)) throw new Error(`Invalid monitor heartbeat: ${path}`);
    }
    if (heartbeat.scanComplete !== undefined && typeof heartbeat.scanComplete !== "boolean") {
      throw new Error(`Invalid monitor heartbeat: ${path}`);
    }
    if (heartbeat.deferredSince !== undefined && (!isRecord(heartbeat.deferredSince)
      || !Object.values(heartbeat.deferredSince).every(isIsoDate))) {
      throw new Error(`Invalid monitor heartbeat: ${path}`);
    }
    return heartbeat as MonitorHeartbeat;
  } catch (error: unknown) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") return undefined;
    throw error;
  }
}

export async function writeHeartbeat(path: string, heartbeat: MonitorHeartbeat): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  const temporaryPath = `${path}.tmp-${process.pid}`;
  await writeFile(temporaryPath, `${JSON.stringify(heartbeat, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
  await rename(temporaryPath, path);
}
