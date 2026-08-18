import { readFile } from "node:fs/promises";

export interface MisePleskConfig {
  reportsDirectory?: string;
  hosts?: string[];
  sudoHosts?: string[];
  maxVulnerabilityLookupsPerHost?: number;
  vulnerabilityCachePath?: string;
  vulnerabilityCacheTtlHours?: number;
  maxConcurrentSitesPerHost?: number;
  maxSitesPerHost?: number;
  maxScanChunksPerHost?: number;
  findingsStatePath?: string;
  scanCycleStatePath?: string;
  notificationOutboxPath?: string;
  notificationHistoryPath?: string;
  notificationCooldownHours?: number;
  heartbeatPath?: string;
  monitorMaxAgeHours?: number;
  sshCommandTimeoutMs?: number;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function aliases(value: unknown, name: string, source: string): string[] | undefined {
  if (value === undefined) return undefined;
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(item))) {
    throw new Error(`${name} must contain safe aliases using letters, numbers, dot, underscore, or dash: ${source}`);
  }
  const result = value as string[];
  if (new Set(result).size !== result.length) throw new Error(`${name} must not contain duplicate aliases: ${source}`);
  return result;
}

function pathValue(value: unknown, name: string, source: string): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "string" || !value.trim()) throw new Error(`${name} must be a non-empty path: ${source}`);
  return value;
}

function numberValue(value: unknown, name: string, source: string, minimum: number): number | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "number" || !Number.isFinite(value) || value < minimum) {
    throw new Error(`${name} must be a finite number >= ${minimum}: ${source}`);
  }
  return value;
}

function integerValue(value: unknown, name: string, source: string, minimum: number): number | undefined {
  const result = numberValue(value, name, source, minimum);
  if (result !== undefined && !Number.isSafeInteger(result)) throw new Error(`${name} must be a safe integer: ${source}`);
  return result;
}

export function validateConfig(value: unknown, source = "config.mise-en-plesk.json"): MisePleskConfig {
  if (!isRecord(value)) throw new Error(`Config must be a JSON object: ${source}`);
  return {
    reportsDirectory: pathValue(value.reportsDirectory, "reportsDirectory", source),
    hosts: aliases(value.hosts, "hosts", source),
    sudoHosts: aliases(value.sudoHosts, "sudoHosts", source),
    maxVulnerabilityLookupsPerHost: integerValue(value.maxVulnerabilityLookupsPerHost, "maxVulnerabilityLookupsPerHost", source, 0),
    vulnerabilityCachePath: pathValue(value.vulnerabilityCachePath, "vulnerabilityCachePath", source),
    vulnerabilityCacheTtlHours: numberValue(value.vulnerabilityCacheTtlHours, "vulnerabilityCacheTtlHours", source, Number.MIN_VALUE),
    maxConcurrentSitesPerHost: integerValue(value.maxConcurrentSitesPerHost, "maxConcurrentSitesPerHost", source, 1),
    maxSitesPerHost: integerValue(value.maxSitesPerHost, "maxSitesPerHost", source, 1),
    maxScanChunksPerHost: integerValue(value.maxScanChunksPerHost, "maxScanChunksPerHost", source, 1),
    findingsStatePath: pathValue(value.findingsStatePath, "findingsStatePath", source),
    scanCycleStatePath: pathValue(value.scanCycleStatePath, "scanCycleStatePath", source),
    notificationOutboxPath: pathValue(value.notificationOutboxPath, "notificationOutboxPath", source),
    notificationHistoryPath: pathValue(value.notificationHistoryPath, "notificationHistoryPath", source),
    notificationCooldownHours: numberValue(value.notificationCooldownHours, "notificationCooldownHours", source, 0),
    heartbeatPath: pathValue(value.heartbeatPath, "heartbeatPath", source),
    monitorMaxAgeHours: numberValue(value.monitorMaxAgeHours, "monitorMaxAgeHours", source, Number.MIN_VALUE),
    sshCommandTimeoutMs: integerValue(value.sshCommandTimeoutMs, "sshCommandTimeoutMs", source, 1_000),
  };
}

export async function readConfigFile(path: string): Promise<MisePleskConfig> {
  return validateConfig(JSON.parse(await readFile(path, "utf8")) as unknown, path);
}
