import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";

export interface PluginVulnerability {
  id: string;
  title: string;
  severity?: string;
  cve: string[];
  source: "WPVulnerability";
  affectedVersions?: VulnerabilityVersionRange;
}

export type VersionOperator = "lt" | "le" | "eq" | "ne" | "gt" | "ge";
export type VulnerabilityApplicability = "applies" | "not-applicable" | "unknown";

export interface VulnerabilityVersionRange {
  minVersion?: string;
  minOperator?: VersionOperator;
  maxVersion?: string;
  maxOperator?: VersionOperator;
  unfixed?: boolean;
  closed?: boolean;
}

export interface PluginVulnerabilitySummary {
  slug: string;
  vulnerabilities: PluginVulnerability[];
}

export type VulnerabilityResource = "core" | "plugin" | "theme";

export interface VulnerabilityResourceSummary {
  resource: VulnerabilityResource;
  identifier: string;
  vulnerabilities: PluginVulnerability[];
}

export type VulnerabilityLookupStatus = "disabled" | "known" | "empty" | "unavailable" | "skipped";

export interface VulnerabilityLookupResult {
  status: VulnerabilityLookupStatus;
  summary?: VulnerabilityResourceSummary;
  checkedAt?: string;
}

export interface VulnerabilityCache {
  get(resource: VulnerabilityResource, identifier: string): Promise<VulnerabilityLookupResult | undefined>;
  set(resource: VulnerabilityResource, identifier: string, result: VulnerabilityLookupResult): Promise<void>;
}

export interface VulnerabilityLookupOptions {
  enabled?: boolean;
  timeoutMs?: number;
  fetchImpl?: typeof fetch;
  debug?: (message: string) => void;
  cache?: VulnerabilityCache;
}

export interface BoundedVulnerabilityLookupOptions {
  enabled: boolean;
  maxLookups?: number;
  budget: { used: number };
  cache?: VulnerabilityCache;
  lookup?: typeof lookupVulnerabilities;
  maxConcurrent?: number;
}

export function createBoundedVulnerabilityLookup(options: BoundedVulnerabilityLookupOptions): typeof lookupVulnerabilities {
  const lookup = options.lookup ?? lookupVulnerabilities;
  const maxLookups = options.maxLookups ?? 25;
  const maxConcurrent = options.maxConcurrent ?? 4;
  if (!Number.isSafeInteger(maxConcurrent) || maxConcurrent < 1) throw new Error("vulnerability lookup concurrency must be a positive safe integer");
  let active = 0;
  const waiters: Array<() => void> = [];
  const withPermit = async <T>(operation: () => Promise<T>): Promise<T> => {
    if (active >= maxConcurrent) await new Promise<void>((resolve) => waiters.push(resolve));
    active += 1;
    try {
      return await operation();
    } finally {
      active -= 1;
      waiters.shift()?.();
    }
  };
  return async (resource, identifier, requestOptions = {}) => {
    if (!options.enabled) return { status: "disabled" };
    return withPermit(async () => {
      try {
        const cached = await options.cache?.get(resource, identifier);
        if (cached) return cached;
      } catch (error: unknown) {
        requestOptions.debug?.(`vulnerability cache ignored: ${error instanceof Error ? error.message : "cache read failed"}`);
      }
      if (options.budget.used >= maxLookups) return { status: "skipped" };
      options.budget.used += 1;
      return lookup === lookupVulnerabilities
        ? performVulnerabilityLookup(resource, identifier, { ...requestOptions, enabled: true, cache: options.cache })
        : lookup(resource, identifier, { ...requestOptions, enabled: true, cache: options.cache });
    });
  };
}

function enabledByEnvironment(): boolean {
  return process.env.MISE_PLESK_ENABLE_VULNS === "1";
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function stringList(value: unknown): string[] {
  if (Array.isArray(value)) return value.flatMap((entry) => stringValue(entry) ?? []);
  const single = stringValue(value);
  return single ? [single] : [];
}

const versionOperators = new Set<VersionOperator>(["lt", "le", "eq", "ne", "gt", "ge"]);
const qualifierRanks: Record<string, number> = { dev: 0, alpha: 1, a: 1, beta: 2, b: 2, rc: 3, final: 4, pl: 5, p: 5 };

function versionOperator(value: unknown): VersionOperator | undefined {
  return typeof value === "string" && versionOperators.has(value as VersionOperator) ? value as VersionOperator : undefined;
}

function booleanFlag(value: unknown): boolean | undefined {
  if (value === true || value === 1 || value === "1") return true;
  if (value === false || value === 0 || value === "0") return false;
  return undefined;
}

function normalizedSeverity(value: unknown): string | undefined {
  const severity = stringValue(value)?.toLowerCase();
  if (!severity) return undefined;
  return ({ c: "critical", h: "high", m: "medium", l: "low" } as Record<string, string>)[severity] ?? severity;
}

type VersionPart = number | keyof typeof qualifierRanks;

function versionParts(value: string): VersionPart[] | undefined {
  const normalized = value.trim().toLowerCase().replace(/^v(?=\d)/, "");
  if (!normalized || /[^0-9a-z._+\-]/.test(normalized)) return undefined;
  const rawParts = normalized.match(/\d+|[a-z]+/g);
  if (!rawParts?.length) return undefined;
  const residue = normalized.replace(/\d+|[a-z]+|[._+\-]/g, "");
  if (residue) return undefined;
  const parts: VersionPart[] = [];
  for (const part of rawParts) {
    if (/^\d+$/.test(part)) {
      const numeric = Number(part);
      if (!Number.isSafeInteger(numeric)) return undefined;
      parts.push(numeric);
      continue;
    }
    if (!(part in qualifierRanks)) return undefined;
    parts.push(part as keyof typeof qualifierRanks);
  }
  return parts;
}

export function isComparableVersion(value: string): boolean {
  return versionParts(value) !== undefined;
}

function lexicalOrder(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function compareVersions(left: string, right: string): number | undefined {
  const leftParts = versionParts(left);
  const rightParts = versionParts(right);
  if (!leftParts || !rightParts) return undefined;
  const length = Math.max(leftParts.length, rightParts.length);
  for (let index = 0; index < length; index += 1) {
    const otherLeft = rightParts[index];
    const otherRight = leftParts[index];
    const leftPart: VersionPart = leftParts[index] ?? (typeof otherLeft === "string" ? "final" : 0);
    const rightPart: VersionPart = rightParts[index] ?? (typeof otherRight === "string" ? "final" : 0);
    if (typeof leftPart !== typeof rightPart) return typeof leftPart === "number" ? 1 : -1;
    const leftValue = typeof leftPart === "number" ? leftPart : qualifierRanks[leftPart];
    const rightValue = typeof rightPart === "number" ? rightPart : qualifierRanks[rightPart];
    if (leftValue !== rightValue) return leftValue < rightValue ? -1 : 1;
  }
  return 0;
}

function comparisonMatches(comparison: number, operator: VersionOperator): boolean {
  if (operator === "lt") return comparison < 0;
  if (operator === "le") return comparison <= 0;
  if (operator === "eq") return comparison === 0;
  if (operator === "ne") return comparison !== 0;
  if (operator === "gt") return comparison > 0;
  return comparison >= 0;
}

export function classifyVulnerabilityApplicability(
  vulnerability: PluginVulnerability,
  installedVersion: string,
): VulnerabilityApplicability {
  const range = vulnerability.affectedVersions;
  if (!range || installedVersion === "unknown") return "unknown";
  const bounds = [
    [range.minVersion, range.minOperator],
    [range.maxVersion, range.maxOperator],
  ] as const;
  let matchedBound = false;
  for (const [version, operator] of bounds) {
    if (version === undefined && operator === undefined) continue;
    if (!version || !operator || !versionOperators.has(operator)) return "unknown";
    const comparison = compareVersions(installedVersion, version);
    if (comparison === undefined) return "unknown";
    matchedBound = true;
    if (!comparisonMatches(comparison, operator)) return "not-applicable";
  }
  return matchedBound ? "applies" : "unknown";
}

function vulnerabilityRecords(payload: unknown): unknown[] {
  if (Array.isArray(payload)) {
    return payload.flatMap((entry) => {
      if (!entry || typeof entry !== "object") return [];
      const vulnerabilities = (entry as Record<string, unknown>).vulnerabilities;
      return Array.isArray(vulnerabilities) ? vulnerabilities : [entry];
    });
  }
  if (!payload || typeof payload !== "object") return [];
  const root = payload as Record<string, unknown>;
  for (const key of ["vulnerabilities", "vulnerability"]) {
    if (Array.isArray(root[key])) return root[key];
  }
  if (root.data && typeof root.data === "object") return vulnerabilityRecords(root.data);
  return [];
}

function mapVulnerability(value: unknown, index: number): PluginVulnerability | null {
  if (!value || typeof value !== "object") return null;
  const record = value as Record<string, unknown>;
  const id = stringValue(record.uuid) ?? stringValue(record.id) ?? stringValue(record.slug) ?? `vulnerability-${index + 1}`;
  const title = stringValue(record.title) ?? stringValue(record.description) ?? stringValue(record.name) ?? id;
  const impact = record.impact && typeof record.impact === "object" ? record.impact as Record<string, unknown> : undefined;
  const cvss = record.cvss && typeof record.cvss === "object" ? record.cvss as Record<string, unknown> : undefined;
  const impactCvss = impact?.cvss && typeof impact.cvss === "object" ? impact.cvss as Record<string, unknown> : undefined;
  const impactCvss3 = impact?.cvss3 && typeof impact.cvss3 === "object" ? impact.cvss3 as Record<string, unknown> : undefined;
  const impactCvss4 = impact?.cvss4 && typeof impact.cvss4 === "object" ? impact.cvss4 as Record<string, unknown> : undefined;
  const severityValue = record.severity ?? impactCvss4?.severity ?? impactCvss3?.severity ?? cvss?.severity ?? impactCvss?.severity;
  const sourceIds = Array.isArray(record.source)
    ? record.source.flatMap((source) => source && typeof source === "object" ? stringList((source as Record<string, unknown>).id) : [])
    : [];
  const cve = [...new Set([...stringList(record.cve ?? record.cves), ...sourceIds.filter((source) => /^CVE-/i.test(source))])].sort(lexicalOrder);
  const operator = record.operator && typeof record.operator === "object" && !Array.isArray(record.operator)
    ? record.operator as Record<string, unknown>
    : undefined;
  const minVersion = stringValue(operator?.min_version);
  const minOperator = versionOperator(operator?.min_operator);
  const maxVersion = stringValue(operator?.max_version);
  const maxOperator = versionOperator(operator?.max_operator);
  const affectedVersions = operator ? {
    ...(minVersion ? { minVersion } : {}),
    ...(minOperator ? { minOperator } : {}),
    ...(maxVersion ? { maxVersion } : {}),
    ...(maxOperator ? { maxOperator } : {}),
    ...(booleanFlag(operator.unfixed) !== undefined ? { unfixed: booleanFlag(operator.unfixed) } : {}),
    ...(booleanFlag(operator.closed) !== undefined ? { closed: booleanFlag(operator.closed) } : {}),
  } : undefined;
  return {
    id,
    title,
    severity: normalizedSeverity(severityValue),
    cve,
    source: "WPVulnerability",
    ...(affectedVersions ? { affectedVersions } : {}),
  };
}

function endpointFor(resource: VulnerabilityResource, identifier: string): string {
  return `https://www.wpvulnerability.net/${resource}/${encodeURIComponent(identifier)}/`;
}

interface StoredCacheEntry {
  fetchedAt: string;
  result: VulnerabilityLookupResult;
}

interface VulnerabilityCacheFile {
  version: 2;
  entries: Record<string, StoredCacheEntry>;
}

function cacheKey(resource: VulnerabilityResource, identifier: string): string {
  return `${resource}:${identifier}`;
}

async function cacheResult(
  cache: VulnerabilityCache | undefined,
  resource: VulnerabilityResource,
  identifier: string,
  result: VulnerabilityLookupResult,
  debug?: (message: string) => void,
): Promise<void> {
  try {
    await cache?.set(resource, identifier, result);
  } catch (error: unknown) {
    debug?.(`vulnerability cache ignored: ${error instanceof Error ? error.message : "cache write failed"}`);
  }
}

export function createFileVulnerabilityCache(path: string, ttlMs = 12 * 60 * 60 * 1000): VulnerabilityCache {
  let statePromise: Promise<VulnerabilityCacheFile> | undefined;
  let writeQueue = Promise.resolve();
  const load = async (): Promise<VulnerabilityCacheFile> => {
    statePromise ??= readFile(path, "utf8")
      .then((contents) => {
        const parsed: unknown = JSON.parse(contents);
        if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error(`Invalid vulnerability cache: ${path}`);
        const value = parsed as { version?: unknown; entries?: unknown };
        if (value.version === 1) return { version: 2, entries: {} } as VulnerabilityCacheFile;
        if (value.version !== 2 || !value.entries || typeof value.entries !== "object" || Array.isArray(value.entries)) throw new Error(`Invalid vulnerability cache: ${path}`);
        return value as VulnerabilityCacheFile;
      })
      .catch((error: unknown) => {
        if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") return { version: 2, entries: {} } as VulnerabilityCacheFile;
        throw error;
      });
    return statePromise;
  };
  const persist = async (state: VulnerabilityCacheFile): Promise<void> => {
    await mkdir(dirname(path), { recursive: true });
    const temporaryPath = `${path}.tmp-${process.pid}`;
    await writeFile(temporaryPath, `${JSON.stringify(state, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
    await rename(temporaryPath, path);
  };
  return {
    async get(resource, identifier) {
      const state = await load();
      const entry = state.entries[cacheKey(resource, identifier)];
      if (!entry || !Number.isFinite(Date.parse(entry.fetchedAt)) || Date.now() - Date.parse(entry.fetchedAt) > ttlMs) return undefined;
      return entry.result;
    },
    async set(resource, identifier, result) {
      if (result.status !== "known" && result.status !== "empty") return;
      const state = await load();
      state.entries[cacheKey(resource, identifier)] = { fetchedAt: new Date().toISOString(), result };
      writeQueue = writeQueue.then(() => persist(state));
      await writeQueue;
    },
  };
}

export async function lookupVulnerabilities(
  resource: VulnerabilityResource,
  identifier: string,
  options: VulnerabilityLookupOptions = {},
): Promise<VulnerabilityLookupResult> {
  const enabled = options.enabled ?? enabledByEnvironment();
  if (!enabled) return { status: "disabled" };

  let cached: VulnerabilityLookupResult | undefined;
  try {
    cached = await options.cache?.get(resource, identifier);
  } catch (error: unknown) {
    options.debug?.(`vulnerability cache ignored: ${error instanceof Error ? error.message : "cache read failed"}`);
  }
  if (cached) return cached;

  return performVulnerabilityLookup(resource, identifier, options);
}

async function performVulnerabilityLookup(
  resource: VulnerabilityResource,
  identifier: string,
  options: VulnerabilityLookupOptions,
): Promise<VulnerabilityLookupResult> {
  const fetchImpl = options.fetchImpl ?? fetch;
  const timeoutMs = options.timeoutMs ?? 5000;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetchImpl(endpointFor(resource, identifier), {
      method: "GET",
      signal: controller.signal,
      headers: { accept: "application/json" },
    });
    if (response.status === 404) {
      const result = { status: "empty", checkedAt: new Date().toISOString() } as const;
      await cacheResult(options.cache, resource, identifier, result, options.debug);
      return result;
    }
    if (!response.ok) {
      options.debug?.(`vulnerability lookup unavailable for ${resource}/${identifier}: HTTP ${response.status}`);
      return { status: "unavailable", checkedAt: new Date().toISOString() };
    }
    let payload: unknown;
    try {
      payload = await response.json();
    } catch {
      options.debug?.(`vulnerability lookup unavailable for ${resource}/${identifier}: invalid JSON`);
      return { status: "unavailable", checkedAt: new Date().toISOString() };
    }
    const mappedVulnerabilities = vulnerabilityRecords(payload)
      .map(mapVulnerability)
      .filter((item): item is PluginVulnerability => item !== null);
    const vulnerabilities = [...new Map(mappedVulnerabilities.map((vulnerability) => [vulnerability.id, vulnerability])).values()]
      .sort((left, right) => lexicalOrder(left.id, right.id));
    if (!vulnerabilities.length) {
      const result = { status: "empty", checkedAt: new Date().toISOString() } as const;
      await cacheResult(options.cache, resource, identifier, result, options.debug);
      return result;
    }
    const result = { status: "known", checkedAt: new Date().toISOString(), summary: { resource, identifier, vulnerabilities } } as const;
    await cacheResult(options.cache, resource, identifier, result, options.debug);
    return result;
  } catch (error: unknown) {
    options.debug?.(`vulnerability lookup unavailable for ${resource}/${identifier}: ${error instanceof Error ? error.message : "request failed"}`);
    return { status: "unavailable", checkedAt: new Date().toISOString() };
  } finally {
    clearTimeout(timeout);
  }
}

export async function lookupPluginVulnerabilities(
  slug: string,
  options: VulnerabilityLookupOptions = {},
): Promise<PluginVulnerabilitySummary | null> {
  const result = await lookupVulnerabilities("plugin", slug, options);
  return result.status === "known" && result.summary
    ? { slug, vulnerabilities: result.summary.vulnerabilities }
    : null;
}
