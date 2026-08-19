import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";

export interface PluginVulnerability {
  id: string;
  title: string;
  severity?: string;
  cve: string[];
  source: "WPVulnerability";
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
  const id = stringValue(record.id) ?? stringValue(record.slug) ?? `vulnerability-${index + 1}`;
  const title = stringValue(record.title) ?? stringValue(record.description) ?? stringValue(record.name) ?? id;
  const impact = record.impact && typeof record.impact === "object" ? record.impact as Record<string, unknown> : undefined;
  const cvss = record.cvss && typeof record.cvss === "object" ? record.cvss as Record<string, unknown> : undefined;
  const impactCvss = impact?.cvss && typeof impact.cvss === "object" ? impact.cvss as Record<string, unknown> : undefined;
  const severityValue = record.severity ?? cvss?.severity ?? impactCvss?.severity;
  const sourceIds = Array.isArray(record.source)
    ? record.source.flatMap((source) => source && typeof source === "object" ? stringList((source as Record<string, unknown>).id) : [])
    : [];
  const cve = [...stringList(record.cve ?? record.cves), ...sourceIds.filter((source) => /^CVE-/i.test(source))];
  return { id, title, severity: stringValue(severityValue), cve, source: "WPVulnerability" };
}

function endpointFor(resource: VulnerabilityResource, identifier: string): string {
  return `https://www.wpvulnerability.net/${resource}/${encodeURIComponent(identifier)}/`;
}

interface StoredCacheEntry {
  fetchedAt: string;
  result: VulnerabilityLookupResult;
}

interface VulnerabilityCacheFile {
  version: 1;
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
        const value = parsed as Partial<VulnerabilityCacheFile>;
        if (value.version !== 1 || !value.entries || typeof value.entries !== "object" || Array.isArray(value.entries)) {
          throw new Error(`Invalid vulnerability cache: ${path}`);
        }
        return value as VulnerabilityCacheFile;
      })
      .catch((error: unknown) => {
        if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") return { version: 1, entries: {} };
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
    const vulnerabilities = vulnerabilityRecords(payload)
      .map(mapVulnerability)
      .filter((item): item is PluginVulnerability => item !== null);
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
