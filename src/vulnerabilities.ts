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

export interface VulnerabilityLookupOptions {
  enabled?: boolean;
  timeoutMs?: number;
  fetchImpl?: typeof fetch;
  debug?: (message: string) => void;
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
  const title = stringValue(record.title) ?? stringValue(record.description) ?? id;
  const severityValue = record.severity ?? (record.cvss && typeof record.cvss === "object" ? (record.cvss as Record<string, unknown>).severity : undefined);
  const cve = stringList(record.cve ?? record.cves);
  return { id, title, severity: stringValue(severityValue), cve, source: "WPVulnerability" };
}

export async function lookupPluginVulnerabilities(
  slug: string,
  options: VulnerabilityLookupOptions = {},
): Promise<PluginVulnerabilitySummary | null> {
  const enabled = options.enabled ?? enabledByEnvironment();
  if (!enabled) return null;

  const fetchImpl = options.fetchImpl ?? fetch;
  const timeoutMs = options.timeoutMs ?? 5000;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetchImpl(`https://www.wpvulnerability.net/plugin/${encodeURIComponent(slug)}/`, {
      method: "GET",
      signal: controller.signal,
      headers: { accept: "application/json" },
    });
    if (!response.ok) return null;
    const payload: unknown = await response.json();
    const vulnerabilities = vulnerabilityRecords(payload)
      .map(mapVulnerability)
      .filter((item): item is PluginVulnerability => item !== null);
    return vulnerabilities.length ? { slug, vulnerabilities } : null;
  } catch (error: unknown) {
    options.debug?.(`vulnerability lookup skipped for ${slug}: ${error instanceof Error ? error.message : "request failed"}`);
    return null;
  } finally {
    clearTimeout(timeout);
  }
}
