import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import {
  classifyVulnerabilityApplicability,
  createBoundedVulnerabilityLookup,
  createFileVulnerabilityCache,
  lookupPluginVulnerabilities,
  lookupVulnerabilities,
  type PluginVulnerability,
} from "../src/vulnerabilities";

describe("WPVulnerability lookup", () => {
  it("does no network I/O when disabled", async () => {
    const fetchImpl = vi.fn();
    await expect(lookupPluginVulnerabilities("sample-plugin", { enabled: false, fetchImpl })).resolves.toBeNull();
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("reports disabled, empty, and unavailable distinctly", async () => {
    const fetchImpl = vi.fn(async (url: RequestInfo | URL) => new Response(String(url).includes("empty") ? "[]" : "service unavailable", { status: String(url).includes("empty") ? 200 : 503 }));

    await expect(lookupVulnerabilities("theme", "empty-theme", { enabled: false, fetchImpl })).resolves.toMatchObject({ status: "disabled" });
    await expect(lookupVulnerabilities("theme", "empty-theme", { enabled: true, fetchImpl })).resolves.toMatchObject({ status: "empty" });
    await expect(lookupVulnerabilities("core", "6.6.1", { enabled: true, fetchImpl })).resolves.toMatchObject({ status: "unavailable" });
  });

  it("uses resource-specific core and theme endpoints", async () => {
    const fetchImpl = vi.fn(async () => new Response(JSON.stringify({ data: { vulnerabilities: [{ id: "CVE-2026-0003", title: "Theme issue" }] } }), { status: 200 }));

    await expect(lookupVulnerabilities("theme", "my-theme", { enabled: true, fetchImpl })).resolves.toMatchObject({
      status: "known",
      summary: { resource: "theme", identifier: "my-theme", vulnerabilities: [{ id: "CVE-2026-0003" }] },
    });
    await expect(lookupVulnerabilities("core", "6.6.1", { enabled: true, fetchImpl })).resolves.toMatchObject({ status: "known" });
    expect(fetchImpl).toHaveBeenNthCalledWith(1, expect.stringContaining("/theme/my-theme/"), expect.any(Object));
    expect(fetchImpl).toHaveBeenNthCalledWith(2, expect.stringContaining("/core/6.6.1/"), expect.any(Object));
  });

  it("reuses fresh known/empty cache entries but never caches unavailable responses", async () => {
    const directory = await mkdtemp(join(tmpdir(), "mise-en-plesk-vuln-cache-"));
    const path = join(directory, "vulnerabilities.json");
    const cache = createFileVulnerabilityCache(path, 60 * 60 * 1000);
    const fetchImpl = vi.fn(async () => new Response(JSON.stringify({ data: { vulnerabilities: [{ id: "CVE-2026-0004", title: "Cached issue" }] } }), { status: 200 }));

    await lookupVulnerabilities("plugin", "cached-plugin", { enabled: true, fetchImpl, cache });
    await lookupVulnerabilities("plugin", "cached-plugin", { enabled: true, fetchImpl, cache });
    expect(fetchImpl).toHaveBeenCalledOnce();
    await expect(readFile(path, "utf8")).resolves.toContain("cached-plugin");

    const unavailableFetch = vi.fn(async () => new Response("down", { status: 503 }));
    await lookupVulnerabilities("plugin", "down-plugin", { enabled: true, fetchImpl: unavailableFetch, cache });
    await lookupVulnerabilities("plugin", "down-plugin", { enabled: true, fetchImpl: unavailableFetch, cache });
    expect(unavailableFetch).toHaveBeenCalledTimes(2);
  });

  it("treats pre-range cache entries as stale and replaces them with the current schema", async () => {
    const directory = await mkdtemp(join(tmpdir(), "mise-en-plesk-vuln-cache-migration-"));
    const path = join(directory, "vulnerabilities.json");
    await writeFile(path, JSON.stringify({
      version: 1,
      entries: {
        "plugin:sample-plugin": {
          fetchedAt: new Date().toISOString(),
          result: { status: "known", summary: { resource: "plugin", identifier: "sample-plugin", vulnerabilities: [{ id: "historical", title: "Historical", cve: [], source: "WPVulnerability" }] } },
        },
      },
    }));
    const fetchImpl = vi.fn(async () => new Response(JSON.stringify({ data: { vulnerability: [] } }), { status: 200 }));
    const cache = createFileVulnerabilityCache(path);

    await expect(lookupVulnerabilities("plugin", "sample-plugin", { enabled: true, fetchImpl, cache })).resolves.toMatchObject({ status: "empty" });
    expect(fetchImpl).toHaveBeenCalledOnce();
    await expect(readFile(path, "utf8")).resolves.toContain('"version": 2');
  });

  it("maps a plugin vulnerability payload through an injected fetch", async () => {
    const fetchImpl = vi.fn(async () => new Response(JSON.stringify({
      data: { vulnerabilities: [{ id: "CVE-2026-0001", title: "Example issue", severity: "high", cves: ["CVE-2026-0001"] }] },
    }), { status: 200, headers: { "content-type": "application/json" } }));

    await expect(lookupPluginVulnerabilities("sample-plugin", { enabled: true, fetchImpl })).resolves.toEqual({
      slug: "sample-plugin",
      vulnerabilities: [{ id: "CVE-2026-0001", title: "Example issue", severity: "high", cve: ["CVE-2026-0001"], source: "WPVulnerability" }],
    });
    expect(fetchImpl).toHaveBeenCalledOnce();
    expect(fetchImpl).toHaveBeenCalledWith(expect.stringContaining("/plugin/sample-plugin/"), expect.any(Object));
  });

  it("maps the public plugin-list response shape", async () => {
    const fetchImpl = vi.fn(async () => new Response(JSON.stringify([{
      slug: "sample-plugin",
      vulnerabilities: [{
        name: "Remote code execution",
        impact: { cvss: { severity: "critical" } },
        source: [{ id: "CVE-2026-0002" }],
      }],
    }]), { status: 200 }));

    await expect(lookupPluginVulnerabilities("sample-plugin", { enabled: true, fetchImpl })).resolves.toMatchObject({
      slug: "sample-plugin",
      vulnerabilities: [{ title: "Remote code execution", severity: "critical", cve: ["CVE-2026-0002"] }],
    });
  });

  it("preserves live API version bounds and classifies only proven affected versions", async () => {
    const fetchImpl = vi.fn(async () => new Response(JSON.stringify({
      data: {
        vulnerability: [{
          uuid: "range-1",
          name: "Example >= 3.3.0 and < 6.6.0",
          operator: {
            min_version: "3.3.0",
            min_operator: "ge",
            max_version: "6.6.0",
            max_operator: "lt",
            unfixed: "0",
            closed: "0",
          },
          impact: { cvss: { severity: "h" } },
        }],
      },
    }), { status: 200 }));

    const summary = await lookupPluginVulnerabilities("sample-plugin", { enabled: true, fetchImpl });
    const vulnerability = summary?.vulnerabilities[0];
    expect(vulnerability).toMatchObject({
      id: "range-1",
      severity: "high",
      affectedVersions: {
        minVersion: "3.3.0",
        minOperator: "ge",
        maxVersion: "6.6.0",
        maxOperator: "lt",
        unfixed: false,
        closed: false,
      },
    });
    expect(classifyVulnerabilityApplicability(vulnerability!, "3.2.9")).toBe("not-applicable");
    expect(classifyVulnerabilityApplicability(vulnerability!, "5.5.0")).toBe("applies");
    expect(classifyVulnerabilityApplicability(vulnerability!, "6.6.0")).toBe("not-applicable");
    expect(classifyVulnerabilityApplicability({
      ...vulnerability!,
      affectedVersions: { maxVersion: "1.0.0", maxOperator: "lt" },
    }, "1.0rc1")).toBe("applies");
  });

  it("deduplicates and orders vulnerability identities and CVEs deterministically", async () => {
    const fetchImpl = vi.fn(async () => new Response(JSON.stringify({ data: { vulnerability: [
      { uuid: "z-record", name: "Z", source: [{ id: "CVE-2026-0002" }, { id: "CVE-2026-0001" }, { id: "CVE-2026-0002" }], operator: { max_version: "2", max_operator: "lt" } },
      { uuid: "a-record", name: "A", source: [], operator: { max_version: "2", max_operator: "lt" } },
    ] } }), { status: 200 }));

    const summary = await lookupPluginVulnerabilities("sample-plugin", { enabled: true, fetchImpl });
    expect(summary?.vulnerabilities.map(({ id }) => id)).toEqual(["a-record", "z-record"]);
    expect(summary?.vulnerabilities[1]?.cve).toEqual(["CVE-2026-0001", "CVE-2026-0002"]);
  });

  it("keeps malformed or absent ranges unknown instead of generating certainty", () => {
    const vulnerability = {
      id: "unknown-range",
      title: "Unknown range",
      cve: [],
      source: "WPVulnerability",
    } satisfies PluginVulnerability;
    expect(classifyVulnerabilityApplicability(vulnerability, "1.2.3")).toBe("unknown");
    expect(classifyVulnerabilityApplicability({
      ...vulnerability,
      affectedVersions: { minVersion: "1.0.0", minOperator: "unsupported" as "ge", unfixed: true, closed: false },
    }, "1.2.3")).toBe("unknown");
    expect(classifyVulnerabilityApplicability(vulnerability, "unknown")).toBe("unknown");
  });

  it("enforces one shared lookup budget under concurrent callers", async () => {
    let active = 0;
    let peak = 0;
    const underlying = vi.fn(async () => {
      active += 1;
      peak = Math.max(peak, active);
      await new Promise((resolve) => setTimeout(resolve, 5));
      active -= 1;
      return { status: "empty" as const };
    });
    const budget = { used: 0 };
    const lookup = createBoundedVulnerabilityLookup({ enabled: true, maxLookups: 2, maxConcurrent: 1, budget, lookup: underlying });

    const results = await Promise.all(["one", "two", "three", "four"].map((slug) => lookup("plugin", slug)));

    expect(underlying).toHaveBeenCalledTimes(2);
    expect(budget.used).toBe(2);
    expect(peak).toBe(1);
    expect(results.map(({ status }) => status)).toEqual(["empty", "empty", "skipped", "skipped"]);
  });
});
