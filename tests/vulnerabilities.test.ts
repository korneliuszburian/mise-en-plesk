import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { createFileVulnerabilityCache, lookupPluginVulnerabilities, lookupVulnerabilities } from "../src/vulnerabilities";

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
});
