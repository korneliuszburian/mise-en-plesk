import { describe, expect, it, vi } from "vitest";
import { lookupPluginVulnerabilities } from "../src/vulnerabilities";

describe("WPVulnerability lookup", () => {
  it("does no network I/O when disabled", async () => {
    const fetchImpl = vi.fn();
    await expect(lookupPluginVulnerabilities("sample-plugin", { enabled: false, fetchImpl })).resolves.toBeNull();
    expect(fetchImpl).not.toHaveBeenCalled();
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
