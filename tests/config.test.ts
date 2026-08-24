import { describe, expect, it } from "vitest";
import { validateConfig } from "../src/config";

describe("mise-en-plesk config", () => {
  it("accepts bounded scan settings and preserves configured paths", () => {
    expect(validateConfig({
      hosts: ["master-ssh", "dev-ssh"],
      sudoHosts: ["master-ssh"],
      maxConcurrentSitesPerHost: 4,
      maxSitesPerHost: 20,
      maxScanChunksPerHost: 100,
      maxVulnerabilityLookupsPerHost: 10,
      vulnerabilityCacheTtlHours: 12,
      sshCommandTimeoutMs: 60000,
      publicSiteChecks: true,
      publicSiteCheckTimeoutMs: 10000,
      findingsStatePath: ".mise-en-plesk/findings.json",
      scanCycleStatePath: ".mise-en-plesk/scan-cycles.json",
    })).toMatchObject({ hosts: ["master-ssh", "dev-ssh"], maxConcurrentSitesPerHost: 4, maxScanChunksPerHost: 100, sshCommandTimeoutMs: 60000, publicSiteChecks: true, publicSiteCheckTimeoutMs: 10000, scanCycleStatePath: ".mise-en-plesk/scan-cycles.json" });
  });

  it("rejects invalid numeric limits and duplicate aliases", () => {
    expect(() => validateConfig({ maxConcurrentSitesPerHost: 0 })).toThrow("maxConcurrentSitesPerHost");
    expect(() => validateConfig({ hosts: ["master-ssh", "master-ssh"] })).toThrow("duplicate aliases");
    expect(() => validateConfig({ hosts: ["../reports"] })).toThrow("safe aliases");
    expect(() => validateConfig({ sshCommandTimeoutMs: 999 })).toThrow("sshCommandTimeoutMs");
    expect(() => validateConfig({ maxScanChunksPerHost: 0 })).toThrow("maxScanChunksPerHost");
    expect(() => validateConfig({ publicSiteChecks: "yes" })).toThrow("publicSiteChecks");
    expect(() => validateConfig({ publicSiteCheckTimeoutMs: 999 })).toThrow("publicSiteCheckTimeoutMs");
  });
});
