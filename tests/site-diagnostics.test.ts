import { describe, expect, it } from "vitest";
import { enrichAuditWithSiteDiagnostics } from "../src/site-diagnostics";
import type { WordPressAudit } from "../src/wp-audit";

const audit: WordPressAudit = {
  installation: {
    path: "/var/www/vhosts/solozaszkola.dev.proudsite.pl/httpdocs",
    domain: "solozaszkola.dev.proudsite.pl",
    classification: { kind: "staging", reason: "staging marker found in the domain or path" },
  },
  coreVersion: "6.9.4",
  plugins: [],
  vulnerabilities: [],
  suspiciousFiles: [],
  health: { reachable: true },
  priorities: [],
};

describe("site diagnostics orchestration", () => {
  it("correlates a public failure with fixed read-only Plesk site information", async () => {
    const commands: unknown[] = [];
    const result = await enrichAuditWithSiteDiagnostics(audit, async (command) => {
      commands.push(command);
      return `Domain name: solozaszkola.dev.proudsite.pl\nDomain status: The domain was suspended by the administrator.\nSSL/TLS support: On\n--WWW-Root--: /var/www/vhosts/solozaszkola.dev.proudsite.pl/httpdocs\n`;
    }, {
      useSudo: true,
      request: async (_url, requestOptions) => {
        if (requestOptions.rejectUnauthorized) throw Object.assign(new Error("expired"), { code: "CERT_HAS_EXPIRED" });
        return { status: 503, finalUrl: "https://solozaszkola.dev.proudsite.pl/" };
      },
    });

    expect(commands).toEqual([{ kind: "plesk-site-info", domain: "solozaszkola.dev.proudsite.pl", useSudo: true }]);
    expect(result).toMatchObject({
      publicSiteHealth: { tls: { status: "invalid" }, http: { status: 503 } },
      pleskSiteInfo: { suspended: true },
    });
  });
});
