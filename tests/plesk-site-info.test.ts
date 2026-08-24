import { describe, expect, it } from "vitest";
import { parsePleskSiteInfo } from "../src/plesk-site-info";

describe("Plesk site information", () => {
  it("parses a suspended domain without retaining unrelated account details", () => {
    const output = `
Domain name:                            solozaszkola.dev.proudsite.pl
Domain status:                          The domain was suspended by the administrator.
Certificate:                            Lets Encrypt solozaszkola.dev.proudsite.pl
SSL/TLS support:                        On
FTP Login:                              private-login
FTP Password:                           ************
--WWW-Root--: /var/www/vhosts/solozaszkola.dev.proudsite.pl/httpdocs
`;

    expect(parsePleskSiteInfo(output)).toEqual({
      domain: "solozaszkola.dev.proudsite.pl",
      status: "The domain was suspended by the administrator.",
      suspended: true,
      certificate: "Lets Encrypt solozaszkola.dev.proudsite.pl",
      tlsEnabled: true,
      documentRoot: "/var/www/vhosts/solozaszkola.dev.proudsite.pl/httpdocs",
    });
    expect(JSON.stringify(parsePleskSiteInfo(output))).not.toContain("private-login");
  });
});
