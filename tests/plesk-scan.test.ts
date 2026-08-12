import { describe, expect, it } from "vitest";
import { scanPleskHost, type SshCommandRunner } from "../src/plesk-scan";
import type { HostConfig } from "../src/ssh-inventory";

const host: HostConfig = {
  alias: "master",
  id: "1",
  name: "Master",
  host: "master.example.test",
  port: 22,
  user: "root",
  identitySource: "bitwarden:1",
};

describe("plesk scan", () => {
  it("collects subscriptions and WordPress config paths using read-only commands", async () => {
    const calls: string[] = [];
    const runner: SshCommandRunner = async (_host, command) => {
      calls.push(command);
      if (command.startsWith("plesk bin subscription")) return "example.test\nshop.test\n";
      return "/var/www/vhosts/example.test/httpdocs/wp-config.php\n";
    };

    await expect(scanPleskHost(host, runner)).resolves.toEqual({
      host: "master",
      subscriptions: ["example.test", "shop.test"],
      wordpress: [{ path: "/var/www/vhosts/example.test/httpdocs", domain: "example.test" }],
    });
    expect(calls).toEqual([
      "plesk bin subscription --list",
      "find /var/www/vhosts -type f -name wp-config.php -print",
    ]);
  });
});
