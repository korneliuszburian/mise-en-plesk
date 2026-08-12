import { describe, expect, it } from "vitest";
import { buildSshInvocation, scanPleskHost, type SshCommandRunner } from "../src/plesk-scan";
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
  it("keeps SSH passwords in the child environment and out of argv", () => {
    const invocation = buildSshInvocation(host, "secret-password");

    expect(invocation.executable).toBe("sshpass");
    expect(invocation.args).toEqual([
      "-e",
      "ssh",
      "-o",
      "ConnectTimeout=10",
      "-o",
      "ConnectionAttempts=1",
      "-p",
      "22",
      "root@master.example.test",
    ]);
    expect(invocation.env?.SSHPASS).toBe("secret-password");
  });

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
      "find /var/www/vhosts -xdev -maxdepth 4 -type f -name wp-config.php -print",
    ]);
  });
});
