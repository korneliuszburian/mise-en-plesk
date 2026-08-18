import { describe, expect, it } from "vitest";
import { buildSshInvocation, classifyWordPressInstallation, scanPleskHost, type SshCommandRunner } from "../src/plesk-scan";
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
  it("classifies WordPress locations without claiming certainty for unknown paths", () => {
    expect(classifyWordPressInstallation("/var/www/vhosts/example.test/httpdocs", "example.test")).toEqual({
      kind: "production",
      reason: "standard Plesk httpdocs path without staging or backup markers",
    });
    expect(classifyWordPressInstallation("/var/www/vhosts/staging.example.test/httpdocs", "staging.example.test")).toEqual({
      kind: "staging",
      reason: "staging marker found in the domain or path",
    });
    expect(classifyWordPressInstallation("/var/www/vhosts/example.test/httpdocs/backup-2026", "example.test")).toEqual({
      kind: "backup",
      reason: "backup marker found in the domain or path",
    });
    expect(classifyWordPressInstallation("/srv/sites/example.test/current", "example.test")).toEqual({
      kind: "unknown",
      reason: "path does not provide a reliable production, staging, or backup signal",
    });
  });

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

  it("supports a local SSH control socket for connection reuse", () => {
    const invocation = buildSshInvocation(host, "secret-password", { controlPath: "/tmp/mise-en-plesk/control" });

    expect(invocation.args).toContain("ControlMaster=auto");
    expect(invocation.args).toContain("ControlPersist=120");
    expect(invocation.args).toContain("ControlPath=/tmp/mise-en-plesk/control");
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
      wordpress: [{
        path: "/var/www/vhosts/example.test/httpdocs",
        domain: "example.test",
        classification: { kind: "production", reason: "standard Plesk httpdocs path without staging or backup markers" },
      }],
    });
    expect(calls).toEqual([
      "plesk bin subscription --list",
      "find /var/www/vhosts -xdev -maxdepth 4 -type f -name wp-config.php -print",
    ]);
  });

  it("bounds remote WordPress discovery for a chunk", async () => {
    const calls: string[] = [];
    const runner: SshCommandRunner = async (_host, command) => {
      calls.push(command);
      if (command.startsWith("plesk bin subscription")) return "example.test\n";
      if (command.includes("awk 'NR > 2")) return "/var/www/vhosts/three.test/httpdocs/wp-config.php\n";
      return [
        "/var/www/vhosts/one.test/httpdocs/wp-config.php",
        "/var/www/vhosts/two.test/httpdocs/wp-config.php",
        "/var/www/vhosts/three.test/httpdocs/wp-config.php",
      ].join("\n");
    };

    await expect(scanPleskHost(host, runner, { wordpressOffset: 2, wordpressLimit: 2 })).resolves.toMatchObject({
      wordpress: [{ domain: "three.test" }],
      wordpressHasMore: false,
    });
    expect(calls[1]).toContain("awk 'NR > 2 && NR <= 5");
  });

  it("rejects unsafe discovery ranges before building a remote command", async () => {
    const runner: SshCommandRunner = async () => "";

    await expect(scanPleskHost(host, runner, { wordpressOffset: -1 })).rejects.toThrow("wordpressOffset");
    await expect(scanPleskHost(host, runner, { wordpressLimit: 0 })).rejects.toThrow("wordpressLimit");
  });

  it("uses non-interactive sudo only when explicitly enabled", async () => {
    const calls: string[] = [];
    const runner: SshCommandRunner = async (_host, command) => {
      calls.push(command);
      return command.startsWith("sudo") ? "/var/www/vhosts/example.test/httpdocs/wp-config.php\n" : "example.test\n";
    };

    await scanPleskHost(host, runner, { wordpressLimit: 1, useSudo: true });

    expect(calls[0]).toBe("sudo -S -p '' -- plesk bin subscription --list");
    expect(calls[1]).toContain("sudo -S -p '' -- find /var/www/vhosts");
  });

  it("falls back to non-root filesystem discovery when Plesk CLI is unavailable", async () => {
    const calls: string[] = [];
    const runner: SshCommandRunner = async (_host, command) => {
      calls.push(command);
      if (command.includes("plesk bin subscription")) throw new Error("must run as root");
      return "/var/www/vhosts/example.test/httpdocs/wp-config.php\n";
    };

    await expect(scanPleskHost(host, runner, { useSudo: true })).resolves.toMatchObject({
      subscriptions: [],
      wordpress: [{ domain: "example.test" }],
      warnings: [expect.stringContaining("filesystem discovery only")],
    });
    expect(calls).toEqual([
      "sudo -S -p '' -- plesk bin subscription --list",
      "find /var/www/vhosts -xdev -maxdepth 4 -type f -name wp-config.php -print",
    ]);
  });
});
