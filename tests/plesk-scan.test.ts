import { chmod, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { buildSshInvocation, classifyWordPressInstallation, parseDiskUsage, parsePhpVersion, parsePleskVersion, runSshCommand, scanPleskHost, type SshCommandRunner } from "../src/plesk-scan";
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
  it("parses read-only host fact output", () => {
    expect(parsePleskVersion("Plesk Obsidian 18.0.67 Update #3\n")).toBe("Plesk Obsidian 18.0.67");
    expect(parsePhpVersion("PHP 8.2.29 (cli) (built: Jun 12 2026 10:00:00)\n")).toBe("8.2.29");
    expect(parseDiskUsage("Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/vda1 100000 65000 35000 65% /var/www/vhosts\n")).toEqual({
      filesystem: "/dev/vda1",
      availableKb: 35000,
      usedPercent: 65,
    });
  });

  it("collects host facts through fixed read-only commands", async () => {
    const calls: string[] = [];
    const runner: SshCommandRunner = async (_host, command) => {
      calls.push(command);
      if (command.startsWith("plesk bin subscription")) return "example.test\n";
      if (command.startsWith("find /var/www/vhosts")) return "/var/www/vhosts/example.test/httpdocs/wp-config.php\n";
      if (command === "plesk version") return "Plesk Obsidian 18.0.67 Update #3\n";
      if (command === "php -v") return "PHP 8.2.29 (cli)\n";
      return "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/vda1 100000 65000 35000 65% /var/www/vhosts\n";
    };

    await expect(scanPleskHost(host, runner, { collectHostFacts: true })).resolves.toMatchObject({
      hostFacts: { pleskVersion: "Plesk Obsidian 18.0.67", phpVersion: "8.2.29", disk: { availableKb: 35000, usedPercent: 65 } },
    });
    expect(calls).toContain("plesk version");
    expect(calls).toContain("php -v");
    expect(calls).toContain("df -P -k /var/www/vhosts");
  });

  it("detects alternate WordPress roots from wp-includes/version.php", async () => {
    const runner: SshCommandRunner = async (_host, command) => {
      if (command.startsWith("plesk bin subscription")) return "example.test\n";
      return "/var/www/vhosts/example.test/httpdocs/wp-includes/version.php\n/var/www/vhosts/other.test/httpdocs/wp-config.php\n";
    };

    await expect(scanPleskHost(host, runner, { includeAlternateWordPressDetection: true })).resolves.toMatchObject({
      wordpress: [
        { path: "/var/www/vhosts/example.test/httpdocs", detectionSignals: ["wp-includes/version.php"] },
        { path: "/var/www/vhosts/other.test/httpdocs", detectionSignals: ["wp-config.php"] },
      ],
    });
  });

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

  it("terminates the whole sshpass process group on command timeout", async () => {
    if (process.platform === "win32") return;
    const directory = await mkdtemp(join(tmpdir(), "mise-en-plesk-ssh-timeout-"));
    const fakeSshpass = join(directory, "sshpass");
    const childPidPath = join(directory, "child.pid");
    await writeFile(fakeSshpass, `#!/bin/sh\n(sleep 30) &\necho $! > "${childPidPath}"\nwhile true; do sleep 1; done\n`);
    await chmod(fakeSshpass, 0o755);
    const previousPath = process.env.PATH;
    process.env.PATH = `${directory}:${previousPath ?? ""}`;
    try {
      await expect(runSshCommand(host, ":", "secret-password", { timeoutMs: 100 })).rejects.toThrow();
      const childPid = Number(await readFile(childPidPath, "utf8"));
      await new Promise((resolve) => setTimeout(resolve, 200));
      expect(() => process.kill(childPid, 0)).toThrow();
    } finally {
      process.env.PATH = previousPath;
    }
  });

  it("bounds captured SSH output before it can exhaust the scanner process", async () => {
    if (process.platform === "win32") return;
    const directory = await mkdtemp(join(tmpdir(), "mise-en-plesk-ssh-output-"));
    const fakeSshpass = join(directory, "sshpass");
    await writeFile(fakeSshpass, "#!/bin/sh\nhead -c 4096 /dev/zero\n");
    await chmod(fakeSshpass, 0o755);
    const previousPath = process.env.PATH;
    process.env.PATH = `${directory}:${previousPath ?? ""}`;
    try {
      await expect(runSshCommand(host, ":", "secret-password", { timeoutMs: 5_000, maxOutputBytes: 256 })).rejects.toThrow("output exceeded 256 bytes");
    } finally {
      process.env.PATH = previousPath;
    }
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
      if (command.includes("position > 2")) return "/var/www/vhosts/three.test/httpdocs/wp-config.php\n";
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
    expect(calls[1]).toContain("candidate=$0");
    expect(calls[1]).toContain("position > 2 && position <= 5");
    expect(calls[1]).toContain("if (position >= 5) exit");
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

  it("returns host health when filesystem discovery loses the SSH connection", async () => {
    const runner: SshCommandRunner = async (_host, command) => {
      if (command.includes("plesk bin subscription")) return "example.test\n";
      throw new Error("Command failed (timeout)");
    };

    await expect(scanPleskHost(host, runner)).resolves.toMatchObject({
      host: "master",
      health: { reachable: false, detail: "Command failed (timeout)" },
      wordpress: [],
      warnings: [expect.stringContaining("filesystem discovery unavailable")],
    });
  });
});
