import { describe, expect, it } from "vitest";
import { scanPleskHost, type SshCommandRunner } from "../src/plesk-scan";
import { renderReadOnlyCommand } from "../src/ssh-transport";
import { buildWpAuditBatchCommand } from "../src/wp-audit";

const host = {
  alias: "dev-ssh",
  id: "dev",
  name: "dev ssh",
  host: "dev.example.test",
  port: 22,
  user: "operator",
  identitySource: "bitwarden:dev",
};

const forbiddenRemoteMutation = /(?:^|[;&|`\n\s])(?:rm|rmdir|mv|cp|chmod|chown|truncate|mkfs|reboot|shutdown|poweroff|wp\s+(?:core|plugin|theme)\s+update|wp\s+db\b|wp\s+eval\b|plesk\s+(?:bin\s+)?(?:subscription|service-node|repair).*\b(?:-remove|-delete|-update)\b|(?:CREATE|ALTER|INSERT|UPDATE|DELETE|DROP)\b)/i;

describe("remote read-only safety contract", () => {
  it("keeps the generated WordPress audit batch free of mutation commands", () => {
    const command = buildWpAuditBatchCommand({ path: "/var/www/vhosts/example.test/httpdocs" }, { useSudo: true });

    expect(command).not.toMatch(forbiddenRemoteMutation);
    expect(command).toContain("core check-update");
    expect(command).toContain("core verify-checksums");
    expect(command).toContain("plugin verify-checksums");
  });

  it("keeps Plesk discovery and host facts inside the fixed read-only command set", async () => {
    const calls: string[] = [];
    const runner: SshCommandRunner = async (_host, command) => {
      const text = renderReadOnlyCommand(command);
      calls.push(text);
      if (text.includes("subscription --list")) return "example.test\n";
      if (text.includes("find /var/www/vhosts")) return "/var/www/vhosts/example.test/httpdocs/wp-config.php\n";
      if (text === "sudo -S -p '' -- plesk version") return "Plesk Obsidian 18.0.67\n";
      if (text === "sudo -S -p '' -- php -v") return "PHP 8.2.0\n";
      return "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/vda 1 1 1 1% /var/www/vhosts\n";
    };

    await scanPleskHost(host, runner, { useSudo: true, collectHostFacts: true, includeAlternateWordPressDetection: true });

    expect(calls.length).toBeGreaterThan(1);
    const allowedCommands = new Set([
      "sudo -S -p '' -- plesk bin subscription --list",
      "sudo -S -p '' -- find /var/www/vhosts -xdev -maxdepth 4 -type f \\( -name wp-config.php -o -path '*/wp-includes/version.php' \\) -print",
      "sudo -S -p '' -- plesk version",
      "sudo -S -p '' -- php -v",
      "sudo -S -p '' -- df -P -k /var/www/vhosts",
    ]);
    for (const command of calls) {
      expect(command).not.toMatch(forbiddenRemoteMutation);
      expect(allowedCommands.has(command)).toBe(true);
    }
  });

  it("renders only known read-only command kinds", () => {
    expect(renderReadOnlyCommand({ kind: "ssh-handshake" })).toBe(":");
    expect(renderReadOnlyCommand({ kind: "plesk-subscriptions", useSudo: true })).toBe("sudo -S -p '' -- plesk bin subscription --list");
    expect(() => renderReadOnlyCommand({ kind: "wp-audit-batch", installationPath: "/tmp/site\n;rm -rf /" })).toThrow("control character");
  });
});
