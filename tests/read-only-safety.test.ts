import { describe, expect, it } from "vitest";
import { runSshCommand, scanPleskHost, type SshCommandRunner } from "../src/plesk-scan";
import { assertReadOnlyRenderedCommand, renderReadOnlyCommand } from "../src/ssh-transport";
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

describe("remote read-only safety contract", () => {
  it("keeps the generated WordPress audit batch free of mutation commands", () => {
    const command = buildWpAuditBatchCommand({ path: "/var/www/vhosts/example.test/httpdocs" }, { useSudo: true });

    expect(() => assertReadOnlyRenderedCommand(command)).not.toThrow();
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
      expect(() => assertReadOnlyRenderedCommand(command)).not.toThrow();
      expect(allowedCommands.has(command)).toBe(true);
    }
  });

  it("renders only known read-only command kinds", () => {
    expect(renderReadOnlyCommand({ kind: "ssh-handshake" })).toBe(":");
    expect(renderReadOnlyCommand({ kind: "plesk-subscriptions", useSudo: true })).toBe("sudo -S -p '' -- plesk bin subscription --list");
    expect(() => renderReadOnlyCommand({ kind: "wp-audit-batch", installationPath: "/tmp/site\n;rm -rf /" })).toThrow("control character");
  });

  it("fails closed at the last execution seam for mutation-shaped commands", () => {
    expect(() => assertReadOnlyRenderedCommand("rm -rf /var/www/vhosts/example.test/httpdocs")).toThrow("mutation detected");
    expect(() => assertReadOnlyRenderedCommand("value=$(rm -rf /var/www/vhosts/example.test/httpdocs)")).toThrow("mutation detected");
    expect(() => assertReadOnlyRenderedCommand("wp plugin update vulnerable-plugin --path='/srv/site'")).toThrow("mutation detected");
    expect(() => assertReadOnlyRenderedCommand("wp db query 'DELETE FROM wp_options'")).toThrow("mutation detected");
    expect(() => assertReadOnlyRenderedCommand("plesk bin subscription --update example.test")).toThrow("mutation detected");
    expect(() => assertReadOnlyRenderedCommand("sh -c 'rm -rf /var/www/vhosts/example.test/httpdocs'")).toThrow("mutation detected");
    expect(() => assertReadOnlyRenderedCommand("sudo sh -c 'wp plugin update vulnerable-plugin'")).toThrow("mutation detected");
    expect(() => assertReadOnlyRenderedCommand("plesk bin subscription -u example.test")).toThrow("mutation detected");
    expect(() => assertReadOnlyRenderedCommand("sudo -S -p '' -- rm -rf /")).toThrow("mutation detected");
    expect(() => assertReadOnlyRenderedCommand("sudo -S -p '' -- plesk bin subscription -u example.test")).toThrow("mutation detected");
    expect(() => assertReadOnlyRenderedCommand("sudo -S -p '' -- sh -c 'rm -rf /'")).toThrow("mutation detected");
    expect(() => assertReadOnlyRenderedCommand("echo ok; sudo -S -p '' -- rm -rf /")).toThrow("mutation detected");
    expect(() => assertReadOnlyRenderedCommand("value=$(sudo -S -p '' -- rm -rf /)")).toThrow("mutation detected");
    expect(() => assertReadOnlyRenderedCommand("plesk bin subscription --create example.test")).toThrow("mutation detected");
    expect(() => assertReadOnlyRenderedCommand("plesk bin subscription --suspend example.test")).toThrow("mutation detected");
    expect(() => assertReadOnlyRenderedCommand("wp plugin activate hello")).toThrow("mutation detected");
    expect(() => assertReadOnlyRenderedCommand("plesk bin subscription --webspace-on example.test")).toThrow("mutation detected");
    expect(() => assertReadOnlyRenderedCommand("plesk bin subscription --lock-subscription example.test")).toThrow("mutation detected");
    expect(() => assertReadOnlyRenderedCommand("wp plugin toggle hello")).toThrow("mutation detected");
    expect(() => assertReadOnlyRenderedCommand("wp theme auto-updates enable")).toThrow("mutation detected");
    expect(() => assertReadOnlyRenderedCommand("wp option set home https://evil.example")).toThrow("mutation detected");
    expect(() => assertReadOnlyRenderedCommand("wp config set DB_HOST evil.example")).toThrow("mutation detected");
    expect(() => assertReadOnlyRenderedCommand("plesk bin subscription --list --update example.test")).toThrow("mutation detected");
    expect(() => assertReadOnlyRenderedCommand("wp core version --exec=\"unlink('/tmp/x')\"")).toThrow("mutation detected");
    expect(() => assertReadOnlyRenderedCommand("php -r \"unlink('/tmp/x')\"")).toThrow("mutation detected");
    expect(() => assertReadOnlyRenderedCommand("plesk bin subscription --list; python3 -c \"import os; os.unlink('/tmp/x')\"")).toThrow("mutation detected");
    expect(() => assertReadOnlyRenderedCommand("wp core version; node -e \"require('fs').unlinkSync('/tmp/x')\"")).toThrow("mutation detected");
    expect(() => assertReadOnlyRenderedCommand("python3 -c \"import os; os.unlink('/tmp/x')\"")).toThrow("mutation detected");
    expect(() => assertReadOnlyRenderedCommand("printf ok > /tmp/mise-test")).toThrow("mutation detected");
    expect(() => assertReadOnlyRenderedCommand("printf ok >> /tmp/mise-test")).toThrow("mutation detected");
    expect(() => assertReadOnlyRenderedCommand("awk 'BEGIN { print \"x\" > \"/tmp/mise-test\" }'")).toThrow("mutation detected");
    expect(() => assertReadOnlyRenderedCommand("cat < /tmp/mise-test")).toThrow("mutation detected");
    expect(() => assertReadOnlyRenderedCommand(":")).not.toThrow();
  });

  it("allows the complete generated read-only audit batch", () => {
    expect(() => assertReadOnlyRenderedCommand(buildWpAuditBatchCommand(
      { path: "/var/www/vhosts/example.test/httpdocs" },
      { useSudo: true },
    ))).not.toThrow();
  });

  it("blocks a forged command before opening an SSH process", async () => {
    await expect(runSshCommand(host, {
      kind: "wp-audit-batch",
      installationPath: "/srv/site;rm -rf /",
    })).rejects.toThrow("mutation detected");
  });
});
