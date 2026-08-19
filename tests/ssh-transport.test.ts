import { describe, expect, it } from "vitest";
import { spawnSync } from "node:child_process";
import { assertReadOnlyRenderedCommand, renderReadOnlyCommand, type ReadOnlyCommand } from "../src/ssh-transport";

describe("read-only SSH command transport", () => {
  it("renders the fixed Plesk discovery probes", () => {
    expect(renderReadOnlyCommand({ kind: "ssh-handshake" })).toBe(":");
    expect(renderReadOnlyCommand({ kind: "remote-capabilities" })).toContain("id -u");
    expect(renderReadOnlyCommand({ kind: "plesk-subscriptions", useSudo: true })).toBe("sudo -S -p '' -- plesk bin subscription --list");
    expect(renderReadOnlyCommand({ kind: "plesk-version", useSudo: false })).toBe("plesk version");
    expect(renderReadOnlyCommand({ kind: "php-version", useSudo: false })).toBe("php -v");
    expect(renderReadOnlyCommand({ kind: "disk-usage", useSudo: false })).toBe("df -P -k /var/www/vhosts");
    expect(renderReadOnlyCommand({ kind: "plesk-wp-toolkit-inventory", useSudo: true }))
      .toBe("sudo -S -p '' -- plesk ext wp-toolkit --list -plugins -themes -format json");
    expect(() => assertReadOnlyRenderedCommand(renderReadOnlyCommand({ kind: "plesk-wp-toolkit-inventory", useSudo: true }))).not.toThrow();
  });

  it("renders a fixed WP-CLI capability probe that always returns structured status", () => {
    const rendered = renderReadOnlyCommand({ kind: "wp-cli-capability", useSudo: true });

    expect(rendered).toContain("sudo -S -p '' -- wp cli version --allow-root");
    expect(rendered).toContain("__MISE_WP_CLI_STATUS_${status}__");
    expect(rendered.endsWith("; :")).toBe(true);
    expect(() => assertReadOnlyRenderedCommand(rendered)).not.toThrow();
  });

  it("renders bounded WordPress discovery as one fixed read-only probe", () => {
    const command: ReadOnlyCommand = {
      kind: "wordpress-candidates",
      useSudo: true,
      includeAlternateDetection: true,
      offset: 2,
      limit: 3,
    };
    const rendered = renderReadOnlyCommand(command);
    expect(rendered).toContain("sudo -S -p '' -- find /var/www/vhosts");
    expect(rendered).toContain("position > 2 && position <= 6");
    expect(rendered).toContain('sub(/\\/web\\/wp$/, "/web", candidate)');
    expect(rendered).toContain("if (position >= 6) exit");
  });

  it("deduplicates canonical Bedrock signals before applying the remote page boundary", () => {
    if (process.platform === "win32") return;
    const rendered = renderReadOnlyCommand({ kind: "wordpress-candidates", includeAlternateDetection: true, offset: 0, limit: 1 });
    const awkStart = rendered.indexOf("awk '");
    const program = rendered.slice(awkStart + 5, -1);
    const result = spawnSync("awk", [program], {
      encoding: "utf8",
      input: [
        "/var/www/vhosts/example.test/httpdocs/web/wp-config.php",
        "/var/www/vhosts/example.test/httpdocs/web/wp/wp-includes/version.php",
        "/var/www/vhosts/other.test/httpdocs/wp-config.php",
      ].join("\n"),
    });

    expect(result.status).toBe(0);
    expect(result.stdout.trim().split("\n")).toEqual([
      "/var/www/vhosts/example.test/httpdocs/web/wp-config.php",
      "/var/www/vhosts/other.test/httpdocs/wp-config.php",
    ]);
  });

  it("accepts canonical Plesk paths and rejects shell metacharacters or control characters", () => {
    expect(renderReadOnlyCommand({ kind: "wp-audit-batch", installationPath: "/var/www/vhosts/example.test/httpdocs", useSudo: false })).toContain("--path='/var/www/vhosts/example.test/httpdocs'");
    expect(() => renderReadOnlyCommand({ kind: "wp-audit-batch", installationPath: "/var/www/vhosts/example.test/httpdocs;id", useSudo: false })).toThrow("canonical absolute Plesk vhost path");
    expect(() => renderReadOnlyCommand({ kind: "wp-audit-batch", installationPath: "/var/www/vhosts/example.test/httpdocs\nrm -rf /", useSudo: false })).toThrow("canonical absolute Plesk vhost path");
    expect(() => renderReadOnlyCommand({ kind: "static-wp-audit-batch", installationPath: "/var/www/vhosts/example.test/httpdocs/../private", useSudo: false })).toThrow("canonical absolute Plesk vhost path");
  });

  it("renders WP audit commands through the official WP Toolkit bridge", () => {
    const rendered = renderReadOnlyCommand({
      kind: "wp-audit-batch",
      installationPath: "/var/www/vhosts/example.test/httpdocs",
      useSudo: true,
      runtime: { kind: "plesk-wp-toolkit", instanceId: 42 },
    });

    expect(rendered.startsWith("sudo -S -p '' -v; ")).toBe(true);
    expect(rendered.match(/sudo -S/g)).toHaveLength(1);
    expect(rendered).toContain("sudo -n -- plesk ext wp-toolkit --wp-cli -instance-id 42 -- core version");
    expect(rendered).not.toContain("value=$(sudo");
    expect(rendered).not.toContain("wp core version --path=");
    expect(() => assertReadOnlyRenderedCommand(rendered)).not.toThrow();
    expect(() => renderReadOnlyCommand({
      kind: "wp-audit-batch",
      installationPath: "/var/www/vhosts/example.test/httpdocs",
      runtime: { kind: "plesk-wp-toolkit", instanceId: 0 },
    })).toThrow("positive safe integer");
  });
});
