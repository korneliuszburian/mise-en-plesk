import { describe, expect, it } from "vitest";
import { renderReadOnlyCommand, type ReadOnlyCommand } from "../src/ssh-transport";

describe("read-only SSH command transport", () => {
  it("renders the fixed Plesk discovery probes", () => {
    expect(renderReadOnlyCommand({ kind: "ssh-handshake" })).toBe(":");
    expect(renderReadOnlyCommand({ kind: "remote-capabilities" })).toContain("id -u");
    expect(renderReadOnlyCommand({ kind: "plesk-subscriptions", useSudo: true })).toBe("sudo -S -p '' -- plesk bin subscription --list");
    expect(renderReadOnlyCommand({ kind: "plesk-version", useSudo: false })).toBe("plesk version");
    expect(renderReadOnlyCommand({ kind: "php-version", useSudo: false })).toBe("php -v");
    expect(renderReadOnlyCommand({ kind: "disk-usage", useSudo: false })).toBe("df -P -k /var/www/vhosts");
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
    expect(rendered).toContain("if (position >= 6) exit");
  });

  it("quotes an installation path without allowing control characters", () => {
    expect(renderReadOnlyCommand({ kind: "wp-audit-batch", installationPath: "/srv/site/it's", useSudo: false })).toContain("--path='/srv/site/it'\\''s'");
    expect(() => renderReadOnlyCommand({ kind: "wp-audit-batch", installationPath: "/srv/site\nrm -rf /", useSudo: false })).toThrow("unsafe installation path");
  });
});
