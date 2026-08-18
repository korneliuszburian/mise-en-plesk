import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";

describe("systemd deployment contract", () => {
  it("keeps the checkout read-only and stores runtime state in /var/lib", async () => {
    const unit = await readFile("deploy/systemd/mise-en-plesk.service.example", "utf8");

    expect(unit).toContain("ProtectSystem=strict");
    expect(unit).toContain("ReadWritePaths=/var/lib/mise-en-plesk");
    expect(unit).toContain("Environment=MISE_PLESK_INVENTORY=/var/lib/mise-en-plesk/inventory.json");
    expect(unit).toContain("Environment=MISE_PLESK_CONFIG=/var/lib/mise-en-plesk/config.mise-en-plesk.json");
    expect(unit).toContain("Environment=MISE_PLESK_REPORTS=/var/lib/mise-en-plesk/reports");
    expect(unit).toContain("Environment=MISE_PLESK_SCAN_CURSOR=/var/lib/mise-en-plesk/scan-cursor.json");
    expect(unit).toContain("Environment=MISE_PLESK_FINDINGS=/var/lib/mise-en-plesk/findings.json");
    expect(unit).toContain("Environment=MISE_PLESK_NOTIFICATION_OUTBOX=/var/lib/mise-en-plesk/notification-outbox.json");
    expect(unit).toContain("Environment=MISE_PLESK_NOTIFICATION_HISTORY=/var/lib/mise-en-plesk/notification-history.json");
    expect(unit).toContain("Environment=HOME=/var/lib/mise-en-plesk");
    expect(unit).toContain("EnvironmentFile=-/etc/mise-en-plesk/mise-en-plesk.env");
    expect(unit).not.toContain("ReadWritePaths=/opt/mise-en-plesk");
  });
});
