#!/usr/bin/env node
import { readInventory, syncFromBitwarden } from "../src/ssh-inventory";
import { scanPleskHost } from "../src/plesk-scan";
import { auditWordPressInstallation, type AuditResult } from "../src/wp-audit";
import { writeAuditReport } from "../src/report";

const inventoryPath = process.env.MISE_PLESK_INVENTORY ?? "inventory.json";

function usage(): never {
  console.error("Usage: mise-plesk-audit sync-ssh | scan <target>");
  process.exit(1);
}

async function main(): Promise<void> {
  const [command, target] = process.argv.slice(2);
  if (command === "sync-ssh") {
    const inventory = await syncFromBitwarden("mise-en-plesk", inventoryPath);
    console.log(`Synced ${Object.keys(inventory).length} host(s) to ${inventoryPath}.`);
    return;
  }
  if (command === "scan" && target) {
    const inventory = await readInventory(inventoryPath);
    if (!inventory[target]) {
      console.error(`Unknown inventory target: ${target}`);
      usage();
    }
    const scan = await scanPleskHost(inventory[target]);
    const wordpress = await Promise.all(scan.wordpress.map((installation) => auditWordPressInstallation(installation)));
    const result: AuditResult = {
      generatedAt: new Date().toISOString(),
      hosts: [{ host: scan.host, wordpress }],
    };
    const reportPath = await writeAuditReport(result, process.env.MISE_PLESK_REPORTS ?? "reports");
    console.log(`Read-only scan complete. Report written to ${reportPath}.`);
    return;
  }
  usage();
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
});
