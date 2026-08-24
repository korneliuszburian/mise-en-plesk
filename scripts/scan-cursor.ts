#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { readScanCursor, reconcileScanCursor, writeScanCursor } from "../src/scan-cursor";
import type { ScanProgress } from "../src/wp-audit";

function usage(): never {
  console.error("Usage: scan-cursor read <path> <host> | advance|reconcile <path> <host> <reportPath>");
  process.exit(1);
}

(async (): Promise<void> => {
  const [command, path, host, reportPath] = process.argv.slice(2);
  if (!command || !path || !host) usage();

  const cursor = await readScanCursor(path);
  if (command === "read") {
    console.log(cursor.hosts[host]?.offset ?? 0);
  } else if ((command === "advance" || command === "reconcile") && reportPath) {
    const report = JSON.parse(await readFile(reportPath, "utf8")) as { scanProgress?: ScanProgress[] };
    const progress = report.scanProgress?.find((item) => item.host === host);
    if (!progress) throw new Error(`Report has no scan progress for ${host}: ${reportPath}`);
    const reconciliation = reconcileScanCursor(cursor, progress);
    if (command === "advance" && reconciliation.outcome === "deferred") {
      throw new Error(`scan progress made no progress for ${progress.host}`);
    }
    if (reconciliation.outcome !== "deferred") await writeScanCursor(path, reconciliation.cursor);
    if (command === "reconcile") console.log(JSON.stringify(reconciliation));
    else console.log(`${reconciliation.previousOffset} -> ${reconciliation.nextOffset} (${reconciliation.outcome})`);
  } else usage();
})().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
});
