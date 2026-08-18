import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";

const execFileAsync = promisify(execFile);

describe("monitor-health CLI", () => {
  it("exposes an incomplete bounded scan without treating it as stale", async () => {
    const directory = await mkdtemp(join(tmpdir(), "mise-en-plesk-monitor-cli-"));
    const heartbeatPath = join(directory, "heartbeat.json");
    const findingsPath = join(directory, "findings.json");
    const lockPath = join(directory, "scan.lock");
    const completedAt = new Date(Date.now() - 5 * 60 * 1000).toISOString();
    const startedAt = new Date(Date.parse(completedAt) - 60 * 1000).toISOString();
    await writeFile(heartbeatPath, JSON.stringify({
      version: 1,
      target: "all",
      startedAt,
      completedAt,
      scanComplete: false,
    }));

    const result = await execFileAsync("pnpm", ["exec", "tsx", "bin/mise-plesk-audit.ts", "monitor-health", "--json"], {
      env: {
        ...process.env,
        MISE_PLESK_HEARTBEAT: heartbeatPath,
        MISE_PLESK_FINDINGS: findingsPath,
        MISE_PLESK_RUN_LOCK: lockPath,
      },
    });

    const output = JSON.parse(result.stdout) as { stale: boolean; heartbeat: { scanComplete?: boolean } };
    expect(output.stale).toBe(false);
    expect(output.heartbeat.scanComplete).toBe(false);
  });
});
