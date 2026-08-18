import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFile, execFileSync } from "node:child_process";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";

const execFileAsync = promisify(execFile);
const repoRoot = process.cwd();

describe("run-scheduled-scan", () => {
  it("uses the configured reports directory when advancing the scan cursor", async () => {
    const root = await mkdtemp(join(tmpdir(), "mise-en-plesk-scheduler-"));
    const reportDirectory = join(root, "custom-reports");
    const configPath = join(root, "config.json");
    const cursorPath = join(root, "scan-cursor.json");
    const lockPath = join(root, "scan.lock");
    const logDirectory = join(root, "logs");
    const fakePnpm = join(root, "pnpm");
    const realPnpm = execFileSync("which", ["pnpm"], { encoding: "utf8" }).trim();

    await writeFile(configPath, JSON.stringify({ hosts: ["master-ssh"], reportsDirectory: reportDirectory, maxSitesPerHost: 1 }));
    await writeFile(fakePnpm, `#!/usr/bin/env bash
set -euo pipefail
if [[ "\${1:-}" == "exec" && "\${2:-}" == "tsx" ]]; then
  exec ${realPnpm} "$@"
fi
if [[ "\${1:-}" == "run" && "\${2:-}" == "mise-plesk-audit" && "\${3:-}" == "scan" ]]; then
  target="\${4:?target missing}"
  stamp="\$(date -u +%Y%m%d)\${MISE_PLESK_REPORT_SUFFIX:?suffix missing}"
  mkdir -p "${reportDirectory}"
  printf '{"scanProgress":[{"host":"%s","offset":0,"scanned":1,"complete":true}]}\\n' "$target" > "${reportDirectory}/plesk-wp-audit-$stamp.json"
  exit 0
fi
exit 0
`, { mode: 0o700 });

    try {
      await execFileAsync("bash", [join(repoRoot, "scripts/run-scheduled-scan.sh")], {
        cwd: repoRoot,
        env: {
          ...process.env,
          MISE_PLESK_CONFIG: configPath,
          MISE_PLESK_RUNNER_BIN: fakePnpm,
          MISE_PLESK_SCAN_CURSOR: cursorPath,
          MISE_PLESK_REPORTS: "",
          MISE_PLESK_SCHEDULE_LOG_DIR: logDirectory,
          MISE_PLESK_SCHEDULE_LOCK_FILE: lockPath,
          MISE_PLESK_SCHEDULED_TARGET: "master-ssh",
        },
      });
    } catch (error: unknown) {
      const failure = error as { stdout?: string; stderr?: string; message?: string };
      throw new Error(`${failure.message ?? "scheduler failed"}\nstdout: ${failure.stdout ?? ""}\nstderr: ${failure.stderr ?? ""}`);
    }

    const cursor = JSON.parse(await readFile(cursorPath, "utf8")) as { hosts: Record<string, { offset: number }> };
    expect(cursor.hosts["master-ssh"]?.offset).toBe(0);
  });
});
