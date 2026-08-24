import { mkdtemp, readdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFile, execFileSync } from "node:child_process";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";

const execFileAsync = promisify(execFile);
const repoRoot = process.cwd();

describe("run-scheduled-scan", () => {
  it("defers an incomplete zero-progress page without failing or moving its cursor", async () => {
    const root = await mkdtemp(join(tmpdir(), "mise-en-plesk-scheduler-deferred-"));
    const reportDirectory = join(root, "reports");
    const configPath = join(root, "config.json");
    const cursorPath = join(root, "scan-cursor.json");
    const logDirectory = join(root, "logs");
    const fakePnpm = join(root, "pnpm");
    const realPnpm = execFileSync("which", ["pnpm"], { encoding: "utf8" }).trim();
    await writeFile(configPath, JSON.stringify({ hosts: ["master-ssh"], reportsDirectory: reportDirectory }));
    await writeFile(cursorPath, JSON.stringify({
      version: 1,
      hosts: { "master-ssh": { offset: 320, updatedAt: "2026-08-24T14:15:17.000Z" } },
    }));
    await writeFile(fakePnpm, `#!/usr/bin/env bash
set -euo pipefail
if [[ "\${1:-}" == "exec" && "\${2:-}" == "tsx" ]]; then
  exec ${realPnpm} "$@"
fi
if [[ "\${1:-}" == "--silent" && "\${2:-}" == "run" && "\${3:-}" == "mise-plesk-audit" && "\${4:-}" == "scan" ]]; then
  target="\${5:?target missing}"
  stamp="\$(date -u +%Y%m%d)\${MISE_PLESK_REPORT_SUFFIX:?suffix missing}"
  mkdir -p "${reportDirectory}"
  printf '{"scanProgress":[{"host":"%s","offset":320,"scanned":0,"complete":false}]}\n' "$target" > "${reportDirectory}/plesk-wp-audit-$stamp.json"
fi
`, { mode: 0o700 });

    const { stdout } = await execFileAsync("bash", [join(repoRoot, "scripts/run-scheduled-scan.sh")], {
      cwd: repoRoot,
      env: {
        ...process.env,
        MISE_PLESK_CONFIG: configPath,
        MISE_PLESK_RUNNER_BIN: fakePnpm,
        MISE_PLESK_SCAN_CURSOR: cursorPath,
        MISE_PLESK_REPORTS: reportDirectory,
        MISE_PLESK_SCHEDULE_LOG_DIR: logDirectory,
        MISE_PLESK_SCHEDULE_LOCK_FILE: join(root, "scan.lock"),
        MISE_PLESK_SCHEDULED_TARGET: "master-ssh",
      },
    });

    const cursor = JSON.parse(await readFile(cursorPath, "utf8")) as { hosts: Record<string, { offset: number }> };
    expect(cursor.hosts["master-ssh"]?.offset).toBe(320);
    expect(stdout).toContain("deferred");
    expect(stdout).toContain("cursors were preserved for retry");
    expect(stdout).not.toContain("scan finished successfully");
  });

  it("fails closed on malformed report progress without moving its cursor", async () => {
    const root = await mkdtemp(join(tmpdir(), "mise-en-plesk-scheduler-malformed-"));
    const reportDirectory = join(root, "reports");
    const configPath = join(root, "config.json");
    const cursorPath = join(root, "scan-cursor.json");
    const fakePnpm = join(root, "pnpm");
    const realPnpm = execFileSync("which", ["pnpm"], { encoding: "utf8" }).trim();
    const originalCursor = {
      version: 1,
      hosts: { "master-ssh": { offset: 320, updatedAt: "2026-08-24T14:15:17.000Z" } },
    };
    await writeFile(configPath, JSON.stringify({ hosts: ["master-ssh"], reportsDirectory: reportDirectory }));
    await writeFile(cursorPath, JSON.stringify(originalCursor));
    await writeFile(fakePnpm, `#!/usr/bin/env bash
set -euo pipefail
if [[ "\${1:-}" == "exec" && "\${2:-}" == "tsx" ]]; then exec ${realPnpm} "$@"; fi
if [[ "\${4:-}" == "scan" ]]; then
  target="\${5:?target missing}"
  stamp="\$(date -u +%Y%m%d)\${MISE_PLESK_REPORT_SUFFIX:?suffix missing}"
  mkdir -p "${reportDirectory}"
  printf '{"scanProgress":[{"host":"%s","offset":"320","scanned":0,"complete":false}]}\n' "$target" > "${reportDirectory}/plesk-wp-audit-$stamp.json"
fi
`, { mode: 0o700 });

    const execution = execFileAsync("bash", [join(repoRoot, "scripts/run-scheduled-scan.sh")], {
      cwd: repoRoot,
      env: {
        ...process.env,
        MISE_PLESK_CONFIG: configPath,
        MISE_PLESK_RUNNER_BIN: fakePnpm,
        MISE_PLESK_SCAN_CURSOR: cursorPath,
        MISE_PLESK_REPORTS: reportDirectory,
        MISE_PLESK_SCHEDULE_LOG_DIR: join(root, "logs"),
        MISE_PLESK_SCHEDULE_LOCK_FILE: join(root, "scan.lock"),
        MISE_PLESK_SCHEDULED_TARGET: "master-ssh",
      },
    });
    const failure = await execution.then(() => undefined, error => error as { code?: number; stdout?: string });
    expect(failure?.code).toBe(1);
    expect(failure?.stdout ?? "").not.toContain("scan finished successfully");
    expect(failure?.stdout ?? "").not.toContain("cursors were preserved for retry");
    expect(JSON.parse(await readFile(cursorPath, "utf8"))).toEqual(originalCursor);
  });

  it("does not claim full success when all-chunks exhausts its bounded cycle", async () => {
    const root = await mkdtemp(join(tmpdir(), "mise-en-plesk-scheduler-all-chunks-"));
    const configPath = join(root, "config.json");
    const heartbeatPath = join(root, "heartbeat.json");
    const fakePnpm = join(root, "pnpm");
    await writeFile(configPath, JSON.stringify({ hosts: ["master-ssh"], reportsDirectory: join(root, "reports") }));
    await writeFile(fakePnpm, `#!/usr/bin/env bash
set -euo pipefail
if [[ "\${4:-}" == "scan" ]]; then
  printf '{"version":1,"target":"all","startedAt":"2026-08-24T14:30:00.000Z","completedAt":"2026-08-24T14:31:00.000Z","scanComplete":false}\n' > "$MISE_PLESK_HEARTBEAT"
fi
`, { mode: 0o700 });

    const { stdout } = await execFileAsync("bash", [join(repoRoot, "scripts/run-scheduled-scan.sh")], {
      cwd: repoRoot,
      env: {
        ...process.env,
        MISE_PLESK_CONFIG: configPath,
        MISE_PLESK_HEARTBEAT: heartbeatPath,
        MISE_PLESK_RUNNER_BIN: fakePnpm,
        MISE_PLESK_SCHEDULE_ALL_CHUNKS: "1",
        MISE_PLESK_SCHEDULE_LOG_DIR: join(root, "logs"),
        MISE_PLESK_SCHEDULE_LOCK_FILE: join(root, "scan.lock"),
        MISE_PLESK_SCHEDULED_TARGET: "all",
      },
    });
    expect(stdout).toContain("incomplete bounded cycle");
    expect(stdout).not.toContain("scan finished successfully");
  });

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
if [[ "\${1:-}" == "--silent" && "\${2:-}" == "run" && "\${3:-}" == "mise-plesk-audit" && "\${4:-}" == "scan" ]]; then
  target="\${5:?target missing}"
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

  it("runs the compiled CLI and cursor with unshifted arguments in Node mode", async () => {
    const root = await mkdtemp(join(tmpdir(), "mise-en-plesk-node-scheduler-"));
    const reportDirectory = join(root, "reports");
    const configPath = join(root, "config.json");
    const fakeNode = join(root, "node");
    const realNode = process.execPath;
    const logDirectory = join(root, "logs");
    await writeFile(configPath, JSON.stringify({ hosts: ["dev-ssh"], reportsDirectory: reportDirectory }));
    await writeFile(fakeNode, `#!/usr/bin/env bash
set -euo pipefail
entry="\${1:?entry missing}"
shift
if [[ "$entry" == "-e" ]]; then
  exec "${realNode}" "$entry" "$@"
fi
if [[ "$entry" == */dist/bin/mise-plesk-audit.js ]]; then
  command="\${1:?command missing}"
  shift
  if [[ "$command" == "scan" ]]; then
    target="\${1:?target missing}"
    stamp="$(date -u +%Y%m%d)\${MISE_PLESK_REPORT_SUFFIX:?suffix missing}"
    mkdir -p "${reportDirectory}"
    printf '{"scanProgress":[{"host":"%s","offset":0,"scanned":1,"complete":true}]}\n' "$target" > "${reportDirectory}/plesk-wp-audit-$stamp.json"
  fi
  exit 0
fi
if [[ "$entry" == */dist/scripts/scan-cursor.js ]]; then
  [[ "\${1:-}" == "read" || "\${1:-}" == "reconcile" ]]
  if [[ "\${1:-}" == "read" ]]; then
    printf '0'
  else
    printf '{"outcome":"completed","previousOffset":0,"nextOffset":0,"cursor":{"version":1,"hosts":{}}}'
  fi
  exit 0
fi
exit 64
`, { mode: 0o700 });

    await execFileAsync("bash", [join(repoRoot, "scripts/run-scheduled-scan.sh")], {
      cwd: repoRoot,
      env: {
        ...process.env,
        MISE_PLESK_CONFIG: configPath,
        MISE_PLESK_RUNNER_BIN: fakeNode,
        MISE_PLESK_SCAN_CURSOR: join(root, "cursor.json"),
        MISE_PLESK_REPORTS: reportDirectory,
        MISE_PLESK_SCHEDULE_LOG_DIR: logDirectory,
        MISE_PLESK_SCHEDULE_LOCK_FILE: join(root, "scan.lock"),
        MISE_PLESK_SCHEDULED_TARGET: "dev-ssh",
      },
    });

    expect((await readdir(reportDirectory)).some((name) => name.endsWith(".json"))).toBe(true);
  });
});
