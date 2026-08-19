import { mkdtemp, readdir, readFile, writeFile } from "node:fs/promises";
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
  [[ "\${1:-}" == "read" || "\${1:-}" == "advance" ]]
  [[ "\${1:-}" == "read" ]] && printf '0'
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
