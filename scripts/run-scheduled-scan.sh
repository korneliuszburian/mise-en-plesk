#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
target="${MISE_PLESK_SCHEDULED_TARGET:-all}"
log_dir="${MISE_PLESK_SCHEDULE_LOG_DIR:-$repo_root/.mise-en-plesk/logs}"
lock_file="${MISE_PLESK_SCHEDULE_LOCK_FILE:-$repo_root/.mise-en-plesk/scan.lock}"
cursor_file="${MISE_PLESK_SCAN_CURSOR:-$repo_root/.mise-en-plesk/scan-cursor.json}"
runner_bin="${MISE_PLESK_RUNNER_BIN:-pnpm}"
chunk_size="${MISE_PLESK_SCAN_CHUNK_SIZE:-20}"
runner_kind="$(basename "$runner_bin")"
node_bin="node"
if [[ "$runner_kind" == "node" ]]; then
  node_bin="$runner_bin"
fi
run_audit() {
  if [[ "$runner_kind" == "pnpm" ]]; then
    "$runner_bin" --silent run mise-plesk-audit "$@"
  elif [[ "$runner_kind" == "node" ]]; then
    "$runner_bin" "$repo_root/dist/bin/mise-plesk-audit.js" "$@"
  else
    "$runner_bin" mise-plesk-audit "$@"
  fi
}

umask 077
mkdir -p "$log_dir"
mkdir -p "$(dirname "$lock_file")"
exec 9>"$lock_file"
if ! flock -n 9; then
  echo "A mise-en-plesk scan is already running: $lock_file" >&2
  exit 75
fi

log_path="$log_dir/scan-$(date -u +%Y%m%dT%H%M%SZ).log"
exec > >(tee -a "$log_path") 2>&1
echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] starting read-only scan target=$target"
cd "$repo_root"
export MISE_PLESK_RUN_LOCK="$lock_file"
export MISE_PLESK_RUN_LOCK_HELD=1
run_audit monitor-health --json
run_audit doctor --json
if [[ "${MISE_PLESK_SCHEDULE_ALL_CHUNKS:-0}" == "1" ]]; then
  run_audit scan "$target" --json --max-sites="$chunk_size" --all-chunks >/dev/null
else
  config_path="${MISE_PLESK_CONFIG:-$repo_root/config.mise-en-plesk.json}"
  if [[ "$target" == "all" ]]; then
    mapfile -t scheduled_targets < <("$node_bin" -e 'const fs=require("node:fs"); const config=JSON.parse(fs.readFileSync(process.argv[1], "utf8")); for (const host of config.hosts ?? []) console.log(host)' "$config_path")
  else
    scheduled_targets=("$target")
  fi
  if [[ "${#scheduled_targets[@]}" -eq 0 ]]; then
    echo "No scheduled hosts configured in $config_path" >&2
    exit 1
  fi
  if [[ -n "${MISE_PLESK_REPORTS:-}" ]]; then
    report_dir="$MISE_PLESK_REPORTS"
  else
    report_dir="$("$node_bin" -e 'const fs=require("node:fs"); const config=JSON.parse(fs.readFileSync(process.argv[1], "utf8")); process.stdout.write(config.reportsDirectory ?? "reports")' "$config_path")"
  fi
  if [[ "$runner_kind" == "pnpm" ]]; then
    cursor_runner=("$runner_bin" exec tsx "$repo_root/scripts/scan-cursor.ts")
  elif [[ "$runner_kind" == "node" ]]; then
    cursor_runner=("$runner_bin" "$repo_root/dist/scripts/scan-cursor.js")
  else
    cursor_runner=("$runner_bin" tsx "$repo_root/scripts/scan-cursor.ts")
  fi
  for scheduled_target in "${scheduled_targets[@]}"; do
    offset="$("${cursor_runner[@]}" read "$cursor_file" "$scheduled_target")"
    run_stamp="$(date -u +%Y%m%dT%H%M%SZ)"
    suffix="-$scheduled_target-$run_stamp"
    report_path="$report_dir/plesk-wp-audit-$(date -u +%Y%m%d)${suffix}.json"
    MISE_PLESK_REPORT_SUFFIX="$suffix" run_audit scan "$scheduled_target" --json --max-sites="$chunk_size" --offset="$offset" >/dev/null
    "${cursor_runner[@]}" advance "$cursor_file" "$scheduled_target" "$report_path"
  done
fi
echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] scan finished successfully"
