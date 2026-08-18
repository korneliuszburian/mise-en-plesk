#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
target="${MISE_PLESK_SCHEDULED_TARGET:-all}"
log_dir="${MISE_PLESK_SCHEDULE_LOG_DIR:-$repo_root/.mise-en-plesk/logs}"
lock_file="${MISE_PLESK_SCHEDULE_LOCK_FILE:-$repo_root/.mise-en-plesk/scan.lock}"
cursor_file="${MISE_PLESK_SCAN_CURSOR:-$repo_root/.mise-en-plesk/scan-cursor.json}"
runner_bin="${MISE_PLESK_RUNNER_BIN:-pnpm}"
chunk_size="${MISE_PLESK_SCAN_CHUNK_SIZE:-20}"
runner_args=("$runner_bin")
if [[ "$(basename "$runner_bin")" == "pnpm" ]]; then
  runner_args+=(run)
fi

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
"${runner_args[@]}" mise-plesk-audit monitor-health --json
"${runner_args[@]}" mise-plesk-audit doctor --json
if [[ "${MISE_PLESK_SCHEDULE_ALL_CHUNKS:-0}" == "1" ]]; then
  "${runner_args[@]}" mise-plesk-audit scan "$target" --json --max-sites="$chunk_size" --all-chunks
else
  config_path="${MISE_PLESK_CONFIG:-$repo_root/config.mise-en-plesk.json}"
  if [[ "$target" == "all" ]]; then
    mapfile -t scheduled_targets < <(node -e 'const fs=require("node:fs"); const config=JSON.parse(fs.readFileSync(process.argv[1], "utf8")); for (const host of config.hosts ?? []) console.log(host)' "$config_path")
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
    report_dir="$(node -e 'const fs=require("node:fs"); const config=JSON.parse(fs.readFileSync(process.argv[1], "utf8")); process.stdout.write(config.reportsDirectory ?? "reports")' "$config_path")"
  fi
  cursor_runner=("$runner_bin")
  if [[ "$(basename "$runner_bin")" == "pnpm" ]]; then
    cursor_runner+=(exec tsx)
  else
    cursor_runner+=(tsx)
  fi
  cursor_runner+=("$repo_root/scripts/scan-cursor.ts")
  for scheduled_target in "${scheduled_targets[@]}"; do
    offset="$("${cursor_runner[@]}" read "$cursor_file" "$scheduled_target")"
    run_stamp="$(date -u +%Y%m%dT%H%M%SZ)"
    suffix="-$scheduled_target-$run_stamp"
    report_path="$report_dir/plesk-wp-audit-$(date -u +%Y%m%d)${suffix}.json"
    MISE_PLESK_REPORT_SUFFIX="$suffix" "${runner_args[@]}" mise-plesk-audit scan "$scheduled_target" --json --max-sites="$chunk_size" --offset="$offset"
    "${cursor_runner[@]}" advance "$cursor_file" "$scheduled_target" "$report_path"
  done
fi
echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] scan finished successfully"
