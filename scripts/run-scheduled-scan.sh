#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
target="${MISE_PLESK_SCHEDULED_TARGET:-all}"
log_dir="${MISE_PLESK_SCHEDULE_LOG_DIR:-$repo_root/.mise-en-plesk/logs}"
lock_file="${MISE_PLESK_SCHEDULE_LOCK_FILE:-$repo_root/.mise-en-plesk/scan.lock}"
runner_bin="${MISE_PLESK_RUNNER_BIN:-pnpm}"
chunk_size="${MISE_PLESK_SCAN_CHUNK_SIZE:-20}"
runner_args=("$runner_bin")
if [[ "$runner_bin" == "pnpm" ]]; then
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
"${runner_args[@]}" mise-plesk-audit scan "$target" --json --max-sites="$chunk_size" --all-chunks
echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] scan finished successfully"
