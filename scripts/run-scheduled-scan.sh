#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
target="${MISE_PLESK_SCHEDULED_TARGET:-all}"
log_dir="${MISE_PLESK_SCHEDULE_LOG_DIR:-$repo_root/.mise-en-plesk/logs}"
lock_file="${MISE_PLESK_SCHEDULE_LOCK_FILE:-$repo_root/.mise-en-plesk/scan.lock}"
runner_bin="${MISE_PLESK_RUNNER_BIN:-pnpm}"

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
"$runner_bin" mise-plesk-audit scan "$target" --json
echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] scan finished successfully"
