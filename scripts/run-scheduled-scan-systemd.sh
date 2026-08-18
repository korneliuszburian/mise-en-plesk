#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -z "${CREDENTIALS_DIRECTORY:-}" ]]; then
  echo "CREDENTIALS_DIRECTORY is missing; run this wrapper from systemd LoadCredential." >&2
  exit 78
fi

session_file="$CREDENTIALS_DIRECTORY/BW_SESSION"
if [[ ! -s "$session_file" ]]; then
  echo "The systemd BW_SESSION credential is missing or empty; refresh it before starting the timer." >&2
  exit 78
fi

export BW_SESSION="$(<"$session_file")"
exec "$repo_root/scripts/run-scheduled-scan.sh"
