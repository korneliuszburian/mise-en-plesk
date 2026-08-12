#!/usr/bin/env bash
set -euo pipefail

if ! command -v bw >/dev/null 2>&1; then
  echo "Bitwarden CLI (bw) is required." >&2
  return 1 2>/dev/null || exit 1
fi

export BW_SESSION="$(bw unlock --raw)"
echo "BW_SESSION exported for this shell. Keep it short-lived and do not commit it."
