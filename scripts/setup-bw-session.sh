#!/usr/bin/env bash
set -euo pipefail

if ! command -v bw >/dev/null 2>&1; then
  echo "Bitwarden CLI (bw) is required." >&2
  return 1 2>/dev/null || exit 1
fi

bw_status="$(bw status 2>/dev/null)" || {
  echo "Could not read Bitwarden CLI status." >&2
  return 1 2>/dev/null || exit 1
}

if [[ "$bw_status" == *'"status":"unauthenticated"'* ]]; then
  echo 'You are not logged in to Bitwarden. Run `bw login` first.' >&2
  return 1 2>/dev/null || exit 1
fi

session="$(bw unlock --raw)" || {
  echo "Bitwarden unlock failed." >&2
  return 1 2>/dev/null || exit 1
}

if [[ -z "$session" ]]; then
  echo "Bitwarden returned an empty session." >&2
  return 1 2>/dev/null || exit 1
fi

export BW_SESSION="$session"
echo "BW_SESSION exported for this shell. Keep it short-lived and do not commit it."
