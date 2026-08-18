#!/usr/bin/env bash
set -euo pipefail

readonly credential_path="/etc/mise-en-plesk/bw-session.cred"
if [[ -z "${BW_SESSION:-}" ]]; then
  echo "BW_SESSION is missing; source the short-lived Bitwarden session first." >&2
  exit 78
fi
if ! command -v systemd-creds >/dev/null 2>&1; then
  echo "systemd-creds is required to rotate the encrypted scheduler credential." >&2
  exit 78
fi

credential_directory="$(dirname "$credential_path")"
sudo install -d -m 0700 "$credential_directory"
printf '%s' "$BW_SESSION" | sudo systemd-creds encrypt --name=BW_SESSION - "$credential_path"
sudo chown root:root "$credential_path"
sudo chmod 0600 "$credential_path"
echo "Updated encrypted systemd BW_SESSION credential at $credential_path."
