#!/usr/bin/env bash
set -euo pipefail

readonly service_unit="/etc/systemd/system/mise-en-plesk.service"
readonly runtime_directive="LoadCredential=BW_SESSION:/run/mise-en-plesk/BW_SESSION"
readonly encrypted_directive="LoadCredentialEncrypted=BW_SESSION:/etc/mise-en-plesk/bw-session.cred"
readonly confirmation_value="update-bw-session"
apply=0
confirmation=""

fail() {
  echo "BW_SESSION credential update failed: $*" >&2
  exit 78
}

for argument in "$@"; do
  case "$argument" in
    --apply) apply=1 ;;
    --confirm=*) confirmation="${argument#--confirm=}" ;;
    --help)
      echo "Usage: scripts/update-systemd-bw-credential.sh [--apply --confirm=$confirmation_value]"
      exit 0
      ;;
    *) fail "unknown option: $argument" ;;
  esac
done

if [[ -L "$service_unit" ]]; then
  fail "installed service unit must not be a symlink"
elif [[ -r "$service_unit" ]] && grep -Fqx "$runtime_directive" "$service_unit"; then
  credential_mode="runtime"
  credential_path="/run/mise-en-plesk/BW_SESSION"
elif [[ -r "$service_unit" ]] && grep -Fqx "$encrypted_directive" "$service_unit"; then
  credential_mode="encrypted"
  credential_path="/etc/mise-en-plesk/bw-session.cred"
elif [[ -r "$service_unit" ]]; then
  fail "service unit has an unsupported BW_SESSION credential directive"
elif command -v systemd-creds >/dev/null 2>&1; then
  credential_mode="encrypted"
  credential_path="/etc/mise-en-plesk/bw-session.cred"
else
  credential_mode="runtime"
  credential_path="/run/mise-en-plesk/BW_SESSION"
fi
readonly credential_mode credential_path

if (( apply == 0 )); then
  echo "DRY RUN: would update the $credential_mode BW_SESSION credential at $credential_path."
  echo "Apply with: sudo $0 --apply --confirm=$confirmation_value"
  exit 0
fi

[[ "$confirmation" == "$confirmation_value" ]] || fail "refusing mutation: use --confirm=$confirmation_value"
[[ "$(id -u)" == "0" ]] || fail "--apply must run as root"
[[ -n "${BW_SESSION:-}" ]] || fail "BW_SESSION is missing; source the short-lived session first"

credential_directory="$(dirname "$credential_path")"
[[ ! -L "$credential_directory" ]] || fail "credential directory must not be a symlink"
[[ ! -L "$credential_path" ]] || fail "credential path must not be a symlink"
install -d -o root -g root -m 0700 "$credential_directory"
temporary_directory="$(mktemp -d "$credential_directory/.rotate.XXXXXX")"
temporary_credential="$temporary_directory/BW_SESSION"
trap 'unlink "$temporary_credential" 2>/dev/null || true; rmdir "$temporary_directory" 2>/dev/null || true' EXIT
if [[ "$credential_mode" == "runtime" ]]; then
  printf '%s' "$BW_SESSION" | install -o root -g root -m 0600 /dev/stdin "$temporary_credential"
  mv -fT "$temporary_credential" "$credential_path"
  echo "Updated ephemeral BW_SESSION credential; it will be cleared on reboot."
else
  command -v systemd-creds >/dev/null 2>&1 || fail "systemd-creds is unavailable"
  printf '%s' "$BW_SESSION" | systemd-creds encrypt --name=BW_SESSION - "$temporary_credential"
  chown root:root "$temporary_credential"
  chmod 0600 "$temporary_credential"
  mv -fT "$temporary_credential" "$credential_path"
  echo "Updated encrypted BW_SESSION credential."
fi
