#!/usr/bin/env bash
set -euo pipefail

unit_directory="${MISE_PLESK_SYSTEMD_UNIT_DIR:-/etc/systemd/system}"
service_unit="$unit_directory/mise-en-plesk.service"
timer_unit="$unit_directory/mise-en-plesk.timer"
state_directory="/var/lib/mise-en-plesk"
optional_environment_file="/etc/mise-en-plesk/mise-en-plesk.env"
runtime_directive="LoadCredential=BW_SESSION:/run/mise-en-plesk/BW_SESSION"
encrypted_directive="LoadCredentialEncrypted=BW_SESSION:/etc/mise-en-plesk/bw-session.cred"

fail() {
  echo "systemd installation check failed: $*" >&2
  exit 1
}

command -v systemctl >/dev/null 2>&1 || fail "systemctl is not available"
command -v systemd-analyze >/dev/null 2>&1 || fail "systemd-analyze is not available"

[[ -r "$service_unit" && ! -L "$service_unit" ]] || fail "service unit is not readable or is a symlink: $service_unit"
[[ -r "$timer_unit" && ! -L "$timer_unit" ]] || fail "timer unit is not readable or is a symlink: $timer_unit"
[[ -d "$state_directory" ]] || fail "runtime state directory is missing: $state_directory"
if grep -Fqx "$runtime_directive" "$service_unit"; then
  credential_kind="ephemeral runtime"
  credential_path="/run/mise-en-plesk/BW_SESSION"
elif grep -Fqx "$encrypted_directive" "$service_unit"; then
  credential_kind="encrypted"
  credential_path="/etc/mise-en-plesk/bw-session.cred"
else
  fail "service does not use a supported BW_SESSION credential directive"
fi
[[ -r "$credential_path" && ! -L "$credential_path" ]] \
  || fail "$credential_kind Bitwarden credential is not readable or is a symlink: $credential_path"
if [[ -e "$optional_environment_file" ]]; then
  [[ -f "$optional_environment_file" ]] || fail "optional environment file is not a regular file: $optional_environment_file"
  environment_mode="$(stat -c '%a' "$optional_environment_file" 2>/dev/null || true)"
  environment_owner="$(stat -c '%U' "$optional_environment_file" 2>/dev/null || true)"
  [[ "$environment_mode" == "644" && "$environment_owner" == "root" ]] \
    || fail "optional environment file must be root-owned mode 0644 (found ${environment_owner:-unknown} ${environment_mode:-unknown})"
  awk '
    /^[[:space:]]*($|#)/ { next }
    /^[A-Za-z_][A-Za-z0-9_]*=/ {
      name = $0; sub(/=.*/, "", name)
      if (name != "MISE_PLESK_HERMES_WHATSAPP_TARGET" && name != "MISE_PLESK_HERMES_BIN") exit 1
      next
    }
    { exit 1 }
  ' "$optional_environment_file" \
    || fail "optional environment file may contain only MISE_PLESK_HERMES_* routing keys"
fi

systemd-analyze verify "$service_unit" "$timer_unit"
systemctl is-enabled --quiet mise-en-plesk.timer || fail "mise-en-plesk.timer is not enabled"
systemctl is-active --quiet mise-en-plesk.timer || fail "mise-en-plesk.timer is not active"

service_user="$(systemctl show mise-en-plesk.service --property=User --value)"
[[ "$service_user" == "mise-en-plesk" ]] || fail "service runs as ${service_user:-root}; expected mise-en-plesk"

grep -Fqx "NoNewPrivileges=yes" "$service_unit" \
  || fail "service is missing NoNewPrivileges=yes"
grep -Fqx "ProtectSystem=strict" "$service_unit" \
  || fail "service is missing ProtectSystem=strict"
grep -Fqx "ReadWritePaths=$state_directory" "$service_unit" \
  || fail "service does not restrict writes to $state_directory"
grep -Fqx "Environment=HOME=$state_directory" "$service_unit" \
  || fail "service does not pin HOME to the service account state directory"

state_owner="$(stat -c '%U' "$state_directory" 2>/dev/null || true)"
[[ "$state_owner" == "mise-en-plesk" ]] \
  || fail "runtime state directory must be owned by mise-en-plesk (found ${state_owner:-unknown})"

credential_mode="$(stat -c '%a' "$credential_path" 2>/dev/null || true)"
credential_owner="$(stat -c '%U' "$credential_path" 2>/dev/null || true)"
[[ "$credential_mode" == "600" && "$credential_owner" == "root" ]] \
  || fail "credential must be root-owned mode 0600 (found ${credential_owner:-unknown} ${credential_mode:-unknown})"

echo "mise-en-plesk systemd installation is enabled, active, non-root, protected, and uses a $credential_kind credential."
