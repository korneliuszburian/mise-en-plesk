#!/usr/bin/env bash
set -euo pipefail

unit_directory="${MISE_PLESK_SYSTEMD_UNIT_DIR:-/etc/systemd/system}"
service_unit="$unit_directory/mise-en-plesk.service"
timer_unit="$unit_directory/mise-en-plesk.timer"
credential_path="/etc/mise-en-plesk/bw-session.cred"

fail() {
  echo "systemd installation check failed: $*" >&2
  exit 1
}

command -v systemctl >/dev/null 2>&1 || fail "systemctl is not available"
command -v systemd-analyze >/dev/null 2>&1 || fail "systemd-analyze is not available"

[[ -r "$service_unit" ]] || fail "service unit is not readable: $service_unit"
[[ -r "$timer_unit" ]] || fail "timer unit is not readable: $timer_unit"
[[ -r "$credential_path" ]] || fail "encrypted Bitwarden credential is not readable: $credential_path"

systemd-analyze verify "$service_unit" "$timer_unit"
systemctl is-enabled --quiet mise-en-plesk.timer || fail "mise-en-plesk.timer is not enabled"
systemctl is-active --quiet mise-en-plesk.timer || fail "mise-en-plesk.timer is not active"

service_user="$(systemctl show mise-en-plesk.service --property=User --value)"
[[ "$service_user" == "mise-en-plesk" ]] || fail "service runs as ${service_user:-root}; expected mise-en-plesk"

grep -Fqx "LoadCredentialEncrypted=BW_SESSION:$credential_path" "$service_unit" \
  || fail "service does not use the expected encrypted BW_SESSION credential"
grep -Fqx "NoNewPrivileges=yes" "$service_unit" \
  || fail "service is missing NoNewPrivileges=yes"
grep -Fqx "ProtectSystem=strict" "$service_unit" \
  || fail "service is missing ProtectSystem=strict"

credential_mode="$(stat -c '%a' "$credential_path" 2>/dev/null || true)"
credential_owner="$(stat -c '%U' "$credential_path" 2>/dev/null || true)"
[[ "$credential_mode" == "600" && "$credential_owner" == "root" ]] \
  || fail "credential must be root-owned mode 0600 (found ${credential_owner:-unknown} ${credential_mode:-unknown})"

echo "mise-en-plesk systemd installation is enabled, active, non-root, and protected."
