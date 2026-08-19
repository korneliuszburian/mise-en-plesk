#!/usr/bin/env bash
set -euo pipefail

unit_directory="${MISE_PLESK_SYSTEMD_UNIT_DIR:-/etc/systemd/system}"
service_unit="$unit_directory/mise-en-plesk.service"
timer_unit="$unit_directory/mise-en-plesk.timer"
state_directory="/var/lib/mise-en-plesk"
optional_environment_file="/etc/mise-en-plesk/mise-en-plesk.env"
runtime_directive="LoadCredential=BW_SESSION:/run/mise-en-plesk/BW_SESSION"
runtime_bw_data="/run/mise-en-plesk/bw-data/data.json"
known_hosts_path="$state_directory/.ssh/known_hosts"
scanner_lock="/run/mise-en-plesk/scan.lock"
whatsapp_dropin="/etc/systemd/system/mise-en-plesk.service.d/whatsapp.conf"
whatsapp_credential="/run/mise-en-plesk/WHATSAPP_ACCESS_TOKEN"
require_whatsapp=0
allow_inactive_timer=0

fail() {
  echo "systemd installation check failed: $*" >&2
  exit 1
}

for argument in "$@"; do
  case "$argument" in
    --require-whatsapp) require_whatsapp=1 ;;
    --allow-inactive-timer) allow_inactive_timer=1 ;;
    --help)
      echo "Usage: scripts/verify-systemd-install.sh [--require-whatsapp] [--allow-inactive-timer]"
      exit 0
      ;;
    *) fail "unknown option: $argument" ;;
  esac
done

command -v systemctl >/dev/null 2>&1 || fail "systemctl is not available"
command -v systemd-analyze >/dev/null 2>&1 || fail "systemd-analyze is not available"

[[ -r "$service_unit" && ! -L "$service_unit" ]] || fail "service unit is not readable or is a symlink: $service_unit"
[[ -r "$timer_unit" && ! -L "$timer_unit" ]] || fail "timer unit is not readable or is a symlink: $timer_unit"
[[ -d "$state_directory" ]] || fail "runtime state directory is missing: $state_directory"
grep -Fqx "$runtime_directive" "$service_unit" \
  || fail "service does not use the required ephemeral BW_SESSION credential"
credential_kind="ephemeral runtime"
credential_path="/run/mise-en-plesk/BW_SESSION"
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
if (( require_whatsapp == 1 )) && [[ ! -e "$whatsapp_dropin" ]]; then
  fail "production WhatsApp routing is required but not configured"
fi
if [[ -e "$whatsapp_dropin" ]]; then
  [[ -f "$whatsapp_dropin" && ! -L "$whatsapp_dropin" ]] \
    || fail "WhatsApp drop-in is not a regular file"
  [[ "$(stat -c '%U:%G %a' "$whatsapp_dropin" 2>/dev/null || true)" == "root:root 644" ]] \
    || fail "WhatsApp drop-in must be root-owned mode 0644"
  grep -Fqx "LoadCredential=WHATSAPP_ACCESS_TOKEN:/run/mise-en-plesk/WHATSAPP_ACCESS_TOKEN" "$whatsapp_dropin" \
    || fail "WhatsApp drop-in does not load the fixed runtime credential"
  [[ -f "$whatsapp_credential" && ! -L "$whatsapp_credential" ]] \
    || fail "WhatsApp runtime credential is missing or is a symlink"
  [[ "$(stat -c '%U:%G %a' "$whatsapp_credential" 2>/dev/null || true)" == "root:root 600" ]] \
    || fail "WhatsApp runtime credential must be root-owned mode 0600"
  whatsapp_routing_count="$(grep -Ec '^Environment=MISE_PLESK_WHATSAPP_(PHONE_NUMBER_ID|RECIPIENT|TEMPLATE_NAME|TEMPLATE_LANGUAGE|GRAPH_VERSION)=[A-Za-z0-9_.]+$' "$whatsapp_dropin" || true)"
  [[ "$whatsapp_routing_count" == "5" ]] \
    || fail "WhatsApp drop-in must contain exactly five validated non-secret routing values"
  if grep -Eq 'ACCESS_TOKEN|Bearer|token=' "$whatsapp_dropin"; then
    grep -Fqx "LoadCredential=WHATSAPP_ACCESS_TOKEN:/run/mise-en-plesk/WHATSAPP_ACCESS_TOKEN" "$whatsapp_dropin" \
      && [[ "$(grep -Ec 'ACCESS_TOKEN|Bearer|token=' "$whatsapp_dropin")" == "1" ]] \
      || fail "WhatsApp drop-in contains secret-like material"
  fi
fi

systemd-analyze verify "$service_unit" "$timer_unit"
systemctl is-enabled --quiet mise-en-plesk.timer || fail "mise-en-plesk.timer is not enabled"
if (( allow_inactive_timer == 0 )); then
  systemctl is-active --quiet mise-en-plesk.timer || fail "mise-en-plesk.timer is not active"
fi

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
grep -Fqx "Environment=BITWARDENCLI_APPDATA_DIR=/run/mise-en-plesk/bw-data" "$service_unit" \
  || fail "service does not use ephemeral Bitwarden CLI state"
grep -Fqx "ReadWritePaths=/run/mise-en-plesk/bw-data" "$service_unit" \
  || fail "service does not restrict Bitwarden CLI writes to its runtime directory"
grep -Fqx "Environment=MISE_PLESK_SCHEDULE_LOCK_FILE=$scanner_lock" "$service_unit" \
  || fail "service does not use the root-parented runtime scanner lock"
grep -Fqx "ReadWritePaths=$scanner_lock" "$service_unit" \
  || fail "service cannot write its root-parented runtime scanner lock"

state_owner="$(stat -c '%U' "$state_directory" 2>/dev/null || true)"
[[ "$state_owner" == "mise-en-plesk" ]] \
  || fail "runtime state directory must be owned by mise-en-plesk (found ${state_owner:-unknown})"

credential_mode="$(stat -c '%a' "$credential_path" 2>/dev/null || true)"
credential_owner="$(stat -c '%U' "$credential_path" 2>/dev/null || true)"
[[ "$credential_mode" == "600" && "$credential_owner" == "root" ]] \
  || fail "credential must be root-owned mode 0600 (found ${credential_owner:-unknown} ${credential_mode:-unknown})"
[[ -r "$runtime_bw_data" && ! -L "$runtime_bw_data" ]] \
  || fail "ephemeral Bitwarden CLI state is missing or is a symlink: $runtime_bw_data"
bw_data_mode="$(stat -c '%a' "$runtime_bw_data" 2>/dev/null || true)"
bw_data_owner="$(stat -c '%U:%G' "$runtime_bw_data" 2>/dev/null || true)"
[[ "$bw_data_mode" == "600" && "$bw_data_owner" == "mise-en-plesk:mise-en-plesk" ]] \
  || fail "Bitwarden CLI state must be owned by mise-en-plesk mode 0600"
runtime_root_mode="$(stat -c '%U:%G %a' /run/mise-en-plesk 2>/dev/null || true)"
bw_directory_mode="$(stat -c '%U:%G %a' /run/mise-en-plesk/bw-data 2>/dev/null || true)"
[[ "$runtime_root_mode" == "root:root 711" ]] || fail "Bitwarden runtime root must be root-owned mode 0711"
[[ "$bw_directory_mode" == "mise-en-plesk:mise-en-plesk 700" ]] \
  || fail "Bitwarden runtime data directory must be owned by mise-en-plesk mode 0700"
scanner_lock_mode="$(stat -c '%U:%G %a' "$scanner_lock" 2>/dev/null || true)"
[[ "$scanner_lock_mode" == "mise-en-plesk:mise-en-plesk 600" ]] \
  || fail "runtime scanner lock must be owned by mise-en-plesk mode 0600"

[[ -r "$known_hosts_path" && ! -L "$known_hosts_path" ]] \
  || fail "verified SSH known_hosts is missing or is a symlink"
known_hosts_mode="$(stat -c '%U:%G %a' "$known_hosts_path" 2>/dev/null || true)"
[[ "$known_hosts_mode" == "mise-en-plesk:mise-en-plesk 600" ]] \
  || fail "known_hosts must be owned by mise-en-plesk mode 0600"

echo "mise-en-plesk systemd installation is enabled, active, non-root, protected, and uses a $credential_kind credential."
