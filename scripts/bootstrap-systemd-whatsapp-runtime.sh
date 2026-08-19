#!/usr/bin/env bash
set -euo pipefail

readonly confirmation_value="bootstrap-whatsapp-runtime"
readonly runtime_root="/run/mise-en-plesk"
readonly credential_path="/run/mise-en-plesk/WHATSAPP_ACCESS_TOKEN"
readonly dropin_directory="/etc/systemd/system/mise-en-plesk.service.d"
readonly dropin_path="$dropin_directory/whatsapp.conf"
readonly scanner_lock="$runtime_root/scan.lock"

apply=0
confirmation=""
leave_timer_stopped=0
for argument in "$@"; do
  case "$argument" in
    --apply) apply=1 ;;
    --confirm=*) confirmation="${argument#--confirm=}" ;;
    --leave-timer-stopped) leave_timer_stopped=1 ;;
    --help)
      echo "Usage: bootstrap-systemd-whatsapp-runtime.sh [--apply --confirm=$confirmation_value]"
      exit 0
      ;;
    *) echo "WhatsApp runtime bootstrap failed: unknown option: $argument" >&2; exit 78 ;;
  esac
done

if (( apply == 0 )); then
  cat <<PLAN
DRY RUN: no credentials, drop-ins, units, timers, or services will be changed.
Would read one JSON object from stdin and install an ephemeral Meta WhatsApp
token plus non-secret routing for the mise-en-plesk systemd service.

Apply only after checking the recipient and approved utility template:
  sudo scripts/bootstrap-systemd-whatsapp-runtime.sh --apply --confirm=$confirmation_value
PLAN
  exit 0
fi

[[ "$confirmation" == "$confirmation_value" ]] || { echo "WhatsApp runtime bootstrap failed: refusing mutation" >&2; exit 78; }
[[ "$(id -u)" == "0" ]] || { echo "WhatsApp runtime bootstrap failed: --apply must run as root" >&2; exit 78; }
[[ -d "$runtime_root" && ! -L "$runtime_root" ]] || { echo "WhatsApp runtime bootstrap failed: runtime root is missing" >&2; exit 78; }
[[ -r /etc/systemd/system/mise-en-plesk.service ]] || { echo "WhatsApp runtime bootstrap failed: service is not installed" >&2; exit 78; }
command -v node >/dev/null 2>&1 || { echo "WhatsApp runtime bootstrap failed: node is unavailable" >&2; exit 78; }
command -v systemctl >/dev/null 2>&1 || { echo "WhatsApp runtime bootstrap failed: systemctl is unavailable" >&2; exit 78; }

for target in "$credential_path" "$dropin_path" "$scanner_lock"; do
  [[ ! -L "$target" ]] || { echo "WhatsApp runtime bootstrap failed: refusing symlink target: $target" >&2; exit 78; }
done
[[ -f "$scanner_lock" ]] || { echo "WhatsApp runtime bootstrap failed: scanner lock is missing" >&2; exit 78; }
command -v flock >/dev/null 2>&1 || { echo "WhatsApp runtime bootstrap failed: flock is unavailable" >&2; exit 78; }

temporary_directory="$(mktemp -d "$runtime_root/.whatsapp-bootstrap.XXXXXX")"
transaction_armed=0
transaction_complete=0

node -e '
const fs = require("node:fs");
const input = JSON.parse(fs.readFileSync(0, "utf8"));
const rules = {
  accessToken: value => typeof value === "string" && value.length >= 20 && value.length <= 16384 && !/[\r\n\0]/.test(value),
  phoneNumberId: value => typeof value === "string" && /^\d{5,32}$/.test(value),
  recipient: value => typeof value === "string" && /^\d{6,20}$/.test(value),
  templateName: value => typeof value === "string" && /^[a-z0-9_]{1,512}$/.test(value),
  templateLanguage: value => typeof value === "string" && /^[A-Za-z]{2}(?:_[A-Za-z]{2})?$/.test(value),
  graphVersion: value => typeof value === "string" && /^v\d+\.\d+$/.test(value),
};
for (const [name, valid] of Object.entries(rules)) {
  if (!valid(input[name])) throw new Error(`invalid ${name}`);
}
fs.writeFileSync(process.argv[1], input.accessToken, { mode: 0o600 });
fs.writeFileSync(process.argv[2], `[Service]\nLoadCredential=WHATSAPP_ACCESS_TOKEN:/run/mise-en-plesk/WHATSAPP_ACCESS_TOKEN\nEnvironment=MISE_PLESK_WHATSAPP_PHONE_NUMBER_ID=${input.phoneNumberId}\nEnvironment=MISE_PLESK_WHATSAPP_RECIPIENT=${input.recipient}\nEnvironment=MISE_PLESK_WHATSAPP_TEMPLATE_NAME=${input.templateName}\nEnvironment=MISE_PLESK_WHATSAPP_TEMPLATE_LANGUAGE=${input.templateLanguage}\nEnvironment=MISE_PLESK_WHATSAPP_GRAPH_VERSION=${input.graphVersion}\n`, { mode: 0o600 });
' "$temporary_directory/token" "$temporary_directory/whatsapp.conf"

timer_was_active=0
credential_replaced=0
dropin_replaced=0

exec 9>>"$scanner_lock"
flock -n 9 || { echo "WhatsApp runtime bootstrap failed: scanner lock is held" >&2; exit 75; }

rollback_whatsapp_runtime() {
  set +e
  local restore_failed=0
  if (( credential_replaced == 1 )); then
    if [[ -e "$temporary_directory/previous-token" ]]; then
      install -o root -g root -m 0600 "$temporary_directory/previous-token" "$credential_path" || restore_failed=1
    else
      unlink "$credential_path" 2>/dev/null || restore_failed=1
    fi
  fi
  if (( dropin_replaced == 1 )); then
    if [[ -e "$temporary_directory/previous-dropin" ]]; then
      install -o root -g root -m 0644 "$temporary_directory/previous-dropin" "$dropin_path" || restore_failed=1
    else
      unlink "$dropin_path" 2>/dev/null || restore_failed=1
    fi
  fi
  systemctl daemon-reload >/dev/null 2>&1 || restore_failed=1
  (( timer_was_active == 0 )) || systemctl start mise-en-plesk.timer >/dev/null 2>&1 || restore_failed=1
  (( restore_failed == 0 )) || echo "WARNING: WhatsApp runtime rollback was incomplete; inspect the credential, drop-in, and timer." >&2
}

finish_whatsapp_bootstrap() {
  local exit_code="$1"
  trap - EXIT INT TERM
  if (( transaction_armed == 1 && transaction_complete == 0 )); then
    rollback_whatsapp_runtime
  fi
  unlink "$temporary_directory/token" "$temporary_directory/whatsapp.conf" \
    "$temporary_directory/previous-token" "$temporary_directory/previous-dropin" 2>/dev/null || true
  rmdir "$temporary_directory" 2>/dev/null || true
  exit "$exit_code"
}
trap 'finish_whatsapp_bootstrap $?' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
transaction_armed=1

if systemctl is-active --quiet mise-en-plesk.timer; then
  timer_was_active=1
  systemctl stop mise-en-plesk.timer
fi
if systemctl is-active --quiet mise-en-plesk.service; then
  (( timer_was_active == 0 )) || systemctl start mise-en-plesk.timer
  echo "WhatsApp runtime bootstrap failed: scanner service is active; retry after it completes" >&2
  exit 75
fi

[[ ! -e "$credential_path" ]] || cp --preserve=mode,ownership "$credential_path" "$temporary_directory/previous-token"
[[ ! -e "$dropin_path" ]] || cp --preserve=mode,ownership "$dropin_path" "$temporary_directory/previous-dropin"

credential_replaced=1
install -o root -g root -m 0600 "$temporary_directory/token" "$credential_path"
install -d -o root -g root -m 0755 "$dropin_directory"
dropin_replaced=1
install -o root -g root -m 0644 "$temporary_directory/whatsapp.conf" "$dropin_path"
systemctl daemon-reload
if (( timer_was_active == 1 && leave_timer_stopped == 0 )); then systemctl start mise-en-plesk.timer; fi
transaction_complete=1

echo "Configured the ephemeral Meta WhatsApp credential and non-secret routing."
if (( leave_timer_stopped == 1 )); then
  echo "The scan timer was intentionally left stopped; activate it only after a guarded delivery test."
fi
echo "No message was sent. Run the guarded whatsapp-test only after confirming the configured recipient."
