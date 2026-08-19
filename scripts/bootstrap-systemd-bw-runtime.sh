#!/usr/bin/env bash
set -euo pipefail

readonly runtime_root="/run/mise-en-plesk"
readonly bw_data_directory="$runtime_root/bw-data"
readonly credential_path="$runtime_root/BW_SESSION"
readonly scanner_lock="$runtime_root/scan.lock"
readonly confirmation_value="bootstrap-bw-runtime"
apply=0
confirmation=""

fail() {
  echo "Bitwarden runtime bootstrap failed: $*" >&2
  return 78
}

for argument in "$@"; do
  case "$argument" in
    --apply) apply=1 ;;
    --confirm=*) confirmation="${argument#--confirm=}" ;;
    --help)
      cat <<'USAGE'
Usage: scripts/bootstrap-systemd-bw-runtime.sh [--apply --confirm=bootstrap-bw-runtime]

Apply mode reads one JSON object from stdin:
  {"bwSession":"...","bwData":{...authenticated Bitwarden CLI data...}}

Secrets are written only below /run/mise-en-plesk and disappear on reboot.
USAGE
      exit 0
      ;;
    *) fail "unknown option: $argument" ;;
  esac
done

if (( apply == 0 )); then
  echo "DRY RUN: would atomically refresh ephemeral BW_SESSION and Bitwarden CLI state below $runtime_root."
  echo "Apply with --apply --confirm=$confirmation_value and provide the JSON payload on stdin."
  exit 0
fi

[[ "$confirmation" == "$confirmation_value" ]] || fail "refusing mutation: use --confirm=$confirmation_value"
[[ "$(id -u)" == "0" ]] || fail "--apply must run as root"
id mise-en-plesk >/dev/null 2>&1 || fail "mise-en-plesk service account does not exist"
[[ "$(id -u mise-en-plesk)" != "0" ]] || fail "mise-en-plesk must not use UID 0"
command -v node >/dev/null 2>&1 || fail "Node.js is unavailable"
command -v systemctl >/dev/null 2>&1 || fail "systemctl is unavailable"
command -v flock >/dev/null 2>&1 || fail "flock is unavailable"

for target in "$runtime_root" "$bw_data_directory" "$credential_path" "$bw_data_directory/data.json" "$scanner_lock"; do
  [[ ! -L "$target" ]] || fail "refusing symlink target: $target"
done

install -d -o root -g root -m 0711 "$runtime_root"
install -d -o mise-en-plesk -g mise-en-plesk -m 0700 "$bw_data_directory"
if [[ ! -e "$scanner_lock" ]]; then
  install -o mise-en-plesk -g mise-en-plesk -m 0600 /dev/null "$scanner_lock"
fi
[[ -f "$scanner_lock" && ! -L "$scanner_lock" ]] || fail "scanner lock must be a regular file"
[[ "$(stat -c '%U:%G %a' "$scanner_lock")" == "mise-en-plesk:mise-en-plesk 600" ]] \
  || fail "scanner lock must be owned by mise-en-plesk mode 0600"
temporary_directory="$(mktemp -d "$runtime_root/.bootstrap.XXXXXX")"
chmod 0711 "$temporary_directory"
install -d -o mise-en-plesk -g mise-en-plesk -m 0700 "$temporary_directory/bw-data"
trap 'unlink "$temporary_directory/BW_SESSION" "$temporary_directory/bw-data/data.json" "$temporary_directory/previous-session" "$temporary_directory/previous-data" 2>/dev/null || true; rmdir "$temporary_directory/bw-data" "$temporary_directory" 2>/dev/null || true' EXIT

BOOTSTRAP_DIRECTORY="$temporary_directory" node -e '
const fs = require("node:fs");
const directory = process.env.BOOTSTRAP_DIRECTORY;
const payload = JSON.parse(fs.readFileSync(0, "utf8"));
if (!directory || !payload || typeof payload !== "object" || Array.isArray(payload)) process.exit(78);
if (typeof payload.bwSession !== "string" || payload.bwSession.trim().length < 16) process.exit(78);
if (!payload.bwData || typeof payload.bwData !== "object" || Array.isArray(payload.bwData)) process.exit(78);
fs.writeFileSync(`${directory}/BW_SESSION`, payload.bwSession.trim(), { mode: 0o600 });
fs.writeFileSync(`${directory}/bw-data/data.json`, JSON.stringify(payload.bwData), { mode: 0o600 });
'

chown root:root "$temporary_directory/BW_SESSION"
chmod 0600 "$temporary_directory/BW_SESSION"
chown mise-en-plesk:mise-en-plesk "$temporary_directory/bw-data/data.json"
chmod 0600 "$temporary_directory/bw-data/data.json"

status_json="$(runuser -u mise-en-plesk -- env -i \
  HOME=/var/lib/mise-en-plesk \
  PATH=/usr/local/bin:/usr/bin:/bin \
  BITWARDENCLI_APPDATA_DIR="$temporary_directory/bw-data" \
  bash -c 'IFS= read -r BW_SESSION; export BW_SESSION; exec bw status' \
  < "$temporary_directory/BW_SESSION")" \
  || fail "staged Bitwarden state could not be opened"
STATUS_JSON="$status_json" node -e '
const status = JSON.parse(process.env.STATUS_JSON ?? "null");
if (status?.status !== "unlocked") process.exit(78);
' || fail "staged Bitwarden state is not unlocked"

timer_was_active=0
session_replaced=0
data_replaced=0

exec 9>>"$scanner_lock"
flock -n 9 || fail "scanner lock is held; retry after the current read-only scan finishes"

rollback_pair() {
  local exit_code=$?
  trap - ERR
  set +e
  local restore_failed=0
  if (( session_replaced == 1 )); then
    if [[ -e "$temporary_directory/previous-session" ]]; then
      install -o root -g root -m 0600 "$temporary_directory/previous-session" "$credential_path" || restore_failed=1
    else
      unlink "$credential_path" 2>/dev/null || restore_failed=1
    fi
  fi
  if (( data_replaced == 1 )); then
    if [[ -e "$temporary_directory/previous-data" ]]; then
      install -o mise-en-plesk -g mise-en-plesk -m 0600 "$temporary_directory/previous-data" "$bw_data_directory/data.json" || restore_failed=1
    else
      unlink "$bw_data_directory/data.json" 2>/dev/null || restore_failed=1
    fi
  fi
  (( timer_was_active == 0 )) || systemctl start mise-en-plesk.timer >/dev/null 2>&1 || restore_failed=1
  (( restore_failed == 0 )) || echo "WARNING: runtime rollback was incomplete; inspect credential state and timer immediately." >&2
  exit "$exit_code"
}
trap rollback_pair ERR

if systemctl cat mise-en-plesk.timer >/dev/null 2>&1; then
  if systemctl is-active --quiet mise-en-plesk.timer; then
    timer_was_active=1
    systemctl stop mise-en-plesk.timer
  fi
  if systemctl is-active --quiet mise-en-plesk.service; then
    (( timer_was_active == 0 )) || systemctl start mise-en-plesk.timer
    fail "scanner service is active; retry after the current read-only scan finishes"
  fi
fi

[[ ! -e "$credential_path" ]] || cp --preserve=mode,ownership "$credential_path" "$temporary_directory/previous-session"
[[ ! -e "$bw_data_directory/data.json" ]] \
  || cp --preserve=mode,ownership "$bw_data_directory/data.json" "$temporary_directory/previous-data"

mv -fT "$temporary_directory/BW_SESSION" "$credential_path"
session_replaced=1
mv -fT "$temporary_directory/bw-data/data.json" "$bw_data_directory/data.json"
data_replaced=1
trap - ERR
if (( timer_was_active == 1 )) && ! systemctl start mise-en-plesk.timer; then
  echo "Runtime state was refreshed, but mise-en-plesk.timer did not restart." >&2
  exit 75
fi
echo "Refreshed ephemeral Bitwarden runtime state without persisting it outside /run."
