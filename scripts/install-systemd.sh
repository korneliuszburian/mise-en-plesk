#!/usr/bin/env bash
set -euo pipefail

readonly checkout="/opt/mise-en-plesk"
readonly unit_directory="/etc/systemd/system"
readonly state_directory="/var/lib/mise-en-plesk"
readonly runtime_credential="/run/mise-en-plesk/BW_SESSION"
readonly encrypted_credential="/etc/mise-en-plesk/bw-session.cred"
readonly confirmation_value="install-systemd"

apply=0
confirmation=""

fail() {
  echo "systemd installer failed: $*" >&2
  return 78
}

for argument in "$@"; do
  case "$argument" in
    --apply) apply=1 ;;
    --confirm=*) confirmation="${argument#--confirm=}" ;;
    --help)
      cat <<'USAGE'
Usage: scripts/install-systemd.sh [--apply --confirm=install-systemd]

The default is a non-mutating dry run. Apply installs only into fixed,
dedicated paths and refuses to overwrite an existing installation.
USAGE
      exit 0
      ;;
    *) fail "unknown option: $argument" ;;
  esac
done

if command -v systemd-creds >/dev/null 2>&1; then
  credential_mode="encrypted"
  credential_path="$encrypted_credential"
  credential_directive="LoadCredentialEncrypted=BW_SESSION:$credential_path"
else
  credential_mode="runtime"
  credential_path="$runtime_credential"
  credential_directive="LoadCredential=BW_SESSION:$credential_path"
fi
readonly credential_mode credential_path credential_directive

if (( apply == 0 )); then
  cat <<PLAN
DRY RUN: no files, users, units, services, or timers will be changed.
Would install the read-only scanner using fixed paths:
  checkout:    $checkout
  unit dir:    $unit_directory
  state dir:   $state_directory
  credential:  $credential_path
  mode:        $credential_mode

Apply only after the checkout and credential have been prepared:
  sudo $checkout/scripts/install-systemd.sh --apply --confirm=$confirmation_value
PLAN
  exit 0
fi

[[ "$confirmation" == "$confirmation_value" ]] \
  || fail "refusing mutation: use --confirm=$confirmation_value"
[[ "$(id -u)" == "0" ]] || fail "--apply must run as root"
[[ -d "$checkout" && ! -L "$checkout" ]] || fail "canonical checkout is missing or is a symlink: $checkout"
[[ -x "$checkout/scripts/run-scheduled-scan-systemd.sh" ]] || fail "systemd runner is missing"
[[ -r "$checkout/deploy/systemd/mise-en-plesk.service.example" ]] || fail "service example is missing"
[[ -r "$checkout/deploy/systemd/mise-en-plesk.timer.example" ]] || fail "timer example is missing"
[[ -r "$checkout/config.mise-en-plesk.json" ]] || fail "scanner config is missing from the checkout"
[[ -r "$checkout/inventory.json" ]] || fail "inventory is missing from the checkout"
[[ -s "$credential_path" && ! -L "$credential_path" ]] || fail "BW_SESSION credential is missing, empty, or a symlink: $credential_path"

[[ -x /usr/local/bin/pnpm ]] || fail "/usr/local/bin/pnpm is not available"
[[ -x /usr/local/bin/bw ]] || fail "/usr/local/bin/bw is not available"
[[ -x /usr/local/bin/node || -x /usr/bin/node ]] || fail "Node.js is not available in the service PATH"
[[ -x /usr/bin/sshpass ]] || fail "/usr/bin/sshpass is not available"
command -v systemctl >/dev/null 2>&1 || fail "systemctl is not available"
command -v systemd-analyze >/dev/null 2>&1 || fail "systemd-analyze is not available"
[[ -d "$checkout/node_modules" ]] || fail "dependencies are missing; run pnpm install --frozen-lockfile in $checkout"

readonly service_unit="$unit_directory/mise-en-plesk.service"
readonly timer_unit="$unit_directory/mise-en-plesk.timer"
for target in "$service_unit" "$timer_unit" "$state_directory"; do
  [[ ! -e "$target" && ! -L "$target" ]] || fail "refusing to overwrite existing target: $target"
done
for unit_name in mise-en-plesk.service mise-en-plesk.timer; do
  if systemctl cat "$unit_name" >/dev/null 2>&1; then
    fail "refusing to shadow an existing systemd unit: $unit_name"
  fi
  if systemctl is-enabled "$unit_name" >/dev/null 2>&1; then
    fail "refusing an existing systemd enablement: $unit_name"
  fi
done

temporary_directory="$(mktemp -d)"
temporary_unit="$temporary_directory/mise-en-plesk.service"
temporary_timer="$temporary_directory/mise-en-plesk.timer"
trap 'unlink "$temporary_unit" "$temporary_timer" 2>/dev/null || true; rmdir "$temporary_directory" 2>/dev/null || true' EXIT
sed "s#^LoadCredentialEncrypted=BW_SESSION:.*#$credential_directive#" \
  "$checkout/deploy/systemd/mise-en-plesk.service.example" > "$temporary_unit"
cp "$checkout/deploy/systemd/mise-en-plesk.timer.example" "$temporary_timer"
grep -Fqx "$credential_directive" "$temporary_unit" || fail "failed to render the credential directive"
systemd-analyze verify "$temporary_unit" "$temporary_timer"

created_user=0
created_state=0
installed_service=0
installed_timer=0
enabled_timer=0

rollback() {
  local exit_code=$?
  trap - ERR
  echo "systemd installer failed; rolling back only targets created by this invocation." >&2
  if (( enabled_timer == 1 )); then
    systemctl disable --now mise-en-plesk.timer >/dev/null 2>&1 || true
  fi
  if (( installed_timer == 1 )); then
    unlink "$timer_unit" 2>/dev/null || true
  fi
  if (( installed_service == 1 )); then
    unlink "$service_unit" 2>/dev/null || true
  fi
  if (( installed_service == 1 || installed_timer == 1 )); then
    systemctl daemon-reload >/dev/null 2>&1 || true
  fi
  if (( created_state == 1 )); then
    unlink "$state_directory/config.mise-en-plesk.json" "$state_directory/inventory.json" 2>/dev/null || true
    rmdir "$state_directory/reports" "$state_directory/logs" "$state_directory" 2>/dev/null || true
  fi
  if (( created_user == 1 )); then
    userdel mise-en-plesk >/dev/null 2>&1 || true
  fi
  exit "$exit_code"
}
trap rollback ERR

if id mise-en-plesk >/dev/null 2>&1; then
  existing_home="$(getent passwd mise-en-plesk | cut -d: -f6)"
  existing_shell="$(getent passwd mise-en-plesk | cut -d: -f7)"
  existing_group="$(id -gn mise-en-plesk)"
  existing_uid="$(id -u mise-en-plesk)"
  existing_gid="$(id -g mise-en-plesk)"
  [[ "$existing_home" == "$state_directory" ]] \
    || fail "existing mise-en-plesk account has unexpected home: ${existing_home:-unknown}"
  [[ "$existing_shell" == "/usr/sbin/nologin" ]] \
    || fail "existing mise-en-plesk account has unexpected shell: ${existing_shell:-unknown}"
  [[ "$existing_group" == "mise-en-plesk" ]] \
    || fail "existing mise-en-plesk account has unexpected primary group: ${existing_group:-unknown}"
  (( existing_uid > 0 && existing_uid < 1000 )) \
    || fail "existing mise-en-plesk account is not a non-root system account"
  (( existing_gid > 0 && existing_gid < 1000 )) \
    || fail "existing mise-en-plesk group is not a non-root system group"
else
  useradd --system --home-dir "$state_directory" --no-create-home --shell /usr/sbin/nologin mise-en-plesk
  created_user=1
fi

[[ "$(id -gn mise-en-plesk)" == "mise-en-plesk" ]] || fail "mise-en-plesk primary group was not created"
service_uid="$(id -u mise-en-plesk)"
service_gid="$(id -g mise-en-plesk)"
(( service_uid > 0 && service_uid < 1000 )) || fail "mise-en-plesk must use a non-root system UID"
(( service_gid > 0 && service_gid < 1000 )) || fail "mise-en-plesk must use a non-root system GID"
install -d -o mise-en-plesk -g mise-en-plesk -m 0750 "$state_directory"
created_state=1
install -d -o mise-en-plesk -g mise-en-plesk -m 0750 \
  "$state_directory/reports" "$state_directory/logs"
readonly service_path="/usr/local/bin:/usr/bin:/bin"
runuser -u mise-en-plesk -- env -i HOME="$state_directory" PATH="$service_path" test -r "$checkout/package.json"
runuser -u mise-en-plesk -- env -i HOME="$state_directory" PATH="$service_path" node --version >/dev/null
runuser -u mise-en-plesk -- env -i HOME="$state_directory" PATH="$service_path" bw --version >/dev/null
runuser -u mise-en-plesk -- env -i HOME="$state_directory" PATH="$service_path" sshpass -V >/dev/null 2>&1
runuser -u mise-en-plesk -- env -i HOME="$state_directory" PATH="$service_path" \
  "$checkout/node_modules/.bin/tsx" --version >/dev/null
runuser -u mise-en-plesk -- env -i HOME="$state_directory" PATH="$service_path" \
  bash -n "$checkout/scripts/run-scheduled-scan.sh" "$checkout/scripts/run-scheduled-scan-systemd.sh"

install -o mise-en-plesk -g mise-en-plesk -m 0640 \
  "$checkout/config.mise-en-plesk.json" "$state_directory/config.mise-en-plesk.json"
install -o mise-en-plesk -g mise-en-plesk -m 0640 \
  "$checkout/inventory.json" "$state_directory/inventory.json"
install -o root -g root -m 0644 "$temporary_unit" "$service_unit"
installed_service=1
install -o root -g root -m 0644 "$temporary_timer" "$timer_unit"
installed_timer=1

systemctl daemon-reload
systemctl enable mise-en-plesk.timer
enabled_timer=1
trap - ERR
if ! systemctl start mise-en-plesk.timer; then
  echo "Installation is complete and enabled, but the timer did not start; inspect systemctl status and retry start without reinstalling." >&2
  exit 75
fi
echo "Installed and enabled mise-en-plesk.timer in read-only scanner mode."
echo "Credential mode: $credential_mode ($credential_path)."
echo "Run $checkout/scripts/verify-systemd-install.sh for live verification."
