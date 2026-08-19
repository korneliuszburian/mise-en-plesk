#!/usr/bin/env bash
set -euo pipefail

readonly repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly confirmation_value="configure-whatsapp-runtime"

apply=0
confirmation=""
for argument in "$@"; do
  case "$argument" in
    --apply) apply=1 ;;
    --confirm=*) confirmation="${argument#--confirm=}" ;;
    --help)
      echo "Usage: scripts/setup-systemd-whatsapp.sh [--apply --confirm=$confirmation_value]"
      exit 0
      ;;
    *) echo "WhatsApp setup failed: unknown option: $argument" >&2; exit 78 ;;
  esac
done

if (( apply == 0 )); then
  cat <<PLAN
DRY RUN: no credential, systemd drop-in, timer, service, or message will be changed.
Interactive apply asks for Meta routing and a System User token, streams the
token directly to the guarded root bootstrap, and verifies the installation.
The token is never placed in argv, an environment variable, or a report. The
root bootstrap stages it in protected runtime storage and leaves the scan timer
stopped, so configuration alone cannot send a message.

Apply with:
  scripts/setup-systemd-whatsapp.sh --apply --confirm=$confirmation_value
PLAN
  exit 0
fi

[[ "$confirmation" == "$confirmation_value" ]] || {
  echo "WhatsApp setup failed: refusing mutation; use --confirm=$confirmation_value" >&2
  exit 78
}
[[ -r /dev/tty && -w /dev/tty ]] || {
  echo "WhatsApp setup failed: an interactive terminal is required" >&2
  exit 78
}
command -v node >/dev/null 2>&1 || { echo "WhatsApp setup failed: node is unavailable" >&2; exit 78; }
command -v sudo >/dev/null 2>&1 || { echo "WhatsApp setup failed: sudo is unavailable" >&2; exit 78; }

# A caller may have enabled xtrace before invoking this script. Disable it
# before any secret is read so expanded values cannot reach terminal logs.
set +x

read -r -p "Meta sender Phone Number ID: " phone_number_id < /dev/tty
read -r -p "Digits-only WhatsApp recipient: " recipient < /dev/tty
read -r -p "Approved utility template name: " template_name < /dev/tty
read -r -p "Template language (for example pl_PL): " template_language < /dev/tty
read -r -p "Current Graph API version shown by Meta (for example v25.0): " graph_version < /dev/tty
read -r -s -p "Meta System User access token: " access_token < /dev/tty
printf '\n' > /dev/tty
trap 'unset access_token' EXIT INT TERM

[[ "$phone_number_id" =~ ^[0-9]{5,32}$ ]] || { echo "WhatsApp setup failed: invalid Phone Number ID" >&2; exit 78; }
[[ "$recipient" =~ ^[0-9]{6,20}$ ]] || { echo "WhatsApp setup failed: recipient must contain digits only" >&2; exit 78; }
[[ "$template_name" =~ ^[a-z0-9_]{1,512}$ ]] || { echo "WhatsApp setup failed: invalid template name" >&2; exit 78; }
[[ "$template_language" =~ ^[A-Za-z]{2}(_[A-Za-z]{2})?$ ]] || { echo "WhatsApp setup failed: invalid template language" >&2; exit 78; }
[[ "$graph_version" =~ ^v[0-9]+\.[0-9]+$ ]] || { echo "WhatsApp setup failed: invalid Graph API version" >&2; exit 78; }
(( ${#access_token} >= 20 && ${#access_token} <= 16384 )) || { echo "WhatsApp setup failed: invalid access token length" >&2; exit 78; }
[[ "$access_token" != *$'\n'* && "$access_token" != *$'\r'* ]] || { echo "WhatsApp setup failed: access token contains a newline" >&2; exit 78; }

read -r -p "Type the recipient again to authorize configuration for $recipient: " recipient_confirmation < /dev/tty
[[ "$recipient_confirmation" == "$recipient" ]] || {
  echo "WhatsApp setup failed: recipient confirmation does not match" >&2
  exit 78
}

printf '%s' "$access_token" \
  | node -e '
      const fs = require("node:fs");
      const [phoneNumberId, recipient, templateName, templateLanguage, graphVersion] = process.argv.slice(1);
      const accessToken = fs.readFileSync(0, "utf8");
      process.stdout.write(JSON.stringify({ accessToken, phoneNumberId, recipient, templateName, templateLanguage, graphVersion }));
    ' "$phone_number_id" "$recipient" "$template_name" "$template_language" "$graph_version" \
  | sudo "$repo_root/scripts/bootstrap-systemd-whatsapp-runtime.sh" \
      --apply --confirm=bootstrap-whatsapp-runtime --leave-timer-stopped
unset access_token
trap - EXIT INT TERM

sudo "$repo_root/scripts/verify-systemd-install.sh" --require-whatsapp --allow-inactive-timer
echo "Meta WhatsApp runtime is configured and the scan timer is stopped. No message was sent."
echo "After re-checking the destination, run:"
echo "  sudo $repo_root/scripts/run-systemd-whatsapp-test.sh --confirm=$recipient"
echo "After the guarded test succeeds, explicitly activate scheduled scans:"
echo "  sudo systemctl start mise-en-plesk.timer"
