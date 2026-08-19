#!/usr/bin/env bash
set -euo pipefail

readonly checkout="/opt/mise-en-plesk"
readonly dropin_path="/etc/systemd/system/mise-en-plesk.service.d/whatsapp.conf"
readonly credential_path="/run/mise-en-plesk/WHATSAPP_ACCESS_TOKEN"

confirmation=""
for argument in "$@"; do
  case "$argument" in
    --confirm=*) confirmation="${argument#--confirm=}" ;;
    --help)
      echo "Usage: sudo scripts/run-systemd-whatsapp-test.sh --confirm=<configured recipient>"
      exit 0
      ;;
    *) echo "WhatsApp systemd test failed: unknown option: $argument" >&2; exit 78 ;;
  esac
done

[[ "$(id -u)" == "0" ]] || { echo "WhatsApp systemd test failed: run as root" >&2; exit 78; }
[[ -f "$dropin_path" && ! -L "$dropin_path" ]] || { echo "WhatsApp systemd test failed: routing drop-in is missing" >&2; exit 78; }
[[ -f "$credential_path" && ! -L "$credential_path" ]] || { echo "WhatsApp systemd test failed: runtime credential is missing" >&2; exit 78; }
[[ -r "$checkout/dist/bin/mise-plesk-audit.js" ]] || { echo "WhatsApp systemd test failed: compiled CLI is missing" >&2; exit 78; }
command -v systemd-run >/dev/null 2>&1 || { echo "WhatsApp systemd test failed: systemd-run is unavailable" >&2; exit 78; }

routing_value() {
  local name="$1"
  local line
  line="$(grep -E "^Environment=${name}=[A-Za-z0-9_.]+$" "$dropin_path" || true)"
  [[ -n "$line" && "$(printf '%s\n' "$line" | wc -l)" == "1" ]] \
    || { echo "WhatsApp systemd test failed: invalid or missing $name" >&2; exit 78; }
  printf '%s' "${line#*=}"
}

phone_number_id="$(routing_value MISE_PLESK_WHATSAPP_PHONE_NUMBER_ID)"
recipient="$(routing_value MISE_PLESK_WHATSAPP_RECIPIENT)"
template_name="$(routing_value MISE_PLESK_WHATSAPP_TEMPLATE_NAME)"
template_language="$(routing_value MISE_PLESK_WHATSAPP_TEMPLATE_LANGUAGE)"
graph_version="$(routing_value MISE_PLESK_WHATSAPP_GRAPH_VERSION)"

[[ "$confirmation" == "$recipient" ]] || {
  echo "WhatsApp systemd test failed: refusing outbound message; pass --confirm=<exact configured recipient>" >&2
  exit 78
}

systemd-run --quiet --wait --collect --pipe \
  --unit=mise-en-plesk-whatsapp-test \
  --uid=mise-en-plesk --gid=mise-en-plesk \
  --working-directory="$checkout" \
  --property="LoadCredential=WHATSAPP_ACCESS_TOKEN:$credential_path" \
  --property="Environment=HOME=/var/lib/mise-en-plesk" \
  --property="Environment=MISE_PLESK_WHATSAPP_PHONE_NUMBER_ID=$phone_number_id" \
  --property="Environment=MISE_PLESK_WHATSAPP_RECIPIENT=$recipient" \
  --property="Environment=MISE_PLESK_WHATSAPP_TEMPLATE_NAME=$template_name" \
  --property="Environment=MISE_PLESK_WHATSAPP_TEMPLATE_LANGUAGE=$template_language" \
  --property="Environment=MISE_PLESK_WHATSAPP_GRAPH_VERSION=$graph_version" \
  --property="UMask=0077" \
  --property="NoNewPrivileges=yes" \
  --property="PrivateTmp=yes" \
  --property="ProtectSystem=strict" \
  /usr/bin/bash -c 'export MISE_PLESK_WHATSAPP_ACCESS_TOKEN="$(<"$CREDENTIALS_DIRECTORY/WHATSAPP_ACCESS_TOKEN")"; exec /usr/local/bin/node dist/bin/mise-plesk-audit.js whatsapp-test "--confirm=$MISE_PLESK_WHATSAPP_RECIPIENT"'
