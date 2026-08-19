#!/usr/bin/env bash
set -euo pipefail

readonly script_directory="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly repository_root="$(cd "$script_directory/.." && pwd)"
readonly inventory_path="$repository_root/inventory.json"
readonly output_path="$repository_root/verified-known-hosts"
readonly trusted_path="${MISE_PLESK_TRUSTED_KNOWN_HOSTS:-$HOME/.ssh/known_hosts}"
readonly confirmation_value="prepare-ssh-trust"
apply=0
confirmation=""

fail() {
  echo "SSH trust preparation failed: $*" >&2
  exit 78
}

for argument in "$@"; do
  case "$argument" in
    --apply) apply=1 ;;
    --confirm=*) confirmation="${argument#--confirm=}" ;;
    --help)
      echo "Usage: scripts/prepare-verified-ssh-trust.sh [--apply --confirm=$confirmation_value]"
      exit 0
      ;;
    *) fail "unknown option: $argument" ;;
  esac
done

if (( apply == 0 )); then
  echo "DRY RUN: would compare live inventory host keys with $trusted_path and write $output_path only on exact fingerprint matches."
  echo "Apply with --apply --confirm=$confirmation_value."
  exit 0
fi

[[ "$confirmation" == "$confirmation_value" ]] || fail "refusing mutation: use --confirm=$confirmation_value"
[[ -r "$inventory_path" && ! -L "$inventory_path" ]] || fail "inventory is missing or a symlink"
[[ -r "$trusted_path" && ! -L "$trusted_path" ]] || fail "trusted known_hosts is missing or a symlink"
[[ ! -L "$output_path" ]] || fail "output path must not be a symlink"
command -v node >/dev/null 2>&1 || fail "Node.js is unavailable"
command -v ssh-keygen >/dev/null 2>&1 || fail "ssh-keygen is unavailable"
command -v ssh-keyscan >/dev/null 2>&1 || fail "ssh-keyscan is unavailable"

temporary_directory="$(mktemp -d "$repository_root/.ssh-trust.XXXXXX")"
output_file="$temporary_directory/verified-known-hosts"
trap 'unlink "$temporary_directory/trusted" "$temporary_directory/live" "$output_file" 2>/dev/null || true; rmdir "$temporary_directory" 2>/dev/null || true' EXIT
touch "$output_file"
chmod 0600 "$output_file"

while IFS=$'\t' read -r host port; do
  [[ "$host" =~ ^[A-Za-z0-9][A-Za-z0-9._:-]*$ ]] || fail "inventory contains an invalid SSH host"
  [[ "$port" =~ ^[0-9]+$ ]] && (( port >= 1 && port <= 65535 )) \
    || fail "inventory contains an invalid SSH port"
  token="[$host]:$port"
  ssh-keygen -F "$token" -f "$trusted_path" 2>/dev/null | grep -v '^#' > "$temporary_directory/trusted" \
    || fail "no existing trusted key for $token"
  ssh-keyscan -T 10 -p "$port" "$host" 2>/dev/null > "$temporary_directory/live" \
    || fail "could not read live host keys for $token"
  [[ -s "$temporary_directory/live" ]] || fail "live host returned no keys for $token"
  trusted_fingerprints="$(ssh-keygen -lf "$temporary_directory/trusted" | awk '{print $2}')"
  while IFS= read -r live_line; do
    [[ -n "$live_line" ]] || continue
    fingerprint="$(printf '%s\n' "$live_line" | ssh-keygen -lf - | awk '{print $2}')"
    grep -Fqx "$fingerprint" <<<"$trusted_fingerprints" \
      || fail "live fingerprint for $token is not present in the trusted known_hosts"
    printf '%s\n' "$live_line" >> "$output_file"
  done < "$temporary_directory/live"
done < <(node -e '
const fs = require("node:fs");
const inventory = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
for (const value of Object.values(inventory)) console.log(`${value.host}\t${value.port}`);
' "$inventory_path")

[[ -s "$output_file" ]] || fail "no verified host keys were produced"
mv -fT "$output_file" "$output_path"
chmod 0600 "$output_path"
echo "Prepared verified-known-hosts from live keys matching the existing trusted store."
