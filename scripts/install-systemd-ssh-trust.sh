#!/usr/bin/env bash
set -euo pipefail

readonly state_directory="/var/lib/mise-en-plesk"
readonly inventory_path="$state_directory/inventory.json"
readonly ssh_directory="$state_directory/.ssh"
readonly known_hosts_path="$ssh_directory/known_hosts"
readonly confirmation_value="install-ssh-trust"
apply=0
confirmation=""

fail() {
  echo "SSH trust installation failed: $*" >&2
  exit 78
}

for argument in "$@"; do
  case "$argument" in
    --apply) apply=1 ;;
    --confirm=*) confirmation="${argument#--confirm=}" ;;
    --help)
      echo "Usage: scripts/install-systemd-ssh-trust.sh [--apply --confirm=$confirmation_value] < verified-known-hosts"
      exit 0
      ;;
    *) fail "unknown option: $argument" ;;
  esac
done

if (( apply == 0 )); then
  echo "DRY RUN: would install verified public SSH host keys for exactly the hosts in $inventory_path."
  echo "Apply with --apply --confirm=$confirmation_value and provide known_hosts lines on stdin."
  exit 0
fi

[[ "$confirmation" == "$confirmation_value" ]] || fail "refusing mutation: use --confirm=$confirmation_value"
[[ "$(id -u)" == "0" ]] || fail "--apply must run as root"
id mise-en-plesk >/dev/null 2>&1 || fail "mise-en-plesk service account does not exist"
[[ -d "$state_directory" && ! -L "$state_directory" ]] || fail "state directory is missing or a symlink"
[[ -r "$inventory_path" && ! -L "$inventory_path" ]] || fail "inventory is missing or a symlink"
[[ ! -L "$ssh_directory" && ! -L "$known_hosts_path" ]] || fail "refusing symlink target"
command -v ssh-keygen >/dev/null 2>&1 || fail "ssh-keygen is unavailable"
command -v node >/dev/null 2>&1 || fail "Node.js is unavailable"

temporary_file="$(mktemp)"
trap 'unlink "$temporary_file" 2>/dev/null || true' EXIT
install -m 0600 /dev/stdin "$temporary_file"
[[ -s "$temporary_file" ]] || fail "known_hosts input is empty"
ssh-keygen -lf "$temporary_file" >/dev/null || fail "known_hosts input contains an invalid public key"

INVENTORY_PATH="$inventory_path" KNOWN_HOSTS_PATH="$temporary_file" node <<'NODE'
const fs = require("node:fs");
const inventory = JSON.parse(fs.readFileSync(process.env.INVENTORY_PATH, "utf8"));
const expected = new Set(Object.values(inventory).map(({ host, port }) => `[${host}]:${port}`));
const seen = new Set();
for (const rawLine of fs.readFileSync(process.env.KNOWN_HOSTS_PATH, "utf8").split(/\r?\n/)) {
  const line = rawLine.trim();
  if (!line || line.startsWith("#")) continue;
  const hosts = line.split(/\s+/, 1)[0].split(",");
  for (const host of hosts) {
    if (!expected.has(host)) throw new Error(`unexpected host key entry: ${host}`);
    seen.add(host);
  }
}
for (const host of expected) if (!seen.has(host)) throw new Error(`missing host key entry: ${host}`);
NODE

install -d -o mise-en-plesk -g mise-en-plesk -m 0700 "$ssh_directory"
temporary_target="$(mktemp "$ssh_directory/.known_hosts.XXXXXX")"
trap 'unlink "$temporary_file" "$temporary_target" 2>/dev/null || true' EXIT
install -o mise-en-plesk -g mise-en-plesk -m 0600 "$temporary_file" "$temporary_target"
mv -fT "$temporary_target" "$known_hosts_path"
echo "Installed verified SSH trust for the configured inventory hosts."
