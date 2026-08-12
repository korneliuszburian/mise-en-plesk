# mise-en-plesk

Small, read-only tooling for auditing WordPress installations on Plesk hosts.

## Quickstart

```sh
pnpm install
pnpm typecheck
pnpm test
source scripts/setup-bw-session.sh
pnpm mise-plesk-audit sync-ssh
pnpm mise-plesk-audit scan master
```

Bitwarden items must be searchable with `mise-en-plesk`, contain a login
username and SSH URI, and use fields for optional metadata such as
`identitySource`. The local `inventory.json` is a cache and is gitignored.

The `scan <target>` command runs a read-only SSH/Plesk/WordPress scan and writes
a Markdown report under `reports/`. Plesk commands are intentionally
read-only; this project does not delete anything, update plugins/themes, or
change databases.
