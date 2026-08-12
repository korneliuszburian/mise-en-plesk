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
pnpm mise-plesk-audit scan all --json
```

Bitwarden items must be searchable with `mise-en-plesk`, contain a login
username and SSH URI, and use fields for optional metadata such as
`identitySource`. The local `inventory.json` is a cache and is gitignored.

The `scan <target>` command runs a read-only SSH/Plesk/WordPress scan and writes
a Markdown report under `reports/`. Plesk commands are intentionally
read-only; this project does not delete anything, update plugins/themes, or
change databases.

`scan all` reads the selected aliases from `config.mise-en-plesk.json`, scans
them sequentially, and writes one aggregate report. Progress is written to
stderr so machine consumers can use the command without mixing progress into
the report. Add `--json` to write the machine-readable report instead of
Markdown. Set `maxVulnerabilityLookupsPerHost` in the config to cap opt-in
WPVulnerability requests per host.

Online plugin vulnerability lookups are opt-in. Set
`MISE_PLESK_ENABLE_VULNS=1` before running `scan` to query the public
WPVulnerability API. With the variable unset (or any value other than `1`),
the scanner performs no external vulnerability API requests. API failures are
reported as missing vulnerability data and never trigger remediation.

The following findings are P1 manual-review signals, not automatic repairs:
very old core, abandoned plugins, known-vulnerable plugins, and PHP files under
`wp-content/uploads`.
