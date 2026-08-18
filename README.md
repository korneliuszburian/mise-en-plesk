# mise-en-plesk

Small, read-only tooling for auditing WordPress installations on Plesk hosts.

## Quickstart

```sh
pnpm install
pnpm typecheck
pnpm test
pnpm mise-plesk-audit doctor
source scripts/setup-bw-session.sh
pnpm mise-plesk-audit sync-ssh
pnpm mise-plesk-audit scan master
pnpm mise-plesk-audit scan all --json
```

Bitwarden items must be searchable with `mise-en-plesk`, contain a login
username and SSH URI, and use fields for optional metadata such as
`identitySource`. The local `inventory.json` is a cache and is gitignored.

The current organization also stores `master ssh` and `dev ssh` as Secure
Notes. Their read-only SSH shape is `host:port\nuser:password` (the separator
may be a literal `\\n`). `sync-ssh` understands these two notes and writes only
host metadata to `inventory.json`; the password is fetched again from
Bitwarden at scan time and passed to `sshpass` through the child environment.
Install `sshpass` locally when password-authenticated SSH is required.

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

The read-only WP-CLI batch also checks for available core/theme updates and
verifies core and plugin checksums. A checksum failure is a review signal, not
an automatic cleanup action; custom or premium plugins may not have matching
WordPress.org checksums.

Each scan also writes a local, gitignored finding state file at
`.mise-en-plesk/findings.json` (override with `MISE_PLESK_FINDINGS` or
`findingsStatePath`). Finding IDs are stable per host/site/signal, so unchanged
risks are suppressed while new, resolved, and reopened risks are emitted in the
JSON report as `findingEvents`. This state is local bookkeeping only; it never
changes a remote host.

Optional alerts use `MISE_PLESK_ALERT_WEBHOOK_URL`. The scanner POSTs only new
or reopened P1 findings; unchanged, resolved, and P2 findings are not sent.
The webhook is provider-neutral so it can target an internal bridge, n8n, or a
WhatsApp Business adapter. Notification failures are logged briefly and never
fail the read-only scan. The URL is read at runtime and is never written to
reports or inventory.

Run `mise-plesk-audit doctor` before a scheduled scan. It checks local
prerequisites, session presence, inventory/config readability, and reports
whether alerting is enabled. Alerting is informational and does not make a
scan fail by itself.
