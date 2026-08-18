# mise-en-plesk

Small, read-only tooling for auditing WordPress installations on Plesk hosts.

Every push and pull request runs the test, typecheck, build, and whitespace
checks on Node.js 20 and 22 through GitHub Actions.

## Quickstart

```sh
pnpm install
pnpm typecheck
pnpm test
pnpm run mise-plesk-audit doctor
source scripts/setup-bw-session.sh
pnpm run mise-plesk-audit sync-ssh
pnpm run mise-plesk-audit scan master-ssh --json --max-sites=20 --all-chunks
pnpm run mise-plesk-audit scan all --json
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

Some non-root SSH accounts can read WordPress files but cannot invoke Plesk
CLI. Add that alias to `sudoHosts` in the local config to enable non-interactive
`sudo -S` for the fixed read-only Plesk/WP commands on that host. The scanner
feeds the short-lived SSH Secure Note password through stdin only; it never
appears in argv, logs, reports, or files. If the sudo password differs, the
scan falls back to non-root filesystem discovery and records a warning.

`scan all` reads the selected aliases from `config.mise-en-plesk.json` (the
example uses `master-ssh` and `dev-ssh`), scans
them sequentially, and writes one aggregate report. Progress is written to
stderr so machine consumers can use the command without mixing progress into
the report. Add `--json` to write the machine-readable report instead of
Markdown. Set `maxVulnerabilityLookupsPerHost` in the config to cap opt-in
WPVulnerability requests per host. Set `maxConcurrentSitesPerHost` to tune
the number of simultaneous site batches per host; the default is 4. For large
hosts, bound a run with `--max-sites=20 --offset=0` and repeat with the next
offset. `maxSitesPerHost` in config provides the same default for every run;
CLI flags take precedence. A bounded run only reconciles findings for the
installations it actually scanned, and only the final chunk can resolve stale
findings for the whole host.
SSH commands have a bounded 60-second timeout by default; set
`sshCommandTimeoutMs` when a large Plesk filesystem needs a different explicit
limit. This changes only the local wait bound, never the remote command set.
`scan` and `monitor-health` use a local process lock at
`.mise-en-plesk/scan.lock` (override with `MISE_PLESK_RUN_LOCK`) so concurrent
processes cannot overwrite finding state or the notification outbox. The
scheduler owns that same lock and passes ownership to its child commands.
For an unattended complete run, use `--all-chunks`; it repeats bounded
discovery until every installation is covered and writes one aggregate report:
`scan all --json --max-sites=20 --all-chunks`. Starting `--all-chunks` at a
non-zero offset intentionally does not resolve findings for the omitted prefix.

Online vulnerability lookups are opt-in. Set
`MISE_PLESK_ENABLE_VULNS=1` before running `scan` to query the public
WPVulnerability API. With the variable unset (or any value other than `1`),
the scanner performs no external vulnerability API requests. The opt-in lookup
covers plugins, themes, and core. API failures are reported as `unavailable`,
never treated as safe, and never trigger remediation. Known and empty responses
are cached locally for 12 hours by default in the ignored
`.mise-en-plesk/vulnerabilities.json`; configure `vulnerabilityCachePath` or
`vulnerabilityCacheTtlHours` to change this. Lookup budgets also include core
and theme resources, and a budget-exhausted result is reported as `partial`.

The following findings are P1 manual-review signals, not automatic repairs:
very old core, abandoned plugins, known-vulnerable plugins, and PHP files under
`wp-content/uploads`.

The read-only WP-CLI batch also checks for available core/theme updates and
verifies core and plugin checksums. A checksum failure is a review signal, not
an automatic cleanup action; custom or premium plugins may not have matching
WordPress.org checksums.

Each host report also includes best-effort SSH-only facts: Plesk version, the
default PHP CLI version, and disk usage for `/var/www/vhosts`. Fact collection
is informational; an unavailable fact never turns a reachable host into a
failed scan.

Every discovered WordPress location includes a conservative classification in
JSON: `production`, `staging`, `backup`, or `unknown`, with the reason for the
classification. Standard Plesk `httpdocs` and `public_html` paths are treated
as production only when no staging or backup marker is present. The scanner
does not infer production status from a `wp-config.php` file alone. Discovery
also accepts `wp-includes/version.php` as an alternate WordPress candidate
signal and preserves the signal in JSON; WP-CLI health still determines
whether the candidate is operational.

Each scan also writes a local, gitignored finding state file at
`.mise-en-plesk/findings.json` (override with `MISE_PLESK_FINDINGS` or
`findingsStatePath`). Finding IDs are stable per host/site/signal, so unchanged
risks are suppressed while new, resolved, and reopened risks are emitted in the
JSON report as `findingEvents`. This state is local bookkeeping only; it never
changes a remote host.

Optional alerts use `MISE_PLESK_ALERT_WEBHOOK_URL`. The scanner POSTs only new
or reopened P1 findings; unchanged, resolved, and P2 findings are not sent.
The webhook is provider-neutral so it can target an internal bridge, n8n, or a
WhatsApp Business adapter. Transient timeout/408/429/5xx failures receive a
bounded retry with backoff; permanent 4xx failures are not retried. Pending P1
events are retained in the local gitignored notification outbox and retried on
the next run, so a temporary alerting outage does not lose a finding. Notification
failures are logged briefly and never fail the read-only scan. The URL is read at
runtime and is never written to reports or inventory.

Direct WhatsApp Business Cloud API delivery is also opt-in. Set
`MISE_PLESK_WHATSAPP_ACCESS_TOKEN`, `MISE_PLESK_WHATSAPP_PHONE_NUMBER_ID`,
`MISE_PLESK_WHATSAPP_RECIPIENT`, and
`MISE_PLESK_WHATSAPP_TEMPLATE_NAME`, and
`MISE_PLESK_WHATSAPP_GRAPH_VERSION`; optionally set
`MISE_PLESK_WHATSAPP_TEMPLATE_LANGUAGE`. The template must be approved in
WhatsApp Manager and provide one body text parameter. Tokens are read only
from the process environment and never persisted.

Run `mise-plesk-audit doctor` before a scheduled scan. It checks local
prerequisites, session presence, inventory/config validity, and reports
whether alerting is enabled. It also reports the monitor heartbeat as an
informational check. Alerting and heartbeat checks do not make a scan fail by
themselves. It also reports whether the WhatsApp configuration is disabled,
complete, or partially configured without printing secret values.

`pnpm run mise-plesk-audit monitor-health --json` evaluates the last completed scan
against `monitorMaxAgeHours` (default two hours), records a deduplicated P1
`monitor-stale` finding, and uses the configured webhook/WhatsApp adapters for
the alert. It is safe to run before every scheduled scan and returns normally
so a stale monitor can still recover by starting the next scan.

For a simple cron/systemd timer integration, run
`scripts/run-scheduled-scan.sh`. It runs `doctor` first and then defaults to
`scan all --json`, writes
0600 logs under `.mise-en-plesk/logs/`, and uses a process-backed `flock`. Set
`MISE_PLESK_SCHEDULED_TARGET`, `MISE_PLESK_SCHEDULE_LOG_DIR`, or
`MISE_PLESK_SCHEDULE_LOCK_FILE` to override the defaults. The scheduled runner
uses bounded complete scans with 20 sites per chunk; override that with
`MISE_PLESK_SCAN_CHUNK_SIZE`. Exit code `75` means
another scan is already running. The lock is process-backed via `flock` and is
released automatically when the runner exits.
