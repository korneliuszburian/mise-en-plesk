# mise-en-plesk

Production-oriented, read-only monitoring for WordPress installations on Plesk
hosts. The target is a complete operational scanner: discovery, risk
classification, persistent findings, bounded scheduling, and alert delivery.
See [the completion audit](docs/completion-audit-2026-08-18.md) for the release
gate; this repository is not intentionally scoped as a disposable v1.

Every push and pull request runs the test, typecheck, build, and whitespace
checks on Node.js 20 and 22 through GitHub Actions.

## Quickstart

```sh
pnpm install
pnpm typecheck
pnpm test
pnpm --silent run mise-plesk-audit doctor
pnpm --silent run mise-plesk-audit remote-preflight dev-ssh --json
source scripts/setup-bw-session.sh
pnpm --silent run mise-plesk-audit sync-ssh
pnpm --silent run mise-plesk-audit scan master-ssh --json --max-sites=20 --all-chunks
pnpm --silent run mise-plesk-audit scan all --json
```

Bitwarden items must be searchable with `mise-en-plesk`, contain a login
username and SSH URI, and use fields for optional metadata such as
`identitySource`. The local `inventory.json` is a cache and is gitignored.

The cache is validated before use: aliases must be safe SSH config names, the
stored alias must match its object key, ports must be valid TCP ports, and host
metadata may not contain control characters or shell-target separators. A
corrupt or hand-edited inventory fails closed before any SSH session starts.

The current organization also stores `master ssh` and `dev ssh` as Secure
Notes. Their read-only SSH shape is `host:port\nuser:password` (the separator
may be a literal `\\n`). `sync-ssh` understands these two notes and writes only
host metadata to `inventory.json`; the password is fetched again from
Bitwarden at scan time and passed to `sshpass` through the child environment.
The cache records only the non-secret `credentialMode` marker for Secure Note
password hosts, so `doctor` can fail early if `sshpass` is unavailable. Install
`sshpass` locally when password-authenticated SSH is required.

`remote-preflight <target>` is a read-only capability check over the same
typed SSH transport. It reports the remote UID, account name, kernel, and
presence of `bw`, Node, pnpm, sshpass, and systemd without installing or
changing anything. Use it before selecting a trusted scheduler runner; a
Plesk dev host is normally a scan target, not automatically a runner.

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
the JSON stream. Add `--json` to write the machine-readable report instead of
Markdown; the same JSON result is emitted on stdout. Set
`maxVulnerabilityLookupsPerHost` in the config to cap opt-in
WPVulnerability requests per host. Set `maxConcurrentSitesPerHost` to tune
the number of simultaneous site batches per host; the default is 4. For large
hosts, bound a run with `--max-sites=20 --offset=0` and repeat with the next
offset. `maxSitesPerHost` in config provides the same default for every run;
CLI flags take precedence. A bounded run only reconciles findings for the
installations it actually scanned. The scheduler accumulates findings in the
gitignored `.mise-en-plesk/scan-cycles.json` state (override with
`MISE_PLESK_SCAN_CYCLES` or `scanCycleStatePath`) and resolves stale findings
only after a complete host cycle. If that cycle state is missing or corrupt,
the scanner fails closed and does not emit false resolutions.
SSH commands have a bounded 60-second timeout by default; set
`sshCommandTimeoutMs` when a large Plesk filesystem needs a different explicit
limit. This changes only the local wait bound, never the remote command set.
`scan` and `monitor-health` use a local process lock at
`.mise-en-plesk/scan.lock` (override with `MISE_PLESK_RUN_LOCK`) so concurrent
processes cannot overwrite finding state or the notification outbox. The
scheduler owns that same lock and passes ownership to its child commands.
For an unattended sweep, use `--all-chunks`; it repeats bounded discovery up
to `maxScanChunksPerHost` (default 100, override with `--max-chunks=N`) and
writes one aggregate report. A budget-exhausted sweep remains incomplete and
does not resolve findings for the omitted suffix:
`scan all --json --max-sites=20 --all-chunks --max-chunks=100`. Starting
`--all-chunks` at a non-zero offset also intentionally does not resolve findings
for the omitted prefix.

`scripts/run-scheduled-scan.sh` uses incremental rotation by default: one
bounded chunk per configured host per cycle, with offsets persisted in the
gitignored `.mise-en-plesk/scan-cursor.json`. Override it with
`MISE_PLESK_SCAN_CURSOR`, or set `MISE_PLESK_SCHEDULE_ALL_CHUNKS=1` for an
explicit full sweep. Rotated JSON reports receive host and UTC-run suffixes so
successive cycles do not overwrite one another.

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

The following are manual-review signals, never automatic repairs: very old
core, abandoned plugins, known-vulnerable plugins, and PHP files under
`wp-content/uploads`. Finding severity controls alert routing: abandoned
plugins and ordinary update signals are P2, while critical/high vulnerabilities,
integrity anomalies, runtime failures, and possible backdoors are P1.

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
or reopened P1 findings; unchanged and P2 findings are not sent. Resolved P1
findings produce recovery notifications.
The webhook is provider-neutral so it can target an internal bridge, n8n, or a
WhatsApp Business adapter. Transient timeout/408/429/5xx failures receive a
bounded retry with backoff; permanent 4xx failures are not retried. Pending P1
events are retained in the local gitignored notification outbox and retried on
the next run, so a temporary alerting outage does not lose a finding. Disabled
channels remain pending, so enabling Hermes Agent later can deliver an alert
that was observed while Hermes was not configured.
Delivery history is stored separately in the gitignored notification history
file and applies a 24-hour per-finding, per-channel cooldown by default. Set
`notificationCooldownHours` in config to change it; set it to `0` to disable
the cooldown. Pending events are grouped by site in provider messages while
remaining individually represented in JSON and the outbox.
New and reopened P1 findings alert immediately; a resolved P1 emits a separate
`recovered` notification so the operator can close the incident loop.
Notification failures are logged briefly and never fail the read-only scan. The
URL is read at runtime and is never written to reports or inventory.

For an operator-owned Hermes Agent setup, alerts can be delivered through
Hermes without copying its WhatsApp credentials into this repository. Set
`MISE_PLESK_HERMES_WHATSAPP_TARGET` to an explicit Hermes target such as
`whatsapp:<chat-id>` and optionally `MISE_PLESK_HERMES_BIN` if `hermes` is not
on `PATH`. The scanner invokes `hermes send --to <target> <message>` only when
the target is configured. Verify it with the guarded command
`pnpm --silent run mise-plesk-audit hermes-test --confirm=<exact-target>`. The Hermes
channel is independent in the crash-safe outbox; a failed delivery is retried
on the next run. No Hermes or WhatsApp process activity occurs when the target
is unset.

Direct WhatsApp Business Cloud API delivery is also opt-in. Set
`MISE_PLESK_WHATSAPP_ACCESS_TOKEN`, `MISE_PLESK_WHATSAPP_PHONE_NUMBER_ID`,
`MISE_PLESK_WHATSAPP_RECIPIENT`, and
`MISE_PLESK_WHATSAPP_TEMPLATE_NAME`, and
`MISE_PLESK_WHATSAPP_GRAPH_VERSION`; optionally set
`MISE_PLESK_WHATSAPP_TEMPLATE_LANGUAGE`. The template must be approved in
WhatsApp Manager and provide one body text parameter. Tokens are read only
from the process environment and never persisted. Multiple pending P1 events
are delivered as bounded messages (900 characters by default); a failed chunk
stays pending while successfully delivered chunks are acknowledged separately.

After checking the configured recipient, verify the real provider path with
`pnpm --silent run mise-plesk-audit whatsapp-test --confirm=<configured recipient>`. This
is the only command that sends an intentional test message; it requires the
confirmation to match the runtime recipient exactly and does not contact
Plesk.

Run `mise-plesk-audit doctor` before a scheduled scan. It checks local
prerequisites, session presence, inventory/config validity, and reports
whether alerting is enabled. It also reports the monitor heartbeat as an
informational check. Alerting and heartbeat checks do not make a scan fail by
themselves. It also reports whether the WhatsApp configuration is disabled,
complete, or partially configured without printing secret values.
Direct `scan` commands repeat the blocking capability checks before opening
any SSH session, so a missing Bitwarden session, inventory, config, or required
password-auth SSH tool fails locally first.

`pnpm --silent run mise-plesk-audit monitor-health --json` evaluates the last completed scan
against `monitorMaxAgeHours` (default two hours), records a deduplicated P1
`monitor-stale` finding, and uses the configured webhook/WhatsApp adapters for
the alert. It is safe to run before every scheduled scan and returns normally
so a stale monitor can still recover by starting the next scan.

For a simple cron/systemd timer integration, run
`scripts/run-scheduled-scan.sh`. It runs `doctor` first and then defaults to
one bounded `scan <host> --json` chunk per configured host, writes
0600 logs under `.mise-en-plesk/logs/`, and uses a process-backed `flock`. Set
`MISE_PLESK_SCHEDULED_TARGET`, `MISE_PLESK_SCHEDULE_LOG_DIR`, or
`MISE_PLESK_SCHEDULE_LOCK_FILE` to override the defaults. The scheduled runner
uses a chunk size of 20 and persists per-host cursors; override that with
`MISE_PLESK_SCAN_CHUNK_SIZE`. Set `MISE_PLESK_SCHEDULE_ALL_CHUNKS=1` for an
explicit complete sweep. Exit code `75` means
another scan is already running. The lock is process-backed via `flock` and is
released automatically when the runner exits. When `MISE_PLESK_REPORTS` is not
set, the runner uses the configured `reportsDirectory` for both report lookup
and cursor advancement.

For a systemd deployment, use the guarded installer from a checkout at
`/opt/mise-en-plesk`. It is a dry run by default, uses fixed dedicated paths,
and refuses to overwrite an existing service, timer, or state directory.
Prepare `config.mise-en-plesk.json`, `inventory.json`, and the credential
before applying it:

```sh
source scripts/setup-bw-session.sh
scripts/update-systemd-bw-credential.sh
sudo --preserve-env=BW_SESSION scripts/update-systemd-bw-credential.sh \
  --apply --confirm=update-bw-session
pnpm install --frozen-lockfile
pnpm build
scripts/install-systemd.sh
sudo scripts/install-systemd.sh --apply --confirm=install-systemd
scripts/verify-systemd-install.sh
```

After installing the units, run the read-only deployment verifier on that
runner:

```sh
scripts/verify-systemd-install.sh
```

It checks unit syntax, timer state, the dedicated non-root service account,
the selected Bitwarden credential mode, and the systemd filesystem hardening.
It does not start, stop, reload, or modify any unit. On systemd 250 or newer,
the installer uses an encrypted credential under `/etc/mise-en-plesk`. Older
systemd uses a root-only, ephemeral credential under `/run/mise-en-plesk`,
which must be restored after every reboot.

The checkout is mounted read-only by systemd. Runtime state, reports, logs,
locks, cursors, findings, and notification outbox data live under
`/var/lib/mise-en-plesk`, owned by the dedicated service account. The timer
runs with `HOME=/var/lib/mise-en-plesk`, so an optional Hermes CLI uses that
account's own `~/.hermes` configuration. The unit optionally reads the
non-secret routing file `/etc/mise-en-plesk/mise-en-plesk.env`; copy
`deploy/systemd/mise-en-plesk.env.example` there and set the target only after
the service account's Hermes setup is complete. The timer runs the incremental
one-chunk-per-host mode. It never performs
remote remediation; `systemctl stop mise-en-plesk.timer` is the local stop
switch. Credential rotation is also a dry run by default. Before the session
expires, source `scripts/setup-bw-session.sh`, inspect
`scripts/update-systemd-bw-credential.sh`, then apply with
`sudo --preserve-env=BW_SESSION scripts/update-systemd-bw-credential.sh --apply --confirm=update-bw-session`.
Do not put a Bitwarden master password or any Plesk credential in unit files.
