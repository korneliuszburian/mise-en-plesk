# mise-en-plesk discovery

Date: 2026-08-18

## Product direction

The Markdown report is an inspection artifact. The useful product is a
read-only security monitor that detects new WordPress risk before a client
reports it, keeps the finding open/resolved state, and sends a concise alert.

```text
Bitwarden inventory
  -> SSH-only Plesk discovery
  -> WordPress probes
  -> vulnerability enrichment
  -> normalized findings
  -> state/diff
  -> WhatsApp notification
```

No remediation belongs in this product yet. A future remediation workflow must
be a separate, explicitly confirmed command.

## Current technical stack

- Node.js 20+ / TypeScript / pnpm.
- TypeScript modules with no application framework or runtime server.
- `tsx` for the CLI, `tsc` for build/typecheck, Vitest for tests.
- Bitwarden CLI is the credential source. Secure Notes currently provide the
  `master` and `dev` SSH credentials at runtime.
- SSH uses `sshpass` when required, a local ControlMaster socket, and bounded
  connection/command timeouts. Passwords are kept out of argv and inventory.
- Plesk discovery uses read-only `plesk bin subscription --list` and filesystem
  discovery of `wp-config.php` and, in the CLI path, the alternate
  `wp-includes/version.php` signal. Candidate signals are preserved so a
  filesystem match is not confused with a healthy live site.
- WordPress checks run remotely through WP-CLI: core version, plugin metadata,
  checksum verification, and PHP files below `wp-content/uploads`.
- Host context is collected through fixed SSH-only commands for Plesk version,
  default PHP CLI version, and `/var/www/vhosts` disk usage; failures become
  warnings instead of aborting the site scan.
- Vulnerability enrichment is opt-in through `MISE_PLESK_ENABLE_VULNS=1` and
  uses the public WPVulnerability API. The API describes itself as free/open,
  provides core/plugin/theme endpoints, and does not require an API key:
  [WPVulnerability API](https://www.wpvulnerability.com/).

## Evidence from the current master scan

The read-only scan found 215 Plesk subscriptions and 377 WordPress config
locations on `master`.

- 377/377 locations were reachable through the SSH/WP audit path.
- 189 were classified as runtime-incompatible.
- 135 returned a WP-CLI/PHP/plugin error requiring manual review.
- 53 completed without a health status error.
- 13 had PHP files below `wp-content/uploads`.

These numbers prove the probes are useful, but also show that a full-fleet
scan is too slow and too noisy to be the alerting unit by itself.

## Current status and remaining work

### Discovery quality

`wp-config.php` is a strong candidate signal, not proof that every path is a
live customer site. The inventory can include staging, backups, `.trash`,
nested copies, and abandoned directories. The scanner now emits a conservative
classification (`production`, `staging`, `backup`, or `unknown`) with a reason.
Standard `httpdocs`/`public_html` paths become production only when no staging
or backup marker is present; ambiguous paths remain unknown.

### Findings and delivery

Typed findings, stable IDs, first/last seen state, resolved/reopened
transitions, and a local atomic notification outbox are implemented. P1 events
are retried with bounded backoff and remain pending after a provider outage;
delivered entries are compacted. The outbox is deliberately local and does not
pretend to provide a distributed delivery guarantee.

### Vulnerability coverage

Online vulnerability lookup is opt-in and now covers core, plugins, and themes.
The adapter records resource status and lookup timestamps, caches only known or
empty responses, and treats API outages as `unavailable` rather than `safe`.
Runtime and infrastructure enrichment remain separate signals.
The resource coverage follows the provider's [API reference](https://docs.wpvulnerability.com/)
and its documented core/plugins/themes scope.

### Runtime

The CLI remains an on-demand process driven by the scheduler script. Proactive
alerting requires an
always-on trusted runner with SSH access, a Bitwarden session/credential
strategy, persistent state, and a WhatsApp sender. This is an operational
deployment decision, not a reason to add a web framework to the scanner.

## Delivered implementation checkpoints

- typed findings with stable IDs and scoped reconciliation;
- local finding state with resolved/reopened transitions;
- core/plugin/theme vulnerability enrichment with bounded lookups and cache;
- webhook and WhatsApp adapters with bounded retry and persistent outbox;
- stale-monitor health check and scheduler-friendly bounded scans;
- per-chunk finding persistence and alert delivery, so a large host does not
  wait for the entire fleet before emitting a new P1.

Remaining work is completion hardening: prove the scheduler on the real
operator machine, validate full-fleet runtime behavior, review outbox
concurrency/retention policy, and complete the final safety and operational
audit. None of those items authorizes remote mutation.

## Explicit non-goals

- No automatic plugin/core/theme updates.
- No file deletion or cleanup.
- No database writes.
- No WordPress plugin installed on customer sites as part of this tool.
- No dashboard or heavy backend before findings/state/alerting prove useful.
- No WhatsApp message for every site or every unchanged finding.

## First implementation ticket

`feat: add typed findings and state transitions`

Acceptance criteria:

1. A scan produces typed findings without changing existing report top-level
   shape.
2. The same finding has the same ID across repeated scans.
3. A new finding is emitted once; an unchanged finding is suppressed; a fixed
   finding produces a resolved event.
4. Tests cover all current P1 classes and state transitions.
5. No remote command outside the existing read-only allowlist is introduced.

## Research-backed probe matrix

The next scanner layer should use the data WP-CLI already exposes instead of
scraping HTML or installing a plugin on customer sites.

### Build now

- `wp core check-update --minor --format=json` for an explicit core update
  signal. WP-CLI documents `core check-update` as a Version Check API lookup
  and `core verify-checksums` as checksum verification:
  [WP-CLI core commands](https://developer.wordpress.org/cli/commands/core/).
- Extend `wp plugin list --format=json` with `auto_update`, `requires_php`,
  and the documented WordPress.org metadata. The official command reference
  supports these fields and JSON output:
  [WP-CLI plugin list](https://developer.wordpress.org/cli/commands/plugin/list/).
- Add `wp plugin verify-checksums --all --strict`. A missing checksum for a
  premium/custom plugin is `unknown/custom-source`, not proof of malware; WP-CLI
  documents that WordPress.org may not have checksums for those plugins:
  [official WP-CLI security checks](https://developer.wordpress.org/news/2024/09/website-security-checks-wp-cli-for-site-owners-and-administrators/).
- Add `wp theme list --format=json` with active/inactive, version, update,
  update_version, and auto_update:
  [WP-CLI theme list](https://developer.wordpress.org/cli/commands/theme/list/).
- Keep file signals read-only: PHP in uploads, unexpected PHP in cache/backup
  directories, and recently changed executable files. Emit evidence and
  confidence, never a claim of infection from one filename alone.
- Collect host-level PHP, web-server, disk-space, and Plesk version facts when
  the remote account can provide them. These should not be duplicated per site.

### Build later, behind explicit flags

- `wp core verify-checksums --include-root` and strict plugin checksums for
  deeper integrity evidence.
- WordPress Site Health read-only checks for loopback, HTTPS, background
  updates, and WordPress.org communication. The official REST reference
  exposes these checks, but using them adds an HTTP path and should not enter
  the SSH-only baseline:
  [WordPress Site Health tests](https://developer.wordpress.org/rest-api/reference/wp-site-health-tests/).
- Multisite-aware scans using `wp site list --field=url`, with child sites
  represented as separate identities.
- Supply-chain intelligence from the vulnerability provider after its schema
  is stable enough to model separately from ordinary CVEs.

### Deliberately exclude

- `wp plugin update`, `wp theme update`, `wp core update`, `wp db`, `rm`,
  `chmod`, and any Plesk action with a mutation flag.
- `wp eval` as a generic health probe; it can load arbitrary application code
  and makes the read-only contract harder to reason about.
- Installing a security plugin on customer sites just to inspect them.

## Risk semantics

WordPress's hardening guidance identifies plugins and themes as key weakness
areas, stresses keeping software current, and frames security as risk
reduction rather than a guarantee:
[WordPress security and hardening](https://developer.wordpress.org/advanced-administration/security/hardening/).

| Signal | Default severity | Meaning |
| --- | --- | --- |
| Confirmed critical/high vulnerability | P1 | Immediate manual review |
| PHP parse/fatal error while loading WP | P1 | Likely client-visible breakage |
| PHP executable in uploads | P1 | Possible backdoor; inspect evidence |
| Core checksum mismatch | P1 | Integrity anomaly; investigate |
| Core/plugin/theme update available | P2 | Maintenance work |
| Abandoned or closed WordPress.org plugin | P2 | Replacement/review needed |
| SSH/WP-CLI unavailable | P1 operational | Monitor cannot establish health |
| Unknown/custom plugin checksum | Info/P2 | Not evidence of compromise |

Every P1 should include `why`, `evidence`, `source`, `firstSeen`, and a
human-readable next action. Unknown must never be reported as safe.

## Alerting design

WhatsApp is a delivery adapter, not part of the scanner core. The core emits:

```text
FindingOpened | FindingReopened | FindingResolved | MonitorStale
```

The notifier layer applies deduplication by stable finding ID, per-finding
cooldown, grouping by site, severity routing, bounded retry/backoff, and a
delivery audit without secrets. P1 is immediate, P2 can be a digest, and info
never needs WhatsApp.

The first notifier is a fake/console adapter for tests. The production adapter
uses the chosen business WhatsApp provider with credentials outside Git,
preferably fetched through the approved secret mechanism. The scanner must
still work when WhatsApp is unavailable and must persist findings independently
of delivery success.

## Operational shape

The full master run is long enough that a single all-fleet cycle is not the
right alerting unit. Use a persistent queue:

1. discover and classify installations;
2. prioritize production and previously risky sites;
3. scan a bounded batch;
4. persist findings immediately;
5. alert on transitions immediately;
6. continue the queue and expose monitor freshness.

This gives early alerts without opening hundreds of new SSH connections or
waiting for every low-risk backup path to finish. A stale monitor alert is a
first-class finding because silence from a dead scanner is not safety.

## Completion gate

The tool is complete only after a requirement-by-requirement audit proves the
read-only command allowlist, credential handling, bounded scan behavior,
finding persistence, alert retry/outbox behavior, scheduler recovery, test
coverage, CI, and bounded runtime scans on the in-scope hosts.

The first production milestone is not a dashboard. It is: a new P1 appears,
one useful WhatsApp message arrives, the same P1 does not spam, and a resolved
finding produces a recovery message — while every remote operation remains
read-only.

## Library and approach discovery

### Recommended baseline stack

#### Keep OpenSSH as the SSH adapter

The current `child_process` + system `ssh` approach is the right default for
this operator environment. It gives us OpenSSH's host-key behavior,
`sshpass` compatibility with the existing Secure Notes, ControlMaster reuse,
and commands that are easy to inspect in a process-level incident review.

The `ssh2` Node module is a credible pure-JavaScript SSH client with exec and
SFTP support, but adopting it would replace a working security boundary and
require us to reimplement connection reuse, password handling, timeout
semantics, and host-key policy in application code:
[ssh2](https://github.com/mscdex/ssh2). Keep it as a future adapter only if we
eventually need native channel multiplexing or key-agent integration.

#### Use a small queue, not a job framework

The scanner needs bounded concurrency and priority, not Redis. The current
explicit batch loop is readable and works. If scheduling requirements outgrow
it, `p-queue` is the smallest obvious upgrade: it supports concurrency,
timeouts, rate caps, priorities, backpressure, and cancellation. It is native
ESM and explicitly describes itself as feature-complete, so adding it would
also require deciding whether to migrate this CommonJS package:
[p-queue](https://github.com/sindresorhus/p-queue).

Recommendation: keep the local queue for the next slice; consider `p-queue`
only when the persistent scan queue is implemented. Do not add BullMQ,
Redis, RabbitMQ, or a worker framework yet.

#### Use SQLite for durable finding state, but pin the runtime deliberately

The first state prototype can use an atomic JSON file. For an always-on
monitor with event history, deduplication, leases, and recovery transitions,
SQLite is a better fit than a growing JSON document.

Node's built-in `node:sqlite` is available in modern Node releases but is
currently documented as a Release Candidate. The repository currently allows
Node 20+, so using it would require raising and pinning the runtime baseline:
[Node SQLite API](https://nodejs.org/download/release/latest-v24.x/docs/api/sqlite.html).

Recommendation: implement the domain repository behind an interface, start
with JSON for the first finding slice, then choose either `node:sqlite` with a
Node 24+ baseline or a mature native SQLite package once the monitor deployment
target is fixed. Do not introduce Postgres for this single-runner tool.

#### Use native `fetch` for vulnerability and notification HTTP

Node already provides the HTTP primitive needed for small JSON APIs. Keep the
current isolated WPVulnerability adapter and add caching/rate limiting around
it. Avoid axios, a provider SDK, or an HTTP framework until a concrete provider
requires one.

WPScan is a useful alternative data source and its API covers WordPress core,
plugins, and themes, but it requires an API token and its terms distinguish
commercial/enterprise usage and prohibit unrestricted data caching. It is
therefore a possible licensed enrichment source, not a drop-in replacement for
the no-key WPVulnerability path:
[WPScan API](https://wpscan.com/docs/api/v3/),
[WPScan API usage terms](https://wpscan.com/api/).

The standalone WPScan CLI is also a Ruby/black-box HTTP scanner with a custom
commercial license. It can be run as an optional external investigation tool,
but it conflicts with the SSH-only baseline and should not become a runtime
dependency of the TypeScript scanner:
[WPScan user documentation](https://github.com/wpscanteam/wpscan/wiki/WPScan-User-Documentation).

#### Use systemd timers for production scheduling

The scheduler should be an OS concern: a systemd timer starts the CLI, logs
stdout/stderr, restarts after failure, and keeps secrets out of the codebase.
`node-cron` would only keep a process alive and would not solve host deployment,
restart, or stale-monitor detection. A local development command can remain
`scan`, while the production wrapper runs queue batches and persists state.

#### Use a notifier port and direct provider HTTP

Define a tiny interface such as:

```ts
interface Notifier {
  send(event: FindingEvent): Promise<void>;
}
```

Implement `ConsoleNotifier` and `FakeNotifier` first. Then add one WhatsApp
provider adapter using native `fetch`, with credentials loaded at runtime from
the approved secret store. Do not use unofficial WhatsApp Web automation
libraries or make WhatsApp delivery a prerequisite for recording a finding.

### What makes the stack production-worthy

- `node:child_process` + OpenSSH for the remote boundary;
- TypeScript domain modules with no container/DI framework;
- explicit bounded queue with per-host and per-site limits;
- JSON first, SQLite behind a repository interface;
- native `fetch` with AbortController, cache, and rate limits;
- systemd timer plus a stale-monitor event;
- fake notifier tests and one provider adapter;
- structured JSON Lines logs with redaction, not a logging framework;
- immutable finding evidence and explicit `unknown` state.

### Stack decisions to make before production monitor deployment

1. Where the always-on runner lives and whether it can access Bitwarden
   non-interactively.
2. Whether the production runtime is pinned to Node 24+ for built-in SQLite or
   stays on Node 20 and uses JSON first.
3. Which WhatsApp Business provider/account is authorized for company alerts.
4. Whether vulnerability enrichment starts with WPVulnerability only or adds a
   licensed WPScan source.
5. Which sites are production versus staging/backup/unknown for alert routing.
