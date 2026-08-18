# Completion audit: 2026-08-18

This is the completion gate for the final read-only company tool. The
repository is not treated as a v1 product. A requirement is only `done` when
the implementation, automated check, and operational evidence agree.

## Status vocabulary

- **done** — implemented and covered by a test or static check, with runtime
  evidence where the requirement crosses a machine boundary;
- **partial** — the code path exists, but operator-owned infrastructure or a
  production credential/configuration is still required for proof;
- **open** — implementation or verification work remains.

## Requirement matrix

| Area | Status | Evidence / gate |
| --- | --- | --- |
| TypeScript, Node.js, pnpm, strict build | done | `package.json`, `tsconfig.json`, `pnpm typecheck`, `pnpm build` |
| Bitwarden CLI session and Secure Note credentials | done | `src/bitwarden.ts`, runtime-only item fetch, credential-mode-aware `src/preflight.ts`, and direct-scan preflight proof |
| Local inventory cache without credentials | done | `src/ssh-inventory.ts`, ignored `inventory.json`, unit tests |
| SSH-only remote access and bounded commands | done | `src/plesk-scan.ts`, fixed command construction, timeout/process-group/output-bound tests |
| Plesk subscription and WordPress discovery | done | `scanPleskHost`, pagination cursor, alternate `version.php` signal, tests |
| WP core/plugin/theme audit | done | `src/wp-audit.ts`, batched WP-CLI probes, tests |
| Vulnerability enrichment | done | opt-in WPVulnerability adapter, cache/budget/error handling, tests |
| Suspicious uploads and integrity signals | done | independent uploads PHP probe, including WP-CLI failure fallback, checksum findings, tests, and real master runtime evidence |
| Stable findings and resolved/reopened state | done | `src/findings.ts`, `src/finding-state.ts`, `src/scan-cycle.ts`, atomic persistence and multi-chunk cycle tests |
| Markdown and JSON reports | done | `src/report.ts`, additive `AuditResult`, report tests, and CLI JSON-stream coverage |
| P1 alert delivery and retry/outbox | done | webhook + grouped/chunked WhatsApp Cloud + Hermes CLI adapters, per-finding/per-channel cooldown history, opened/reopened/resolved recovery events, bounded retry/outbox tests, partial-ack coverage, disabled-channel backlog proof, and crash-safe enqueue-before-state replay coverage |
| Stale monitor signal | done | `src/monitor-health.ts`, CLI and tests |
| Locking and concurrent-run protection | done | local lock, scheduler `flock`, lock tests |
| Bounded scan and per-host rotation | done | streamed/deduplicated paginated filesystem discovery, `scan-cursor.ts` plus `scan-cycle.ts`, scheduler, cursor/cycle tests and bounded runtime proof on master/dev |
| Production scheduler packaging | partial | non-root systemd service/timer examples, encrypted `LoadCredentialEncrypted` contract, optional non-secret Hermes `EnvironmentFile`, repeatable credential rotation helper, checkout read-only policy with mutable state under `/var/lib/mise-en-plesk`, scheduler integration coverage including custom `reportsDirectory`, and README install/stop instructions; deployment on the operator's actual always-on runner remains unverified |
| Master and dev real-host proof | done | current checkout completed fresh bounded read-only scans through `pnpm --silent`: `master-ssh` reported 216 subscriptions/1 candidate and `runtime-incompatible` (PHP 7.2.24 vs WP 7.0.4), `dev-ssh` reported 92 subscriptions/1 candidate and `wp-cli-broken` (`/usr/local/bin/wp: 404`); both SSH hosts were reachable, stdout parsed as JSON, and no credentials were written to reports |
| WhatsApp production delivery proof | partial | direct Cloud adapter plus Hermes CLI adapter, fake-client/process tests, and recipient-bound `whatsapp-test`/`hermes-test` confirmations are implemented; approved template, Hermes session, target, and runtime env are operator-owned |
| Full-fleet rotation proof | done | current checkout completed two scheduler cycles across both configured hosts; each host advanced independently from offset `0` to `2`, with four unique timestamped reports and persistent findings/outbox state |
| CI on supported Node versions | done | `.github/workflows/ci.yml`, Node 20/22 matrix; current `master` CI history has passed both jobs |
| Public repository / review trail | done | GitHub remote, semantic commit history, two-axis review required per major slice |
| Remote mutation safety audit | done | `tests/read-only-safety.test.ts` checks generated Plesk/WP commands against the forbidden mutation set |

## Latest local gate evidence

- `doctor --json`: `ok: true`; Node, `bw`, SSH, `sshpass`, `BW_SESSION`, inventory,
  and config all passed. Hermes and direct WhatsApp were correctly disabled because
  no provider target/credentials were configured in this shell.
- `pnpm test`: 28 files / 128 tests passed.
- `pnpm typecheck`, `pnpm build`, `git diff --check`, `bash -n scripts/*.sh`, and
  `systemd-analyze verify` on copied unit examples passed.
- GitHub Actions run `32134127563` passed both Node 20 and Node 22 jobs for
  commit `d8abbfa`.

## Completion gates

Before calling the goal complete, the following must be green in this
checkout:

1. `pnpm test`, `pnpm typecheck`, `pnpm build`, and `git diff --check`.
2. A bounded read-only scan of `master-ssh` and `dev-ssh`, with reports and
   cursor progress inspected without printing credentials.
3. A static command allowlist/regression test proving that remote probes do
   not contain mutation commands (`rm`, update commands, database writes,
   chmod, or arbitrary sudo).
4. A standards/spec review of the final implementation diff, followed by
   fixes, a semantic commit, push, and green GitHub CI.
5. A documented operator deployment check for the scheduler and selected WhatsApp
   adapter, followed by `whatsapp-test --confirm=<recipient>` or
   `hermes-test --confirm=<target>` and one recovery delivery.
   Missing production secrets are an infrastructure prerequisite, not a reason
   to weaken the read-only scanner or fake delivery evidence.

The package version remains pre-release until these gates are green. That is
an honest release-state marker, not a product scope decision: the target is
the complete tool described by this matrix.
