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
| Bitwarden CLI session and Secure Note credentials | done | `src/bitwarden.ts`, runtime-only item fetch, `src/preflight.ts` |
| Local inventory cache without credentials | done | `src/ssh-inventory.ts`, ignored `inventory.json`, unit tests |
| SSH-only remote access and bounded commands | done | `src/plesk-scan.ts`, fixed command construction, timeout/process-group tests |
| Plesk subscription and WordPress discovery | done | `scanPleskHost`, pagination cursor, alternate `version.php` signal, tests |
| WP core/plugin/theme audit | done | `src/wp-audit.ts`, batched WP-CLI probes, tests |
| Vulnerability enrichment | done | opt-in WPVulnerability adapter, cache/budget/error handling, tests |
| Suspicious uploads and integrity signals | done | independent uploads PHP probe, including WP-CLI failure fallback, checksum findings, tests, and real master runtime evidence |
| Stable findings and resolved/reopened state | done | `src/findings.ts`, `src/finding-state.ts`, atomic persistence/tests |
| Markdown and JSON reports | done | `src/report.ts`, additive `AuditResult`, report tests |
| P1 alert delivery and retry/outbox | done | webhook + WhatsApp adapters, retry/outbox tests |
| Stale monitor signal | done | `src/monitor-health.ts`, CLI and tests |
| Locking and concurrent-run protection | done | local lock, scheduler `flock`, lock tests |
| Bounded scan and per-host rotation | done | streamed paginated filesystem discovery, `scan-cursor.ts`, scheduler, cursor tests and bounded runtime proof on master/dev |
| Production scheduler packaging | partial | non-root systemd service/timer examples, encrypted `LoadCredentialEncrypted` contract, repeatable credential rotation helper, hardened filesystem policy, and README install/stop instructions; deployment on the operator's actual always-on runner remains unverified |
| Master and dev real-host proof | done | current checkout completed bounded read-only scans: `master-ssh` reported 216 subscriptions/1 candidate and classified the site as runtime-incompatible, `dev-ssh` reported 92 subscriptions/1 candidate and classified the site as WP-CLI-broken; no credentials were written to reports |
| WhatsApp production delivery proof | partial | adapter, fake-client tests, and recipient-bound `whatsapp-test --confirm=<recipient>` are implemented; approved template and runtime env are operator-owned |
| Full-fleet rotation proof | done | current checkout completed two scheduler cycles across both configured hosts; each host advanced independently from offset `0` to `2`, with four unique timestamped reports and persistent findings/outbox state |
| CI on supported Node versions | done | `.github/workflows/ci.yml`, Node 20/22 matrix; CI run `32125853131` passed both jobs |
| Public repository / review trail | done | GitHub remote, semantic commit history, two-axis review required per major slice |
| Remote mutation safety audit | done | `tests/read-only-safety.test.ts` checks generated Plesk/WP commands against the forbidden mutation set |

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
5. A documented operator deployment check for the scheduler and WhatsApp
   adapter, followed by `whatsapp-test --confirm=<recipient>` and one recovery delivery.
   Missing production secrets are an infrastructure prerequisite, not a reason
   to weaken the read-only scanner or fake delivery evidence.

The package version remains pre-release until these gates are green. That is
an honest release-state marker, not a product scope decision: the target is
the complete tool described by this matrix.
