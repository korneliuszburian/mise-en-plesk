# Scheduler resilience runtime proof — 2026-08-24

Scope: controlled deployment and read-only runtime verification of scheduler
resilience commit `f71ba09`, deployed through documentation head `bf3fd10`.

## Deployment evidence

- Exact deployed commit:
  `bf3fd108ae66fe05fcd345150428fef4034a5024`.
- Candidate gate on the dev runner: 38/38 test files, 247/247 tests,
  typecheck, build, and shell syntax passed.
- Previous checkout preserved at
  `/var/lib/mise-en-plesk/deployment-backups/bf3fd108ae66fe05fcd345150428fef4034a5024-before/checkout`.
- Deployment verifier passed with `/opt/mise-en-plesk` owned by `root:root`,
  mode `0755`, an enabled/active timer, and the non-root hardened service.
- No Meta WhatsApp drop-in or credential was present; no outbound message was
  attempted.

The timer was started while an earlier cycle was still in systemd's
`activating` state. That mixed-version cycle exited successfully but was not
accepted as proof. The subsequent manually requested service invocation began
and ended entirely on `bf3fd10`; only that cycle is used below.

## Full new-version cycle

The service completed with `Result=success` and `ExecMainStatus=0`.

- Master filesystem discovery reached its read timeout at persisted offset
  340. The scanner emitted `340 -> 340 (deferred)`, preserved the cursor, and
  continued to the next host.
- Dev audited its bounded 20-site page and emitted `20 -> 40 (advanced)`.
- The final scheduler message reported one deferred host page and explicitly
  stated that cursors were preserved for retry; it did not claim an entirely
  successful fleet cycle.
- Durable state contained `deferredSince.master-ssh`, no `failedAt`, and
  cursors `{ master-ssh: 340, dev-ssh: 40 }`.
- After completion the timer remained active and the service returned to
  inactive.

Remote activity remained inside the typed read-only command policy: Plesk and
WP Toolkit inventory, WP-CLI reads, bounded filesystem discovery, integrity
checks, and suspicious-upload reads. No Plesk, WordPress, database, plugin,
theme, or filesystem mutation was executed.

This proves the reviewed scheduler behavior against the real transient timeout
that previously failed the service: a source gap is durable and retryable,
does not corrupt progress, and does not prevent another host from advancing.
