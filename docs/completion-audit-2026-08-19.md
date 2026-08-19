# Completion audit: 2026-08-19

This is the current completion gate for the final read-only company tool. A
requirement is `done` only when implementation, automated verification, and
cross-machine runtime evidence agree. `partial` means an operator-owned
external integration still needs real proof; it does not mean the scanner code
is a prototype.

## Requirement matrix

| Area | Status | Evidence |
| --- | --- | --- |
| Strict TypeScript / Node / pnpm | done | Node 20+ contract, strict typecheck, build, Node 20/22 CI |
| Bitwarden Secure Notes / no persisted credentials | done | runtime-only Bitwarden lookup, ephemeral systemd credential and CLI state |
| SSH-only bounded host access | done | fixed typed command allowlist, timeout/output/process bounds, master/dev runtime proof |
| Plesk and WordPress discovery | done | subscriptions, canonical paths, WP Toolkit, WP-CLI and filesystem fallback |
| Classic and Bedrock audit | done | canonical layout evidence, static core/plugin/theme/uploads probes, explicit unavailable states |
| Vulnerability and risk findings | done | bounded/cacheable WPVulnerability lookups, integrity, abandoned/update/backdoor findings |
| Persistent lifecycle state | done | stable finding IDs, transition sequence, opened/resolved/reopened events and scoped reconciliation |
| Markdown / additive JSON reports | done | reports, findings, progress, source/capability evidence and tests |
| Bounded fleet rotation | done | independent host cursors, chunk budgets, full-cycle state and natural master/dev cycles |
| Scheduler deployment | done | non-root hardened systemd service/timer deployed on dev runner; timer enabled and active |
| Monitor heartbeat / stale alert | done | persisted heartbeat and `monitor-stale` lifecycle finding |
| Notification reliability | done | outbox v2 records only active channels; v1 ambiguous backlog retires; cooldown, partial acceptance, recovery and crash replay tests |
| Provider semantics | done | `accepted/failed/unknown`; ambiguous network outcomes pause automatic retry; stable event refs prevent silent duplicate confusion |
| Meta WhatsApp transport | done | approved-template request, strict `wamid.*` acceptance, durable `wamid -> eventReferences` receipts |
| Meta credential deployment | done | guarded stdin bootstrap, root-only ephemeral credential, non-secret drop-in, lock, rollback on error/INT/TERM |
| Guarded production test path | done | exact-recipient confirmation and transient hardened systemd unit using the service credential context |
| Hermes | done as optional pilot | real CLI adapter retained; research rejects Baileys/Hermes Cloud as the production critical channel |
| Remote mutation safety | done | no Plesk/WP write, update, delete, DB mutation or arbitrary sudo path |
| Real WhatsApp submission and recovery | partial | requires operator-owned Meta WABA, System User token, sender phone ID, approved utility template and exact recipient |

## Current verification

- Commit `5ec743f` passed the two-axis Standards/Spec review after three review
  rounds; all blocker/high/medium findings were fixed.
- GitHub Actions run `32270965303` passed both supported Node jobs.
- Local gate: 38 test files / 233 tests, `pnpm typecheck`, `pnpm build`,
  `bash -n scripts/*.sh`, systemd unit verification, and `git diff --check`.
- Dev runner deployment is exact commit
  `5ec743f3cfc8b45aa894689ec6461b40231dc97a`; the prior checkout is preserved
  under `/var/lib/mise-en-plesk/deployment-backups/5ec743f3cfc8b45aa894689ec6461b40231dc97a-before/checkout`.
- On the deployed checkout: 38/38 test files and 233/233 tests passed,
  typecheck/build passed, shell syntax passed, and the read-only deployment
  verifier confirmed an enabled, active, non-root, hardened timer.
- Static classic/Bedrock and natural bounded fleet evidence is recorded in
  [`runtime-proof-static-bedrock-2026-08-19.md`](runtime-proof-static-bedrock-2026-08-19.md).
- No WhatsApp/Hermes target or credential was configured during deployment; no
  outbound test message was sent.

## Final external gate

The implementation is complete. The product is not operationally complete
until the selected company Meta account supplies:

1. a WhatsApp Business Account and sender phone-number ID;
2. a System User token with `whatsapp_business_messaging`;
3. an approved utility template with exactly one body text parameter;
4. the digits-only recipient and current Graph version shown by the Meta app.

After checking those values, provision the ephemeral runtime through
`bootstrap-systemd-whatsapp-runtime.sh`, run
`verify-systemd-install.sh --require-whatsapp`, and invoke the exact-recipient
guarded `run-systemd-whatsapp-test.sh`. Then produce one controlled P1 opening
and resolution through an isolated local finding-state fixture, proving two
accepted `wamid` receipts without running any mutating remote command. Actual
handset `delivered/read/failed` proof remains a separate Meta status-webhook
integration; until that webhook exists this tool claims provider acceptance,
never handset delivery.

The package remains pre-release until the real submission/recovery gate is
recorded. No code defect is currently known to block that proof.
