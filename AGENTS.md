# mise-en-plesk agent guide

## Roles

- Korneliusz is the human operator and final decision-maker.
- Codex is the primary executor for code and shell work.
- A reviewer agent may research security guidance and perform code review.

## Safety contract

Plesk access is read-only by default. The initial tool runs inventory and audit
commands only. Any mutating command needs an explicit request from Korneliusz
in the current conversation, a clearly named CLI subcommand, and confirmation
guards. Never commit or persist credentials; Bitwarden CLI is the credential
source. `sudoHosts` is an explicit exception only for the fixed read-only
Plesk/WP/find commands; its short-lived Secure Note password is sent through
stdin, never argv/logs/files. Never add arbitrary sudo command execution.

Risk priorities are P1 manual-review signals: very old core, abandoned plugin,
vulnerable plugin, or PHP files under `wp-content/uploads`. With
`MISE_PLESK_ENABLE_VULNS=1`, the audit performs opt-in lookups against the
WPVulnerability API; otherwise it performs no vulnerability API requests. The
monitor heartbeat and `monitor-stale` finding are local operational signals;
they never trigger remote commands or remediation.

`whatsapp-test --confirm=<configured recipient>` is the only intentional
outbound test message. Never run it without checking the configured recipient
in the current task.

## Skills

Use the globally installed skills: `/setup-mise-en-plesk`,
`/grill-plesk-task`, `/audit-plesk-wordpresses`, `/to-spec`, `/to-tickets`,
`research`, `tdd`, and `code-review`. Do not duplicate their definitions in
this repository.

Normal workflow: `/grill-plesk-task` → `/to-spec` → `/to-tickets` → Codex
implementation → tests → `code-review`.

## Local requirements

Node.js 20+, pnpm, Bitwarden CLI (`bw`), access to the relevant vault, SSH,
and `sshpass` for password-authenticated Secure Notes. Run
`source scripts/setup-bw-session.sh` before syncing.

## Git history

Use Conventional Commits for every new commit: `feat:`, `fix:`, `test:`,
`docs:`, `refactor:`, `chore:`, or another valid semantic type with an
optional scope. Keep the subject imperative and concise.
