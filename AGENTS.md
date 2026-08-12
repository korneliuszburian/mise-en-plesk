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
source.

## Skills

Use the globally installed skills: `/setup-mise-en-plesk`,
`/grill-plesk-task`, `/audit-plesk-wordpresses`, `/to-spec`, `/to-tickets`,
`research`, `tdd`, and `code-review`. Do not duplicate their definitions in
this repository.

Normal workflow: `/grill-plesk-task` → `/to-spec` → `/to-tickets` → Codex
implementation → tests → `code-review`.

## Local requirements

Node.js 20+, pnpm, Bitwarden CLI (`bw`), access to the relevant vault, and
standard SSH tooling. Run `source scripts/setup-bw-session.sh` before syncing.

## Git history

Use Conventional Commits for every new commit: `feat:`, `fix:`, `test:`,
`docs:`, `refactor:`, `chore:`, or another valid semantic type with an
optional scope. Keep the subject imperative and concise.
