# Static WordPress filesystem adapter runtime proof — 2026-08-19

Scope: post-review deployment and read-only runtime verification of the static
classic/Bedrock adapter. Vulnerability API lookups were disabled. Reports used
isolated state paths where a targeted proof was required; no domain or
installation path is recorded here.

Remote execution remained inside the typed read-only policy:

- fixed `grep -m 1` reads of the classic and Bedrock core version files;
- bounded, filesystem-local (`-xdev`) `find` listings of classic and Bedrock
  plugin/theme roots;
- read-only PHP-file discovery in both possible uploads roots;
- no application PHP, WP-CLI, database query, Plesk registration, write,
  deletion, update, or remediation command.

## Deployment

Feature commit `24831ff` and runtime-fix commit `f7eebd1` passed CI on Node.js
20 and 22. The final deployed checkout is exactly `f7eebd1`; its verified
rollback snapshot is
`/var/lib/mise-en-plesk/deployment-backups/f7eebd1-before` at `24831ff`.

On the dev runner, frozen install, 219 tests, typecheck, build, and the systemd
installation verifier passed. The timer is enabled and active, and the service
completed naturally with exit status 0.

## Fleet-cycle result

One natural bounded scheduler cycle audited 20 sites per host:

- dev: 2 static classic, 7 WP-CLI, and 11 explicit unavailable-source audits;
- master: 3 static classic, 12 WP-CLI, 4 Toolkit/hybrid, and 2 explicit
  unavailable-source audits;
- failed static sections remained typed `unavailable`; no report converted an
  unavailable read into an empty-success claim;
- suspicious PHP uploads remained findings (1 dev site and 8 master sites),
  with no deletion or remediation.

## Canonical Bedrock result

A separate one-site dev proof selected a canonical Bedrock candidate discovered
through `web/wp/wp-includes/version.php`. It used isolated reports, heartbeat,
finding, cycle, outbox, history, cache, and lock paths.

- The installation changed from an explicit source gap to
  `auditSource: static-filesystem`.
- Layout was identified as canonical Bedrock.
- Core version `6.9` was read from the declaration under `web/wp`.
- The resolved roots were project `httpdocs`, document `web`, core `web/wp`,
  and content `web/app`; uploads inspection therefore used `web/app/uploads`.
- Nine plugin slugs and two theme directories remained after excluding the
  `plugins/index.php` guard file.
- Plugin inventory, theme inventory, and suspicious-uploads coverage were all
  `available`; update state remained explicitly unavailable.
- Runtime health, activation state, versions, updates, and checksums remained
  explicitly unavailable rather than being invented.

The first targeted run exposed a real aliasing bug: for a version-only Bedrock
core candidate, classic and Bedrock probes referenced the same `version.php`
and were falsely marked ambiguous. Commit `f7eebd1` fixes this only when typed
core-root evidence resolves to a separate Bedrock document root and canonical
`composer.json` plus `config/application.php` markers are present. Missing
markers still fail closed, while suspicious uploads evidence is retained.

This proves the reviewed static adapter recovers correctly sourced evidence
for real classic and canonical Bedrock installations while preserving the
remote read-only contract. Unsupported layouts remain explicit P1 manual-review
gaps rather than guessed audits.
