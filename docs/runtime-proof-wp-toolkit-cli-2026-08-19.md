# Official WP Toolkit WP-CLI bridge runtime proof — 2026-08-19

Scope: one bounded registered WordPress installation on each configured host,
executed from the local checkout. Vulnerability API lookups were disabled.
All remote execution used the scanner-owned typed read-only command policy.

The tested runtime command boundary was:

```sh
plesk ext wp-toolkit --wp-cli -instance-id ID -- <allowlisted read command>
```

The scanner did not forward operator-provided commands, execute WP Toolkit
vendor PHP, alter WordPress/Plesk/database state, or write remote files.

## Transport proof

- Registered installations used the official WP Toolkit bridge instead of the
  broken or mismatched host `wp` executable.
- The non-root sudo batch authenticated once with `sudo -S -p '' -v`, then
  used `sudo -n --` for scanner-owned commands in the same remote shell. The
  password was sent only through stdin and was not repeated between sections.
- Batch sections streamed output between fixed markers instead of using shell
  command substitution. This avoided a live Plesk bridge status `139` observed
  only inside command substitution.
- Every batch uses a random 128-bit marker nonce, preventing accidental or
  precomputed marker collisions in command output. It is not an isolation
  boundary against code able to inspect the parent process command line; such
  code remains a reported compromise signal requiring manual review.
- Marker names now match the parser (`CORE_UPDATE` and `PLUGIN_CHECKSUMS`), so
  non-zero checksum statuses are no longer silently read as missing sections.
- Mutation regression checks reject Toolkit-bridged plugin updates and database
  writes before SSH execution.

## Dev bounded proof

- The host `/usr/local/bin/wp` remained unavailable (`404: Not Found`), while
  the registered installation completed through `plesk-wp-toolkit` transport.
- The audit returned core `6.9.4`, reachable health, 12 plugins, 5 themes,
  verified core checksums, and a real non-zero plugin checksum result.
- The report retained the plugin checksum failure detail for manual review.

## Master bounded proof

- The registered installation completed through `plesk-wp-toolkit` transport
  with core `7.0.4`, reachable health, 19 plugins, and 3 themes.
- Core checksums were verified; plugin checksum verification returned a real
  non-zero result and retained its diagnostic detail.
- Four PHP files under uploads were reported as suspicious evidence without
  any remediation.
- Duplicate WP Toolkit registration warnings remained visible.

## Local verification

- `pnpm test`: 37 files, 199 tests passed.
- `pnpm typecheck`: passed.
- `pnpm build`: passed.
- `git diff --check`: passed.

## Post-commit systemd deployment proof

Commit `014b6af` was deployed to `/opt/mise-en-plesk` on the dev runner after
CI passed on Node.js 20 and 22. The deployment created and validated the exact
backup `/var/lib/mise-en-plesk/deployment-backups/014b6af-before`, then passed
the remote frozen install, 199 tests, typecheck, build, systemd verifier, and
timer restart.

A fresh systemd cycle finished naturally with exit status 0:

- master bounded chunk: 20 sites; 19 used Toolkit transport, 18 completed with
  full WP-CLI audit data, 17 core checksum checks verified, and one site
  retained an explicit WP-CLI error instead of aborting the host scan;
- dev bounded chunk: 20 sites; 12 registered sites used Toolkit transport and
  completed reachable audits, while eight unregistered paths remained
  explicit `auditSource: none` gaps;
- checksum adapter failures became `unavailable`; only recognized mismatch
  output produced integrity failures;
- suspicious-upload findings remained present on both hosts and no remediation
  command was executed.

This validates the official registered-installation adapter in the deployed
scheduler. Unregistered and Bedrock installations remain a separate adapter
slice and are not claimed as complete here.
