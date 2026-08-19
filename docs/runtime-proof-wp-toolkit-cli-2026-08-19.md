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

These bounded proofs validate the official registered-installation adapter.
A post-commit systemd fleet cycle is still required before this slice is
considered deployed. Unregistered and Bedrock installations remain a separate
adapter slice and are not claimed as complete here.
