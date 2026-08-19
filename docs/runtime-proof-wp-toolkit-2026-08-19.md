# WP Toolkit fallback runtime proof — 2026-08-19

Scope: one bounded WordPress installation per configured host, executed from
the local checkout with isolated temporary report, heartbeat, finding, cycle,
outbox, history, and lock paths. Vulnerability API lookups were disabled.

Remote command set was limited to the scanner's typed read-only policy:

- `plesk bin subscription --list`
- bounded `find` discovery and `find .../wp-content/uploads -name '*.php'`
- `wp cli version`, existing WP-CLI audit reads where available
- `plesk ext wp-toolkit --list -plugins -themes -format json`
- Plesk/PHP/disk informational probes

No remote files, WordPress state, Plesk state, plugins, themes, or databases
were modified.

## Dev

- Host WP-CLI capability probe correctly classified the existing
  `/usr/local/bin/wp` (`404: Not Found`) as unavailable.
- WP Toolkit returned 46 registered installations. The parser accepted the
  live empty-array and null plugin/theme variants.
- The selected installation completed through `plesk-wp-toolkit` with core
  version, 10 plugins, 5 themes, update findings, Toolkit health, and an
  independent uploads scan.
- Core and plugin checksum status was `unavailable`, not falsely `verified` or
  `failed`; WordPress.org freshness was listed as a limitation.

## Master

- WP Toolkit returned one duplicate registration path (IDs 135 and 435). The
  records carried equivalent visible metadata; the parser retained a
  deterministic record, conservatively merged risk flags, and emitted a host
  warning.
- The selected installation completed through `hybrid`: working WP-CLI reads
  were preserved and metadata that failed under the host CLI runtime came from
  WP Toolkit.
- The result contained core version, 17 plugins, 3 themes, Toolkit health,
  independent suspicious-upload evidence, and explicit integrity provenance.

These bounded proofs validate capability selection and data shape handling;
the systemd deployment still requires a fresh post-commit full-cycle proof.
