# Public-site health runtime proof — 2026-08-24

Scope: one isolated, bounded, read-only audit of
`solozaszkola.dev.proudsite.pl` from the local checkout. Vulnerability lookups,
notification transports, and production scanner state were disabled or routed
to a temporary directory.

## Evidence

- The registered installation executed through the official Plesk WP Toolkit
  bridge and reported `auditSource: plesk-wp-toolkit` and
  `wpCliTransport: plesk-wp-toolkit`.
- WordPress remained internally reachable. Core `6.9.4`, 12 plugins, five
  themes, and verified core checksums were collected.
- Plugin checksum verification was explicitly unavailable because the Toolkit
  execution returned a permission failure. It was not reported as verified or
  as a checksum mismatch.
- The independent public probe reproduced HTTP `503` and an invalid TLS
  certificate. The served certificate expired on `2026-06-21T11:40:54Z`.
- The conditional typed Plesk inspection reported that the website was
  administratively suspended. This explains the public `503` without implying
  that WordPress itself is unreachable.
- Because the installation is classified as staging, the invalid certificate
  and administrative suspension are P2 findings. The known suspension
  suppresses a duplicate generic HTTP-error finding while preserving HTTP 503
  evidence in the report.

## Safety

Remote execution remained inside the typed read-only policy: WP Toolkit audit
reads and `plesk bin site --info <validated-domain>`. Credentials were passed
through the existing stdin/environment transport without TTY or argv exposure.
No Plesk, WordPress, database, plugin, theme, certificate, service, or
filesystem mutation was performed.
