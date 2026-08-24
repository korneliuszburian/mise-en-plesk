# Public-site health research

Date: 2026-08-24
Scope: official/primary sources only; no remote-host access was performed.

## Conclusions

1. Use two independent evidence planes: read-only Plesk inspection explains the configured origin, while an external HTTP/TLS probe establishes what a visitor actually receives. A Plesk certificate repository entry alone does not prove that nginx currently serves that certificate.
2. For a reported nginx `503`, capture the public response first, then correlate it with domain configuration, service status, PHP handler configuration, and the domain's nginx/Apache logs. HTTP `503` means the server is temporarily unable to handle the request; a `Retry-After` header may describe when to retry ([RFC 9110, section 15.6.4](https://www.rfc-editor.org/rfc/rfc9110.html#name-503-service-unavailable)).
3. Prefer Plesk WP Toolkit's integrated WP-CLI bridge over a global `wp` binary. A plugin checksum `permission denied` is not documented as expected behavior; classify it as an audit execution/permissions failure, not as a checksum mismatch or a clean result.

## 1. Read-only Plesk interfaces for a domain returning 503

### Supported CLI surface

Keep an explicit allowlist containing only informational operations:

| Question | Read-only interface | What it establishes |
| --- | --- | --- |
| Is the website configured and active? | `plesk bin site --info <domain>` | Website configuration. Plesk documents `--info` as displaying website configuration and `--list` as listing domains ([Plesk `site` CLI](https://docs.plesk.com/en-US/obsidian/cli-linux/using-command-line-utilities/site-sites.67067/)). |
| What PHP/web-server settings apply? | `plesk bin site --show-php-settings <domain>`; `plesk bin subscription --show-web-server-settings <domain>` | Selected PHP configuration and nginx/Apache settings ([Plesk `site` CLI](https://docs.plesk.com/en-US/obsidian/cli-linux/using-command-line-utilities/site-sites.67067/), [Plesk `subscription` CLI](https://docs.plesk.com/en-US/obsidian/cli-linux/using-command-line-utilities/subscription-subscriptions.37768/)). |
| Is the selected PHP handler known and enabled? | `plesk bin php_handler --list -json true`; optionally `--get-usage -id <id> -json true` | Structured handler inventory and domain usage. Do not use `--reread`, enable/disable, add/remove, or replace ([Plesk `php_handler` CLI](https://docs.plesk.com/en-US/obsidian/cli-linux/using-command-line-utilities/php_handler-php-handlers.72490/)). |
| Are nginx/Apache/PHP-related services running? | `plesk bin service --list -detail`; `plesk bin service --status <service>` | Plesk-supported status queries. Never permit start/stop/restart in the scanner ([Plesk `service` CLI](https://docs.plesk.com/en-US/obsidian/cli-linux/using-command-line-utilities/service-services.40786/)). |
| What did the origin report? | Read/tail only the domain's `error_log` and `proxy_error_log` under `/var/www/vhosts/system/<domain>/logs/` | Apache and nginx diagnostic evidence. Plesk documents these domain logs and their purpose ([Plesk domain logs](https://docs.plesk.com/en-US/obsidian/administrator-guide/website-management/customer-account-administration/log-files.65210/), [Plesk log locations](https://docs.plesk.com/en-US/obsidian/advanced-administration-guide-linux/statistics-and-logs.68646/)). |

Plesk CLI normally requires `root` or `psaadm` privileges, so sudo access should remain a fixed command allowlist rather than arbitrary shell access ([Plesk CLI overview](https://docs.plesk.com/en-US/obsidian/cli-linux/command-line-utilities-overview.37764/)). On standard Linux hosting, nginx commonly proxies dynamic requests to Apache; therefore an nginx-branded `503` does not by itself identify whether nginx, Apache, PHP-FPM, or the application is the failing layer ([Plesk Apache with nginx](https://docs.plesk.com/en-US/obsidian/administrator-guide/web-servers/apache-and-nginx-web-servers-linux/apache-with-nginx.70837/)).

### Certificate metadata and status

- `plesk bin certificate --list -domain <domain>` is the documented read-only command for listing certificates in a domain repository ([Plesk `certificate` CLI](https://docs.plesk.com/en-US/obsidian/cli-linux/using-command-line-utilities/certificate-ssltls-certificates.39009/)).
- XML API's `<certificate><get-pool>` retrieves certificate repository entries for selected subscriptions. This is useful when structured remote inventory is required ([Plesk XML API `get-pool`](https://docs.plesk.com/en-US/obsidian/api-rpc/about-xml-api/reference/managing-ssltls-certificates/retrieving-list-of-certificates.68395/)).
- Plesk REST uses authenticated HTTPS endpoints under `/api/v2`; official documentation defines `GET` as read-only and shows `GET /domains`. Only the Plesk administrator can use this API, and its generated Swagger document on the specific server is authoritative for endpoints available in that installed version ([Plesk REST API](https://docs.plesk.com/en-US/onyx/api-rpc/about-rest-api.79359/)).

Do not infer public TLS health solely from these control-plane records. Probe `https://<domain>/` by hostname so DNS, the HTTP `Host` header, and TLS SNI select the same virtual host a visitor uses. Record certificate authorization, hostname match, issuer/subject/SANs, validity interval, negotiated protocol, and days to expiry. Node exposes peer-certificate metadata through `TLSSocket.getPeerCertificate()` and trust outcome through `authorized`/`authorizationError` ([Node.js TLS API](https://nodejs.org/api/tls.html#tlssocketgetpeercertificatedetailed)).

## 2. External HTTP/TLS probe contract

Recommended scanner behavior:

- Run from outside the Plesk host/network path. Keep it independent from SSH audit success so it detects DNS, routing, edge, SNI, redirect, TLS, and origin failures visible to clients.
- Use a bounded `GET /` as the primary availability probe, with a small response-body limit. `HEAD` intentionally omits response content, so it cannot validate a page marker and may exercise a less representative application path ([RFC 9110 `HEAD`](https://www.rfc-editor.org/rfc/rfc9110.html#name-head)).
- Set explicit connect and total deadlines, do not retry within the primary measurement, and retain phase-specific outcomes: DNS, TCP, TLS, first byte, status, redirect chain, and total duration. Retry/debounce belongs in alert policy, preventing one probe from hiding latency or intermittent failure.
- Follow redirects only with a bounded hop count; record every hop and the final URL/status. Treat unexpected cross-host redirects as a separate finding.
- Validate TLS normally. Never turn `rejectUnauthorized`/certificate verification off for the health verdict. A separate diagnostic handshake may collect metadata after a validation failure, but must remain failed.
- Store a bounded body fingerprint or expected marker rather than the full response. This distinguishes a branded proxy/error page returning `200` from the expected site while avoiding collection of customer content.
- Classify transport failure, TLS failure, timeout, HTTP `5xx`, unexpected redirect, and content mismatch separately. Alert after configurable consecutive failures and emit a resolution only after configurable consecutive successes.

These choices match the primary Prometheus Blackbox Exporter model: HTTP/HTTPS probes expose success and timing, support explicit timeout, accepted status codes, method, redirect handling and TLS requirements, and publish certificate-expiry/TLS metadata ([Blackbox Exporter README](https://github.com/prometheus/blackbox_exporter/blob/master/README.md), [official configuration](https://github.com/prometheus/blackbox_exporter/blob/master/CONFIGURATION.md), [HTTP/TLS probe implementation](https://github.com/prometheus/blackbox_exporter/blob/master/prober/http.go)). For this repository, implementing the small probe contract directly in Node is reasonable; adopting Prometheus later should not change the report model.

## 3. WP Toolkit `--wp-cli` and checksum permissions

Plesk documents WP-CLI as integrated into WP Toolkit, requiring either an installation `-instance-id` or a `-main-domain-id` plus relative `-path`, followed by `--` and the WP-CLI subcommand. The documented read-only plugin example is:

```sh
plesk ext wp-toolkit --wp-cli -instance-id <id> -- plugin list
```

This bridge targets the selected Toolkit installation and requires no separately installed global WP-CLI binary ([Plesk `wp-toolkit` CLI](https://docs.plesk.com/en-US/obsidian/cli-linux/using-command-line-utilities/wptoolkit-wp-toolkit.78685/), [Plesk WP Toolkit guide](https://docs.plesk.com/en-US/obsidian/administrator-guide/website-management/wordpress-toolkit.73391/)). The scanner should therefore resolve and retain Toolkit instance IDs during discovery and invoke only an allowlisted set of read-only WP-CLI subcommands through this bridge.

`wp plugin verify-checksums --all` reads installed plugin files and compares them with checksums fetched from WordPress.org. Official WP-CLI documentation identifies unavailable checksums—not filesystem permission denial—as an expected limitation; custom, premium, or otherwise non-WordPress.org plugins can yield HTTP 404 and be skipped ([WP-CLI command reference](https://developer.wordpress.org/cli/commands/plugin/verify-checksums/), [WordPress security-check guidance](https://developer.wordpress.org/news/2024/09/website-security-checks-wp-cli-for-site-owners-and-administrators/)). Therefore:

- checksum mismatch: integrity finding;
- checksums unavailable/404: `unsupported` or `no-upstream-checksum`, not compromised;
- `permission denied`: `audit-incomplete` with the affected path/operation, not expected success and not proof of compromise;
- bridge/bootstrap/PHP failure: `wp-cli-error` or the existing more specific health category.

No official source found states that plugin checksum permission failures are expected under WP Toolkit. The most defensible interpretation is a local execution-context or filesystem-access problem requiring read-only diagnosis; the scanner must preserve it as evidence and continue auditing other installations.

## Implementation direction

1. Make WP Toolkit instance ID the preferred execution adapter; retain global/direct WP-CLI only as an explicitly validated fallback.
2. Add an independent public probe result to each site: DNS/TCP/TLS/HTTP phases, redirect chain, status, bounded timing, served-certificate metadata, and content marker result.
3. Add a read-only Plesk diagnostic bundle for failed public probes using only the allowlisted informational commands and bounded log tails above.
4. Keep observed public TLS state separate from Plesk repository/configuration state and report disagreement explicitly.
5. Preserve all failures as typed, additive evidence; never auto-repair, restart services, regenerate configuration, renew certificates, or change WordPress files/settings.
