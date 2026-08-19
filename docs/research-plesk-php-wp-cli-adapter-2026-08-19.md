# Read-only Plesk PHP / WP-CLI adapter research

Date: 2026-08-19

Scope: official Plesk Obsidian, WP-CLI, and Roots Bedrock documentation/source only. This note describes discovery and audit interfaces; it does not authorize arbitrary WP-CLI commands.

## Conclusions

### 1. Reading the domain document root and selected PHP

For an SSH-local Plesk adapter, the documented read-only CLI calls are:

```sh
plesk bin site --info example.com
plesk bin site --show-php-settings example.com
plesk bin php_handler --list -json true
```

`site --info` is explicitly documented as displaying website configuration, while `site --show-php-settings` displays its current PHP configuration. The same `site` reference defines `-www-root` as the website home relative to the subscription root and `-php_handler_id` as the selected handler. [`site` CLI reference](https://docs.plesk.com/en-US/obsidian/cli-linux/using-command-line-utilities/site-sites.67067/)

The stable mapping from handler ID to the PHP CLI executable is `php_handler --list -json true`: Plesk documents JSON as intended for scripts and defines `clipath` as the PHP CLI binary. Do not derive the CLI binary merely from an FPM/CGI executable path. [`php_handler` CLI reference](https://docs.plesk.com/en-US/obsidian/cli-linux/using-command-line-utilities/php_handler-php-handlers.72490/)

For a structured remote alternative, the Plesk XML API hosting descriptor exposes `www_root` and `php_handler_id`. It is useful where XML API authentication is already available, but it is not needed for an SSH-only implementation. [Plesk XML API hosting properties](https://docs.plesk.com/en-US/obsidian/api-rpc/about-xml-api/reference/managing-sites-domains/site-settings/hosting.66557/)

Limitation: `site --info` is documented as human-readable output, not a JSON contract. Prefer WP Toolkit JSON for WordPress inventory; otherwise isolate and fixture-test the Plesk-version-specific `site --info` parser. Resolve its relative `www-root` only against the subscription’s authoritative vhost root, never by string-concatenating unvalidated domain input.

### 2. WP Toolkit is the supported WP-CLI boundary

Plesk officially integrates WP-CLI behind:

```sh
plesk ext wp-toolkit --list -format json
plesk ext wp-toolkit --info -instance-id ID -format json
plesk ext wp-toolkit --wp-cli -instance-id ID -- core version
```

The documented interface supports selecting an installation by instance ID, or by main domain ID plus relative path. `--list` and `--info` support JSON; `--wp-cli` executes a WP-CLI subcommand for that selected installation. [Plesk WP Toolkit CLI reference](https://docs.plesk.com/en-US/obsidian/cli-linux/using-command-line-utilities/wptoolkit-wp-toolkit.78685/)

Therefore WP Toolkit should be the primary runtime adapter when installed and the installation is registered. This is an architectural inference: because Plesk owns the documented installation-selection bridge, it is safer to let that bridge establish Plesk-specific execution context than to reproduce undocumented internals.

Only an explicit allowlist of observational WP-CLI commands is safe. The `--wp-cli` bridge itself is not read-only: the same official interface accepts mutating commands. The scanner must reject unknown commands and flags before SSH execution.

No official source reviewed exposes an installed `vendor/boot-fs.php` as a public CLI/API. Treating it as internal is an inference from the documented public boundary: Plesk documents `plesk ext wp-toolkit ...`, not extension vendor files. Never require, execute, or couple to `boot-fs.php`; its path and behavior have no cited compatibility contract.

### 3. `--path` and Bedrock

WP-CLI defines `--path=<path>` as the “Path to the WordPress files”; command-line arguments override project and global YAML configuration. Its runner turns a relative path into `cwd/path`, normalizes it, and uses it as the WordPress root/`ABSPATH`. [WP-CLI configuration reference](https://make.wordpress.org/cli/handbook/references/config/) and [WP-CLI `Runner::find_wp_root()` source](https://github.com/wp-cli/wp-cli/blob/main/php/WP_CLI/Runner.php)

These paths differ in canonical Bedrock:

- project root: contains `composer.json`, `.env`, `config/`, `vendor/`, `web/`, and `wp-cli.yml`;
- web/document root: `<project>/web`;
- WordPress core root / WP-CLI path: `<project>/web/wp`;
- content root: `<project>/web/app` (`wp-content` equivalent);
- uploads: `<project>/web/app/uploads`.

Roots documents `web` as the webserver document root, `web/wp` as Composer-managed WordPress core, and `web/app` as the renamed content directory. [Bedrock folder structure](https://roots.io/bedrock/docs/folder-structure/) The canonical Bedrock source sets `WP_CONTENT_DIR` to `web/app` and `ABSPATH` to `web/wp/`. [Bedrock `config/application.php`](https://github.com/roots/bedrock/blob/master/config/application.php) Its checked-in WP-CLI config is exactly `path: web/wp` with `server.docroot: web`. [Bedrock `wp-cli.yml`](https://github.com/roots/bedrock/blob/master/wp-cli.yml)

Consequently, “directory containing `wp-config.php`” is not a sufficient universal WP-CLI path rule. For Bedrock, run from the project root and honor its `wp-cli.yml`, or pass the canonical core root (`web/wp`) while preserving the project/environment context. File heuristics must use the discovered/configured content root; a hard-coded `<path>/wp-content/uploads` misses Bedrock.

### 4. Recommended architecture and fallback

1. **Capability preflight (read-only):** detect `plesk ext wp-toolkit --help`; obtain registered installations through `--list -format json`; obtain domains through documented Plesk listing/info commands; obtain handler metadata once through `php_handler --list -json true`.
2. **Primary adapter — WP Toolkit:** for registered installations, execute only scanner-owned allowlisted observational commands through `--wp-cli -instance-id ... -- ...`. Prefer instance IDs over reconstructed paths.
3. **Direct adapter — selected Plesk PHP:** for unregistered installations or a broken Toolkit bridge, resolve domain → handler ID → handler `clipath`; execute a separately verified WP-CLI PHAR with that exact PHP CLI binary, as the subscription system user, and with an explicit core path. Plesk also documents versioned PHP binaries under `/opt/plesk/php/<version>/bin/php`, but `clipath` is the stronger machine-readable mapping. [Plesk PHP command-line guide](https://docs.plesk.com/en-US/obsidian/administrator-guide/web-hosting/php-management/running-php-scripts-from-the-command-line.76345/)
4. **Layout adapter:** classify classic WordPress versus Bedrock using bounded file presence checks and canonical markers (`wp-load.php`, Bedrock `composer.json`/`config/application.php`/`web/wp`), then retain separate `projectRoot`, `documentRoot`, `coreRoot`, and `contentRoot` values.
5. **Static-only fallback:** if no trusted WP-CLI runtime works, report a degraded audit and collect only bounded filesystem metadata/checksums and suspicious-file paths. Do not source application PHP, inspect Plesk vendor internals, download a binary, change PHP, register Toolkit instances, or repair the site.

Operational limitations:

- Loading WordPress through WP-CLI executes site PHP and can fail on incompatible PHP, broken plugins, missing environment variables, or Bedrock Composer state even when SSH and files are reachable.
- `--skip-plugins` and `--skip-themes` can reduce ordinary plugin/theme bootstrap failures, but WP-CLI states that must-use plugins still load; a fallback using these flags remains a degraded observation, not proof of site health. [WP-CLI global parameters](https://make.wordpress.org/cli/handbook/references/config/)
- Toolkit sees registered installations; filesystem discovery is still required for abandoned/unregistered copies, but it should not register them.
- Multisite may require an explicit `--url` to select a site; absence of it can make results ambiguous.
- Every subprocess must have bounded output, timeout, concurrency, literal argv construction, validated absolute paths, and a command/flag allowlist. Any unsupported capability should become typed “unavailable/degraded” evidence, never an attempted repair.
