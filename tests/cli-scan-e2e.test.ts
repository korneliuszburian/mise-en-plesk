import { mkdir, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";

const execFileAsync = promisify(execFile);

const fakeBw = `#!/usr/bin/env bash
set -euo pipefail
printf '%s\\n' "$*" >> "\${FAKE_BW_LOG}"
if [[ "\${1:-}" == "--version" ]]; then
  echo "bw test-double"
else
  printf '%s\\n' '{"id":"item-1","name":"test ssh","login":{"username":"scanner","uris":[{"uri":"ssh://fake.example"}]}}'
fi
`;

const fakeSsh = `#!/usr/bin/env bash
set -euo pipefail
if [[ "$*" == *"-O exit"* ]]; then exit 0; fi
command="\${!#}"
printf '%s\\n' "$command" >> "\${FAKE_SSH_LOG}"
case "$command" in
  "-V") printf 'OpenSSH test-double\\n' ;;
  ":") exit 0 ;;
  "plesk bin subscription --list") printf 'example.test\\n' ;;
  "plesk version") printf 'Plesk Obsidian 18.0.67\\n' ;;
  "php -v") printf 'PHP 8.2.29 (cli)\\n' ;;
  "df -P -k /var/www/vhosts") printf 'Filesystem 1024-blocks Used Available Capacity Mounted on\\n/dev/vda1 100000 65000 35000 65%% /var/www/vhosts\\n' ;;
  *"__MISE_WP_CLI_BEGIN__"*)
    if [[ "\${FAKE_WP_CLI_BROKEN:-0}" == "1" ]]; then
      printf '__MISE_WP_CLI_BEGIN__\\n/usr/local/bin/wp: 1: 404: not found\\n__MISE_WP_CLI_STATUS_127__\\n__MISE_WP_CLI_END__\\n'
    else
      printf '__MISE_WP_CLI_BEGIN__\\nWP-CLI 2.12.0\\n__MISE_WP_CLI_STATUS_0__\\n__MISE_WP_CLI_END__\\n'
    fi
    ;;
  *"plesk ext wp-toolkit --list -plugins -themes -format json") printf '%s\\n' "\${FAKE_TOOLKIT_JSON:-[]}" ;;
  *"find /var/www/vhosts"*"awk"*)
    if [[ "\${FAKE_STATIC_BEDROCK:-0}" == "1" ]]; then
      printf '/var/www/vhosts/example.test/httpdocs/web/wp/wp-includes/version.php\\n'
    elif [[ "\${FAKE_STATIC_CLASSIC:-0}" == "1" ]]; then
      printf '/var/www/vhosts/example.test/httpdocs/wp-config.php\\n'
    elif [[ "$command" == *"position > 1"* ]]; then
      printf '/var/www/vhosts/second.test/httpdocs/wp-config.php\\n'
    else
      printf '/var/www/vhosts/example.test/httpdocs/wp-config.php\\n/var/www/vhosts/second.test/httpdocs/wp-config.php\\n'
    fi
    ;;
  *"find /var/www/vhosts -xdev"*)
    if [[ "\${FAKE_STATIC_BEDROCK:-0}" == "1" ]]; then
      printf '/var/www/vhosts/example.test/httpdocs/web/wp/wp-includes/version.php\\n'
    elif [[ "\${FAKE_STATIC_CLASSIC:-0}" == "1" ]]; then
      printf '/var/www/vhosts/example.test/httpdocs/wp-config.php\\n'
    else
      printf '/var/www/vhosts/example.test/httpdocs/wp-config.php\\n/var/www/vhosts/second.test/httpdocs/wp-config.php\\n'
    fi
    ;;
  *"_CLASSIC_VERSION_BEGIN__"*)
    [[ "\${FAKE_STATIC_BEDROCK:-0}" == "1" || "\${FAKE_STATIC_CLASSIC:-0}" == "1" ]] || { echo "static audit unavailable" >&2; exit 97; }
    marker_nonce="$(printf '%s' "$command" | sed -n 's/.*__MISE_\\([a-f0-9]\\{32\\}\\)_CLASSIC_VERSION_BEGIN__.*/\\1/p')"
    [[ "$marker_nonce" =~ ^[a-f0-9]{32}$ ]] || exit 96
    if [[ "\${FAKE_STATIC_CLASSIC:-0}" == "1" ]]; then
      cat <<EOF
__MISE_\${marker_nonce}_CLASSIC_VERSION_BEGIN__
\\$wp_version = '6.7.2';
__MISE_\${marker_nonce}_CLASSIC_VERSION_STATUS_0__
__MISE_\${marker_nonce}_CLASSIC_VERSION_END__
__MISE_\${marker_nonce}_BEDROCK_VERSION_BEGIN__

__MISE_\${marker_nonce}_BEDROCK_VERSION_STATUS_2__
__MISE_\${marker_nonce}_BEDROCK_VERSION_END__
__MISE_\${marker_nonce}_BEDROCK_COMPOSER_BEGIN__

__MISE_\${marker_nonce}_BEDROCK_COMPOSER_STATUS_1__
__MISE_\${marker_nonce}_BEDROCK_COMPOSER_END__
__MISE_\${marker_nonce}_BEDROCK_CONFIG_BEGIN__

__MISE_\${marker_nonce}_BEDROCK_CONFIG_STATUS_1__
__MISE_\${marker_nonce}_BEDROCK_CONFIG_END__
__MISE_\${marker_nonce}_CLASSIC_PLUGINS_BEGIN__
akismet
__MISE_\${marker_nonce}_CLASSIC_PLUGINS_STATUS_0__
__MISE_\${marker_nonce}_CLASSIC_PLUGINS_END__
__MISE_\${marker_nonce}_BEDROCK_PLUGINS_BEGIN__

__MISE_\${marker_nonce}_BEDROCK_PLUGINS_STATUS_1__
__MISE_\${marker_nonce}_BEDROCK_PLUGINS_END__
__MISE_\${marker_nonce}_CLASSIC_THEMES_BEGIN__
twentytwentyfive
__MISE_\${marker_nonce}_CLASSIC_THEMES_STATUS_0__
__MISE_\${marker_nonce}_CLASSIC_THEMES_END__
__MISE_\${marker_nonce}_BEDROCK_THEMES_BEGIN__

__MISE_\${marker_nonce}_BEDROCK_THEMES_STATUS_1__
__MISE_\${marker_nonce}_BEDROCK_THEMES_END__
__MISE_\${marker_nonce}_CLASSIC_UPLOADS_BEGIN__
/var/www/vhosts/example.test/httpdocs/wp-content/uploads/shell.php
__MISE_\${marker_nonce}_CLASSIC_UPLOADS_STATUS_0__
__MISE_\${marker_nonce}_CLASSIC_UPLOADS_END__
__MISE_\${marker_nonce}_BEDROCK_UPLOADS_BEGIN__

__MISE_\${marker_nonce}_BEDROCK_UPLOADS_STATUS_1__
__MISE_\${marker_nonce}_BEDROCK_UPLOADS_END__
EOF
      exit 0
    fi
    cat <<EOF
__MISE_\${marker_nonce}_CLASSIC_VERSION_BEGIN__

__MISE_\${marker_nonce}_CLASSIC_VERSION_STATUS_2__
__MISE_\${marker_nonce}_CLASSIC_VERSION_END__
__MISE_\${marker_nonce}_BEDROCK_VERSION_BEGIN__
\\$wp_version = '6.8.3';
__MISE_\${marker_nonce}_BEDROCK_VERSION_STATUS_0__
__MISE_\${marker_nonce}_BEDROCK_VERSION_END__
__MISE_\${marker_nonce}_BEDROCK_COMPOSER_BEGIN__
/var/www/vhosts/example.test/httpdocs/composer.json
__MISE_\${marker_nonce}_BEDROCK_COMPOSER_STATUS_0__
__MISE_\${marker_nonce}_BEDROCK_COMPOSER_END__
__MISE_\${marker_nonce}_BEDROCK_CONFIG_BEGIN__
/var/www/vhosts/example.test/httpdocs/config/application.php
__MISE_\${marker_nonce}_BEDROCK_CONFIG_STATUS_0__
__MISE_\${marker_nonce}_BEDROCK_CONFIG_END__
__MISE_\${marker_nonce}_CLASSIC_PLUGINS_BEGIN__

__MISE_\${marker_nonce}_CLASSIC_PLUGINS_STATUS_1__
__MISE_\${marker_nonce}_CLASSIC_PLUGINS_END__
__MISE_\${marker_nonce}_BEDROCK_PLUGINS_BEGIN__
akismet
__MISE_\${marker_nonce}_BEDROCK_PLUGINS_STATUS_0__
__MISE_\${marker_nonce}_BEDROCK_PLUGINS_END__
__MISE_\${marker_nonce}_CLASSIC_THEMES_BEGIN__

__MISE_\${marker_nonce}_CLASSIC_THEMES_STATUS_1__
__MISE_\${marker_nonce}_CLASSIC_THEMES_END__
__MISE_\${marker_nonce}_BEDROCK_THEMES_BEGIN__
sage
__MISE_\${marker_nonce}_BEDROCK_THEMES_STATUS_0__
__MISE_\${marker_nonce}_BEDROCK_THEMES_END__
__MISE_\${marker_nonce}_CLASSIC_UPLOADS_BEGIN__

__MISE_\${marker_nonce}_CLASSIC_UPLOADS_STATUS_1__
__MISE_\${marker_nonce}_CLASSIC_UPLOADS_END__
__MISE_\${marker_nonce}_BEDROCK_UPLOADS_BEGIN__
/var/www/vhosts/example.test/httpdocs/web/app/uploads/shell.php
__MISE_\${marker_nonce}_BEDROCK_UPLOADS_STATUS_0__
__MISE_\${marker_nonce}_BEDROCK_UPLOADS_END__
EOF
    ;;
  *"_CORE_BEGIN__"*)
    [[ "\${FAKE_WP_SITE_BROKEN:-0}" == "1" ]] && { echo "site bootstrap failed" >&2; exit 97; }
    marker_nonce="$(printf '%s' "$command" | sed -n 's/.*__MISE_\\([a-f0-9]\\{32\\}\\)_CORE_BEGIN__.*/\\1/p')"
    [[ "$marker_nonce" =~ ^[a-f0-9]{32}$ ]] || exit 96
    cat <<EOF
__MISE_\${marker_nonce}_CORE_BEGIN__
6.6.1
__MISE_\${marker_nonce}_CORE_STATUS_0__
__MISE_\${marker_nonce}_CORE_END__
__MISE_\${marker_nonce}_CORE_UPDATE_BEGIN__
[]
__MISE_\${marker_nonce}_CORE_UPDATE_STATUS_0__
__MISE_\${marker_nonce}_CORE_UPDATE_END__
__MISE_\${marker_nonce}_PLUGINS_BEGIN__
[]
__MISE_\${marker_nonce}_PLUGINS_STATUS_0__
__MISE_\${marker_nonce}_PLUGINS_END__
__MISE_\${marker_nonce}_PLUGIN_CHECKSUMS_BEGIN__
Success: No plugins have been checked.
__MISE_\${marker_nonce}_PLUGIN_CHECKSUMS_STATUS_0__
__MISE_\${marker_nonce}_PLUGIN_CHECKSUMS_END__
__MISE_\${marker_nonce}_THEMES_BEGIN__
[]
__MISE_\${marker_nonce}_THEMES_STATUS_0__
__MISE_\${marker_nonce}_THEMES_END__
__MISE_\${marker_nonce}_CHECKSUMS_BEGIN__
Success: WordPress installation verifies against checksums.
__MISE_\${marker_nonce}_CHECKSUMS_STATUS_0__
__MISE_\${marker_nonce}_CHECKSUMS_END__
__MISE_\${marker_nonce}_UPLOADS_BEGIN__

__MISE_\${marker_nonce}_UPLOADS_STATUS_0__
__MISE_\${marker_nonce}_UPLOADS_END__
EOF
    ;;
  *"wp-content/uploads"*) printf '/var/www/vhosts/example.test/httpdocs/wp-content/uploads/shell.php\\n' ;;
  *) echo "unexpected fake SSH command: $command" >&2; exit 97 ;;
esac
`;

async function prepareRuntime(): Promise<{ root: string; env: NodeJS.ProcessEnv }> {
  const root = await mkdtemp(join(tmpdir(), "mise-en-plesk-cli-scan-e2e-"));
  const bin = join(root, "bin");
  await mkdir(bin);
  await writeFile(join(bin, "bw"), fakeBw, { mode: 0o700 });
  await writeFile(join(bin, "ssh"), fakeSsh, { mode: 0o700 });
  const inventoryPath = join(root, "inventory.json");
  await writeFile(inventoryPath, JSON.stringify({ test: {
    alias: "test",
    id: "item-1",
    name: "test ssh",
    host: "fake.example",
    port: 22,
    user: "scanner",
    identitySource: "bitwarden:item-1",
  } }));
  const configPath = join(root, "config.json");
  await writeFile(configPath, JSON.stringify({ hosts: ["test"], maxConcurrentSitesPerHost: 1 }));
  const env = {
    ...process.env,
    PATH: `${bin}:${process.env.PATH ?? ""}`,
    BW_SESSION: "test-session",
    MISE_PLESK_INVENTORY: inventoryPath,
    MISE_PLESK_CONFIG: configPath,
    MISE_PLESK_REPORTS: join(root, "reports"),
    MISE_PLESK_HEARTBEAT: join(root, "heartbeat.json"),
    MISE_PLESK_FINDINGS: join(root, "findings.json"),
    MISE_PLESK_SCAN_CYCLES: join(root, "scan-cycles.json"),
    MISE_PLESK_RUN_LOCK: join(root, "scan.lock"),
    MISE_PLESK_DISABLE_PUBLIC_SITE_CHECKS: "1",
    FAKE_BW_LOG: join(root, "bw.log"),
    FAKE_SSH_LOG: join(root, "ssh.log"),
  };
  return { root, env };
}

async function runScan(args: string[], env: NodeJS.ProcessEnv): Promise<{ heartbeat: { scanComplete?: boolean }; report: { scanProgress?: Array<{ complete: boolean }> } }> {
  await execFileAsync("pnpm", ["exec", "tsx", "bin/mise-plesk-audit.ts", "scan", "test", "--json", ...args], { env });
  const heartbeat = JSON.parse(await readFile(env.MISE_PLESK_HEARTBEAT!, "utf8")) as { scanComplete?: boolean };
  const reports = await readdir(env.MISE_PLESK_REPORTS!);
  const reportName = reports.find((name) => name.endsWith(".json"));
  if (!reportName) throw new Error("E2E scan did not write a JSON report");
  const report = JSON.parse(await readFile(join(env.MISE_PLESK_REPORTS!, reportName), "utf8")) as { scanProgress?: Array<{ complete: boolean }> };
  return { heartbeat, report };
}

describe("scan CLI end-to-end", () => {
  it("reports an explicit source gap when broken WP-CLI has no Toolkit registration", async () => {
    const runtime = await prepareRuntime();
    try {
      runtime.env.FAKE_WP_CLI_BROKEN = "1";
      await writeFile(runtime.env.MISE_PLESK_CONFIG!, JSON.stringify({ hosts: ["test"], maxSitesPerHost: 1 }));

      await runScan([], runtime.env);
      const reportName = (await readdir(runtime.env.MISE_PLESK_REPORTS!)).find((name) => name.endsWith(".json"));
      const report = JSON.parse(await readFile(join(runtime.env.MISE_PLESK_REPORTS!, reportName!), "utf8")) as {
        hosts: Array<{ wordpress: Array<{ auditSource?: string; limitations?: string[] }> }>;
      };

      expect(report.hosts[0]?.wordpress[0]).toMatchObject({
        auditSource: "none",
        limitations: [
          "Host WP-CLI unavailable: WP-CLI executable unavailable",
          "Plesk WP Toolkit has no matching installation registration",
          "Static filesystem audit could not identify a supported WordPress layout",
        ],
      });
    } finally {
      await rm(runtime.root, { recursive: true, force: true });
    }
  }, 30_000);

  it("falls back to Plesk WP Toolkit when host WP-CLI is broken", async () => {
    const runtime = await prepareRuntime();
    try {
      runtime.env.FAKE_WP_CLI_BROKEN = "1";
      runtime.env.FAKE_TOOLKIT_JSON = JSON.stringify([{
        id: 5,
        fullPath: "/var/www/vhosts/example.test/httpdocs",
        version: "7.0",
        outdatedWp: true,
        unsupportedPhp: false,
        broken: false,
        infected: false,
        alive: true,
        stateText: "Working",
        plugins: { akismet: { name: "akismet", status: "active", version: "5.3", update_version: "5.4" } },
        themes: {},
      }]);
      await writeFile(runtime.env.MISE_PLESK_CONFIG!, JSON.stringify({ hosts: ["test"], maxSitesPerHost: 1 }));

      await runScan([], runtime.env);
      const reportName = (await readdir(runtime.env.MISE_PLESK_REPORTS!)).find((name) => name.endsWith(".json"));
      const report = JSON.parse(await readFile(join(runtime.env.MISE_PLESK_REPORTS!, reportName!), "utf8")) as {
        hosts: Array<{ wordpress: Array<{ coreVersion: string; auditSource?: string; wpCliTransport?: string; integrity?: Record<string, string>; suspiciousFiles: string[] }> }>;
        findings: Array<{ code: string }>;
      };

      expect(report.hosts[0]?.wordpress[0]).toMatchObject({
        coreVersion: "6.6.1",
        auditSource: "plesk-wp-toolkit",
        wpCliTransport: "plesk-wp-toolkit",
        integrity: { coreChecksums: "verified", pluginChecksums: "verified" },
        suspiciousFiles: [],
      });
      expect(report.findings.some((finding) => finding.code.startsWith("wp-cli-"))).toBe(false);
      expect(await readFile(join(runtime.root, "ssh.log"), "utf8"))
        .toContain("plesk ext wp-toolkit --wp-cli -instance-id 5 -- core version");
    } finally {
      await rm(runtime.root, { recursive: true, force: true });
    }
  }, 30_000);

  it("falls back to a static Bedrock audit when WP-CLI and Toolkit registration are unavailable", async () => {
    const runtime = await prepareRuntime();
    try {
      runtime.env.FAKE_WP_CLI_BROKEN = "1";
      runtime.env.FAKE_STATIC_BEDROCK = "1";
      await writeFile(runtime.env.MISE_PLESK_CONFIG!, JSON.stringify({ hosts: ["test"], maxSitesPerHost: 1 }));

      await runScan([], runtime.env);
      const reportName = (await readdir(runtime.env.MISE_PLESK_REPORTS!)).find((name) => name.endsWith(".json"));
      const report = JSON.parse(await readFile(join(runtime.env.MISE_PLESK_REPORTS!, reportName!), "utf8")) as {
        hosts: Array<{ wordpress: Array<{ auditSource?: string; coreVersion: string; layout?: { kind: string }; suspiciousFiles: string[] }> }>;
      };

      expect(report.hosts[0]?.wordpress[0]).toMatchObject({
        auditSource: "static-filesystem",
        coreVersion: "6.8.3",
        layout: { kind: "bedrock" },
        suspiciousFiles: ["/var/www/vhosts/example.test/httpdocs/web/app/uploads/shell.php"],
      });
    } finally {
      await rm(runtime.root, { recursive: true, force: true });
    }
  }, 30_000);

  it("falls back to static evidence when host WP-CLI exists but one unregistered site fails", async () => {
    const runtime = await prepareRuntime();
    try {
      runtime.env.FAKE_STATIC_BEDROCK = "1";
      runtime.env.FAKE_WP_SITE_BROKEN = "1";
      await writeFile(runtime.env.MISE_PLESK_CONFIG!, JSON.stringify({ hosts: ["test"], maxSitesPerHost: 1 }));

      await runScan([], runtime.env);
      const reportName = (await readdir(runtime.env.MISE_PLESK_REPORTS!)).find((name) => name.endsWith(".json"));
      const report = JSON.parse(await readFile(join(runtime.env.MISE_PLESK_REPORTS!, reportName!), "utf8")) as {
        hosts: Array<{ wordpress: Array<{ auditSource?: string; health: { status?: string }; limitations?: string[] }> }>;
      };

      expect(report.hosts[0]?.wordpress[0]).toMatchObject({
        auditSource: "static-filesystem",
        health: { status: "wp-cli-error" },
      });
      expect(report.hosts[0]?.wordpress[0]?.limitations).toContain("WP-CLI audit failed for this installation: WP-CLI command failed");
    } finally {
      await rm(runtime.root, { recursive: true, force: true });
    }
  }, 30_000);

  it("audits a classic WordPress fallback end to end", async () => {
    const runtime = await prepareRuntime();
    try {
      runtime.env.FAKE_WP_CLI_BROKEN = "1";
      runtime.env.FAKE_STATIC_CLASSIC = "1";
      await writeFile(runtime.env.MISE_PLESK_CONFIG!, JSON.stringify({ hosts: ["test"], maxSitesPerHost: 1 }));

      await runScan([], runtime.env);
      const reportName = (await readdir(runtime.env.MISE_PLESK_REPORTS!)).find((name) => name.endsWith(".json"));
      const report = JSON.parse(await readFile(join(runtime.env.MISE_PLESK_REPORTS!, reportName!), "utf8")) as {
        hosts: Array<{ wordpress: Array<{ auditSource?: string; coreVersion: string; layout?: { kind: string; contentRoot: string }; suspiciousFiles: string[] }> }>;
      };

      expect(report.hosts[0]?.wordpress[0]).toMatchObject({
        auditSource: "static-filesystem",
        coreVersion: "6.7.2",
        layout: { kind: "classic", contentRoot: "/var/www/vhosts/example.test/httpdocs/wp-content" },
        suspiciousFiles: ["/var/www/vhosts/example.test/httpdocs/wp-content/uploads/shell.php"],
      });
    } finally {
      await rm(runtime.root, { recursive: true, force: true });
    }
  }, 30_000);

  it("propagates complete, budget-incomplete, and offset-incomplete state", async () => {
    const runtimes: Array<{ root: string; env: NodeJS.ProcessEnv }> = [];
    try {
      const complete = await prepareRuntime();
      runtimes.push(complete);
      const completeResult = await runScan([], complete.env);
      expect(completeResult.heartbeat.scanComplete).toBe(true);
      expect(completeResult.report.scanProgress?.[0]?.complete).toBe(true);
      expect(await readFile(join(complete.root, "bw.log"), "utf8")).toContain("get item item-1");
      expect(await readFile(join(complete.root, "ssh.log"), "utf8")).toContain("plesk bin subscription --list");

      const incomplete = await prepareRuntime();
      runtimes.push(incomplete);
      await writeFile(incomplete.env.MISE_PLESK_CONFIG!, JSON.stringify({ hosts: ["test"], maxSitesPerHost: 1, maxScanChunksPerHost: 1 }));
      const incompleteResult = await runScan(["--all-chunks", "--max-chunks=1"], incomplete.env);
      expect(incompleteResult.heartbeat.scanComplete).toBe(false);
      expect(incompleteResult.report.scanProgress?.[0]?.complete).toBe(false);

      const offset = await prepareRuntime();
      runtimes.push(offset);
      await writeFile(offset.env.MISE_PLESK_CONFIG!, JSON.stringify({ hosts: ["test"], maxSitesPerHost: 1 }));
      const offsetResult = await runScan(["--offset=1"], offset.env);
      expect(offsetResult.heartbeat.scanComplete).toBe(false);
      expect(offsetResult.report.scanProgress?.[0]?.complete).toBe(true);
      const report = JSON.parse(await readFile(join(offset.env.MISE_PLESK_REPORTS!, (await readdir(offset.env.MISE_PLESK_REPORTS!)).find((name) => name.endsWith(".json"))!), "utf8")) as { hosts: Array<{ wordpress: Array<{ installation: { domain?: string } }> }> };
      expect(report.hosts[0]?.wordpress[0]?.installation.domain).toBe("second.test");
    } finally {
      await Promise.all(runtimes.map(({ root }) => rm(root, { recursive: true, force: true })));
    }
  }, 30_000);

  it("probes WP capabilities and fetches Toolkit inventory once across host chunks", async () => {
    const runtime = await prepareRuntime();
    try {
      await writeFile(runtime.env.MISE_PLESK_CONFIG!, JSON.stringify({ hosts: ["test"], maxSitesPerHost: 1, maxScanChunksPerHost: 3 }));

      await runScan(["--all-chunks"], runtime.env);
      const commands = await readFile(join(runtime.root, "ssh.log"), "utf8");

      expect(commands.match(/__MISE_WP_CLI_BEGIN__/g)).toHaveLength(1);
      expect(commands.match(/plesk ext wp-toolkit --list -plugins -themes -format json/g)).toHaveLength(1);
    } finally {
      await rm(runtime.root, { recursive: true, force: true });
    }
  }, 30_000);
});
