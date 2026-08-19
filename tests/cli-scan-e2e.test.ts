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
    if [[ "$command" == *"position > 1"* ]]; then
      printf '/var/www/vhosts/second.test/httpdocs/wp-config.php\\n'
    else
      printf '/var/www/vhosts/example.test/httpdocs/wp-config.php\\n/var/www/vhosts/second.test/httpdocs/wp-config.php\\n'
    fi
    ;;
  *"find /var/www/vhosts -xdev"*) printf '/var/www/vhosts/example.test/httpdocs/wp-config.php\\n/var/www/vhosts/second.test/httpdocs/wp-config.php\\n' ;;
  *"__MISE_CORE_BEGIN__"*) cat <<'EOF'
__MISE_CORE_BEGIN__
6.6.1
__MISE_CORE_STATUS_0__
__MISE_CORE_END__
__MISE_CORE_UPDATE_BEGIN__
[]
__MISE_CORE_UPDATE_STATUS_0__
__MISE_CORE_UPDATE_END__
__MISE_PLUGINS_BEGIN__
[]
__MISE_PLUGINS_STATUS_0__
__MISE_PLUGINS_END__
__MISE_PLUGIN_CHECKSUMS_BEGIN__
Success: No plugins have been checked.
__MISE_PLUGIN_CHECKSUMS_STATUS_0__
__MISE_PLUGIN_CHECKSUMS_END__
__MISE_THEMES_BEGIN__
[]
__MISE_THEMES_STATUS_0__
__MISE_THEMES_END__
__MISE_CHECKSUMS_BEGIN__
Success: WordPress installation verifies against checksums.
__MISE_CHECKSUMS_STATUS_0__
__MISE_CHECKSUMS_END__
__MISE_UPLOADS_BEGIN__

__MISE_UPLOADS_STATUS_0__
__MISE_UPLOADS_END__
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
          "Host WP-CLI unavailable: /usr/local/bin/wp: 1: 404: not found",
          "Plesk WP Toolkit has no matching installation registration",
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
        hosts: Array<{ wordpress: Array<{ coreVersion: string; auditSource?: string; integrity?: Record<string, string>; suspiciousFiles: string[] }> }>;
        findings: Array<{ code: string }>;
      };

      expect(report.hosts[0]?.wordpress[0]).toMatchObject({
        coreVersion: "7.0",
        auditSource: "plesk-wp-toolkit",
        integrity: { coreChecksums: "unavailable", pluginChecksums: "unavailable" },
        suspiciousFiles: ["/var/www/vhosts/example.test/httpdocs/wp-content/uploads/shell.php"],
      });
      expect(report.findings.some((finding) => finding.code.startsWith("wp-cli-"))).toBe(false);
      expect(await readFile(join(runtime.root, "ssh.log"), "utf8")).not.toContain("__MISE_CORE_BEGIN__");
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
