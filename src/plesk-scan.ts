import { execFile } from "node:child_process";
import { dirname } from "node:path";
import { promisify } from "node:util";
import type { HostConfig } from "./ssh-inventory";

const execFileAsync = promisify(execFile);

export interface WordPressInstallation {
  path: string;
  domain?: string;
}

export interface PleskScanResult {
  host: string;
  subscriptions: string[];
  wordpress: WordPressInstallation[];
}

export type SshCommandRunner = (host: HostConfig, command: string) => Promise<string>;

export async function runSshCommand(host: HostConfig, command: string): Promise<string> {
  const result = await execFileAsync("ssh", [host.alias, command]);
  return result.stdout;
}

export function parseLineList(output: string): string[] {
  return output.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
}

function wordpressPath(configPath: string): WordPressInstallation {
  const path = dirname(configPath);
  const marker = "/var/www/vhosts/";
  const relative = path.startsWith(marker) ? path.slice(marker.length) : "";
  const domain = relative.split("/")[0] || undefined;
  return { path, domain };
}

export async function scanPleskHost(
  host: HostConfig,
  runner: SshCommandRunner = runSshCommand,
): Promise<PleskScanResult> {
  const subscriptions = parseLineList(await runner(host, "plesk bin subscription --list"));
  const configPaths = parseLineList(
    await runner(host, "find /var/www/vhosts -type f -name wp-config.php -print"),
  );
  return { host: host.alias, subscriptions, wordpress: configPaths.map(wordpressPath) };
}
