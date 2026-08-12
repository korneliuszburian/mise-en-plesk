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

export function buildSshInvocation(host: HostConfig, password?: string): {
  executable: "ssh" | "sshpass";
  args: string[];
  env?: NodeJS.ProcessEnv;
} {
  const sshArgs = ["-p", String(host.port), `${host.user}@${host.host}`];
  if (!password) return { executable: "ssh", args: [...sshArgs] };
  return {
    executable: "sshpass",
    args: ["-e", "ssh", ...sshArgs],
    env: { ...process.env, SSHPASS: password },
  };
}

export async function runSshCommand(host: HostConfig, command: string, password?: string): Promise<string> {
  const invocation = buildSshInvocation(host, password);
  try {
    const result = await execFileAsync(invocation.executable, [...invocation.args, command], {
      env: invocation.env,
      timeout: 60_000,
    });
    return result.stdout;
  } catch (error: unknown) {
    const failure = error as { stderr?: string; message?: string };
    throw new Error(failure.stderr?.trim() || failure.message || "SSH command failed.");
  }
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
    await runner(host, "find /var/www/vhosts -xdev -type f -name wp-config.php -print"),
  );
  return { host: host.alias, subscriptions, wordpress: configPaths.map(wordpressPath) };
}
