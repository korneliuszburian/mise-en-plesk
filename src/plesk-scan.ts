import { execFile } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { dirname } from "node:path";
import { tmpdir } from "node:os";
import { promisify } from "node:util";
import type { HostConfig } from "./ssh-inventory";

const execFileAsync = promisify(execFile);

function execFileWithInput(
  executable: string,
  args: string[],
  options: Parameters<typeof execFileAsync>[2],
  input?: string,
): Promise<{ stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = execFile(executable, args, options, (error, stdout, stderr) => {
      if (error) {
        Object.assign(error, { stdout: stdout.toString(), stderr: stderr.toString() });
        reject(error);
        return;
      }
      resolve({ stdout: stdout.toString(), stderr: stderr.toString() });
    });
    if (input !== undefined) child.stdin?.end(input);
  });
}

export interface WordPressInstallation {
  path: string;
  domain?: string;
}

export interface PleskScanResult {
  host: string;
  subscriptions: string[];
  wordpress: WordPressInstallation[];
  wordpressHasMore?: boolean;
  warnings?: string[];
}

export interface PleskScanOptions {
  wordpressOffset?: number;
  wordpressLimit?: number;
  useSudo?: boolean;
}

export type SshCommandRunner = (host: HostConfig, command: string) => Promise<string>;

interface SshInvocationOptions {
  controlPath?: string;
  stdin?: string;
}

export function buildSshInvocation(host: HostConfig, password?: string, options: SshInvocationOptions = {}): {
  executable: "ssh" | "sshpass";
  args: string[];
  env?: NodeJS.ProcessEnv;
} {
  const controlArgs = options.controlPath
    ? ["-o", "ControlMaster=auto", "-o", "ControlPersist=120", "-o", `ControlPath=${options.controlPath}`]
    : [];
  const sshArgs = ["-o", "ConnectTimeout=10", "-o", "ConnectionAttempts=1", ...controlArgs, "-p", String(host.port), `${host.user}@${host.host}`];
  if (!password) return { executable: "ssh", args: [...sshArgs] };
  return {
    executable: "sshpass",
    args: ["-e", "ssh", ...sshArgs],
    env: { ...process.env, SSHPASS: password },
  };
}

export async function runSshCommand(host: HostConfig, command: string, password?: string, options: SshInvocationOptions = {}): Promise<string> {
  const invocation = buildSshInvocation(host, password, options);
  try {
    const result = await execFileWithInput(invocation.executable, [...invocation.args, command], {
      env: invocation.env,
      timeout: 20_000,
    }, options.stdin);
    return result.stdout;
  } catch (error: unknown) {
    const failure = error as { stdout?: string; stderr?: string; message?: string; code?: string | number };
    const detail = [failure.stdout, failure.stderr, failure.message]
      .filter((value): value is string => Boolean(value?.trim()))
      .map((value) => value.trim())
      .join("\n");
    throw new Error(detail || `SSH command failed${failure.code !== undefined ? ` (exit code ${failure.code})` : ""}.`);
  }
}

export interface SshSession {
  run(command: string): Promise<string>;
  close(): Promise<void>;
}

export async function createSshSession(host: HostConfig, password?: string, sudoPassword?: string): Promise<SshSession> {
  const directory = await mkdtemp(`${tmpdir()}/mise-en-plesk-`);
  const controlPath = `${directory}/control`;
  const run = (command: string) => runSshCommand(host, command, password, {
    controlPath,
    stdin: sudoPassword === undefined ? undefined : `${sudoPassword}\n`,
  });
  await run(":");

  return {
    run,
    async close(): Promise<void> {
      try {
        await execFileAsync("ssh", [
          "-o", "ControlPath=" + controlPath,
          "-O", "exit",
          "-p", String(host.port),
          `${host.user}@${host.host}`,
        ], { timeout: 5_000 });
      } finally {
        await rm(directory, { recursive: true, force: true });
      }
    },
  };
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

function shortError(error: unknown): string {
  const detail = error instanceof Error ? error.message : String(error);
  return detail.replace(/\s+/g, " ").trim().slice(0, 200) || "command failed";
}

export async function scanPleskHost(
  host: HostConfig,
  runner: SshCommandRunner = runSshCommand,
  options: PleskScanOptions = {},
): Promise<PleskScanResult> {
  const offset = options.wordpressOffset ?? 0;
  const limit = options.wordpressLimit;
  if (!Number.isSafeInteger(offset) || offset < 0) throw new Error("wordpressOffset must be a non-negative safe integer.");
  if (limit !== undefined && (!Number.isSafeInteger(limit) || limit < 1)) {
    throw new Error("wordpressLimit must be a positive safe integer.");
  }
  let prefix = options.useSudo ? "sudo -S -p '' -- " : "";
  const warnings: string[] = [];
  let subscriptions: string[] = [];
  try {
    subscriptions = parseLineList(await runner(host, `${prefix}plesk bin subscription --list`));
  } catch (error: unknown) {
    warnings.push(`Plesk CLI subscription discovery unavailable; using filesystem discovery only: ${shortError(error)}`);
    prefix = "";
  }
  const discoveryCommand = limit === undefined
    ? `${prefix}find /var/www/vhosts -xdev -maxdepth 4 -type f -name wp-config.php -print`
    : `${prefix}find /var/www/vhosts -xdev -maxdepth 4 -type f -name wp-config.php -print | sort | awk 'NR > ${offset} && NR <= ${offset + limit + 1} { print }'`;
  const configPaths = parseLineList(
    await runner(host, discoveryCommand),
  );
  const wordpressHasMore = limit === undefined ? undefined : configPaths.length > limit;
  return {
    host: host.alias,
    subscriptions,
    wordpress: (wordpressHasMore ? configPaths.slice(0, limit) : configPaths).map(wordpressPath),
    ...(limit === undefined ? {} : { wordpressHasMore }),
    ...(warnings.length ? { warnings } : {}),
  };
}
