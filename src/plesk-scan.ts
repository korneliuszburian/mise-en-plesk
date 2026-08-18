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
  classification?: WordPressInstallationClassification;
  detectionSignals?: WordPressDetectionSignal[];
}

export type WordPressDetectionSignal = "wp-config.php" | "wp-includes/version.php";

export type WordPressSiteKind = "production" | "staging" | "backup" | "unknown";

export interface WordPressInstallationClassification {
  kind: WordPressSiteKind;
  reason: string;
}

export interface PleskScanResult {
  host: string;
  subscriptions: string[];
  wordpress: WordPressInstallation[];
  wordpressHasMore?: boolean;
  hostFacts?: HostFacts;
  pleskCliAvailable?: boolean;
  warnings?: string[];
}

export interface HostFacts {
  pleskVersion?: string;
  phpVersion?: string;
  disk?: {
    filesystem: string;
    availableKb: number;
    usedPercent: number;
  };
}

export interface PleskScanOptions {
  wordpressOffset?: number;
  wordpressLimit?: number;
  useSudo?: boolean;
  collectHostFacts?: boolean;
  includeAlternateWordPressDetection?: boolean;
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

export function parsePleskVersion(output: string): string | undefined {
  return output.match(/Plesk(?:\s+\w+)?\s+\d+\.\d+\.\d+/i)?.[0];
}

export function parsePhpVersion(output: string): string | undefined {
  return output.match(/PHP\s+(\d+\.\d+\.\d+)/i)?.[1];
}

export function parseDiskUsage(output: string): HostFacts["disk"] | undefined {
  for (const line of output.split(/\r?\n/)) {
    const fields = line.trim().split(/\s+/);
    if (fields.length < 5 || !/^\d+%$/.test(fields[4])) continue;
    const availableKb = Number(fields[3]);
    const usedPercent = Number(fields[4].slice(0, -1));
    if (fields[0] && Number.isSafeInteger(availableKb) && Number.isInteger(usedPercent)) {
      return { filesystem: fields[0], availableKb, usedPercent };
    }
  }
  return undefined;
}

function wordpressPath(candidatePath: string, includeDetectionSignal = false): WordPressInstallation {
  const isVersionFile = candidatePath.endsWith("/wp-includes/version.php");
  const path = isVersionFile ? dirname(dirname(candidatePath)) : dirname(candidatePath);
  const marker = "/var/www/vhosts/";
  const relative = path.startsWith(marker) ? path.slice(marker.length) : "";
  const domain = relative.split("/")[0] || undefined;
  return {
    path,
    domain,
    classification: classifyWordPressInstallation(path, domain),
    ...(includeDetectionSignal ? { detectionSignals: [isVersionFile ? "wp-includes/version.php" : "wp-config.php"] } : {}),
  };
}

function parseWordPressCandidates(paths: string[], includeDetectionSignal: boolean): WordPressInstallation[] {
  const installations = new Map<string, WordPressInstallation>();
  for (const candidatePath of paths) {
    const installation = wordpressPath(candidatePath, includeDetectionSignal);
    const existing = installations.get(installation.path);
    if (!existing) {
      installations.set(installation.path, installation);
      continue;
    }
    if (installation.detectionSignals?.[0] && !existing.detectionSignals?.includes(installation.detectionSignals[0])) {
      existing.detectionSignals = [...(existing.detectionSignals ?? []), installation.detectionSignals[0]];
    }
  }
  return [...installations.values()];
}

function hasPathMarker(value: string, marker: string): boolean {
  return new RegExp(`(?:^|[\\/._-])${marker}(?:[0-9]*)?(?=$|[\\/._-])`, "i").test(value);
}

export function classifyWordPressInstallation(path: string, domain?: string): WordPressInstallationClassification {
  const value = `${path} ${domain ?? ""}`.toLowerCase();
  if (["backup", "backups", "old", "copy", "trash"].some((marker) => hasPathMarker(value, marker))) {
    return { kind: "backup", reason: "backup marker found in the domain or path" };
  }
  if (["staging", "stage", "dev", "development", "testing", "qa", "uat", "preprod", "preview", "sandbox"].some((marker) => hasPathMarker(value, marker))
    || /(?:^|\/)test(?:$|[\\/._-])/i.test(path)
    || domain?.split(".")[0].toLowerCase() === "test") {
    return { kind: "staging", reason: "staging marker found in the domain or path" };
  }
  if (/(?:^|\/)httpdocs(?:$|\/)/i.test(path) || /(?:^|\/)public_html(?:$|\/)/i.test(path)) {
    return { kind: "production", reason: "standard Plesk httpdocs path without staging or backup markers" };
  }
  return { kind: "unknown", reason: "path does not provide a reliable production, staging, or backup signal" };
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
  let pleskCliAvailable = true;
  try {
    subscriptions = parseLineList(await runner(host, `${prefix}plesk bin subscription --list`));
  } catch (error: unknown) {
    pleskCliAvailable = false;
    warnings.push(`Plesk CLI subscription discovery unavailable; using filesystem discovery only: ${shortError(error)}`);
    prefix = "";
  }
  const discoveryCommand = limit === undefined
    ? `${prefix}find /var/www/vhosts -xdev -maxdepth 4 -type f ${options.includeAlternateWordPressDetection ? "\\( -name wp-config.php -o -path '*/wp-includes/version.php' \\)" : "-name wp-config.php"} -print`
    : `${prefix}find /var/www/vhosts -xdev -maxdepth 4 -type f ${options.includeAlternateWordPressDetection ? "\\( -name wp-config.php -o -path '*/wp-includes/version.php' \\)" : "-name wp-config.php"} -print | sort | awk 'NR > ${offset} && NR <= ${offset + limit + 1} { print }'`;
  const configPaths = parseLineList(
    await runner(host, discoveryCommand),
  );
  const wordpressHasMore = limit === undefined ? undefined : configPaths.length > limit;
  let hostFacts: HostFacts | undefined;
  if (options.collectHostFacts) {
    hostFacts = {};
    const facts = [
      ["Plesk version", `${prefix}plesk version`, (output: string) => { hostFacts!.pleskVersion = parsePleskVersion(output); }],
      ["PHP version", `${prefix}php -v`, (output: string) => { hostFacts!.phpVersion = parsePhpVersion(output); }],
      ["disk usage", `${prefix}df -P -k /var/www/vhosts`, (output: string) => { hostFacts!.disk = parseDiskUsage(output); }],
    ] as const;
    for (const [name, command, assign] of facts) {
      try {
        const output = await runner(host, command);
        assign(output);
      } catch (error: unknown) {
        warnings.push(`Host fact ${name.toLowerCase()} unavailable: ${shortError(error)}`);
      }
    }
    if (!hostFacts.pleskVersion && !hostFacts.phpVersion && !hostFacts.disk) hostFacts = undefined;
  }
  return {
    host: host.alias,
    subscriptions,
    wordpress: parseWordPressCandidates(wordpressHasMore ? configPaths.slice(0, limit) : configPaths, Boolean(options.includeAlternateWordPressDetection)),
    ...(limit === undefined ? {} : { wordpressHasMore }),
    ...(hostFacts ? { hostFacts } : {}),
    ...(pleskCliAvailable ? {} : { pleskCliAvailable: false }),
    ...(warnings.length ? { warnings } : {}),
  };
}
