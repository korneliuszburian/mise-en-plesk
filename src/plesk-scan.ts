import { execFile, spawn } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { dirname } from "node:path";
import { tmpdir } from "node:os";
import { promisify } from "node:util";
import type { HostConfig } from "./ssh-inventory";
import { renderReadOnlyCommand, type ReadOnlyCommand } from "./ssh-transport";

const execFileAsync = promisify(execFile);

function execFileWithInput(
  executable: string,
  args: string[],
  options: { env?: NodeJS.ProcessEnv; timeout?: number; maxOutputBytes?: number },
  input?: string,
): Promise<{ stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const timeoutMs = typeof options.timeout === "number" ? options.timeout : undefined;
    let stdout = "";
    let stderr = "";
    let timedOut = false;
    let outputLimitExceeded = false;
    const maxOutputBytes = options.maxOutputBytes ?? 8 * 1024 * 1024;
    let forceKillTimer: NodeJS.Timeout | undefined;
    const child = spawn(executable, args, {
      env: options.env,
      stdio: ["pipe", "pipe", "pipe"],
      detached: process.platform !== "win32",
    });
    const terminate = (signal: NodeJS.Signals): void => {
      if (!child.pid) return;
      try {
        if (process.platform === "win32") child.kill(signal);
        else process.kill(-child.pid, signal);
      } catch {
        // The process may have exited between the timeout and cleanup.
      }
    };
    const timeoutTimer = timeoutMs === undefined ? undefined : setTimeout(() => {
      timedOut = true;
      terminate("SIGTERM");
      forceKillTimer = setTimeout(() => terminate("SIGKILL"), 500);
    }, timeoutMs);
    const appendOutput = (stream: "stdout" | "stderr", chunk: Buffer): void => {
      if (outputLimitExceeded) return;
      const currentBytes = Buffer.byteLength(stdout) + Buffer.byteLength(stderr);
      if (currentBytes + chunk.byteLength > maxOutputBytes) {
        outputLimitExceeded = true;
        terminate("SIGTERM");
        forceKillTimer = setTimeout(() => terminate("SIGKILL"), 500);
        return;
      }
      if (stream === "stdout") stdout += chunk.toString();
      else stderr += chunk.toString();
    };
    child.stdout?.on("data", (chunk: Buffer) => appendOutput("stdout", chunk));
    child.stderr?.on("data", (chunk: Buffer) => appendOutput("stderr", chunk));
    child.once("error", (error: Error) => {
      if (timeoutTimer) clearTimeout(timeoutTimer);
      if (forceKillTimer) clearTimeout(forceKillTimer);
      Object.assign(error, { stdout, stderr });
      reject(error);
    });
    child.once("close", (code, signal) => {
      if (timeoutTimer) clearTimeout(timeoutTimer);
      if (forceKillTimer) clearTimeout(forceKillTimer);
      const error = new Error(outputLimitExceeded
        ? `Command failed (output exceeded ${maxOutputBytes} bytes)`
        : `Command failed${timedOut ? " (timeout)" : ""}${signal ? ` (${signal})` : code !== null ? ` (exit code ${code})` : ""}`);
      if (code === 0 && !outputLimitExceeded) {
        resolve({ stdout, stderr });
        return;
      }
      Object.assign(error, { stdout, stderr, code: code ?? signal });
      reject(error);
    });
    child.stdin?.end(input);
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
  health?: HostHealth;
  wordpressHasMore?: boolean;
  hostFacts?: HostFacts;
  pleskCliAvailable?: boolean;
  warnings?: string[];
}

export interface HostHealth {
  reachable: boolean;
  detail?: string;
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

export type SshCommandRunner = (host: HostConfig, command: ReadOnlyCommand) => Promise<string>;

export type LegacySshCommandRunner = (host: HostConfig, command: string) => Promise<string>;

export function adaptLegacySshRunner(runner: LegacySshCommandRunner): SshCommandRunner {
  return (host, command) => runner(host, renderReadOnlyCommand(command));
}

interface SshInvocationOptions {
  controlPath?: string;
  stdin?: string;
  timeoutMs?: number;
  maxOutputBytes?: number;
}

export const DEFAULT_SSH_COMMAND_TIMEOUT_MS = 60_000;

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

export async function runSshCommand(host: HostConfig, command: ReadOnlyCommand, password?: string, options: SshInvocationOptions = {}): Promise<string> {
  const invocation = buildSshInvocation(host, password, options);
  try {
    const result = await execFileWithInput(invocation.executable, [...invocation.args, renderReadOnlyCommand(command)], {
      env: invocation.env,
      timeout: options.timeoutMs ?? DEFAULT_SSH_COMMAND_TIMEOUT_MS,
      maxOutputBytes: options.maxOutputBytes,
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
  run(command: ReadOnlyCommand): Promise<string>;
  close(): Promise<void>;
}

export async function createSshSession(host: HostConfig, password?: string, sudoPassword?: string, commandTimeoutMs = DEFAULT_SSH_COMMAND_TIMEOUT_MS): Promise<SshSession> {
  const directory = await mkdtemp(`${tmpdir()}/mise-en-plesk-`);
  const controlPath = `${directory}/control`;
  const run = (command: ReadOnlyCommand) => runSshCommand(host, command, password, {
    controlPath,
    stdin: sudoPassword === undefined ? undefined : `${sudoPassword}\n`,
    timeoutMs: commandTimeoutMs,
  });
  try {
    await run({ kind: "ssh-handshake" });
  } catch (error: unknown) {
    await rm(directory, { recursive: true, force: true });
    throw error;
  }

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
  const warnings: string[] = [];
  let subscriptions: string[] = [];
  let pleskCliAvailable = true;
  try {
    subscriptions = parseLineList(await runner(host, { kind: "plesk-subscriptions", useSudo: options.useSudo }));
  } catch (error: unknown) {
    pleskCliAvailable = false;
    warnings.push(`Plesk CLI subscription discovery unavailable; using filesystem discovery only: ${shortError(error)}`);
  }
  const filesystemUseSudo = pleskCliAvailable && options.useSudo;
  let configPaths: string[];
  try {
    configPaths = parseLineList(await runner(host, {
      kind: "wordpress-candidates",
      useSudo: filesystemUseSudo,
      includeAlternateDetection: options.includeAlternateWordPressDetection,
      offset,
      limit,
    }));
  } catch (error: unknown) {
    const detail = shortError(error);
    return {
      host: host.alias,
      subscriptions,
      wordpress: [],
      health: { reachable: false, detail },
      ...(pleskCliAvailable ? {} : { pleskCliAvailable: false }),
      warnings: [...warnings, `WordPress filesystem discovery unavailable: ${detail}`],
    };
  }
  const wordpressHasMore = limit === undefined ? undefined : configPaths.length > limit;
  let hostFacts: HostFacts | undefined;
  if (options.collectHostFacts) {
    hostFacts = {};
    const facts = [
      ["Plesk version", { kind: "plesk-version", useSudo: filesystemUseSudo }, (output: string) => { hostFacts!.pleskVersion = parsePleskVersion(output); }],
      ["PHP version", { kind: "php-version", useSudo: filesystemUseSudo }, (output: string) => { hostFacts!.phpVersion = parsePhpVersion(output); }],
      ["disk usage", { kind: "disk-usage", useSudo: filesystemUseSudo }, (output: string) => { hostFacts!.disk = parseDiskUsage(output); }],
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
