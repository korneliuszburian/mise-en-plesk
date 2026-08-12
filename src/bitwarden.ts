import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

export type BwRunner = (args: string[], env?: NodeJS.ProcessEnv) => Promise<string>;

export interface BitwardenField {
  name?: string;
  value?: string | null;
}

export interface BitwardenItem {
  id: string;
  name: string;
  notes?: string | null;
  login?: {
    username?: string;
    uris?: Array<{ uri?: string | null }>;
  };
  fields?: BitwardenField[];
}

export interface HostDescriptor {
  id: string;
  name: string;
  host: string;
  port: number;
  user: string;
  identitySource: string;
}

export interface SecureNoteSshCredentials {
  host: string;
  port: number;
  user: string;
  password: string;
}

export function ensureBwSession(env: NodeJS.ProcessEnv = process.env): string {
  const session = env.BW_SESSION?.trim();
  if (!session) {
    throw new Error(
      "BW_SESSION is not set. Run `source scripts/setup-bw-session.sh` in this shell first.",
    );
  }
  return session;
}

async function runBw(args: string[], env: NodeJS.ProcessEnv = process.env): Promise<string> {
  const result = await execFileAsync("bw", args, { env });
  return result.stdout;
}

export async function getBitwardenItem(
  id: string,
  env: NodeJS.ProcessEnv = process.env,
  runner: BwRunner = runBw,
): Promise<BitwardenItem> {
  const session = ensureBwSession(env);
  const output = await runner(["get", "item", id], { ...env, BW_SESSION: session });
  return JSON.parse(output) as BitwardenItem;
}

export async function listBitwardenItems(
  searchTerm: string,
  env: NodeJS.ProcessEnv = process.env,
  runner: BwRunner = runBw,
): Promise<BitwardenItem[]> {
  const session = ensureBwSession(env);
  const output = await runner(["list", "items", "--search", searchTerm], {
    ...env,
    BW_SESSION: session,
  });
  const parsed: unknown = JSON.parse(output);
  if (!Array.isArray(parsed)) throw new Error("Bitwarden returned a non-list response.");
  return parsed as BitwardenItem[];
}

function fieldValue(item: BitwardenItem, name: string): string | undefined {
  return item.fields?.find((field) => field.name?.toLowerCase() === name.toLowerCase())?.value ?? undefined;
}

function parseSshUri(rawUri: string): { host: string; port: number } {
  const value = rawUri.includes("://") ? rawUri : `ssh://${rawUri}`;
  const parsed = new URL(value);
  if (!parsed.hostname) throw new Error("Bitwarden item has an SSH URI without a host.");
  return { host: parsed.hostname, port: Number(parsed.port) || 22 };
}

export function normalizeHostDescriptor(item: BitwardenItem): HostDescriptor {
  const rawUri = item.login?.uris?.find((entry) => entry.uri)?.uri;
  const secureNote = parseSecureNoteSsh(item.notes);
  if (!rawUri && !secureNote) {
    throw new Error(`Bitwarden item ${item.id} has no SSH login URI or supported secure note.`);
  }
  const { host, port } = rawUri ? parseSshUri(rawUri) : secureNote!;
  const user = item.login?.username?.trim() ?? secureNote?.user;
  if (!user) throw new Error(`Bitwarden item ${item.id} has no login username.`);
  return {
    id: item.id,
    name: item.name,
    host,
    port,
    user,
    identitySource: fieldValue(item, "identitySource") ?? `bitwarden:${item.id}`,
  };
}

export function parseSecureNoteSsh(notes: string | null | undefined): SecureNoteSshCredentials | null {
  if (!notes) return null;
  const match = notes.trim().match(/^([^:\s]+):(\d+)(?:\\n|\n)([^:\s]+):(.+)$/s);
  if (!match) return null;
  const port = Number(match[2]);
  if (!Number.isInteger(port) || port < 1 || port > 65535) return null;
  return { host: match[1], port, user: match[3], password: match[4] };
}

export function extractSecureNoteSshCredentials(item: BitwardenItem): SecureNoteSshCredentials | null {
  return parseSecureNoteSsh(item.notes);
}
