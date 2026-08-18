import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import {
  listBitwardenItems,
  type BitwardenItem,
  getBitwardenItem,
  normalizeHostDescriptor,
  type HostDescriptor,
} from "./bitwarden";

export interface HostConfig extends HostDescriptor {
  alias: string;
}

export type Inventory = Record<string, HostConfig>;

export interface BitwardenSync {
  listItems: (searchTerm: string) => Promise<BitwardenItem[]>;
}

const safeAliasPattern = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
const reservedAliases = new Set(["__proto__", "constructor", "prototype"]);

function nonEmptyString(value: unknown, field: string, source: string): string {
  if (typeof value !== "string" || !value.trim() || /[\u0000-\u001f\u007f]/.test(value)) {
    throw new Error(`${source}.${field} must be a non-empty string without control characters`);
  }
  return value;
}

function validateHostConfig(value: unknown, alias: string): HostConfig {
  const source = `Inventory entry ${alias}`;
  if (!safeAliasPattern.test(alias) || reservedAliases.has(alias)) {
    throw new Error(`Inventory alias is unsafe: ${alias}`);
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${source} must be an object`);
  }
  const host = value as Partial<HostConfig>;
  const entryAlias = nonEmptyString(host.alias, "alias", source);
  if (entryAlias !== alias) throw new Error(`Inventory key must match host alias: ${alias}`);
  const port = host.port;
  if (typeof port !== "number" || !Number.isSafeInteger(port) || port < 1 || port > 65535) {
    throw new Error(`${source}.port must be a valid TCP port`);
  }
  const hostName = nonEmptyString(host.host, "host", source);
  if (/[\s/@]/.test(hostName)) throw new Error(`${source}.host contains unsafe SSH target characters`);
  const user = nonEmptyString(host.user, "user", source);
  if (/[\s/@:]/.test(user)) throw new Error(`${source}.user contains unsafe SSH username characters`);
  if (host.credentialMode !== undefined && host.credentialMode !== "secure-note-password") {
    throw new Error(`${source}.credentialMode is invalid`);
  }
  return {
    id: nonEmptyString(host.id, "id", source),
    name: nonEmptyString(host.name, "name", source),
    host: hostName,
    port,
    user,
    identitySource: nonEmptyString(host.identitySource, "identitySource", source),
    ...(host.credentialMode ? { credentialMode: host.credentialMode } : {}),
    alias: entryAlias,
  };
}

function validateInventory(value: unknown): Inventory {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Inventory must be a JSON object keyed by alias.");
  }
  const inventory: Inventory = {};
  for (const [alias, host] of Object.entries(value)) inventory[alias] = validateHostConfig(host, alias);
  return inventory;
}

function aliasFor(name: string): string {
  const alias = name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
  return alias || "host";
}

export async function readInventory(path = "inventory.json"): Promise<Inventory> {
  return validateInventory(JSON.parse(await readFile(path, "utf8")) as unknown);
}

export async function writeInventory(path: string, inventory: Inventory): Promise<void> {
  const validated = validateInventory(inventory);
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${JSON.stringify(validated, null, 2)}\n`, "utf8");
}

export async function syncFromBitwarden(
  searchTerm: string,
  path = "inventory.json",
  sync: BitwardenSync = { listItems: (term) => listBitwardenItems(term) },
): Promise<Inventory> {
  const inventory: Inventory = {};
  let items = await sync.listItems(searchTerm);
  if (!items.length && searchTerm === "mise-en-plesk") {
    items = (await sync.listItems("")).filter((item) => /^(master|dev) ssh$/i.test(item.name));
  }
  for (const item of items) {
    const descriptor = normalizeHostDescriptor(item);
    let alias = aliasFor(descriptor.name);
    let suffix = 2;
    while (inventory[alias]) alias = `${aliasFor(descriptor.name)}-${suffix++}`;
    inventory[alias] = { alias, ...descriptor };
  }
  await writeInventory(path, inventory);
  return inventory;
}

export async function getInventoryHostItem(host: HostConfig): Promise<BitwardenItem> {
  return getBitwardenItem(host.id);
}

export function renderSshConfig(inventory: Inventory): string {
  return Object.values(inventory).map((host) => [
    `Host ${host.alias}`,
    `  HostName ${host.host}`,
    `  Port ${host.port}`,
    `  User ${host.user}`,
    "",
  ].join("\n")).join("\n");
}
