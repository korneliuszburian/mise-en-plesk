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

function aliasFor(name: string): string {
  const alias = name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
  return alias || "host";
}

export async function readInventory(path = "inventory.json"): Promise<Inventory> {
  const value: unknown = JSON.parse(await readFile(path, "utf8"));
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Inventory must be a JSON object keyed by alias.");
  }
  return value as Inventory;
}

export async function writeInventory(path: string, inventory: Inventory): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${JSON.stringify(inventory, null, 2)}\n`, "utf8");
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
