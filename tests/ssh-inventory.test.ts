import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { type HostDescriptor } from "../src/bitwarden";
import {
  readInventory,
  syncFromBitwarden,
  writeInventory,
} from "../src/ssh-inventory";

const descriptor: HostDescriptor = {
  id: "1",
  name: "Master Plesk",
  host: "master.example.test",
  port: 22,
  user: "root",
  identitySource: "ssh-key",
};

describe("ssh inventory", () => {
  it("writes and reads a typed inventory file", async () => {
    const directory = await mkdtemp(join(tmpdir(), "mise-en-plesk-"));
    const path = join(directory, "inventory.json");
    const inventory = { master: { ...descriptor, alias: "master" } };

    await writeInventory(path, inventory);
    await expect(readInventory(path)).resolves.toEqual(inventory);
    await expect(readFile(path, "utf8")).resolves.toContain('"master"');
  });

  it("syncs normalized Bitwarden hosts into aliases", async () => {
    const directory = await mkdtemp(join(tmpdir(), "mise-en-plesk-"));
    const path = join(directory, "inventory.json");
    const inventory = await syncFromBitwarden("mise-en-plesk", path, {
      listItems: async () => [
        { id: "1", name: "Master Plesk", login: { username: "root", uris: [{ uri: "master.example.test" }] } },
      ],
    });

    expect(inventory).toEqual({
      "master-plesk": {
        alias: "master-plesk",
        id: "1",
        name: "Master Plesk",
        host: "master.example.test",
        port: 22,
        user: "root",
        identitySource: "bitwarden:1",
      },
    });
    await expect(readInventory(path)).resolves.toEqual(inventory);
  });

  it("falls back to named master and dev secure notes when the tag search is empty", async () => {
    const directory = await mkdtemp(join(tmpdir(), "mise-en-plesk-"));
    const path = join(directory, "inventory.json");
    const searches: string[] = [];
    const inventory = await syncFromBitwarden("mise-en-plesk", path, {
      listItems: async (term) => {
        searches.push(term);
        if (term === "") return [
          { id: "master", name: "master ssh", notes: "master.example.test:2222\nroot:secret" },
          { id: "dev", name: "dev ssh", notes: "dev.example.test:2222\nroot:secret" },
          { id: "other", name: "Unrelated note", notes: "other.example.test:2222\nroot:secret" },
        ];
        return [];
      },
    });

    expect(searches).toEqual(["mise-en-plesk", ""]);
    expect(Object.keys(inventory)).toEqual(["master-ssh", "dev-ssh"]);
    expect(inventory["master-ssh"]).not.toHaveProperty("password");
  });

  it("rejects a cached inventory entry with an invalid SSH boundary", async () => {
    const directory = await mkdtemp(join(tmpdir(), "mise-en-plesk-"));
    const path = join(directory, "inventory.json");
    await writeFile(path, JSON.stringify({
      master: { ...descriptor, alias: "master", port: 0 },
    }));

    await expect(readInventory(path)).rejects.toThrow("master.port must be a valid TCP port");
  });

  it("rejects an inventory key that does not match the host alias", async () => {
    const directory = await mkdtemp(join(tmpdir(), "mise-en-plesk-"));
    const path = join(directory, "inventory.json");
    await writeFile(path, JSON.stringify({
      other: { ...descriptor, alias: "master" },
    }));

    await expect(readInventory(path)).rejects.toThrow("Inventory key must match host alias");
  });

  it("rejects an SSH username containing separators", async () => {
    const directory = await mkdtemp(join(tmpdir(), "mise-en-plesk-"));
    const path = join(directory, "inventory.json");
    await writeFile(path, JSON.stringify({
      master: { ...descriptor, alias: "master", user: "root@example" },
    }));

    await expect(readInventory(path)).rejects.toThrow("master.user contains unsafe SSH username characters");
  });
});
