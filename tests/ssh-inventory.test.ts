import { mkdtemp, readFile } from "node:fs/promises";
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
});
