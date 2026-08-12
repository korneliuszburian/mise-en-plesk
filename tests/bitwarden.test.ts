import { describe, expect, it } from "vitest";
import {
  normalizeHostDescriptor,
  parseSecureNoteSsh,
  type BitwardenItem,
  type BwRunner,
  listBitwardenItems,
} from "../src/bitwarden";

describe("bitwarden", () => {
  it("lists items using the session and search term", async () => {
    const calls: string[][] = [];
    const runner: BwRunner = async (args) => {
      calls.push(args);
      return JSON.stringify([{ id: "1", name: "Master" }]);
    };

    await expect(
      listBitwardenItems("mise-en-plesk", { BW_SESSION: "session" }, runner),
    ).resolves.toEqual([{ id: "1", name: "Master" }]);
    expect(calls[0]).toEqual(["list", "items", "--search", "mise-en-plesk"]);
  });

  it("fails with an actionable message when BW_SESSION is missing", async () => {
    await expect(listBitwardenItems("mise-en-plesk", {}, async () => "[]"))
      .rejects.toThrow("BW_SESSION is not set");
  });

  it("normalizes a Bitwarden login item into a host descriptor", () => {
    const item: BitwardenItem = {
      id: "host-1",
      name: "Master Plesk",
      login: { username: "root", uris: [{ uri: "ssh://master.example.test:2222" }] },
      fields: [{ name: "identitySource", value: "ssh-key" }],
    };

    expect(normalizeHostDescriptor(item)).toEqual({
      id: "host-1",
      name: "Master Plesk",
      host: "master.example.test",
      port: 2222,
      user: "root",
      identitySource: "ssh-key",
    });
  });

  it("normalizes the host part of a secure SSH note without exposing its password", () => {
    const item: BitwardenItem = {
      id: "secure-note-1",
      name: "master ssh",
      notes: "master.example.test:2222\nroot:test-password",
    };

    expect(normalizeHostDescriptor(item)).toEqual({
      id: "secure-note-1",
      name: "master ssh",
      host: "master.example.test",
      port: 2222,
      user: "root",
      identitySource: "bitwarden:secure-note-1",
    });
    expect(parseSecureNoteSsh(item.notes)).toEqual({
      host: "master.example.test",
      port: 2222,
      user: "root",
      password: "test-password",
    });
  });

  it("accepts the literal backslash-n separator used by Bitwarden secure notes", () => {
    expect(parseSecureNoteSsh("master.example.test:2222\\nroot:test-password")).toEqual({
      host: "master.example.test",
      port: 2222,
      user: "root",
      password: "test-password",
    });
  });
});
