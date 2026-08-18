import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { acquireLocalLock } from "../src/local-lock";

describe("local process lock", () => {
  it("prevents a second process in the same process from acquiring the lock", async () => {
    const directory = await mkdtemp(join(tmpdir(), "mise-en-plesk-lock-"));
    const path = join(directory, "run.lock");
    const first = await acquireLocalLock(path);
    await expect(acquireLocalLock(path)).rejects.toThrow("holds the local lock");
    await first.release();
    const second = await acquireLocalLock(path);
    await second.release();
  });

  it("recovers a lock owned by a dead process", async () => {
    const directory = await mkdtemp(join(tmpdir(), "mise-en-plesk-lock-"));
    const path = join(directory, "run.lock");
    await writeFile(path, JSON.stringify({ pid: 2147483647, acquiredAt: "2020-01-01T00:00:00.000Z" }));
    const lock = await acquireLocalLock(path);
    await expect(lock.release()).resolves.toBeUndefined();
  });

  it("does not delete an invalid lock automatically", async () => {
    const directory = await mkdtemp(join(tmpdir(), "mise-en-plesk-lock-"));
    const path = join(directory, "run.lock");
    await writeFile(path, "incomplete");
    await expect(acquireLocalLock(path)).rejects.toThrow("lock exists but is invalid");
  });
});
