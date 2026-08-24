import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { advanceScanCursor, emptyScanCursor, readScanCursor, reconcileScanCursor, writeScanCursor } from "../src/scan-cursor";

describe("scan cursor", () => {
  it("advances a host by observed progress and resets completed hosts", () => {
    const first = advanceScanCursor(emptyScanCursor(), { host: "dev-ssh", offset: 0, scanned: 20, complete: false });
    expect(first.hosts["dev-ssh"].offset).toBe(20);
    const complete = advanceScanCursor(first, { host: "dev-ssh", offset: 20, scanned: 0, complete: true });
    expect(complete.hosts["dev-ssh"].offset).toBe(0);
  });

  it("round-trips the cursor atomically", async () => {
    const directory = await mkdtemp(join(tmpdir(), "mise-en-plesk-cursor-"));
    const path = join(directory, "nested", "cursor.json");
    const cursor = advanceScanCursor(emptyScanCursor(), { host: "master-ssh", offset: 0, scanned: 10, complete: false });
    await writeScanCursor(path, cursor);
    await expect(readScanCursor(path)).resolves.toEqual(cursor);
  });

  it("refuses to advance after an incomplete scan made no progress", () => {
    expect(() => advanceScanCursor(emptyScanCursor(), { host: "master-ssh", offset: 0, scanned: 0, complete: false }))
      .toThrow("made no progress");
    const maximalCursor = { version: 1 as const, hosts: { "master-ssh": { offset: Number.MAX_SAFE_INTEGER, updatedAt: "2026-08-24T14:15:17.000Z" } } };
    expect(() => advanceScanCursor(maximalCursor, { host: "master-ssh", offset: Number.MAX_SAFE_INTEGER, scanned: 1, complete: false }))
      .toThrow("safe integer");
  });

  it("can explicitly defer a transient zero-progress page without moving the cursor", () => {
    const cursor = advanceScanCursor(emptyScanCursor(), { host: "master-ssh", offset: 0, scanned: 320, complete: false });
    const result = reconcileScanCursor(cursor, { host: "master-ssh", offset: 320, scanned: 0, complete: false });
    expect(result).toMatchObject({ outcome: "deferred", previousOffset: 320, nextOffset: 320 });
    expect(result.cursor).toEqual(cursor);
  });

  it.each([
    { offset: 0, scanned: 20, complete: false },
    { offset: 500, scanned: 20, complete: false },
    { offset: 0, scanned: 0, complete: true },
  ])("rejects report progress that does not match the persisted cursor: %j", (progress) => {
    const cursor = advanceScanCursor(emptyScanCursor(), { host: "master-ssh", offset: 0, scanned: 320, complete: false });
    expect(() => reconcileScanCursor(cursor, { host: "master-ssh", ...progress })).toThrow("does not match cursor 320");
  });

  it("rejects malformed completion flags", () => {
    expect(() => advanceScanCursor(emptyScanCursor(), { host: "master-ssh", offset: 0, scanned: 0, complete: "true" as unknown as boolean }))
      .toThrow("completion flag");
  });
});
