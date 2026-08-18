import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import type { ScanProgress } from "./wp-audit";

export interface ScanCursorEntry {
  offset: number;
  updatedAt: string;
}

export interface ScanCursor {
  version: 1;
  hosts: Record<string, ScanCursorEntry>;
}

export function emptyScanCursor(): ScanCursor {
  return { version: 1, hosts: {} };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function isCursorEntry(value: unknown): value is ScanCursorEntry {
  return isRecord(value)
    && typeof value.offset === "number" && Number.isSafeInteger(value.offset) && value.offset >= 0
    && typeof value.updatedAt === "string";
}

export function validateScanCursor(value: unknown, path = "scan cursor"): ScanCursor {
  if (!isRecord(value) || value.version !== 1 || !isRecord(value.hosts)
    || !Object.values(value.hosts).every(isCursorEntry)) {
    throw new Error(`Invalid ${path}.`);
  }
  return value as unknown as ScanCursor;
}

export function advanceScanCursor(
  cursor: ScanCursor,
  progress: ScanProgress,
): ScanCursor {
  if (typeof progress.complete !== "boolean") throw new Error("scan progress has an invalid completion flag");
  if (!progress.host || !Number.isSafeInteger(progress.offset) || progress.offset < 0) {
    throw new Error("scan progress has an invalid host or offset");
  }
  if (!Number.isSafeInteger(progress.scanned) || progress.scanned < 0) {
    throw new Error("scan progress has an invalid scanned count");
  }
  if (!progress.complete && progress.scanned < 1) {
    throw new Error(`scan progress made no progress for ${progress.host}`);
  }
  if (!progress.complete && progress.offset > Number.MAX_SAFE_INTEGER - progress.scanned) {
    throw new Error(`scan progress exceeded safe integer range for ${progress.host}`);
  }
  const nextOffset = progress.complete ? 0 : progress.offset + progress.scanned;
  return {
    version: 1,
    hosts: {
      ...cursor.hosts,
      [progress.host]: { offset: nextOffset, updatedAt: new Date().toISOString() },
    },
  };
}

export async function readScanCursor(path: string): Promise<ScanCursor> {
  try {
    return validateScanCursor(JSON.parse(await readFile(path, "utf8")) as unknown, path);
  } catch (error: unknown) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") return emptyScanCursor();
    throw error;
  }
}

export async function writeScanCursor(path: string, cursor: ScanCursor): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  const temporaryPath = `${path}.tmp-${process.pid}`;
  await writeFile(temporaryPath, `${JSON.stringify(cursor, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
  await rename(temporaryPath, path);
}
