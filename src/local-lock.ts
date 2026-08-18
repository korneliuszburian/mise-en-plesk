import { mkdir, open, readFile, unlink } from "node:fs/promises";
import { dirname } from "node:path";

interface LockRecord {
  pid: number;
  acquiredAt: string;
}

export interface LocalLock {
  release(): Promise<void>;
}

function isLockRecord(value: unknown): value is LockRecord {
  return Boolean(value)
    && typeof value === "object"
    && Number.isSafeInteger((value as LockRecord).pid)
    && typeof (value as LockRecord).acquiredAt === "string";
}

function processExists(pid: number): boolean {
  if (pid === process.pid) return true;
  try {
    process.kill(pid, 0);
    return true;
  } catch (error: unknown) {
    return Boolean(error && typeof error === "object" && "code" in error && error.code === "EPERM");
  }
}

async function readLockRecord(path: string): Promise<LockRecord | undefined> {
  try {
    const parsed: unknown = JSON.parse(await readFile(path, "utf8"));
    return isLockRecord(parsed) ? parsed : undefined;
  } catch {
    return undefined;
  }
}

export async function acquireLocalLock(path: string): Promise<LocalLock> {
  await mkdir(dirname(path), { recursive: true });
  const record: LockRecord = { pid: process.pid, acquiredAt: new Date().toISOString() };

  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      const handle = await open(path, "wx", 0o600);
      try {
        await handle.writeFile(`${JSON.stringify(record)}\n`, "utf8");
      } finally {
        await handle.close();
      }
      let released = false;
      return {
        async release(): Promise<void> {
          if (released) return;
          released = true;
          const current = await readLockRecord(path);
          if (current?.pid !== record.pid || current.acquiredAt !== record.acquiredAt) return;
          try {
            await unlink(path);
          } catch (error: unknown) {
            if (!(error && typeof error === "object" && "code" in error && error.code === "ENOENT")) throw error;
          }
        },
      };
    } catch (error: unknown) {
      const exists = error && typeof error === "object" && "code" in error && error.code === "EEXIST";
      if (!exists) throw error;
      const current = await readLockRecord(path);
      if (!current) throw new Error(`Local lock exists but is invalid; inspect before removing it: ${path}`);
      if (current && processExists(current.pid)) {
        throw new Error(`Another mise-en-plesk process holds the local lock: ${path}`);
      }
      if (attempt === 1) throw new Error(`Could not recover stale local lock: ${path}`);
      try {
        await unlink(path);
      } catch (unlinkError: unknown) {
        if (!(unlinkError && typeof unlinkError === "object" && "code" in unlinkError && unlinkError.code === "ENOENT")) throw unlinkError;
      }
    }
  }
  throw new Error(`Could not acquire local lock: ${path}`);
}
