import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { createMonitorStaleFinding, isHeartbeatStale, readHeartbeat, writeHeartbeat, type MonitorHeartbeat } from "../src/monitor-health";

describe("monitor heartbeat", () => {
  it("considers a missing completion and an old completion stale", () => {
    const now = new Date("2026-08-18T12:00:00.000Z");
    expect(isHeartbeatStale(undefined, now, 60 * 60 * 1000)).toBe(true);
    expect(isHeartbeatStale({ version: 1, target: "all", startedAt: "2026-08-18T11:30:00.000Z" }, now, 60 * 60 * 1000)).toBe(true);
    expect(isHeartbeatStale({ version: 1, target: "all", startedAt: "2026-08-18T11:00:00.000Z", completedAt: "2026-08-18T11:30:00.000Z" }, now, 60 * 60 * 1000)).toBe(false);
    expect(isHeartbeatStale({ version: 1, target: "all", startedAt: "2026-08-18T09:00:00.000Z", completedAt: "2026-08-18T10:00:00.000Z" }, now, 60 * 60 * 1000)).toBe(true);
  });

  it("writes heartbeat metadata atomically and reads it back", async () => {
    const directory = await mkdtemp(join(tmpdir(), "mise-en-plesk-heartbeat-"));
    const path = join(directory, "heartbeat.json");
    const heartbeat: MonitorHeartbeat = {
      version: 1,
      target: "dev-ssh",
      startedAt: "2026-08-18T11:00:00.000Z",
      completedAt: "2026-08-18T11:05:00.000Z",
      scanComplete: false,
      reportPath: "reports/plesk-wp-audit-20260818.json",
    };

    await writeHeartbeat(path, heartbeat);

    await expect(readHeartbeat(path)).resolves.toEqual(heartbeat);
    await expect(readFile(path, "utf8")).resolves.toContain('"version": 1');
  });

  it("creates one stable P1 finding for stale monitor state", () => {
    const finding = createMonitorStaleFinding(undefined, new Date("2026-08-18T12:00:00.000Z"));

    expect(finding).toMatchObject({
      id: "finding-monitor-stale",
      code: "monitor-stale",
      severity: "P1",
      installationPath: "__monitor__",
    });
  });
});
