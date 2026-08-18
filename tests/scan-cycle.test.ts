import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  appendScanCycleFindings,
  completeScanCycle,
  emptyScanCycleState,
  prepareScanCycle,
  readScanCycleState,
  writeScanCycleState,
} from "../src/scan-cycle";
import type { Finding } from "../src/findings";

const finding = (id: string): Finding => ({
  id,
  code: "plugin-update",
  severity: "P2",
  host: "master-ssh",
  installationPath: `/srv/${id}`,
  plugin: id,
  message: `plugin ${id} has an update available`,
});

describe("scan cycle state", () => {
  it("accumulates chunks and only completes an eligible cycle", () => {
    let state = prepareScanCycle(emptyScanCycleState(), "master-ssh", 0, "2026-08-18T10:00:00.000Z");
    state = appendScanCycleFindings(state, "master-ssh", [finding("one")]);
    state = prepareScanCycle(state, "master-ssh", 20);
    state = appendScanCycleFindings(state, "master-ssh", [finding("two")]);

    const completed = completeScanCycle(state, "master-ssh");
    expect(completed.findings?.map((item) => item.id)).toEqual(["one", "two"]);
    expect(completed.state.hosts["master-ssh"]).toBeUndefined();
  });

  it("refuses to complete a cycle whose offset state was missing", () => {
    let state = prepareScanCycle(emptyScanCycleState(), "master-ssh", 20);
    state = appendScanCycleFindings(state, "master-ssh", [finding("one")]);

    expect(completeScanCycle(state, "master-ssh").findings).toBeNull();
  });

  it("round-trips and validates persisted cycle state", async () => {
    const directory = await mkdtemp(join(tmpdir(), "mise-en-plesk-cycle-"));
    const path = join(directory, "nested", "cycles.json");
    const state = appendScanCycleFindings(
      prepareScanCycle(emptyScanCycleState(), "dev-ssh", 0),
      "dev-ssh",
      [finding("dev")],
    );

    await writeScanCycleState(path, state);
    await expect(readScanCycleState(path)).resolves.toEqual(state);
    await expect(readFile(path, "utf8")).resolves.toContain('"version": 1');

    await writeFile(path, JSON.stringify({ version: 1, hosts: { broken: { findings: [] } } }));
    await expect(readScanCycleState(path)).rejects.toThrow("Invalid");
  });
});
