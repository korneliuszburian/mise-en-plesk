import { describe, expect, it } from "vitest";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { reconcileFindings, emptyFindingState, readFindingState, writeFindingState, type FindingState } from "../src/finding-state";
import type { Finding } from "../src/findings";

const finding = (id: string): Finding => ({
  id,
  code: "plugin-update",
  severity: "P2",
  host: "master-ssh",
  installationPath: "/srv/site",
  plugin: id,
  message: `plugin ${id} has an update available`,
});

describe("finding state transitions", () => {
  it("opens new findings and keeps existing findings quiet", () => {
    const now = "2026-08-12T00:00:00.000Z";
    const first = reconcileFindings(emptyFindingState(), [finding("one")], now);
    expect(first.events.map((event) => event.type)).toEqual(["opened"]);
    expect(first.state.findings.one).toMatchObject({ status: "open", firstSeen: now, lastSeen: now });

    const second = reconcileFindings(first.state, [finding("one")], "2026-08-13T00:00:00.000Z");
    expect(second.events).toEqual([]);
    expect(second.state.findings.one).toMatchObject({ status: "open", firstSeen: now, lastSeen: "2026-08-13T00:00:00.000Z" });
  });

  it("resolves missing findings and emits a reopen event when they return", () => {
    const opened = reconcileFindings(emptyFindingState(), [finding("one")], "2026-08-12T00:00:00.000Z");
    const resolved = reconcileFindings(opened.state, [], "2026-08-13T00:00:00.000Z");
    expect(resolved.events).toEqual([expect.objectContaining({ type: "resolved", finding: expect.objectContaining({ id: "one" }) })]);
    expect(resolved.state.findings.one).toMatchObject({ status: "resolved", resolvedAt: "2026-08-13T00:00:00.000Z" });

    const reopened = reconcileFindings(resolved.state, [finding("one")], "2026-08-14T00:00:00.000Z");
    expect(reopened.events).toEqual([expect.objectContaining({ type: "reopened", finding: expect.objectContaining({ id: "one" }) })]);
    expect(reopened.state.findings.one).toMatchObject({ status: "open", firstSeen: "2026-08-12T00:00:00.000Z", lastSeen: "2026-08-14T00:00:00.000Z" });
    expect((reopened.state.findings.one as FindingState["findings"][string]).resolvedAt).toBeUndefined();
  });

  it("persists state as local JSON", async () => {
    const directory = await mkdtemp(join(tmpdir(), "mise-en-plesk-findings-"));
    const path = join(directory, "nested", "findings.json");
    const state = reconcileFindings(emptyFindingState(), [finding("one")], "2026-08-12T00:00:00.000Z").state;
    await writeFindingState(path, state);
    await expect(readFindingState(path)).resolves.toEqual(state);
    await expect(readFile(path, "utf8")).resolves.toContain('"version": 1');
  });

  it("does not resolve findings belonging to hosts outside the scan scope", () => {
    const master = finding("master-finding");
    const dev = { ...finding("dev-finding"), host: "dev-ssh" };
    const initial = reconcileFindings(emptyFindingState(), [master, dev], "2026-08-12T00:00:00.000Z").state;
    const result = reconcileFindings(initial, [], "2026-08-13T00:00:00.000Z", new Set(["master-ssh"]));

    expect(result.state.findings["master-finding"].status).toBe("resolved");
    expect(result.state.findings["dev-finding"].status).toBe("open");
    expect(result.events.map((event) => event.finding.id)).toEqual(["master-finding"]);
  });
});
