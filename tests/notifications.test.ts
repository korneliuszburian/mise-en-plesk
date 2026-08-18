import { describe, expect, it } from "vitest";
import { notifyFindingEvents } from "../src/notifications";
import type { FindingEvent } from "../src/finding-state";

const event = (severity: "P1" | "P2", type: "opened" | "reopened" | "resolved"): FindingEvent => ({
  type,
  occurredAt: "2026-08-18T00:00:00.000Z",
  finding: {
    id: "finding-1",
    code: "plugin-vulnerable",
    severity,
    host: "master-ssh",
    installationPath: "/srv/site",
    domain: "example.test",
    message: "plugin sample has known vulnerabilities",
    status: "open",
    firstSeen: "2026-08-18T00:00:00.000Z",
    lastSeen: "2026-08-18T00:00:00.000Z",
  },
});

describe("finding notifications", () => {
  it("does not perform network I/O when disabled", async () => {
    let calls = 0;
    await expect(notifyFindingEvents([event("P1", "opened")], { fetchImpl: async () => { calls += 1; throw new Error("must not call"); } })).resolves.toEqual({ sent: false, eligibleEvents: 1 });
    expect(calls).toBe(0);
  });

  it("posts only new or reopened P1 findings", async () => {
    let request: RequestInit | undefined;
    const result = await notifyFindingEvents([
      event("P1", "opened"),
      event("P1", "resolved"),
      event("P2", "opened"),
    ], {
      webhookUrl: "https://alerts.example.test/hook",
      fetchImpl: async (_url, init) => {
        request = init;
        return new Response(null, { status: 202 });
      },
    });

    expect(result).toEqual({ sent: true, eligibleEvents: 1 });
    expect(request?.method).toBe("POST");
    expect(JSON.parse(String(request?.body))).toMatchObject({
      kind: "wordpress-risk-alert",
      events: [{ type: "opened", finding: { severity: "P1", domain: "example.test" } }],
    });
  });

  it("swallows webhook failures so scans can still finish", async () => {
    const debug: string[] = [];
    await expect(notifyFindingEvents([event("P1", "reopened")], {
      webhookUrl: "https://alerts.example.test/hook",
      fetchImpl: async () => { throw new Error("network down"); },
      debug: (message) => debug.push(message),
    })).resolves.toEqual({ sent: false, eligibleEvents: 1 });
    expect(debug[0]).toContain("alert notification skipped");
  });
});
