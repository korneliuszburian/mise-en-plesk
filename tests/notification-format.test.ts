import { describe, expect, it } from "vitest";
import { chunkFindingEvents } from "../src/notification-format";
import type { FindingEvent } from "../src/finding-state";

function event(id: string, domain: string, message: string): FindingEvent {
  return {
    type: "opened",
    occurredAt: "2026-08-18T00:00:00.000Z",
    finding: {
      id, code: "plugin-vulnerable", severity: "P1", host: "dev-ssh",
      installationPath: "/srv/site", domain, message,
      status: "open", firstSeen: "2026-08-18T00:00:00.000Z", lastSeen: "2026-08-18T00:00:00.000Z",
    },
  };
}

describe("notification formatting", () => {
  it("groups findings from one site while keeping separate sites distinct", () => {
    const chunks = chunkFindingEvents([
      event("one", "example.test", "plugin risk"),
      event("two", "example.test", "uploads risk"),
      event("three", "other.test", "core risk"),
    ], 500);

    expect(chunks).toHaveLength(1);
    expect(chunks[0]?.events.map((item) => item.finding.id)).toEqual(["one", "two", "three"]);
    expect(chunks[0]?.text).toContain("dev-ssh/example.test:");
    expect(chunks[0]?.text).toContain("- opened: uploads risk");
    expect(chunks[0]?.text).toContain("[event one.0]");
    expect(chunks[0]?.text).toContain("dev-ssh/other.test:");
  });

  it("splits an oversized site group into bounded chunks", () => {
    const chunks = chunkFindingEvents([event("one", "example.test", "a very long risk message"), event("two", "example.test", "another very long risk message")], 20);
    expect(chunks.every((chunk) => chunk.text.length <= 20)).toBe(true);
    expect(chunks.flatMap((chunk) => chunk.events).map((item) => item.finding.id)).toEqual(["one", "two"]);
  });

  it("labels resolved findings as recovered", () => {
    const resolved = { ...event("resolved", "example.test", "risk cleared"), type: "resolved" } satisfies FindingEvent;
    expect(chunkFindingEvents([resolved], 500)[0]?.text).toContain("recovered");
  });
});
