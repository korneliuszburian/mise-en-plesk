import { describe, expect, it } from "vitest";
import { isCompleteScanPage, nextScanOffset } from "../src/scan-lifecycle";

describe("scan lifecycle", () => {
  it("does not complete a page after host discovery becomes unreachable", () => {
    expect(isCompleteScanPage({ health: { reachable: false, detail: "timeout" } }, undefined, 0)).toBe(false);
    expect(isCompleteScanPage({ health: { reachable: false, detail: "timeout" }, wordpressHasMore: false }, 10, 0)).toBe(false);
    expect(isCompleteScanPage({ pleskCliAvailable: false }, undefined, 0)).toBe(false);
  });

  it("completes unbounded and bounded pages only at their valid boundaries", () => {
    expect(isCompleteScanPage({}, undefined, 0)).toBe(true);
    expect(isCompleteScanPage({}, undefined, 1)).toBe(false);
    expect(isCompleteScanPage({ wordpressHasMore: true }, 10, 0)).toBe(false);
    expect(isCompleteScanPage({ wordpressHasMore: false }, 10, 10)).toBe(true);
  });

  it("advances only when a bounded page made progress", () => {
    expect(nextScanOffset(10, 4)).toBe(14);
    expect(() => nextScanOffset(10, 0)).toThrow("no progress");
    expect(() => nextScanOffset(Number.MAX_SAFE_INTEGER, 1)).toThrow("safe integer");
  });
});
