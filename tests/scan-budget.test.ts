import { describe, expect, it } from "vitest";
import { shouldContinueScanChunks } from "../src/scan-budget";

describe("scan chunk budget", () => {
  it("stops at the configured per-host chunk boundary", () => {
    expect(shouldContinueScanChunks(true, false, 1, 2)).toBe(true);
    expect(shouldContinueScanChunks(true, false, 2, 2)).toBe(false);
    expect(shouldContinueScanChunks(true, true, 1, 2)).toBe(false);
    expect(shouldContinueScanChunks(false, false, 1, 2)).toBe(false);
  });
});
