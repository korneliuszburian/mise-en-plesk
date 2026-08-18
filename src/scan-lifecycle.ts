import type { HostHealth } from "./plesk-scan";

export interface ScanPageCompletionInput {
  health?: HostHealth;
  pleskCliAvailable?: boolean;
  wordpressHasMore?: boolean;
}

/** A page is complete only when discovery itself did not report a host failure. */
export function isCompleteScanPage(
  page: ScanPageCompletionInput,
  maxSites: number | undefined,
  offset: number,
): boolean {
  if (page.health?.reachable === false) return false;
  if (page.pleskCliAvailable === false) return false;
  if (maxSites === undefined) return offset === 0;
  return page.wordpressHasMore === false;
}

export function nextScanOffset(offset: number, scannedInstallationCount: number): number {
  if (!Number.isSafeInteger(offset) || offset < 0) throw new Error("scan offset must be a non-negative safe integer");
  if (!Number.isSafeInteger(scannedInstallationCount) || scannedInstallationCount < 1) {
    throw new Error("scan page made no progress");
  }
  if (offset > Number.MAX_SAFE_INTEGER - scannedInstallationCount) throw new Error("scan offset exceeded safe integer range");
  return offset + scannedInstallationCount;
}
