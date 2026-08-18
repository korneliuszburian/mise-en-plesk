export function shouldContinueScanChunks(
  allChunks: boolean,
  executionComplete: boolean,
  chunksProcessed: number,
  maxChunks: number,
): boolean {
  if (!allChunks || executionComplete) return false;
  return chunksProcessed < maxChunks;
}
