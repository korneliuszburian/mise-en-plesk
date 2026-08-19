export interface RetryOptions {
  maxAttempts?: number;
  retryDelayMs?: number;
  sleepImpl?: (milliseconds: number) => Promise<void>;
  retryNetworkErrors?: boolean;
}

function retryableStatus(status: number): boolean {
  return status === 408 || status === 429 || status >= 500;
}

function sleep(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

export async function fetchWithRetry(
  fetchImpl: typeof fetch,
  input: RequestInfo | URL,
  init: RequestInit,
  timeoutMs: number,
  options: RetryOptions = {},
): Promise<Response> {
  const maxAttempts = Math.max(1, Math.min(5, Math.floor(options.maxAttempts ?? 3)));
  const retryDelayMs = Math.max(0, options.retryDelayMs ?? 250);
  const sleepImpl = options.sleepImpl ?? sleep;
  let lastError: unknown;

  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetchImpl(input, { ...init, signal: controller.signal });
      if (response.ok || !retryableStatus(response.status) || attempt === maxAttempts) return response;
      lastError = new Error(`HTTP ${response.status}`);
    } catch (error: unknown) {
      lastError = error;
      if (options.retryNetworkErrors === false || attempt === maxAttempts) throw error;
    } finally {
      clearTimeout(timeout);
    }
    await sleepImpl(retryDelayMs * attempt);
  }

  throw lastError instanceof Error ? lastError : new Error("request failed");
}
