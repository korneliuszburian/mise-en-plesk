import { Resolver } from "node:dns/promises";
import { request as httpsRequest, type RequestOptions } from "node:https";
import { BlockList, isIP } from "node:net";
import type { DetailedPeerCertificate, TLSSocket } from "node:tls";
import type { WordPressAudit } from "./wp-audit";

export interface PublicSiteHealth {
  url: string;
  checkedAt: string;
  tls: {
    status: "valid" | "invalid" | "unavailable";
    error?: string;
    validFrom?: string;
    validTo?: string;
  };
  http: {
    reachable: boolean;
    status?: number;
    finalUrl?: string;
    error?: string;
  };
}

export interface PublicSiteResponse {
  status: number;
  finalUrl: string;
  certificate?: { validFrom?: string; validTo?: string };
}

export type PublicSiteRequest = (
  url: URL,
  options: { rejectUnauthorized: boolean; timeoutMs: number; signal: AbortSignal },
) => Promise<PublicSiteResponse>;

export interface PublicSiteProbeOptions {
  timeoutMs?: number;
  now?: Date;
  request?: PublicSiteRequest;
}

function publicHostname(domain: string): string {
  const value = domain.trim().toLowerCase().replace(/\.$/, "");
  if (!value.includes(".")
    || value.length > 253
    || isIP(value) !== 0
    || !/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(value)) {
    throw new Error("public site probe requires a public DNS hostname");
  }
  return value;
}

const blockedIpv4 = new BlockList();
const blockedIpv6 = new BlockList();
for (const [network, prefix] of [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8],
  ["169.254.0.0", 16], ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.0.2.0", 24],
  ["192.88.99.0", 24], ["192.168.0.0", 16], ["198.18.0.0", 15], ["198.51.100.0", 24],
  ["203.0.113.0", 24], ["224.0.0.0", 4], ["240.0.0.0", 4],
] as const) blockedIpv4.addSubnet(network, prefix, "ipv4");
for (const [network, prefix] of [
  ["::", 3], ["4000::", 2], ["8000::", 1], ["2001::", 23], ["2001:db8::", 32],
  ["2002::", 16], ["3fff::", 20],
] as const) blockedIpv6.addSubnet(network, prefix, "ipv6");

export function isPublicAddress(address: string): boolean {
  const family = isIP(address);
  if (family === 0) return false;
  return family === 4
    ? !blockedIpv4.check(address, "ipv4")
    : !blockedIpv6.check(address, "ipv6");
}

async function resolvePublicAddress(hostname: string, signal: AbortSignal): Promise<{ address: string; family: 4 | 6 }> {
  const resolver = new Resolver();
  const cancel = (): void => resolver.cancel();
  signal.addEventListener("abort", cancel, { once: true });
  try {
    const [ipv4, ipv6] = await Promise.allSettled([resolver.resolve4(hostname), resolver.resolve6(hostname)]);
    if (signal.aborted) throw new Error("public HTTPS probe timed out");
    const addresses = [
      ...(ipv4.status === "fulfilled" ? ipv4.value.map((address) => ({ address, family: 4 as const })) : []),
      ...(ipv6.status === "fulfilled" ? ipv6.value.map((address) => ({ address, family: 6 as const })) : []),
    ];
    const selected = addresses.find(({ address }) => isPublicAddress(address));
    if (!selected) throw new Error("public site hostname did not resolve to a public address");
    return selected;
  } finally {
    signal.removeEventListener("abort", cancel);
  }
}

function certificateFrom(socket: { getPeerCertificate(detailed: true): DetailedPeerCertificate }): PublicSiteResponse["certificate"] {
  const certificate = socket.getPeerCertificate(true);
  return {
    ...(certificate.valid_from ? { validFrom: certificate.valid_from } : {}),
    ...(certificate.valid_to ? { validTo: certificate.valid_to } : {}),
  };
}

async function nodeRequest(
  initialUrl: URL,
  options: { rejectUnauthorized: boolean; timeoutMs: number; signal: AbortSignal },
): Promise<PublicSiteResponse> {
  let current = initialUrl;
  const deadline = Date.now() + options.timeoutMs;
  for (let redirects = 0; redirects <= 5; redirects += 1) {
    if (current.protocol !== "https:") throw new Error("public site probe refuses non-HTTPS redirects");
    const hostname = publicHostname(current.hostname);
    const resolved = await resolvePublicAddress(hostname, options.signal);
    const remainingMs = deadline - Date.now();
    if (remainingMs <= 0) throw new Error("public HTTPS probe timed out");
    const response = await new Promise<PublicSiteResponse & { location?: string }>((resolve, reject) => {
      const requestOptions: RequestOptions = {
        protocol: "https:",
        hostname,
        port: current.port || 443,
        path: `${current.pathname}${current.search}`,
        method: "GET",
        headers: { Host: hostname, "User-Agent": "mise-en-plesk/1 public-health", Connection: "close" },
        rejectUnauthorized: options.rejectUnauthorized,
        servername: hostname,
        signal: options.signal,
        lookup: ((_hostname: string, lookupOptions: { all?: boolean }, callback: (...args: unknown[]) => void) => {
          if (lookupOptions.all) callback(null, [resolved]);
          else callback(null, resolved.address, resolved.family);
        }) as NonNullable<RequestOptions["lookup"]>,
      };
      const request = httpsRequest(requestOptions, (incoming) => {
        const certificate = certificateFrom(incoming.socket as TLSSocket);
        resolve({
          status: incoming.statusCode ?? 0,
          finalUrl: current.toString(),
          certificate,
          ...(incoming.headers.location ? { location: incoming.headers.location } : {}),
        });
        // Status, redirects, and the TLS peer are sufficient for availability.
        // Never retain or download customer page content.
        incoming.destroy();
      });
      request.setTimeout(remainingMs, () => request.destroy(new Error("public HTTPS probe timed out")));
      request.once("error", reject);
      request.end();
    });
    if (response.status < 300 || response.status >= 400 || !response.location) return response;
    current = new URL(response.location, current);
  }
  throw new Error("public HTTPS probe exceeded redirect limit");
}

function normalizedDate(value?: string): string | undefined {
  if (!value) return undefined;
  const time = Date.parse(value);
  return Number.isFinite(time) ? new Date(time).toISOString() : undefined;
}

function safeError(error: unknown): string {
  const value = error as { code?: string; message?: string };
  if (value.code === "CERT_HAS_EXPIRED") return "certificate has expired";
  if (value.code === "CERT_NOT_YET_VALID") return "certificate is not yet valid";
  if (value.code?.startsWith("ERR_TLS_CERT_ALTNAME")) return "certificate hostname mismatch";
  return (value.message ?? "public HTTPS probe failed").replace(/\s+/g, " ").trim().slice(0, 200);
}

function isCertificateError(error: unknown): boolean {
  const value = error as { code?: string; message?: string };
  return Boolean(value.code?.includes("CERT") || /certificate|self[- ]signed|unable to verify/i.test(value.message ?? ""));
}

export async function probePublicSite(domain: string, options: PublicSiteProbeOptions = {}): Promise<PublicSiteHealth> {
  const hostname = publicHostname(domain);
  const url = new URL(`https://${hostname}/`);
  const checkedAt = (options.now ?? new Date()).toISOString();
  const request = options.request ?? nodeRequest;
  const timeoutMs = options.timeoutMs ?? 10_000;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  timeout.unref();
  const deadline = Date.now() + timeoutMs;
  const remainingMs = (): number => {
    const remaining = deadline - Date.now();
    if (remaining <= 0) throw new Error("public HTTPS probe timed out");
    return remaining;
  };
  try {
    const strictRemaining = remainingMs();
    const response = await request(url, { rejectUnauthorized: true, timeoutMs: strictRemaining, signal: controller.signal });
    return {
      url: url.toString(),
      checkedAt,
      tls: {
        status: "valid",
        ...(normalizedDate(response.certificate?.validFrom) ? { validFrom: normalizedDate(response.certificate?.validFrom) } : {}),
        ...(normalizedDate(response.certificate?.validTo) ? { validTo: normalizedDate(response.certificate?.validTo) } : {}),
      },
      http: { reachable: true, status: response.status, finalUrl: response.finalUrl },
    };
  } catch (error: unknown) {
    const detail = controller.signal.aborted ? "public HTTPS probe timed out" : safeError(error);
    if (!isCertificateError(error)) {
      return { url: url.toString(), checkedAt, tls: { status: "unavailable", error: detail }, http: { reachable: false, error: detail } };
    }
    try {
      const diagnosticRemaining = remainingMs();
      const response = await request(url, { rejectUnauthorized: false, timeoutMs: diagnosticRemaining, signal: controller.signal });
      return {
        url: url.toString(),
        checkedAt,
        tls: {
          status: "invalid",
          error: detail,
          ...(normalizedDate(response.certificate?.validFrom) ? { validFrom: normalizedDate(response.certificate?.validFrom) } : {}),
          ...(normalizedDate(response.certificate?.validTo) ? { validTo: normalizedDate(response.certificate?.validTo) } : {}),
        },
        http: { reachable: true, status: response.status, finalUrl: response.finalUrl },
      };
    } catch (httpError: unknown) {
      return {
        url: url.toString(),
        checkedAt,
        tls: { status: "invalid", error: detail },
        http: { reachable: false, error: safeError(httpError) },
      };
    }
  } finally {
    clearTimeout(timeout);
  }
}

export async function attachPublicSiteHealth(
  audit: WordPressAudit,
  options: PublicSiteProbeOptions & { enabled?: boolean } = {},
): Promise<WordPressAudit> {
  if (options.enabled === false || !audit.installation.domain) return audit;
  try {
    return { ...audit, publicSiteHealth: await probePublicSite(audit.installation.domain, options) };
  } catch (error: unknown) {
    const detail = safeError(error);
    return {
      ...audit,
      limitations: [...(audit.limitations ?? []), `Public site probe unavailable: ${detail}`],
    };
  }
}
