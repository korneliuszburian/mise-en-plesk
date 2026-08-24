import { describe, expect, it } from "vitest";
import { isPublicAddress, probePublicSite, type PublicSiteRequest } from "../src/public-site-health";

describe("public site health", () => {
  it("rejects private and reserved destinations across IPv4 and IPv6", () => {
    for (const address of [
      "10.0.0.1", "100.64.0.1", "127.0.0.1", "169.254.1.1", "172.16.0.1",
      "192.0.2.1", "192.168.1.1", "198.18.0.1", "198.51.100.1", "203.0.113.1",
      "::1", "::ffff:127.0.0.1", "2001:db8::1", "3fff::1", "fc00::1", "fe80::1", "ff02::1",
    ]) expect(isPublicAddress(address), address).toBe(false);
    expect(isPublicAddress("91.244.231.92")).toBe(true);
    expect(isPublicAddress("2606:4700:4700::1111")).toBe(true);
  });

  it("records an expired certificate and still diagnoses the HTTP response", async () => {
    const calls: boolean[] = [];
    const request: PublicSiteRequest = async (_url, options) => {
      calls.push(options.rejectUnauthorized);
      if (options.rejectUnauthorized) {
        throw Object.assign(new Error("certificate has expired"), { code: "CERT_HAS_EXPIRED" });
      }
      return {
        status: 503,
        finalUrl: "https://solozaszkola.dev.proudsite.pl/",
        certificate: {
          validFrom: "Mar 23 11:40:55 2026 GMT",
          validTo: "Jun 21 11:40:54 2026 GMT",
        },
      };
    };

    await expect(probePublicSite("solozaszkola.dev.proudsite.pl", {
      request,
      now: new Date("2026-08-24T15:13:29Z"),
    })).resolves.toEqual({
      url: "https://solozaszkola.dev.proudsite.pl/",
      checkedAt: "2026-08-24T15:13:29.000Z",
      tls: {
        status: "invalid",
        error: "certificate has expired",
        validFrom: "2026-03-23T11:40:55.000Z",
        validTo: "2026-06-21T11:40:54.000Z",
      },
      http: {
        reachable: true,
        status: 503,
        finalUrl: "https://solozaszkola.dev.proudsite.pl/",
      },
    });
    expect(calls).toEqual([true, false]);
  });

  it("rejects non-public hostnames before transport", async () => {
    let called = false;
    await expect(probePublicSite("localhost", {
      request: async () => {
        called = true;
        throw new Error("must not run");
      },
    })).rejects.toThrow("public DNS hostname");
    expect(called).toBe(false);
  });

  it("does not call a transport outage an invalid certificate", async () => {
    await expect(probePublicSite("offline.example.com", {
      request: async () => { throw Object.assign(new Error("connect ECONNREFUSED"), { code: "ECONNREFUSED" }); },
      now: new Date("2026-08-24T15:13:29Z"),
    })).resolves.toEqual({
      url: "https://offline.example.com/",
      checkedAt: "2026-08-24T15:13:29.000Z",
      tls: { status: "unavailable", error: "connect ECONNREFUSED" },
      http: { reachable: false, error: "connect ECONNREFUSED" },
    });
  });

  it("aborts transport work at the total deadline", async () => {
    let aborted = false;
    const result = await probePublicSite("slow.example.com", {
      timeoutMs: 20,
      request: async (_url, requestOptions) => new Promise((_resolve, reject) => {
        requestOptions.signal.addEventListener("abort", () => {
          aborted = true;
          reject(new Error("aborted"));
        }, { once: true });
      }),
    });

    expect(aborted).toBe(true);
    expect(result).toMatchObject({
      tls: { status: "unavailable", error: "public HTTPS probe timed out" },
      http: { reachable: false, error: "public HTTPS probe timed out" },
    });
  });
});
