import { lookup } from "node:dns/promises";
import { lookup as dnsLookup } from "node:dns";
import { isIP } from "node:net";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";

/**
 * Thrown when a URL is rejected for pointing at a non-public / internal target.
 * Callers should treat this as a 400 (bad user input), not a 500.
 */
export class SsrfError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SsrfError";
  }
}

/**
 * Returns true if `ip` is loopback, private, link-local, CGNAT, multicast, or
 * otherwise not a routable public address — i.e. a target an SSRF attacker
 * would use to reach internal services or cloud metadata (169.254.169.254).
 */
export function isPrivateOrReservedIp(ip: string): boolean {
  const kind = isIP(ip);

  if (kind === 4) {
    const p = ip.split(".").map(Number);
    if (p[0] === 0) return true; // 0.0.0.0/8 "this host"
    if (p[0] === 10) return true; // 10.0.0.0/8 private
    if (p[0] === 127) return true; // 127.0.0.0/8 loopback
    if (p[0] === 169 && p[1] === 254) return true; // 169.254.0.0/16 link-local (incl. cloud metadata)
    if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true; // 172.16.0.0/12 private
    if (p[0] === 192 && p[1] === 168) return true; // 192.168.0.0/16 private
    if (p[0] === 100 && p[1] >= 64 && p[1] <= 127) return true; // 100.64.0.0/10 CGNAT
    if (p[0] >= 224) return true; // 224.0.0.0/4 multicast + 240.0.0.0/4 reserved
    return false;
  }

  if (kind === 6) {
    const low = ip.toLowerCase();
    if (low === "::1" || low === "::") return true; // loopback / unspecified
    if (low.startsWith("fe80")) return true; // link-local
    if (low.startsWith("fc") || low.startsWith("fd")) return true; // fc00::/7 unique-local
    // IPv4-mapped (::ffff:a.b.c.d) — unwrap and re-check the embedded v4 address.
    const mapped = low.match(/::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/);
    if (mapped) return isPrivateOrReservedIp(mapped[1]);
    return false;
  }

  // Not a bare IP; caller resolves the hostname before reaching here.
  return false;
}

/**
 * Rejects a URL that is not a public http(s) endpoint. Blocks non-http schemes
 * (file:, gopher:, etc.), the literal "localhost" host, and any hostname that
 * resolves to a private/internal/reserved IP. Every DNS answer is checked, so a
 * name with one public and one internal A-record is still rejected.
 *
 * NOTE: a small TOCTOU window remains — DNS can change between this check and
 * the actual request (DNS rebinding). We re-run this immediately before each
 * delivery to keep that window to milliseconds; pinning the resolved IP for the
 * connection is a further hardening step tracked for follow-up.
 */
export async function assertUrlIsPublic(rawUrl: string): Promise<void> {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new SsrfError("Invalid URL");
  }

  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new SsrfError("Only http and https URLs are allowed");
  }

  // Strip IPv6 brackets: new URL("http://[::1]/").hostname === "[::1]" in some runtimes.
  const hostname = url.hostname.toLowerCase().replace(/^\[/, "").replace(/\]$/, "");

  if (hostname === "localhost" || hostname.endsWith(".localhost")) {
    throw new SsrfError("URL host is not allowed");
  }

  // Literal IP host — check directly, no DNS needed.
  if (isIP(hostname)) {
    if (isPrivateOrReservedIp(hostname)) {
      throw new SsrfError("URL resolves to a private or internal address");
    }
    return;
  }

  let addresses: { address: string }[];
  try {
    addresses = await lookup(hostname, { all: true });
  } catch {
    throw new SsrfError("Could not resolve URL host");
  }

  if (addresses.length === 0) {
    throw new SsrfError("URL host did not resolve");
  }

  for (const { address } of addresses) {
    if (isPrivateOrReservedIp(address)) {
      throw new SsrfError("URL resolves to a private or internal address");
    }
  }
}

/**
 * SSRF-safe POST. Closes the DNS-rebinding TOCTOU by validating the address at
 * the moment of connection: the custom `lookup` is the same resolution the
 * socket connects to, so a name can't resolve public during a pre-check and
 * internal at connect time. Does not follow redirects (node http never does),
 * so redirect-to-internal is also blocked.
 */
export function fetchPublicUrl(
  rawUrl: string,
  init: { method?: string; headers?: Record<string, string>; body?: string; timeoutMs?: number }
): Promise<{ status: number }> {
  const url = new URL(rawUrl);
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    return Promise.reject(new SsrfError("Only http and https URLs are allowed"));
  }
  // Node skips `lookup` for literal-IP hosts, so guard those directly here.
  const bareHost = url.hostname.replace(/^\[/, "").replace(/\]$/, "");
  if (isIP(bareHost) && isPrivateOrReservedIp(bareHost)) {
    return Promise.reject(
      new SsrfError("URL resolves to a private or internal address")
    );
  }
  const request = url.protocol === "https:" ? httpsRequest : httpRequest;

  // Validate at connect time. `dns.lookup` here is what the socket uses, so
  // there is no gap between check and connect (no rebinding window).
  const pinnedLookup: typeof dnsLookup = ((hostname: string, opts: any, cb: any) => {
    const callback = typeof opts === "function" ? opts : cb;
    dnsLookup(hostname, { all: false }, (err, address, family) => {
      if (err) return callback(err);
      if (isPrivateOrReservedIp(address)) {
        return callback(new SsrfError("URL resolves to a private or internal address"));
      }
      callback(null, address, family);
    });
  }) as typeof dnsLookup;

  return new Promise((resolve, reject) => {
    const req = request(
      url,
      { method: init.method || "GET", headers: init.headers, lookup: pinnedLookup },
      (res) => {
        res.resume(); // drain; we only care that it was delivered
        resolve({ status: res.statusCode || 0 });
      }
    );
    req.setTimeout(init.timeoutMs ?? 10000, () => req.destroy(new Error("timeout")));
    req.on("error", reject);
    if (init.body) req.write(init.body);
    req.end();
  });
}
