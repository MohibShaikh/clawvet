import { lookup } from "node:dns/promises";
import { isIP } from "node:net";

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
