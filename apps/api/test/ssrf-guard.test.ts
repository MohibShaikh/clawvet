import { describe, it, expect } from "vitest";
import {
  isPrivateOrReservedIp,
  assertUrlIsPublic,
  fetchPublicUrl,
  SsrfError,
} from "../src/services/ssrf-guard.js";

describe("isPrivateOrReservedIp", () => {
  it("flags private/loopback/link-local/metadata IPv4", () => {
    for (const ip of [
      "127.0.0.1",
      "10.1.2.3",
      "172.16.0.1",
      "172.31.255.255",
      "192.168.1.1",
      "169.254.169.254", // cloud metadata
      "100.64.0.1", // CGNAT
      "0.0.0.0",
      "224.0.0.1", // multicast
    ]) {
      expect(isPrivateOrReservedIp(ip), ip).toBe(true);
    }
  });

  it("flags loopback/link-local/ULA and mapped IPv6", () => {
    for (const ip of ["::1", "::", "fe80::1", "fc00::1", "fd12::1", "::ffff:127.0.0.1"]) {
      expect(isPrivateOrReservedIp(ip), ip).toBe(true);
    }
  });

  it("allows public IPs", () => {
    for (const ip of ["8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700::1111"]) {
      expect(isPrivateOrReservedIp(ip), ip).toBe(false);
    }
  });
});

describe("assertUrlIsPublic", () => {
  const rejects = async (url: string) => {
    await expect(assertUrlIsPublic(url)).rejects.toBeInstanceOf(SsrfError);
  };

  it("rejects non-http(s) schemes", async () => {
    await rejects("file:///etc/passwd");
    await rejects("gopher://127.0.0.1/");
    await rejects("ftp://example.com/");
  });

  it("rejects localhost and internal IP literals", async () => {
    await rejects("http://localhost/hook");
    await rejects("http://127.0.0.1:3001/");
    await rejects("http://169.254.169.254/latest/meta-data/");
    await rejects("http://[::1]/");
    await rejects("http://192.168.0.10/");
  });

  it("rejects malformed URLs", async () => {
    await rejects("not-a-url");
  });

  it("accepts a normal public https URL", async () => {
    await expect(assertUrlIsPublic("https://example.com/webhook")).resolves.toBeUndefined();
  });
});

describe("fetchPublicUrl (connect-time SSRF guard)", () => {
  it("rejects non-http schemes", async () => {
    await expect(fetchPublicUrl("file:///etc/passwd", {})).rejects.toBeInstanceOf(SsrfError);
  });

  it("rejects internal IP literals (Node skips lookup for these)", async () => {
    await expect(fetchPublicUrl("http://127.0.0.1:9/", {})).rejects.toBeInstanceOf(SsrfError);
    await expect(fetchPublicUrl("http://169.254.169.254/", {})).rejects.toBeInstanceOf(SsrfError);
    await expect(fetchPublicUrl("http://[::1]/", {})).rejects.toBeInstanceOf(SsrfError);
  });

  it("rejects hostnames that resolve to a private address (rebind defense)", async () => {
    // localhost resolves to 127.0.0.1 via the pinned connect-time lookup, so
    // the request is refused before any socket connects to an internal host.
    await expect(fetchPublicUrl("http://localhost:9/", {})).rejects.toBeInstanceOf(SsrfError);
  });
});
