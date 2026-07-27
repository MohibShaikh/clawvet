import { describe, it, expect } from "vitest";
import { generateApiKey, hashApiKey, API_KEY_PREFIX } from "../src/services/api-key.js";

describe("api keys", () => {
  it("generates prefixed, unpredictable keys", () => {
    const a = generateApiKey();
    const b = generateApiKey();
    expect(a.startsWith(API_KEY_PREFIX)).toBe(true);
    expect(a).not.toBe(b);
    // 24 random bytes -> 48 hex chars after the prefix
    expect(a.length).toBe(API_KEY_PREFIX.length + 48);
  });

  it("hashes deterministically so lookup by hash works", () => {
    const key = generateApiKey();
    expect(hashApiKey(key)).toBe(hashApiKey(key));
  });

  it("produces a hash that is not the key itself", () => {
    const key = generateApiKey();
    const hash = hashApiKey(key);
    expect(hash).not.toBe(key);
    expect(hash).not.toContain(key);
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("gives different hashes for different keys", () => {
    expect(hashApiKey(generateApiKey())).not.toBe(hashApiKey(generateApiKey()));
  });
});
