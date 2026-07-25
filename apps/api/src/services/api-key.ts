import { createHash, randomBytes } from "node:crypto";

const API_KEY_PREFIX = "cg_";
const API_KEY_BYTES = 24; // 192 bits

/**
 * API keys are stored as a SHA-256 hash, never in cleartext, so a read of the
 * users table cannot yield a usable credential.
 *
 * A fast hash is the right choice here (not bcrypt/argon2): these are 192-bit
 * random tokens with no guessable structure, so there is no offline brute-force
 * to slow down — and auth runs on every request, where a slow KDF would be a
 * DoS lever. Password hashing is a different problem with different inputs.
 */
export function hashApiKey(key: string): string {
  return createHash("sha256").update(key).digest("hex");
}

/** Non-secret display hint, e.g. "cg_…a1b2". Safe to return from the API. */
export function apiKeyLast4(key: string): string {
  return key.slice(-4);
}

/**
 * Mints a new key. The cleartext is returned exactly once — to be shown to the
 * user at creation — while only the hash and last4 are ever persisted.
 */
export function generateApiKey(): {
  key: string;
  hash: string;
  last4: string;
} {
  const key = `${API_KEY_PREFIX}${randomBytes(API_KEY_BYTES).toString("hex")}`;
  return { key, hash: hashApiKey(key), last4: apiKeyLast4(key) };
}
