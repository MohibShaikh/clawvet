import { createHash, randomBytes } from "node:crypto";

/**
 * API keys are credentials, so the database stores a hash rather than the key
 * itself: a leaked backup, a SQL injection, or an over-sharing endpoint then
 * yields nothing usable. The plaintext is shown to the user exactly once, at
 * creation — it cannot be recovered afterwards, only regenerated.
 *
 * A plain SHA-256 (not a slow KDF) is right here: keys are 192 bits of CSPRNG
 * output, so there is no dictionary to attack and nothing for a work factor to
 * buy. It also keeps lookup a single indexed query.
 */
export const API_KEY_PREFIX = "cg_";

export function generateApiKey(): string {
  return `${API_KEY_PREFIX}${randomBytes(24).toString("hex")}`;
}

export function hashApiKey(key: string): string {
  return createHash("sha256").update(key).digest("hex");
}
