-- Store API keys as SHA-256 hashes instead of cleartext.
--
-- Previously `users.api_key` held the usable credential in plaintext, so any
-- read of this table (backup, replica, insider, or a future SQL injection)
-- disclosed every user's live key.
--
-- Existing keys CANNOT be migrated in place: hashing them here would be
-- correct, but the cleartext is already exposed in every backup taken to date,
-- so those keys must be considered compromised and rotated rather than
-- preserved. This migration therefore drops them; users mint a new key via
-- POST /api/v1/auth/api-key/rotate.
--
-- If you would rather preserve continuity and accept the risk, replace the
-- DROP below with:
--   UPDATE users SET api_key_hash = encode(digest(api_key, 'sha256'), 'hex'),
--                    api_key_last4 = right(api_key, 4)
--     WHERE api_key IS NOT NULL;   -- requires pgcrypto

ALTER TABLE users ADD COLUMN IF NOT EXISTS api_key_hash text;
ALTER TABLE users ADD COLUMN IF NOT EXISTS api_key_last4 text;

ALTER TABLE users DROP CONSTRAINT IF EXISTS users_api_key_hash_unique;
ALTER TABLE users ADD CONSTRAINT users_api_key_hash_unique UNIQUE (api_key_hash);

-- Drop the cleartext column. All existing keys are invalidated by design.
ALTER TABLE users DROP COLUMN IF EXISTS api_key;
