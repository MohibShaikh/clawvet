# Security Policy

## Reporting a vulnerability

If you find a security issue in ClawVet, please report it privately rather than
opening a public issue:

- Use GitHub's **Private Vulnerability Reporting** on this repository
  (Security → Report a vulnerability), or
- Email **mohibuddin9@gmail.com** with details and reproduction steps.

Please include the affected version, a description of the issue, and a
proof-of-concept if you have one. I aim to acknowledge reports within a few
days and will keep you updated on a fix.

Please give a reasonable window to release a fix before any public disclosure.

## Supported versions

Security fixes are applied to the latest published `clawvet` release on npm.
Please upgrade to the newest version before reporting.

## Self-hosted API server

The hosted API (`apps/api`) is not part of the published npm CLI. If you run it:

- **`JWT_SECRET` is required** — the server refuses to start without it. Use a
  unique random value (`node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`).
- **API keys are stored hashed** (SHA-256). The plaintext is shown once by
  `POST /api/v1/auth/api-key`; it cannot be recovered, only regenerated.
- **`CORS_ORIGIN`** should list your dashboard origin(s). It no longer defaults
  to reflecting any origin.
- **Semantic analysis sends skill content to your configured LLM provider.**
  Do not enable it for private or internal skills unless that is acceptable.

Upgrading an existing deployment to hashed API keys (keys are preserved):

```sql
CREATE EXTENSION IF NOT EXISTS pgcrypto;
ALTER TABLE users ADD COLUMN api_key_hash text UNIQUE;
UPDATE users SET api_key_hash = encode(digest(api_key, 'sha256'), 'hex');
ALTER TABLE users DROP COLUMN api_key;
```

## Telemetry & privacy

ClawVet's CLI telemetry is **opt-in** and best-effort. When enabled, it sends an
anonymous device ID, the CLI version, OS/platform, environment tag
(production/development/ci), risk score/grade, and a **SHA-256 hash** of the
skill name — never the raw skill name, file contents, paths, or credentials.
Disable it any time with `CLAWVET_TELEMETRY=0` or in `~/.clawvet/config.json`.
