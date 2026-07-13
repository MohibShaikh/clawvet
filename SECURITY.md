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

## Telemetry & privacy

ClawVet's CLI telemetry is **opt-in** and best-effort. When enabled, it sends an
anonymous device ID, the CLI version, OS/platform, environment tag
(production/development/ci), risk score/grade, and a **SHA-256 hash** of the
skill name — never the raw skill name, file contents, paths, or credentials.
Disable it any time with `CLAWVET_TELEMETRY=0` or in `~/.clawvet/config.json`.
