# Changelog

## 0.7.0

- Security: validate `--remote` slug against `/^[a-z0-9][a-z0-9_-]{0,63}$/i` and URL-encode before fetching from ClawHub. Blocks path traversal in skill names.
- UX: `audit` now prints a final grade summary (e.g. `Grades: A 5  D 1  F 2`) and flags any D/F skills as needing review.
- UX: risk scores rounded to integers — no more `54.599999999999994/100` in terminal output.
- Fix: `--version` now reads from `package.json` at runtime (was hardcoded `0.6.0` and drifted).
- Internal: dependency security pass — fastify, drizzle-orm, yaml, bullmq, vitest, drizzle-kit, next bumped to clear all 18 npm audit advisories. `yaml@^2.8.3` is the notable one — fixes a parser stack overflow that was exploitable via deeply-nested YAML in untrusted SKILL.md input.

## 0.6.3

- Hardened telemetry flow — awaits before process exit
- Skip opt-in prompt in non-TTY/CI environments
- Show feedback CTA every 5th scan instead of every scan
- Reworded SKILL.md to avoid AV false positives

## 0.6.0

- Trust badges for skill READMEs
- Ban lists via `.clawvetban` files
- Live telemetry endpoint

## 0.5.1

- Telemetry wired to Val Town endpoint

## 0.5.0

- Confidence scores on findings
- Fix suggestions in terminal and SARIF output
- Content-hash caching for repeat scans
- Feedback form via `npx clawvet feedback`
