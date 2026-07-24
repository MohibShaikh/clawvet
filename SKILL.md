---
name: clawvet
version: 0.8.2
description: Code quality and safety linter for OpenClaw skills. Runs 6 analysis passes before you install.
author: MohibShaikh
license: MIT
homepage: https://github.com/MohibShaikh/clawvet
repository: https://github.com/MohibShaikh/clawvet
metadata:
  openclaw:
    requires:
      bins:
        - node
        - npm
      env: []
    category: security
    tags:
      - security
      - linter
      - supply-chain
      - code-quality
---

# clawvet

Safety linter for OpenClaw skills. Analyzes skills for issues before installation.

## Usage

Scan a local skill:

```bash
npx clawvet scan ./skill-folder/
```

JSON output for CI/CD:

```bash
npx clawvet scan ./skill-folder/ --format json
```

Audit all installed skills:

```bash
npx clawvet audit
```

Watch mode — auto-block risky installs:

```bash
npx clawvet watch --threshold 50
```

Submit feedback or get alerts:

```bash
npx clawvet feedback
```

## Analysis Passes

1. **Skill Parser** — Extracts YAML frontmatter, code blocks, URLs, and domains
2. **Static Analysis** — 54 pattern rules across multiple categories
3. **Metadata Validator** — Checks for undeclared binaries, env vars, missing descriptions
4. **Dependency Checker** — Flags auto-install and global package installs
5. **Typosquat Detector** — Levenshtein distance against popular skill names
6. **Semantic Analysis** — AI-powered contextual analysis (Pro)

## What's New in v0.7–v0.8

- **Cross-file payload assembly (0.8.0)** — folder scans now assemble files referenced from `SKILL.md` (e.g. a `setup.sh`) before analysis, so a payload split across multiple files can no longer evade detection.
- **Robust semantic parsing (0.8.0)** — semantic analysis correctly parses LLM responses wrapped in markdown code fences.
- **Path-traversal hardening (0.7.0)** — `--remote` slugs are validated and URL-encoded before fetching from ClawHub.
- **Grade summaries (0.7.0)** — `audit` prints a final grade summary and flags D/F skills for review; risk scores are rounded to integers.
- **Shell-free CLI (0.7.2)** — replaced `exec()` in `feedback`/`scan --subscribe` with a shell-free `execFile` opener.
- **Privacy-preserving telemetry (0.7.2–0.7.3)** — skill names are SHA-256 hashed before sending; `audit` emits a session-level completion event. Still opt-in.
- **Accurate skill naming (0.7.1)** — skills with no `name` in frontmatter report the containing folder name instead of `unknown`.

## What's New in v0.6

- **Reliable telemetry** — Telemetry now awaits before exit, so no data is lost.
- **CI-safe** — Opt-in prompt is skipped in non-TTY environments (piped stdin, CI).
- **Less noise** — Feedback CTA shows every 5th scan instead of every scan.
- **Trust badges** — Generate trust badges for skill READMEs with `npx clawvet badge`.
- **Ban lists** — Block skills by name/author/slug via `.clawvetban` files.
- **Confidence scores** — Each finding shows a confidence percentage. Risk scores are weighted accordingly.
- **Fix suggestions** — Every finding includes an actionable remediation in terminal and SARIF output.
- **Content-hash caching** — Repeat scans of unchanged files are near-instant.
- **Trust badges** — Run `npx clawvet badge ./skill/` to generate a shields.io trust badge for your README.
- **Ban list** — Create a `.clawvetban` file to block skills by name, author, or slug.
- **Feedback form** — Run `npx clawvet feedback` to share what you think.

## Note on Monorepo

The `clawvet` npm package contains only the CLI scanner (`packages/cli` + `packages/shared`). It is a stateless tool with no databases, no authentication, and no network access by default. The repository also contains an optional web dashboard (`apps/api` + `apps/web`) for self-hosted deployments — these are NOT included in the npm package.

## Risk Grades

| Score | Grade | Action |
|-------|-------|--------|
| 0-10 | A | Safe to install |
| 11-25 | B | Safe to install |
| 26-50 | C | Review before installing |
| 51-75 | D | Review carefully |
| 76-100 | F | Do not install |
