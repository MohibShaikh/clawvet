---
name: clawvet
version: 0.6.1
description: Stateless CLI security scanner for OpenClaw skills. The npm package runs fully offline with zero database or auth dependencies. Detects threats across 6 analysis passes before you install.
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
      - scanner
      - supply-chain
      - malware-detection
---

# clawvet

Security scanner for OpenClaw skills. Analyzes skills for threats before installation.

## Usage

Scan a local skill:

```bash
npx clawvet scan ./skill-folder/
```

JSON output for CI/CD:

```bash
npx clawvet scan ./skill-folder/ --format json --fail-on high
```

Audit all installed skills:

```bash
npx clawvet audit
```

Watch mode — auto-block risky installs:

```bash
npx clawvet watch --threshold 50
```

Submit feedback or get threat alerts:

```bash
npx clawvet feedback
```

## Analysis Passes

1. **Skill Parser** — Extracts YAML frontmatter, code blocks, URLs, IPs, domains
2. **Static Analysis** — 54 pattern rules across multiple threat categories
3. **Metadata Validator** — Checks for undeclared binaries, env vars, missing descriptions
4. **Dependency Checker** — Flags auto-install and global package installs
5. **Typosquat Detector** — Levenshtein distance against popular skill names
6. **Semantic Analysis** — AI-powered detection of social engineering and injection (Pro)

## What's New in v0.6

- **Confidence scores** — Each finding shows a confidence percentage based on context. Risk scores are weighted accordingly.
- **Fix suggestions** — Every finding includes an actionable remediation shown in terminal and SARIF output.
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
