---
name: clawvet
version: 0.9.0
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

Scanning a folder also assembles the companion files the `SKILL.md` references
(e.g. `bash ./setup.sh`), so payloads split across multiple files are caught.

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

Report a bug or send feedback (opens a prefilled GitHub issue):

```bash
npx clawvet feedback
```

## Analysis Passes

1. **Skill Parser** — Extracts YAML frontmatter, code blocks, URLs, and domains
2. **Static Analysis** — 57 pattern rules across 13 categories
3. **Metadata Validator** — Checks for undeclared binaries, env vars, missing descriptions
4. **Dependency Checker** — Flags auto-install and global package installs
5. **Typosquat Detector** — Levenshtein distance against popular skill names
6. **Semantic Analysis** — AI-powered contextual analysis (optional, bring your own API key)

## What's New in v0.9

- **Cross-file payload assembly** — folder scans now include the companion files
  a `SKILL.md` references, closing the split-payload blind spot.
- **Bring your own LLM** — the optional semantic pass works with Anthropic,
  OpenAI, Zhipu, or a local model via Ollama. No key ships with ClawVet.
- **Feedback via GitHub** — `npx clawvet feedback` opens a prefilled issue
  instead of a form.
- **Security hardening** — see SECURITY.md; the self-hosted API server now
  requires `JWT_SECRET`, stores API keys hashed, and validates webhook targets
  against SSRF.

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
