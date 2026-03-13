---
name: clawvet
version: 0.5.0
description: Vet OpenClaw skills for security threats before installing them. 6-pass scanner with confidence scores, fix suggestions, and content-hash caching.
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

Scan any OpenClaw skill for security threats before you install it.

## Usage

Scan a local skill:

```bash
npx clawvet scan ./skill-folder/
```

Scan with JSON output (for CI/CD):

```bash
npx clawvet scan ./skill-folder/ --format json --fail-on high
```

Audit all installed skills:

```bash
npx clawvet audit
```

Watch for new skill installs and auto-block risky ones:

```bash
npx clawvet watch --threshold 50
```

Submit feedback or get threat alerts:

```bash
npx clawvet feedback
```

## What it detects

clawvet runs 6 analysis passes on every skill:

1. **Skill Parser** — Extracts YAML frontmatter, code blocks, URLs, IPs, domains
2. **Static Analysis** — 54 regex patterns: RCE, reverse shells, credential theft, DNS exfil, obfuscation
3. **Metadata Validator** — Undeclared binaries, env vars, missing descriptions
4. **Dependency Checker** — `npx -y` auto-install, global npm installs
5. **Typosquat Detector** — Levenshtein distance against popular skills
6. **Semantic Analysis** — AI-powered social engineering and prompt injection detection (Pro)

## v0.5.0 — What's New

- **Confidence scores** — Each finding shows a confidence percentage based on context (code block vs prose vs heading). Risk scores are weighted by confidence to reduce false positive noise.
- **Fix suggestions** — Every finding includes an actionable remediation suggestion shown in terminal and SARIF output.
- **Content-hash caching** — Repeat scans of unchanged files are near-instant (SHA-256 LRU cache).
- **Telemetry & feedback** — Opt-in anonymous usage stats. `clawvet feedback` opens the feedback form.

## Risk Grades

| Score | Grade | Action |
|-------|-------|--------|
| 0-10 | A | Safe to install |
| 11-25 | B | Safe to install |
| 26-50 | C | Review before installing |
| 51-75 | D | Review carefully |
| 76-100 | F | Do not install |
