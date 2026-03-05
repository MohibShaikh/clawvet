---
name: clawvet
version: 0.2.3
description: Vet OpenClaw skills for security threats before installing them. 6-pass scanner detects RCE, credential theft, prompt injection, typosquatting, and social engineering.
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

## What it detects

clawvet runs 6 analysis passes on every skill:

1. **Skill Parser** — Extracts YAML frontmatter, code blocks, URLs, IPs, domains
2. **Static Analysis** — 54 regex patterns: RCE, reverse shells, credential theft, DNS exfil, obfuscation
3. **Metadata Validator** — Undeclared binaries, env vars, missing descriptions
4. **Dependency Checker** — `npx -y` auto-install, global npm installs
5. **Typosquat Detector** — Levenshtein distance against popular skills
6. **Semantic Analysis** — AI-powered social engineering and prompt injection detection (Pro)

## Risk Grades

| Score | Grade | Action |
|-------|-------|--------|
| 0-10 | A | Safe to install |
| 11-25 | B | Safe to install |
| 26-50 | C | Review before installing |
| 51-75 | D | Review carefully |
| 76-100 | F | Do not install |
