# ClawVet

[![CI](https://github.com/MohibShaikh/clawvet/actions/workflows/ci.yml/badge.svg)](https://github.com/MohibShaikh/clawvet/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/clawvet)](https://www.npmjs.com/package/clawvet)
[![npm downloads](https://img.shields.io/npm/dw/clawvet)](https://www.npmjs.com/package/clawvet)

Skill vetting & supply chain security for the OpenClaw ecosystem. Scans SKILL.md files for prompt injection, credential theft, remote code execution, typosquatting, and social engineering — catching threats that VirusTotal misses.

## Why

In Feb 2026 researchers found 824+ malicious skills (~20% of ClawHub). The "ClawHavoc" campaign distributed infostealers via fake skills. ClawVet runs 6 independent analysis passes on every skill to catch what single-pass scanners miss.

## Quick Start

```bash
# Scan a local skill
npx clawvet scan ./my-skill/

# JSON output for CI/CD
npx clawvet scan ./my-skill/ --format json --fail-on high

# Audit all installed skills
npx clawvet audit
```

## Architecture

```
clawvet/
├── apps/
│   ├── api/          # Fastify backend (scanner engine, REST API, BullMQ worker)
│   └── web/          # Next.js 14 dashboard
├── packages/
│   ├── cli/          # `clawvet` CLI tool
│   └── shared/       # Types + scanner engine + 54 threat detection patterns
├── docker-compose.yml
└── turbo.json
```

## 6-Pass Scanner Engine

| Pass | Module | What it catches |
|------|--------|-----------------|
| 1 | `skill-parser` | Parses YAML frontmatter, extracts code blocks, URLs, IPs, domains |
| 2 | `static-analysis` | 54 regex patterns: RCE, reverse shells, credential theft, obfuscation, exfiltration |
| 3 | `metadata-validator` | Undeclared binaries/env vars, missing/vague descriptions, bad semver |
| 4 | `semantic-analysis` | Claude AI analyzes instructions for social engineering & prompt injection |
| 5 | `dependency-checker` | npx -y auto-install, global npm installs, risky packages |
| 6 | `typosquat-detector` | Levenshtein distance against top ClawHub skills |

## Risk Scoring

- Each **critical** finding: +30 points
- Each **high** finding: +15 points
- Each **medium** finding: +7 points
- Each **low** finding: +3 points
- Score capped at 100. Grades: A (0-10), B (11-25), C (26-50), D (51-75), F (76-100)

## API

```
POST   /api/v1/scans          # Submit skill content for scanning
GET    /api/v1/scans/:id      # Get scan result
GET    /api/v1/scans           # List scans (paginated)
GET    /api/v1/stats           # Public stats
POST   /api/v1/webhooks        # Register webhook
DELETE /api/v1/webhooks/:id    # Remove webhook
GET    /api/v1/auth/github     # GitHub OAuth flow
```

## Development

```bash
# Install deps
npm install

# Run tests (61 tests across 6 suites)
cd apps/api && npx vitest run

# Start API server
cd apps/api && npm run dev

# Start web dashboard
cd apps/web && npm run dev

# Start Postgres + Redis
docker-compose up -d

# Push DB schema
cd apps/api && npm run db:push
```

## Environment Variables

Copy `.env.example` to `.env`:

```
DATABASE_URL=postgres://clawvet:clawvet@localhost:5432/clawvet
REDIS_URL=redis://localhost:6379
ANTHROPIC_API_KEY=sk-ant-...    # For AI semantic analysis
GITHUB_CLIENT_ID=               # For OAuth
GITHUB_CLIENT_SECRET=
```

## Monorepo Structure

This repo is a **monorepo** with two separate concerns:

| Package | Published | Description |
|---------|-----------|-------------|
| `packages/cli` | Yes (`npx clawvet`) | Stateless CLI scanner — no databases, no auth, fully offline by default |
| `packages/shared` | Yes (`@clawvet/shared`) | Scanner engine, types, and 54 threat patterns |
| `apps/api` | No (self-hosted) | Optional Fastify backend with Postgres, Redis, GitHub OAuth |
| `apps/web` | No (self-hosted) | Optional Next.js dashboard |

The **npm package `clawvet`** contains only `packages/cli` + `packages/shared`. It has **zero** database, Redis, or OAuth dependencies. The `apps/` directory is for the optional self-hosted web dashboard and is **not** included in the published package.

## Telemetry

ClawVet includes **opt-in** anonymous telemetry. On first run, you are asked whether to enable it. You can also control it via environment variable:

```bash
# Disable telemetry
export CLAWVET_TELEMETRY=off

# Enable telemetry
export CLAWVET_TELEMETRY=on
```

When enabled, the following data is sent (and **nothing else**):

| Field | Example | Purpose |
|-------|---------|---------|
| `deviceId` | `a1b2c3d4-...` | Random UUID, not tied to identity |
| `scanCount` | `42` | How many scans this device has run |
| `ts` | `2026-03-14T...` | Timestamp |
| `os` | `win32` | Platform |
| `osVersion` | `10.0.26200` | OS version |
| `cliVersion` | `0.7.2` | CLI version |
| `environment` | `production` | `production` / `development` / `ci` (dev & CI traffic filtered out) |
| `skillHash` | `9f2a…` (SHA-256) | Hash of the skill name — the raw name is **never** sent |
| `riskScore` | `15` | Numeric risk score |
| `riskGrade` | `B` | Letter grade |
| `findingsCount` | `3` | Number of findings |
| `cached` | `false` | Whether result came from cache |

**Never sent:** raw skill names, file contents, source code, file paths, environment variables, API keys, or any personally identifiable information.

Config is stored in `~/.clawvet/config.json`.

## Tests

72 tests covering:
- All 6 fixture skills (benign → malicious)
- Edge cases (empty files, malformed YAML, unicode, 100KB adversarial input)
- Regex catastrophic backtracking safety
- 54 threat patterns across 12 categories
- API route validation (auth, webhooks, scans — incl. authenticated scan listing)
- SSRF guard (scheme allowlist + private/metadata IP-range blocking)
- CLI end-to-end integration (--format json, --fail-on, exit codes)

## License

MIT
