# ClawVet

[![CI](https://github.com/MohibShaikh/clawvet/actions/workflows/ci.yml/badge.svg)](https://github.com/MohibShaikh/clawvet/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/clawvet)](https://www.npmjs.com/package/clawvet)
[![npm downloads](https://img.shields.io/npm/dw/clawvet)](https://www.npmjs.com/package/clawvet)

Skill vetting and supply chain security for the OpenClaw ecosystem. ClawVet scans SKILL.md files for prompt injection, credential theft, remote code execution, typosquatting, and social engineering, catching threats that VirusTotal misses. It runs fully offline by default, with an optional AI stage you turn on when you want it.

## Demo

![ClawVet demo](clawvet-demo.gif)

A safe skill scores a clean **A**. A skill that pipes `curl` to `bash` and reads your `~/.aws/credentials` gets flagged **CRITICAL** and fails CI.

Reproduce it yourself (Windows PowerShell):

```powershell
.\demo.ps1            # uses the installed `clawvet` (npm i -g clawvet)
.\demo.ps1 -Local     # uses this repo's build, no global install needed
```

## Why

In Feb 2026 researchers found 824+ malicious skills, around 20% of ClawHub. The "ClawHavoc" campaign distributed infostealers via fake skills. ClawVet runs six independent analysis passes on every skill to catch what single-pass scanners miss.

## Quick start

```bash
# Scan a local skill
npx clawvet scan ./my-skill/

# JSON output for CI/CD
npx clawvet scan ./my-skill/ --format json --fail-on high

# Turn on the AI semantic stage (needs ANTHROPIC_API_KEY)
npx clawvet scan ./my-skill/ --semantic

# Audit all installed skills
npx clawvet audit
```

The scanner is static and offline by default, so `npx clawvet scan` works in CI with no key and no network. The AI stage is opt-in: pass `--semantic`, or set `ANTHROPIC_API_KEY` and it turns on. Nothing is sent anywhere unless you ask for it.

## Architecture

```
clawvet/
├── apps/
│   ├── api/          # Fastify backend (scanner engine, REST API, BullMQ worker)
│   └── web/          # Next.js 14 dashboard
├── packages/
│   ├── cli/          # `clawvet` CLI tool
│   └── shared/       # Types + scanner engine + 57 threat detection patterns
├── benchmarks/       # Labeled corpus + eval harness (see benchmarks/README.md)
├── docker-compose.yml
└── turbo.json
```

## Scanner engine

Six analysis passes turn a SKILL.md into a list of findings.

| Pass | Module | What it catches |
|------|--------|-----------------|
| 1 | `skill-parser` | Parses YAML frontmatter, extracts code blocks, URLs, IPs, domains |
| 2 | `static-analysis` | 57 regex patterns: RCE, reverse shells, credential theft, obfuscation, exfiltration |
| 3 | `metadata-validator` | Undeclared binaries/env vars, missing/vague descriptions, bad semver |
| 4 | `semantic-analysis` | Opt-in. Claude reads the instructions for social engineering and prompt injection |
| 5 | `dependency-checker` | npx -y auto-install, global npm installs, risky packages |
| 6 | `typosquat-detector` | Levenshtein distance against top ClawHub skills |

Pass 4 only runs with `--semantic` or an `ANTHROPIC_API_KEY`. The other five are pure static work with no API and no cost.

## Risk scoring

Findings are turned into a 0-100 score in three steps.

1. Weight each finding by severity and confidence: critical 30, high 15, medium 7, low 3.
2. Discount repeats. The first hit of a rule counts full, each extra hit of the same rule counts at 0.25. A skill that reads `~/.ssh` on four lines is mostly one concern repeated, not four.
3. Context pass. If the skill has no exfiltration or remote-exec sink, downweight its dual-use capabilities (reading a credential file, `docker exec`, installing a cron job). Reading `~/.aws/credentials` is theft when it is piped to a webhook and configuration when it is not.

A disqualifying finding, such as a known C2 IP, pins the score to the F band on its own and is never averaged away.

Grades: A (0-10), B (11-25), C (26-50), D (51-75), F (76-100). The CLI recommends approve below 26, warn at 26-75, block at 76+.

## Benchmarks

`benchmarks/` holds a labeled corpus of 101 SKILL.md fixtures (51 malicious, 30 benign, 20 hard negatives) and `eval.py`, a stdlib-only harness that reports precision, recall, F1, MCC, ROC-AUC and bootstrap confidence intervals.

Hard negatives are legitimate skills that trip credential and exec rules, an ssh helper that reads `~/.ssh/config`, a base64 utility, a `curl | bash` installer. They carry label 0, so their scores count against the false-positive rate. That is where the context pass earns its keep.

Static-only baseline at the warn threshold, from the committed `benchmarks/results.csv`:

```
precision 0.926   recall 0.980   F1 0.952   FPR 0.080   MCC 0.903   ROC-AUC 0.969
95% CI  F1 [0.904, 0.990]   MCC [0.810, 0.980]
```

Regenerate and re-run:

```bash
npx tsx benchmarks/scan-all.mjs
python3 benchmarks/eval.py benchmarks/results.csv --threshold 26
```

### Two corpora, two very different numbers

The scoring changes here were measured as a before/after pair. All four rows below are measured on this repo with the committed harness; nothing here is a competitor number (see the note that follows).

| ClawVet | Corpus | P | R | F1 | FPR | notes |
|---|---|---|---|---|---|---|
| before (linear scoring) | 101 in-text, 51/50 | 0.820 | 0.980 | 0.893 | 0.220 | threshold 26 |
| after (dedup + context) | 101 in-text, 51/50 | 0.926 | 0.980 | 0.952 | 0.080 | threshold 26 |
| after | 500 real-world, 50/450 | 0.000 | 0.000 | 0.000 | 0.111 | threshold 26 |
| after | 500 real-world, 50/450 | 0.296 | 0.580 | 0.392 | 0.153 | threshold 20 |

The 101-skill corpus is hand-authored: the malicious payload sits in the SKILL.md text, which is exactly what regex is built to catch, so the numbers look great. The 500-skill corpus is real ClawHub and reconstructed ClawHavoc skills.

On the real set the scanner does fire, it just doesn't fire hard enough. Every ClawHavoc skill trips medium social-engineering rules (prerequisite install, copy-paste command, npm install), because the markdown carries the install-me envelope while the actual payload lives in referenced scripts and binaries. Those mediums cap out at 24, one notch under the 26 warn threshold, so at the shipped cutoff recall is 0. To cross 26 you need a high-severity hit (15+ points) or about seven mediums, and the high-severity behavior is never in the file. Drop the threshold to 20, the "suspicious" cutoff, and recall climbs to 0.58 at precision 0.30. ROC-AUC is 0.841 on the real set versus 0.969 on the synthetic one: the signal is there but weak, and a threshold tuned on synthetic data sits just above where real malware lands.

Read that as the case for the design, not against it. Static is a cheap first-stage filter for the in-text threat class. The real-world collapse is the evidence for why the opt-in semantic stage has to exist, and it is the more honest headline than a single 0.95 F1.

The before/after gain on the 101 corpus: F1 +0.059, FPR -0.140, MCC +0.126. The two confusion matrices differ only in benign fixtures flipping from false positive to true negative (7 fixed, 0 broken), so McNemar is exact at p = 0.0156. The wins are all hard negatives, ssh-config-manager (47 to 9) and dotenv-loader (33 to 5), skills that trip credential rules without an exfiltration sink.

### Other tools, as reported in their papers

Verified against the arXiv full texts, not repeated from memory. Each row is on that paper's own corpus, so none of this is head-to-head with the rows above. The one anchor is SkillSieve, which measured ClawVet itself on their real 390-skill set and got F1 0.248, which lines up with the real-corpus collapse above.

| Tool | Source | Corpus | P | R | F1 | FPR |
|---|---|---|---|---|---|---|
| ClawVet (their measurement) | SkillSieve, arXiv:2604.06550 tbl. main | 390 real, 55/335 | 0.162 | 0.527 | 0.248 | 0.448 |
| SkillSieve L1 (static) | SkillSieve, arXiv:2604.06550 | 390 real, 55/335 | 0.342 | 1.000 | 0.509 | 0.316 |
| SkillSieve + SSD | SkillSieve, arXiv:2604.06550 | 390 real, 55/335 | 0.663 | 1.000 | 0.797 | 0.084 |
| SkillSieve full (+ jury) | SkillSieve, arXiv:2604.06550 | 390 real, 55/335 | 0.912 | 0.945 | 0.929 | 0.015 |
| Behavioral pipeline | Liu et al., arXiv:2602.06547 | 300 eval / 98,380 funnel | 0.996 | n/r | n/r | - |
| SkillFortify | Bhardwaj, arXiv:2603.00195 | 540 synthetic, 270/270 | 1.000 | 0.926 | 0.962 | 0.000 |

Caveats worth carrying into any writeup:
- Liu et al. report precision only (0.996, about 0.6 false positives per fold) and deliberately do not report recall or F1; their 157 confirmed skills are a precision-first lower bound, not a recall estimate.
- SkillFortify's 0% FPR is empirical on a 540-skill synthetic benchmark (270 malicious, 270 benign) and is stated as benchmark-specific, not a universal guarantee. Its formal soundness theorem is scoped more narrowly, and its own E3 experiment is a negative result: information-flow analysis added no detections over pattern matching.
- SkillSieve's static-only layer L1 hits recall 1.000 on their real set where ClawVet's static layer hits 0 on ours. Different corpora, but that gap is the thing to explain, and the honest lead for the paper.

To make any of this head-to-head, run every tool against one shared open corpus and report that single table.

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

# Run tests (89 API tests across 11 suites, 46 shared)
npx turbo test

# Start API server
cd apps/api && npm run dev

# Start web dashboard
cd apps/web && npm run dev

# Start Postgres + Redis
docker-compose up -d

# Push DB schema
cd apps/api && npm run db:push
```

## Environment variables

Copy `.env.example` to `.env`:

```
DATABASE_URL=postgres://clawvet:clawvet@localhost:5432/clawvet
REDIS_URL=redis://localhost:6379
ANTHROPIC_API_KEY=sk-ant-...    # For the opt-in AI semantic stage
GITHUB_CLIENT_ID=               # For OAuth
GITHUB_CLIENT_SECRET=
```

## Monorepo structure

This repo is a monorepo with two separate concerns.

| Package | Published | Description |
|---------|-----------|-------------|
| `packages/cli` | Yes (`npx clawvet`) | Stateless CLI scanner. No databases, no auth, offline by default |
| `packages/shared` | Yes (`@clawvet/shared`) | Scanner engine, types, and 57 threat patterns |
| `apps/api` | No (self-hosted) | Optional Fastify backend with Postgres, Redis, GitHub OAuth |
| `apps/web` | No (self-hosted) | Optional Next.js dashboard |

The npm package `clawvet` contains only `packages/cli` and `packages/shared`. It has zero database, Redis, or OAuth dependencies. The `apps/` directory is the optional self-hosted dashboard and is not part of the published package.

## Telemetry

ClawVet includes opt-in anonymous telemetry. On first run you are asked whether to enable it. You can also control it with an environment variable:

```bash
export CLAWVET_TELEMETRY=off   # disable
export CLAWVET_TELEMETRY=on    # enable
```

When enabled, the following is sent and nothing else:

| Field | Example | Purpose |
|-------|---------|---------|
| `deviceId` | `a1b2c3d4-...` | Random UUID, not tied to identity |
| `scanCount` | `42` | How many scans this device has run |
| `ts` | `2026-03-14T...` | Timestamp |
| `os` | `win32` | Platform |
| `osVersion` | `10.0.26200` | OS version |
| `cliVersion` | `0.10.0` | CLI version |
| `environment` | `production` | `production` / `development` / `ci` (dev and CI traffic filtered out) |
| `skillHash` | `9f2a…` (SHA-256) | Hash of the skill name. The raw name is never sent |
| `riskScore` | `15` | Numeric risk score |
| `riskGrade` | `B` | Letter grade |
| `findingsCount` | `3` | Number of findings |
| `cached` | `false` | Whether the result came from cache |

Never sent: raw skill names, file contents, source code, file paths, environment variables, API keys, or any personally identifiable information. Config is stored in `~/.clawvet/config.json`.

## Tests

89 API tests plus 46 shared tests, covering:
- The benchmark corpus (101 fixtures) and the six built-in fixture skills
- Edge cases (empty files, malformed YAML, unicode, 100KB adversarial input)
- Regex catastrophic backtracking safety
- 57 threat patterns across 13 categories
- Risk scoring: diminishing-returns repeats, context downweighting, disqualifying floor
- API route validation (auth, webhooks, scans, incl. authenticated scan listing)
- SSRF guard (scheme allowlist plus private/metadata IP-range blocking)
- Semantic-pass prompt injection defense (unguessable boundary, untrusted-data framing)
- Cross-file payload assembly (split payloads, precision guard, binary skip)
- CLI end-to-end integration (--format json, --fail-on, exit codes)

## License

MIT
