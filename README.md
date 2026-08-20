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
3. Context pass, which reads the findings together rather than one at a time:
   - No exfiltration or remote-exec sink in the skill? Downweight its dual-use capabilities (reading a credential file, `docker exec`, installing a cron job). Reading `~/.aws/credentials` is theft when it is piped to a webhook and configuration when it is not.
   - A credential read *and* an outbound send? Raise one critical "Credential exfiltration" finding.
   - "Install a prerequisite" *and* "run this command"? Raise one high "Install-me envelope" finding. That pair is how a skill gets code it does not contain executed.

Metadata findings (undeclared binaries and env vars, missing description) are reported but do not affect the score. They are documentation hygiene, not risk.

A disqualifying finding, such as a known C2 IP, pins the score to the F band on its own and is never averaged away.

Grades: A (0-10), B (11-25), C (26-50), D (51-75), F (76-100). The CLI recommends approve below 26, warn at 26-75, block at 76+.

## Benchmarks

`benchmarks/` holds two labeled corpora and `eval.py`, a stdlib-only harness that reports precision, recall, F1, MCC, ROC-AUC and bootstrap confidence intervals.

Hard negatives are legitimate skills that trip credential and exec rules, an ssh helper that reads `~/.ssh/config`, a base64 utility, a `curl | bash` installer. They carry label 0, so their scores count against the false-positive rate. That is where the context pass earns its keep.

Static-only baseline at the warn threshold, from the committed results:

```
101 in-text corpus   P 0.909  R 0.980  F1 0.943  FPR 0.100
500 real-world       P 0.727  R 0.960  F1 0.828  FPR 0.040  ROC-AUC 0.969
95% CI (real)  F1 [0.745, 0.897]   MCC [0.737, 0.886]
```

Regenerate and re-run:

```bash
npx tsx benchmarks/scan-all.mjs
python3 benchmarks/eval.py benchmarks/results.csv --threshold 26

npx tsx benchmarks/scan-corpus500.mjs
python3 benchmarks/eval.py benchmarks/corpus500/results.csv --threshold 26
```

### Two corpora

The 101-skill corpus is hand-authored, with the malicious payload written into the SKILL.md text. That is exactly what regex is built to catch, so it flatters the scanner and is best read as a regression suite. The 500-skill corpus is real: 50 ClawHavoc skills, 400 clean ClawHub skills, and 50 hard negatives, where the payload usually lives in a referenced script rather than the markdown. Numbers below are all measured on this repo with the committed harness at threshold 26.

| ClawVet | Corpus | P | R | F1 | FPR |
|---|---|---|---|---|---|
| 0.9.0 (linear scoring) | 101 in-text | 0.820 | 0.980 | 0.893 | 0.220 |
| 0.11.0 | 101 in-text | 0.909 | 0.980 | 0.943 | 0.100 |
| 0.10.0 | 500 real-world | 0.000 | 0.000 | 0.000 | 0.111 |
| 0.11.0 | 500 real-world | 0.727 | 0.960 | 0.828 | 0.040 |

The 0.000 row is not a typo. Through 0.10.0 every ClawHavoc skill in the real corpus scored 14 to 24, and the warn threshold is 26, so the scanner caught none of them. The cause was mechanical rather than fundamental: the markdown carries the install-me envelope (install a prerequisite, run a command) while the payload sits in a referenced file, and both halves of that envelope are medium severity, so they capped two points under the line.

0.11.0 closes it by treating the envelope as one finding rather than two mediums, and by raising a credential read plus an outbound send to a single critical finding. Both are co-occurrence rules, so they cost almost nothing in false positives: the envelope pair appears in 48 of 50 malicious skills and 0 of 450 benign ones. Removing metadata hygiene from the score did the rest, since a skill using eight ordinary unix tools was collecting 24 points for incomplete frontmatter alone.

What remains is the honest limit. Two malicious skills are still missed, and the clearest of them is a browser-automation skill whose malice is "registering for internet services as Alex Chen" and "solving CAPTCHAs and bypassing browser-checks", stated in fluent English with no dangerous token anywhere. No pattern reaches that. Of the 18 remaining false positives, most are skills that genuinely do run `curl | bash` or `python -c`, which is statically indistinguishable from the malicious use. Both classes are what the opt-in semantic stage is for.

### Other tools, as reported in their papers

Verified against the arXiv full texts, not repeated from memory. Each row is on that paper's own corpus, so none of this is head-to-head with the rows above. The one anchor is SkillSieve, which measured ClawVet 0.6.0 on their real 390-skill set and got F1 0.248.

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
