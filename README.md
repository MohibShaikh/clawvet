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
# Install once, then run the copy you installed
npm install -g clawvet

# Scan a local skill
clawvet scan ./my-skill/

# JSON output for CI/CD
clawvet scan ./my-skill/ --format json --fail-on high

# Audit all installed skills
clawvet audit
```

Install it rather than running `npx clawvet`. A fresh `npx` fetch runs whatever version the registry serves at that moment, which is the wrong habit for a tool you use to vet other code. Updating is a deliberate `npm update -g clawvet`, and every release carries npm provenance you can check first with `npm view clawvet dist.attestations`.

The CLI is static and offline, so it works in CI with no key and no network, and nothing is sent anywhere. It has no AI pass: semantic analysis runs only in the hosted API, and the CLI rejects `--semantic` rather than appearing to run it.

## Install-time enforcement

`clawvet gate` is an OpenClaw [`security.installPolicy`](https://docs.openclaw.ai/tools/skills-config)
hook. OpenClaw stages the source, writes the install metadata to the command's
stdin, and reads back one JSON verdict before the install completes. It runs
whether or not an agent remembers to scan anything.

Install `clawvet` globally once, then print a ready-to-paste config with the
paths already resolved:

```bash
npm install -g clawvet
clawvet gate --print-config
```

Do not use `npx clawvet gate --print-config`. The config embeds resolved paths,
and npx resolves them into its cache (`~/.npm/_npx/...`). A cache cleanup later
removes the policy executable the config points at. Every install then fails
closed, and the only fix is pasting the config again. A global install is
permanent.

Use the printed block rather than writing the paths by hand. OpenClaw requires
the policy command and any interpreter script argument to be regular files, and
rejects symlinks. `npm i -g clawvet` installs a symlink into `bin/`, so
pointing `installPolicy` at `which clawvet` fails. `--print-config` resolves
through to the real `dist/index.js` and invokes it via an absolute `node` path.
The block is valid as-is; it includes the `source: "exec"` field OpenClaw's
config validation requires.

OpenClaw also refuses to execute the policy through insecure paths. The
resolved `node` and `dist/index.js`, and every directory above them, must not
be writable by group or others. A stock npm global install is `0755`, so
pasting the block and running an install can fail with `... exec.command
parent directory permissions are too open`. The fix is to remove the
group/other-write bits on the directories the block names, typically the node
installation and the npm global prefix. A launcher-managed node such as
`~/.local/share/fnm/node-versions/<version>` is commonly installed
group-writable and needs the same treatment. The failure message names the
offending directory; start there.

`targets` is `["skill"]`. ClawVet reads `SKILL.md` and the files it references,
so a plugin that ships no `SKILL.md` is allowed through, and `"plugin"` is not
listed because it would claim a protection that does not exist yet. A skill
target that stages no `SKILL.md` is blocked: with the policy aimed only at
skills, an instruction-less "skill" is either not a skill or installs its
payload without saying so.

OpenClaw itself runs `clawvet` through whatever `node` launched it, so install
`clawvet` with the same node that runs OpenClaw. OpenClaw 2026.8.2 requires
Node 22.22.3+ (or 24.15.0+, or 25.9.0+); `clawvet` engine is `>=22.0.0`.

Verdicts map onto ClawVet's own vocabulary:

| Risk score | Grade | ClawVet | installPolicy |
|-----------|-------|---------|---------------|
| 0-25 | A / B | `approve` | `allow` |
| 26-75 | C / D | `warn` | `warn` |
| 76-100 | F | `block` | `block` |

A `warn` is not a pass. OpenClaw's docs are explicit: "A warning stops the
install before commit." An interactive CLI install asks the operator to confirm,
and Gateway-backed or automatic installs stay blocked without an
operator-confirmation path.

**Choosing a threshold.** `--block-at <score>` moves the blocking line, default
76. ClawHavoc campaign fixtures score 28-36, below that line, but their
instructions to download and run code block under either profile regardless of
score: all 49 corpus500 ClawHavoc skills that ship their referenced files block.
`--block-at 26` also denies anything scoring 26 or more, at the cost of denying
dual-use skills. A finding marked `disqualifying`, such as a known-malicious C2 address,
blocks at any threshold.

Static passes only. Runtime depends on the referenced files; the host enforces
the configured timeout and fails closed if inspection takes too long. The semantic pass is never reached, so
no API key and no network round trip.

Anything the host cannot parse fails closed. A malformed payload, an unreadable
staged path, or a scanner error returns `block` with a reason rather than a bare
non-zero exit, so the operator sees why the install stopped.

### Inspection coverage

Local folder and direct `SKILL.md` scans follow recognized file references
recursively through the skill directory, including references inside helpers.
JSON reports include `coverage.complete`, inspected file/line ranges, and any
coverage issues. Reference discovery is static: it recognizes filenames,
concrete interpreter/script paths, and local Markdown links. Skill-root
placeholders such as `{baseDir}/`, `$SKILL_DIR/` and `<skill-dir>/` resolve to
the bundle, so the script behind them is inspected. Recognized dynamic
commands, globs, computed imports, runtime evaluation, remote modules, and
download-to-execution paths make coverage incomplete; the profile below decides
which of those block. These checks run inside referenced helpers too. Literal inline commands are inspected up to four nested
levels; exceeding that limit also fails coverage.

Markdown prose is not shell. Outside a fence, only inline code and lines that
start with a recognized command (optionally after "Run") are read as commands,
so a price table or a bullet that mentions `python3` is not. Fences are read by
language: shell fences as shell, text and data fences like prose, and
unlabelled and other code fences with both the shell and the code-loading
rules, since a fence label cannot hide a command. A line that starts with `|`
is a table row, not a command.

**Profiles.** Coverage gaps are not equal, so a profile decides what each one
does. The default profile blocks on clear evidence that code is hidden, swapped,
or fetched and run: a downloaded file that is later run or followed,
instructions to download and run code, `curl | sh` from any host other than an
exact trusted vendor installer such as `astral.sh` or `sh.rustup.rs`, a path
outside the skill, encoded or remote execution, process calls and `eval` on
unresolved arguments, and anything ClawVet could not read. Other gaps, such as
a package fetched at install time with `npx`, a computed command, an unused
download, or a document linked from outside the skill, pass quietly and stay
listed in `coverage`. The gate then asks the operator only when the scan's own
findings are borderline. A gate that asks too often gets switched off or
approved without reading, which protects no one.

`--strict` on `gate` and `scan` blocks every gap in inspection and asks about
the reviewable ones. Registry installs such as `pip install requests` are not a
gap under either profile; the dependency checker scores the package names.
Measurements of both profiles are in `benchmarks/gate-eval/`.

The gate stays offline: it never executes a skill or downloads its dependencies.
To resolve these coverage failures, stage fixed dependencies locally, use
literal paths, and remove their runtime downloads. A clean staged file does not
clear a runtime replacement downloaded over it. Ordinary API data requests do
not fail coverage solely because they use the network.

Downloads made with `curl`, `wget`, PowerShell, or Python `urlretrieve` are
checked for code destinations and later use as instructions. A script that
reads from the network (`requests`, `httpx`, `urlopen`, `fetch`, `axios`) and
writes a literal filename counts as downloading it; running or importing that
file afterwards blocks. A bundled harmless
copy does not clear a runtime replacement, including an instruction file such as
`notes.txt`. Reading or summarizing ordinary API data remains supported. These
are bounded syntax checks, not general data-flow analysis of arbitrary programs.

Known gap: prose that tells the agent to fetch a page and do what it says, with
no file in between, is not detected. Telling that apart from ordinary setup
docs ("follow the instructions at <url> to get an API key") takes reading for
meaning, which the offline CLI does not do. Review a skill's external links
yourself before installing it.

`scan --remote` fetches only the manifest, reports incomplete coverage, and exits
1 even if that manifest has no findings. Responses are bounded to 256 KiB.
Stage the full skill locally before relying on a gate verdict.

A gap that blocks under the active profile returns `block` regardless of
`--block-at`, and cannot produce `allow`. Local scans then return `status:
"failed"`, `recommendation: "block"`, and exit 1; any reported score describes
only the inspected content. Audits return a nonzero exit status for them, and
badges are not generated. `review` and `approve` always use the strict profile:
approving a skill should mean all of it was inspected.

Limits are 256 KiB per inspected file (including the manifest), 2 MiB of inspected
content, 1,024 directory entries, and 16 nested directory levels. Symlinks and
special files anywhere in the inventory make coverage incomplete; referenced
binary or invalid UTF-8 files do too. These conservative limits can reject
legitimate skills; resolve the reported issue and rescan instead of lowering the
risk threshold. Keep the staged directory unchanged while inspection runs.

Complete coverage means the recognized references were inspected within these
limits. These checks recognize supported syntax, not every possible program:
obfuscated or unsupported runtime loading can still evade static detection.
Complete coverage does not certify a skill as safe. `watch` reports file changes; install enforcement requires
`gate`.

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
| 4 | `semantic-analysis` | Hosted API only. Claude reads the instructions for social engineering and prompt injection |
| 5 | `dependency-checker` | npx -y auto-install, global npm installs, risky packages |
| 6 | `typosquat-detector` | Levenshtein distance against top ClawHub skills |

Pass 4 runs only in the hosted API. The CLI runs the other five, which are pure static work with no API and no cost.

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
500 real-world       P 0.774  R 0.960  F1 0.857  FPR 0.031  ROC-AUC 0.977
397 live clean       FPR 0.023  (false positives only, no positive class available)
95% CI (real)  F1 [0.780, 0.921]   MCC [0.769, 0.912]
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
| 0.11.1 | 500 real-world | 0.774 | 0.960 | 0.857 | 0.031 |

The 0.000 row is not a typo. Through 0.10.0 every ClawHavoc skill in the real corpus scored 14 to 24, and the warn threshold is 26, so the scanner caught none of them. The cause was mechanical rather than fundamental: the markdown carries the install-me envelope (install a prerequisite, run a command) while the payload sits in a referenced file, and both halves of that envelope are medium severity, so they capped two points under the line.

0.11.0 closes it by treating the envelope as one finding rather than two mediums, and by raising a credential read plus an outbound send to a single critical finding. Both are co-occurrence rules, so they cost almost nothing in false positives: the envelope pair appears in 48 of 50 malicious skills and 0 of 450 benign ones. Removing metadata hygiene from the score did the rest, since a skill using eight ordinary unix tools was collecting 24 points for incomplete frontmatter alone.

### Held out: false positives on live ClawHub skills

The corpora above are ones this repo assembled, so the false-positive numbers in them reflect choices made here. As a check, 397 skills that ClawHub's own scan labels clean were pulled from the `tomhu/ClawSkills` snapshot and scanned cold.

```
397 live clean skills   flagged at >=26: 9   FPR 0.023   median score 0   p90 11
```

Reading all nine: eight genuinely run the construct they were flagged for, `python3 -c`, `node -e`, `curl | sh`, or a read of `~/.openclaw/`. The ninth is a security-auditing skill, which scores at the top of the range because it names `.ssh`, `.aws`, and `.env` as the paths it inspects. A skill about scanning looks much like a skill worth scanning, and no pattern separates the two.

Worth knowing before reading the table above as a general improvement: the precision gains from 0.11.0 to 0.11.1 land almost entirely in the hard-negatives tier. Every one of the 14 remaining false positives is a hard negative, and the clean tier sits at 0 out of 400. Run the same versions against these 397 live skills and the false-positive count does not move at all, staying at 9 in both. Two skills merely score lower without crossing back under the threshold. The fixes are correct, and they are measured against 50 cases picked because they trip rules, so the F1 jump reads wider than it is.

There is no matching recall figure here, and that is a real gap rather than an omission. Confirmed malware is vanishingly rare in the live registry: across 3,907 records there was 1 blocked skill and 2 labelled malicious, while "suspicious" covers roughly 78% of everything and carries no information. Without a usable positive class, the generalization question stays open, and it is probably why every paper in this area builds its own curated benchmark instead.

One caution on interpreting the 500-skill numbers: 49 of its 50 malicious skills are ClawHavoc variants, so they share one campaign's shape. The envelope rule works well against that shape. Whether it transfers to a different campaign is untested.

What remains is the honest limit. Two malicious skills are still missed. The clearest is a browser-automation skill that describes signing up for services under a fabricated identity and working around bot checks, all in ordinary English with no dangerous token anywhere. No pattern reaches that. Of the 14 remaining false positives on the 500-skill corpus, most are skills that genuinely do run `curl | bash` or `python -c`, which is statically indistinguishable from the malicious use. Both classes are what the opt-in semantic stage is for.

### Prior work

Related systems and measurement studies, listed so the comparison can be made rather than asserted. Their reported figures are not reproduced here: each is measured on that paper's own corpus with its own labelling, so none of it is head-to-head with the numbers above, and any comparison worth publishing should come from running the tools yourself on one shared corpus.

- SkillSieve, a hierarchical triage framework combining static checks with LLM analysis: [arXiv:2604.06550](https://arxiv.org/abs/2604.06550). It includes a measurement of an earlier ClawVet release on its own benchmark.
- A large-scale empirical study of malicious agent skills in the wild: [arXiv:2602.06547](https://arxiv.org/abs/2602.06547).
- SkillFortify, formal analysis and supply chain security for agent skills: [arXiv:2603.00195](https://arxiv.org/abs/2603.00195).
- ClawHub security signals across multiple scanners: [arXiv:2606.01494](https://arxiv.org/abs/2606.01494) and the [OpenClaw/clawhub-security-signals](https://huggingface.co/datasets/OpenClaw/clawhub-security-signals) dataset. Note that this dataset stores `skill_md_content` with newlines stripped, which breaks frontmatter and code-fence parsing for any structure-aware scanner.

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
| `packages/cli` | Yes (`npm install -g clawvet`) | Stateless CLI scanner. No databases, no auth, offline by default |
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
