# clawvet

**Skill vetting & supply chain security for OpenClaw.**

ClawVet scans OpenClaw `SKILL.md` files for prompt injection, credential theft, remote code execution, typosquatting, and social engineering — before they reach your agent.

## Demo

![ClawVet CLI demo](https://raw.githubusercontent.com/MohibShaikh/clawvet/master/clawvet-demo.gif)

## Install

```bash
npm install -g clawvet
```

Releases are published with npm provenance, so the tarball is signed and
traceable to the GitHub Actions run that built it. `npm view clawvet
dist.attestations` shows the attestation without installing anything, and
`npm audit signatures` verifies it inside a project install (it rejects global
ones). Pin `clawvet@<version>` if you want a fixed release rather than current
detection rules.

## Usage

### Scan a local skill

```bash
clawvet scan ./my-skill/
clawvet scan ./my-skill/SKILL.md
```

### JSON output (for CI/CD)

```bash
clawvet scan ./my-skill/ --format json
```

### Fail on severity threshold

```bash
clawvet scan ./my-skill/ --fail-on high
# exits 1 if any high or critical findings
```

### Fetch and scan from ClawHub

```bash
clawvet scan weather-forecast --remote
```

### Audit all installed skills

```bash
clawvet audit
```

### Watch for new skill installs

```bash
clawvet watch --threshold 50
```

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

Check `npm view clawvet dist.attestations` before installing; `npm audit
signatures` does not accept global installs.

The gate is persistent. Once the block is in your config it scans every skill
install from then on and fails closed on anything it cannot parse. Scope it
with `--block-at <score>` when printing the config; the default is 76, so
scores block only at F, while clear evidence of hidden or fetched code blocks
at any score. To remove it, set `security.installPolicy.enabled` to false or
delete the block, then `npm uninstall -g clawvet`.

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


## What it detects

ClawVet runs a 6-pass analysis on every skill:

| Pass | What it checks |
|------|---------------|
| **Skill Parser** | Extracts YAML frontmatter, code blocks, URLs, IPs, domains |
| **Static Analysis** | 57 regex patterns: RCE, reverse shells, credential theft, obfuscation, DNS exfil, privilege escalation |
| **Metadata Validator** | Undeclared binaries, env vars, missing descriptions, invalid semver |
| **Dependency Checker** | `npx -y` auto-install, global `npm install`, risky packages |
| **Typosquat Detector** | Levenshtein distance against popular skills, suspicious naming patterns |
| **Semantic Analysis** | AI-powered detection of social engineering & prompt injection (optional) |

## Risk Scoring

| Score | Grade | Action |
|-------|-------|--------|
| 0-10 | A | Approve |
| 11-25 | B | Approve |
| 26-50 | C | Warn |
| 51-75 | D | Warn |
| 76-100 | F | Block |

## CI/CD Integration

```yaml
# GitHub Actions example. Add clawvet as a dev dependency first
# (`npm install --save-dev clawvet`) so the lockfile pins the exact
# version; --no-install then refuses to fetch anything else.
- name: Vet skill
  run: npx --no-install clawvet scan ./my-skill --format json --fail-on high
```

## License

MIT
