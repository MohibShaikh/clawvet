# clawvet

**Skill vetting & supply chain security for OpenClaw.**

ClawVet scans OpenClaw `SKILL.md` files for prompt injection, credential theft, remote code execution, typosquatting, and social engineering — before they reach your agent.

## Demo

![ClawVet CLI demo](https://raw.githubusercontent.com/MohibShaikh/clawvet/master/clawvet-demo.gif)

## Install

```bash
npm install -g clawvet
```

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

Print a ready-to-paste config with the paths already resolved:

```bash
clawvet gate --print-config
```

Use that rather than writing the paths by hand. OpenClaw requires the policy
command and any interpreter script argument to be regular files, and rejects
symlinks. `npm i -g clawvet` installs a symlink into `bin/`, so pointing
`installPolicy` at `which clawvet` fails. `--print-config` resolves through to
the real `dist/index.js` and invokes it via an absolute `node` path.

`targets` is `["skill"]`. ClawVet reads `SKILL.md` and the files it references,
so a plugin that ships no `SKILL.md` has no instruction layer to inspect and is
allowed through. Do not add `"plugin"` until that is a real scanner.

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
76. ClawHavoc campaign fixtures score 28-36, so at the default they warn, which
stops the install pending review rather than denying it outright. `--block-at
26` denies them outright at the cost of denying dual-use skills that score above
26. A finding marked `disqualifying`, such as a known-malicious C2 address,
blocks at any threshold.

Static passes only, so it fits the install timeout: 119 ms end to end including
node startup, against the 10 s default. The semantic pass is never reached, so
no API key and no network round trip.

Anything the host cannot parse fails closed. A malformed payload, an unreadable
staged path, or a scanner error returns `block` with a reason rather than a bare
non-zero exit, so the operator sees why the install stopped.

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
# GitHub Actions example
- name: Vet skill
  run: npx clawvet scan ./my-skill --format json --fail-on high
```

## License

MIT
