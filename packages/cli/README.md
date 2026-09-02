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
