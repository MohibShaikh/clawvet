# Install-Time Gate and Inspection Coverage

Reference documentation for `clawvet gate` (`security.installPolicy`), setup troubleshooting, coverage profiles, limits, and known gaps.

## Setting up `clawvet gate`

`clawvet gate` hooks into OpenClaw's [`security.installPolicy`](https://docs.openclaw.ai/tools/skills-config). OpenClaw stages the source, writes install metadata to stdin, and reads one JSON verdict from stdout before completing the install. It runs whether or not an agent remembers to scan.

Install `clawvet` globally once, then print a ready-to-paste config block:

```bash
npm install -g clawvet
clawvet gate --print-config
```

Do not use `npx clawvet gate --print-config`. The config embeds resolved paths, and `npx` resolves them into its cache (`~/.npm/_npx/...`). A cache cleanup later removes the executable the config points at, causing every install to fail closed until you paste the config again. A global install is permanent.

Use the printed block rather than writing paths by hand. OpenClaw requires the policy command and any interpreter script argument to be regular files, and rejects symlinks. `npm i -g clawvet` installs a symlink into `bin/`, so pointing `installPolicy` at `which clawvet` fails. `--print-config` resolves through to the real `dist/index.js`, invokes it via an absolute `node` path, and includes the `source: "exec"` field OpenClaw's config validation requires.

### Directory permissions troubleshooting

OpenClaw refuses to execute the policy through group- or world-writable paths. The resolved `node` and `dist/index.js`, and every parent directory above them, must not be writable by group or others. A launcher-managed Node installation such as `~/.local/share/fnm/node-versions/<version>` is commonly group-writable and triggers `... exec.command parent directory permissions are too open`.

`clawvet gate --print-config` checks these paths automatically and prints any writable directories plus the exact `chmod go-w` command to stderr (keeping stdout pure JSON). You can also fix a path named in an OpenClaw error directly:

```bash
chmod g-w,o-w "/path/from/the/error"
# For example, an fnm-managed node:
chmod g-w,o-w ~/.local/share/fnm/node-versions/v22.17.1
```

### Node versions and targets

- **Node versions:** OpenClaw runs `clawvet` with the absolute `node` path in the printed block (the Node that ran `--print-config`), which can differ from the Node running OpenClaw. OpenClaw 2026.11.5 requires Node 24.16+; `clawvet` requires Node `>=22.0.0`.
- **Targets:** `targets` is `["skill"]`. ClawVet reads `SKILL.md` and the files it references, so a plugin without `SKILL.md` is allowed through, and `"plugin"` is omitted because it would claim protection that does not exist yet. A skill target that stages no `SKILL.md` is blocked.
- **Removing the gate:** set `security.installPolicy.enabled` to `false` or delete the block, then run `npm uninstall -g clawvet`.

## Verdicts, thresholds, and flags

| Risk score | Grade | ClawVet | `installPolicy` |
|---|---|---|---|
| 0-25 | A / B | `approve` | `allow` |
| 26-75 | C / D | `warn` | `warn` |
| 76-100 | F | `block` | `block` |

A `warn` is not a pass. OpenClaw stops the install before commit: interactive CLI installs prompt for confirmation, and Gateway-backed or automatic installs stay blocked without an operator-confirmation path.

- **`--block-at <score>`:** moves the score blocking line (default `76`). ClawHavoc fixtures score 28-36, below that line, but their download-and-execute instructions block under either profile regardless of score. `--block-at 26` denies anything scoring 26+, at the cost of blocking dual-use skills. Any `disqualifying` finding (such as a known C2 address) blocks at any threshold.
- **Update permission checks (on by default):** every scan extracts permissions (connected sites, credential stores, secret env vars, persistence locations, and proved high-risk behaviours), printed under Permissions by `clawvet scan` and included as `capabilities` in JSON. `clawvet gate` records what each allowed install could do under `~/.local/state/clawvet/installed` (using `XDG_STATE_HOME` when set, otherwise `os.homedir()`, so existing `--print-config` blocks work without changing `passEnv`). When OpenClaw stages an update for the same owner and slug, the gate asks (`warn`, naming each new permission) if the update adds a secret read, persistence, a high-risk behaviour, or a risky site (raw IP, tunnel, request bin, paste/file drop, abuse-prone TLD, or a code host under another owner; the publisher's own GitHub/GitLab account is exempt). `--strict` asks about every new site on updates, and `--no-update-check` disables the comparison. The check never relaxes a `block` or `warn` to `allow`, and any ledger read/write error leaves the verdict unchanged.
- **LLM judge (`--semantic`):** static and offline by default. Print the config with `--semantic` to add the LLM judge; the printed block lists key variables under `passEnv` because OpenClaw starts the policy with an empty environment (keys stay in the gateway environment). ClawVet sends static findings and coverage gaps as evidence; the judge returns benign, suspicious, or malicious (`allow`, `warn`, `block`), and can clear a gap only by citing a real quote from the skill. Floors that no judge verdict can lower: unreadable content blocks, runtime-fetched code always asks, truncated bundles clear nothing, disqualifying indicators block, and anything static findings alone would block at least asks. If the judge times out or has no key, the static verdict stands and an `allow` becomes a `warn` (set `--semantic-on-error ignore` to keep the static verdict). `--strict` keeps static coverage rules. `scan --semantic` uses the same judge and floors, adding a `semantic` field to JSON output.
- **Baselines (`--baseline <file-or-dir>`):** accepts reviewed findings, each bound to the SHA-256 hash of the file it came from so editing that file restores the finding. Baselines inside the skill directory, disqualifying findings, and unpinnable gaps (such as runtime-downloaded code) are refused. Write one with `clawvet scan <skill> --write-baseline <file> --reason "..."`.
- **Fail-closed:** any malformed payload, unreadable staged path, or scanner error returns `block` with a reason rather than a bare non-zero exit.

## Inspection coverage

Local folder and direct `SKILL.md` scans follow recognized file references recursively through the skill directory, including references inside helpers. JSON reports include `coverage.complete`, inspected file/line ranges, and any coverage issues.

Reference discovery is static: it recognizes filenames, concrete interpreter/script paths, and local Markdown links. Skill-root placeholders (`{baseDir}/`, `$SKILL_DIR/`, `<skill-dir>/`), `$(dirname "$0")` / idiomatic `$SCRIPT_DIR` paths, and nested monorepo skill paths (`skills/.../<name>/...`) resolve to the bundle so the underlying scripts are inspected. Literal inline commands are inspected up to four nested levels; exceeding that limit fails coverage.

Markdown prose is not treated as shell. Outside a fence, only inline code and lines starting with a recognized command (optionally after an imperative such as "Run") are read as commands. Fences are read by language: shell fences as shell, text/data fences like prose, and unlabelled or other code fences with both shell and code-loading rules so a fence label cannot hide commands. Standalone JSON, YAML, and TOML files are read as data rather than shell, HTML files use code rules, and lines starting with `|` are treated as table rows.

### Coverage profiles

- **Default profile:** blocks on clear evidence that code is hidden, swapped, or fetched and run: a downloaded file that is later executed or followed, instructions to download and run code, `curl | sh` from any host other than an exact trusted vendor installer (`astral.sh`, `sh.rustup.rs`, `get.docker.com`, etc.), encoded or remote execution, `eval` or process calls on unresolved arguments, and anything ClawVet could not read. A referenced script missing from the bundle (`missing-file`) or a path leading outside the skill (`escape`) asks instead in `gate` (stopping the install and naming the file to check), while `scan`, `audit`, and badges still fail coverage so CI fails until fixed or baselined. Other gaps (such as `npx` runtime package fetches, computed commands, unused downloads, or outside documents) stay quiet in the default gate profile and remain listed in `coverage`.
- **`--strict` profile:** blocks every gap in inspection, asks about reviewable ones, and asks about every new site on updates. Registry installs such as `pip install requests` are not a coverage gap under either profile; the dependency checker scores package names. Measurements of both profiles are in [benchmarks/gate-eval](../benchmarks/gate-eval/).

### Downloads, limits, and known gaps

- **Offline guarantee:** the gate never executes a skill or downloads dependencies. To resolve coverage failures, stage dependencies locally, use literal paths, and remove runtime downloads. A clean bundled copy does not clear a runtime download written over it. Ordinary API data requests do not fail coverage.
- **Download correlation:** downloads via `curl`, `wget`, PowerShell, or Python `urlretrieve`, and scripts that combine network reads (`requests`, `httpx`, `urlopen`, `fetch`, `axios`) with literal file writes, are correlated with later execution, imports, or instruction use (including instruction files such as `notes.txt`). These are bounded syntax checks, not general dataflow analysis of arbitrary programs.
- **Known gap:** prose that instructs the agent to fetch a web page and follow its instructions with no file in between is not statically detected (separating it from ordinary setup docs like "follow the instructions at `<url>` to get an API key" requires semantic understanding; use `--semantic` or review external links manually).
- **`scan --remote`:** fetches only the manifest (bounded to 256 KiB), always reports incomplete coverage, and exits 1. Stage the full skill locally before approving an install.
- **Enforcement on incomplete coverage:** a blocking coverage gap returns `block` regardless of `--block-at`. Local scans return `status: "failed"`, `recommendation: "block"`, and exit 1; audits exit nonzero; badges are not generated. `review` and `approve` always enforce `--strict`.
- **Limits:** 256 KiB per inspected file (including the manifest), 2 MiB total inspected content, 1,024 directory entries, and 16 nested directory levels. Symlinks, special files, and referenced binary or invalid UTF-8 files fail coverage. Keep the staged directory unchanged while inspection runs.
- **Scope note:** complete coverage means recognized references were inspected within these limits; obfuscated or unsupported runtime loading can still evade static checks, and complete coverage does not certify a skill as safe. `watch` monitors file changes; install-time enforcement requires `gate`.
