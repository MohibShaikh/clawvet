# ClawVet Launch & Distribution Drafts

Ready-to-publish drafts grounded strictly in verified sandbox measurements ([docs/launch-report-2026.md](launch-report-2026.md)).

---

## 1. Hacker News (Show HN)

**Title:** `Show HN: ClawVet – Offline AST scanner and rug-pull permissions diff for AI agent skills`

**Text:**

I built ClawVet (MIT, Node/TS + WebAssembly Tree-sitter) after realizing that AI coding agent skills (`SKILL.md`, `.cursorrules`, `AGENTS.md`, Claude Code hooks, and MCP configs) run with full shell/credential access but have no install-time permission checks or update diffs.

What it does:
- `clawvet audit --summary`: scans installed skills, rules, hooks, and MCP configs across OpenClaw, Claude Code, Cursor, Codex, and Windsurf, and prints a Machine Permissions Summary (which items touch `~/.ssh`, `~/.aws`, `~/.openclaw`, persistence locations, secret env vars, or risky hosts).
- `clawvet init`: one-command setup for OpenClaw's `security.installPolicy` gate (resolves npm symlinks, checks `chmod go-w`, backs up config) and an advisory Claude Code `PostToolUse` guard hook.
- Offline rug-pull diff: records extracted capabilities on install and prompts on updates that add credential reads, OS persistence, high-risk behaviours, or risky external hosts.
- GitHub Action with `comment-pr: true`: posts a sticky PR Permissions Diff comment showing newly added hosts/secrets/persistence.
- Zero-install browser playground (`web-demo/`): runs `@clawvet/shared` + WebAssembly Tree-sitter 100% client-side.

Empirical numbers (all untrusted corpora run in a `--network none` Docker sandbox):
- Across 209 unique real ClawHub skills: 63.6% contact external hosts, 48.8% read secret-named env vars (40.2% undeclared in `requires.env`), 4.8% access host credential stores (`~/.ssh`, `~/.openclaw`, etc.), and 3.3% write OS persistence (`cron`, `systemd`/`launchd`, shell rc, `authorized_keys`).
- Held-out SkillTrustBench v1.1 (556 multi-file skills): `clawvet gate` static scores 0.660 accuracy / 0.511 macro F1 (0.815 malicious F1); adding `--semantic` (Claude Haiku 5.5, BYOK or local Ollama/vLLM) scores 0.833 accuracy / 0.770 macro F1 / 0.934 malicious F1 (vs published leaderboard numbers for Cisco Skill Scanner 0.775 / 0.614 and NVIDIA SkillSpector 0.712 / 0.511; Tencent A.I.G leads at 0.874 / 0.832).
- Update rug-pull benchmark (748 benign ClawHub updates + 219 MalSkillBench pairs, held-out test half): offline gate + permissions diff catches 95.2% of code-injection rug-pulls (up from 83.9% gate-alone) and 95.2% of mixed attacks, while prompting on 5.1% of benign updates.

Honest caveat: pure natural-language prompt-injection rug-pulls with no code payload only hit 36.4% statically on the held-out test split; that class still requires `--semantic`.

Install: `npm i -g clawvet && clawvet audit --summary`
Repo & full report: https://github.com/MohibShaikh/clawvet

---

## 2. Reddit: r/ClaudeAI

**Title:** `I scanned 209 real AI agent skills in a sandbox: 40% read undeclared secret env vars and 4.8% touch ~/.ssh or credential stores. Built a 10-second local audit tool.`

**Body:**

Most of us have accumulated Claude Code skills (`~/.claude/skills`), slash commands (`.claude/commands`), hooks (`settings.json`), Cursor rules (`.cursor/rules`), and `.mcp.json` servers without a clear picture of what they actually touch.

I built **ClawVet** (open-source, MIT, runs 100% offline by default, zero telemetry unless opted in) to audit them in one command:

```bash
npm install -g clawvet
clawvet audit --summary
```

At the end it prints a **Machine Permissions Summary** showing:
- Which skills/rules/hooks/MCP servers access `~/.ssh`, `~/.aws`, `~/.openclaw`, or registry tokens
- Which ones write persistence (`cron`, `systemd`/`launchd`, `~/.zshrc`, `authorized_keys`)
- External hosts contacted (highlighting tunnels, raw IPs, webhooks, and OAST canaries)
- Undeclared secret env vars and high-risk AST dataflow findings (e.g. credential read flowing into an outbound POST)

You can also run `clawvet init` (supports `--dry-run`) to wire up:
- A lightweight Claude Code `PostToolUse` hook that only scans newly written/edited skills, rules, and MCP configs (skips normal code files)
- OpenClaw's `security.installPolicy` install gate with offline rug-pull update diffs

Benchmarks (sandboxed):
- Beats Cisco Skill Scanner and NVIDIA SkillSpector on the held-out SkillTrustBench v1.1 subset (`0.833` accuracy / `0.770` macro F1 with `--semantic` Haiku, `0.934` malicious F1).
- Catches **95.2%** of code-injection rug-pull updates completely offline at a **5.1%** benign prompt rate.

GitHub: https://github.com/MohibShaikh/clawvet

---

## 3. Reddit: r/LocalLLaMA

**Title:** `ClawVet: Open-source offline AST taint scanner for AI agent skills & MCP configs (optional local Ollama/vLLM semantic pass)`

**Body:**

Sharing an open-source security scanner I built for AI agent skills, rules, hooks, and MCP configs (OpenClaw, Claude Code, Cursor, Codex, Windsurf).

Why it fits local workflows:
- **100% offline by default**: 6 deterministic passes including WebAssembly Tree-sitter AST dataflow for Python, JS/TS, and shell (never executes the scanned skill).
- **Local LLM support for `--semantic`**: set `CLAWVET_LLM_PROVIDER=openai`, `CLAWVET_LLM_BASE_URL=http://localhost:11434/v1`, and `CLAWVET_LLM_MODEL=...` to run the semantic prompt-injection judge on Ollama or vLLM with zero cloud keys.
- **Offline rug-pull detection**: compares every skill update against what the installed version could access (catches 95.2% of held-out code-injection rug-pulls with no LLM needed, 5.1% benign prompt rate).
- **Zero telemetry by default**, no database, single npm package.

Quick try:
```bash
npm i -g clawvet && clawvet audit --summary
```

Full benchmarks and methodology: https://github.com/MohibShaikh/clawvet/blob/master/docs/launch-report-2026.md

---

## 4. Reddit: r/netsec

**Title:** `Measuring AI agent skill permissions and offline rug-pull detection (SkillTrustBench + 748 ClawHub updates)`

**Body:**

We evaluated static + Tree-sitter AST taint analysis and capability-diff update gating for AI agent skill packages inside a `--network none` Docker sandbox.

Summary of findings:
- **Real-world permission surface (209 unique ClawHub skills):** 63.6% contact external hosts, 48.8% read secret-named env vars (40.2% undeclared in manifest), 4.8% touch host credential stores (`~/.ssh`, `~/.openclaw`, `~/.aws`, registry tokens, `/etc/shadow`), 3.3% write OS persistence.
- **Update rug-pull detection (held-out split of 748 benign ClawHub update pairs + 219 MalSkillBench pairs):** single-version static gate catches 83.9% of code-injection rug-pulls; diffing extracted capabilities (sites, credential stores, persistence, proved behaviours) against the previously approved version raises held-out code-injection detection to **95.2%** (mixed attacks **95.2%**) while prompting on **5.1%** of benign updates.
- **SkillTrustBench v1.1 (held-out 556-case subset):** static gate reaches 0.660 acc / 0.511 macro F1 / 0.815 malicious F1; pairing static evidence with a grounded LLM judge (`--semantic`, Haiku 5.5, hard security floors enforced) reaches **0.833 acc / 0.770 macro F1 / 0.934 malicious F1** (Cisco Skill Scanner: 0.775 / 0.614; NVIDIA SkillSpector: 0.712 / 0.511; Tencent A.I.G: 0.874 / 0.832).
- **Limitation:** pure natural-language prompt-injection updates with zero new code capabilities only hit 36.4% statically on held-out test pairs; LLM triage remains necessary for non-code social engineering.

Full write-up & reproduction scripts: https://github.com/MohibShaikh/clawvet/blob/master/docs/launch-report-2026.md

---

## 5. X / Twitter Thread

**Tweet 1:**
We scanned 209 real AI agent skills in a no-network sandbox to see what they actually touch:
- 63.6% contact external hosts
- 40.2% read undeclared secret env vars
- 4.8% access ~/.ssh, ~/.openclaw, or credential stores
- 3.3% touch OS persistence (cron, launchd/systemd, shell rc)

You can audit your own machine in 10 seconds:
`npm i -g clawvet && clawvet audit --summary`

**Tweet 2:**
`clawvet audit` scans across OpenClaw, Claude Code (skills, commands, hooks), Cursor (`.cursor/rules`, `.cursorrules`), Codex (`AGENTS.md`, skills), Windsurf, and MCP configs (`.mcp.json`, Claude Desktop) and prints a single Machine Permissions Summary.

**Tweet 3:**
The scariest agent supply-chain attack isn't a blatant v1.0.0 malware skill. It's a clean v1.0.0 skill that adds 3 lines of credential exfil in v1.0.1.

ClawVet diffs extracted capabilities on every update offline:
- 95.2% of held-out code-injection rug-pulls caught (up from 83.9%)
- Only 5.1% prompt rate on benign ClawHub updates

**Tweet 4:**
On the held-out SkillTrustBench v1.1 leaderboard subset (556 multi-file skills):
- ClawVet (`--semantic`, Haiku): 0.833 acc / 0.770 macro F1 / 0.934 malicious F1
- Cisco Skill Scanner: 0.775 / 0.614
- NVIDIA SkillSpector: 0.712 / 0.511

Static + WebAssembly Tree-sitter AST dataflow runs 100% offline.

**Tweet 5:**
Zero JSON editing to protect your machine:
`clawvet init --dry-run`
`clawvet init`

And for skill repos, add `comment-pr: true` to the GitHub Action for automatic sticky PR Permissions Diff comments on every pull request.

MIT open source: https://github.com/MohibShaikh/clawvet

---

## 6. OpenClaw / Claude Code Discord Announcement

Shipped a major ClawVet update for multi-agent auditing and one-command setup:
- `clawvet audit --summary`: audits OpenClaw, Claude Code (skills, commands, hooks), Cursor rules, Codex, Windsurf, and MCP server configs with a Machine Permissions Summary
- `clawvet init` (`--dry-run` supported): auto-detects OpenClaw `openclaw.json` + Claude Code `settings.json`, creates backups, checks/fixes `chmod go-w`, and runs an immediate audit
- GitHub Action `comment-pr: true`: posts a sticky PR Permissions Diff comment + README trust badge on skill PRs
- Static browser playground (`web-demo/`): 100% client-side WebAssembly Tree-sitter scanning

Install / upgrade: `npm i -g clawvet && clawvet audit --summary`
Benchmarks & write-up: https://github.com/MohibShaikh/clawvet/blob/master/docs/launch-report-2026.md

---

## 7. Awesome-List Submission Snippets

- **`awesome-claude-code` / `awesome-mcp-security` / `awesome-openclaw`:**
  `- [ClawVet](https://github.com/MohibShaikh/clawvet) - Offline static + Tree-sitter AST security scanner, install-time rug-pull gate, and multi-agent audit CLI (OpenClaw, Claude Code, Cursor, Codex, MCP configs) with GitHub Action PR Permissions Diff comments.`
