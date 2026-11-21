# What AI Agent Skills Actually Touch: Benchmarking Skill Scanners and Offline Rug-Pull Detection

AI coding agents (OpenClaw, Claude Code, Cursor, Codex, Windsurf) execute natural-language skill packages (`SKILL.md`), instruction rules (`.cursorrules`, `AGENTS.md`, `CLAUDE.md`), lifecycle hooks, and MCP servers directly with the developer's shell, filesystem, and credentials.

Installing a skill today looks like installing a browser extension in 2010: there is no permissions manifest enforced at install time, and a clean v1.0.0 skill can silently add credential theft or persistence in v1.0.1.

To measure both the real-world permission footprint and how well offline static + AST analysis catches supply-chain rug-pulls, we evaluated **ClawVet** inside a no-network Docker sandbox across three corpora:

1. **SkillTrustBench v1.1** (held-out 556-case leaderboard subset: 316 malicious, 74 suspicious, 166 normal multi-file bundles).
2. **Real ClawHub skill ecosystem** (945 version snapshots across 212 unique skills, including 748 consecutive real version updates across 209 multi-version skills).
3. **Update rug-pull pairs** (748 benign ClawHub updates + 219 MalSkillBench generated code-injection, prompt-injection, and mixed attack pairs built from benign seeds).

All benchmark harnesses live in this repository ([docs/benchmarks.md](benchmarks.md), [benchmarks/capability-diff/README.md](../benchmarks/capability-diff/README.md), [benchmarks/security-signals/README.md](../benchmarks/security-signals/README.md)).

---

## 1. What real ClawHub skills touch on your machine

Extracting code-level capabilities across 209 unique real ClawHub skills (latest scanned version per multi-version skill, offline in our no-network sandbox) reveals a wide unreviewed permission surface:

| Capability observed in code | Unique skills (of 209) | Share |
|---|---:|---:|
| Any network, secret, env, persistence, or high-risk capability | 149 | 71.3% |
| Contacts external network hosts | 133 | 63.6% |
| Reads secret-named environment variables (`*_KEY`, `*_TOKEN`, `*_SECRET`) | 102 | 48.8% |
| Reads **undeclared** secret env vars (missing from `requires.env`) | 84 | 40.2% |
| Declares secret env vars in frontmatter (`requires.env`) | 19 | 9.1% |
| Triggers high-risk behaviours in code | 50 | 23.9% |
| Accesses host credential stores (`~/.ssh`, `~/.openclaw`, `~/.aws`, registry tokens, `/etc/shadow`) | 10 | 4.8% |
| Writes OS persistence locations (`cron`, `systemd`/`launchd`, `~/.ssh/authorized_keys`, shell rc files) | 7 | 3.3% |

Over **40% of real skills read secret-named environment variables without declaring them**, and nearly **1 in 20 touches host credential stores** such as `~/.ssh` or `~/.openclaw` credential files. Most users installing skills have never seen this permission list.

---

## 2. Held-out SkillTrustBench v1.1 results

SkillTrustBench v1.1 defines a fixed 556-case held-out leaderboard subset with full multi-file skill bundles. Design and prompts were frozen before running once on the held-out subset:

| Scanner / Configuration | Accuracy | Macro F1 | Malicious F1 | Malicious recall |
|---|---:|---:|---:|---:|
| `clawvet gate` (offline static + AST dataflow) | 0.660 | 0.511 | 0.815 | 0.788 |
| NVIDIA SkillSpector (published leaderboard) | 0.712 | 0.511 | - | - |
| Cisco Skill Scanner (published leaderboard) | 0.775 | 0.614 | - | - |
| **`clawvet gate --semantic` (Claude Haiku 5.5)** | **0.833** | **0.770** | **0.934** | **0.918** |
| Tencent A.I.G (published leaderboard, Haiku) | 0.874 | 0.832 | - | - |

Key takeaway: combining deterministic offline static + Tree-sitter AST taint analysis with a grounded `--semantic` judge (which must quote verbatim evidence from the skill and cannot override hard security floors) outperforms both Cisco Skill Scanner (+5.8 accuracy, +15.6 macro F1) and NVIDIA SkillSpector (+12.1 accuracy, +25.9 macro F1) on the same held-out subset.

---

## 3. Catching rug-pull updates offline with Permissions Diff

A classic blind spot of single-version scanners is the **version rug-pull**: v1.0.0 is clean and gets installed, then v1.0.1 adds 3 lines reading `~/.ssh/id_rsa` or phoning home to a tunnel/webhook domain. A numeric score alone often stays below the hard-block threshold when the surrounding skill is legitimate.

ClawVet solves this offline without an LLM:

1. On every allowed install, `clawvet gate` records a lightweight capability summary (connected sites, credential stores, persistence locations, high-risk behaviours) in `~/.local/state/clawvet/installed`.
2. On every update, ClawVet diffs the new version's extracted capabilities against the installed version.
3. Under the quiet default, ClawVet interrupts and prompts the operator (`warn`, naming each new permission with `file:line`) whenever an update adds a secret read, OS persistence, a high-risk behaviour, or a risky site (tunnels, request bins, raw IPs, abuse-prone TLDs, or third-party code hosts; the publisher's own GitHub/GitLab account is exempt).

Measured on the **held-out test half** (748 benign ClawHub updates + 219 MalSkillBench rug-pull pairs, offline):

| Metric (held-out test half) | Gate alone | Gate + Permissions Diff |
|---|---:|---:|
| Code-injection rug-pulls caught | 83.9% | **95.2%** |
| Mixed rug-pulls caught | - | **95.2%** (100.0% tune) |
| Benign updates prompting on permission diff | - | **5.1%** (3.6% tune; 12.8% `--strict`) |
| Benign ClawHub updates stopped overall (`v0.16.2` -> `v0.17.0`) | 64.7% -> 33.6% | 65.5% -> **34.1%** |

At the same time, fixing coverage false positives (such as unbundled doc links and sibling helper scripts) cut hard blocks across the 212 unique ClawHub skills by more than half: **37.3% -> 17.5%** unique hard blocks (**374 -> 160** versions, **-57.2%**) while raising clean allows from **41.0% -> 65.6%** with **0 regressions**, and sped up full scanning **1.50x** (40.6 s -> 27.1 s; 2 MiB bundles **2.0x-2.25x faster**; capability extraction **8.4x faster**).

### Honest limitations

Static + AST analysis is strong on code payloads and capability escalation, not on pure natural-language social engineering:

- On pure **prompt-injection** rug-pulls (no code payload, no new capability), static gate + diff catches **36.4%** on the held-out test half (**50.0%** tune). That is specifically where `--semantic` (Anthropic or any local Ollama/vLLM OpenAI-compatible endpoint) is needed.
- On the MalSkillBench static tune half (`v0.16.2` -> `v0.17.0`), benign hard blocks dropped **152 -> 124** (-28, 0 regressions) and malware hard blocks rose **1,184 -> 1,215** (+31), while total stopped stayed flat at **1,435 / 2,023** (9 new real code-injection catches offsetting 9 mostly prompt-injection skills that had previously been caught only by coverage false positives).

---

## 4. Check your own machine in 10 seconds

ClawVet audits skills, instruction rules, hooks, and MCP configs across **OpenClaw, Claude Code, Cursor, Codex, and Windsurf**, and prints an aggregate **Machine Permissions Summary**:

```bash
npm install -g clawvet

# See what your installed skills, rules, hooks & MCP configs can access right now
clawvet audit --summary

# One-command setup for OpenClaw installPolicy + Claude Code PostToolUse guard
clawvet init --dry-run
clawvet init
```

You can also add sticky **PR Permissions Diff** comments to any skill repository via GitHub Actions:

```yaml
- uses: MohibShaikh/clawvet@v0.18.0
  with:
    path: skills/my-skill
    fail-on: high
    comment-pr: true
```

## Reproducing the numbers

```bash
# Run unit + regression tests
npm install
npx turbo test --filter=@clawvet/shared --filter=@clawvet/api

# Run the no-network sandbox benchmark (requires local ClawHub/MSB dataset paths)
benchmarks/capability-diff/sandbox.sh
```

Full methodology and earlier release baselines are documented in [docs/benchmarks.md](benchmarks.md) and [docs/gate-and-coverage.md](gate-and-coverage.md).
