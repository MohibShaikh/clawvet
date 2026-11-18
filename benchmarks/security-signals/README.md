# Skill-security benchmarks: SkillTrustBench and ClawHub Security Signals

These scripts measure `clawvet gate`, with and without the `--semantic` judge,
on the two benchmarks OpenClaw's ClawScan uses. Every skill in them is
untrusted, so scanning happens only inside `sandbox.sh`: a container with no
network, the repo and the skills read-only, nothing else from `$HOME`, and only
`OUT` writable. Downloads go to `~/.cache/clawvet-bench/`, never into the repo.

## Result

SkillTrustBench v1.1, the fixed 556-case leaderboard subset (316 malicious, 74
suspicious, 166 normal), measured once with the design frozen first:

| | Accuracy | Macro F1 | Malicious F1 | Malicious recall |
|---|---|---|---|---|
| static | 0.660 | 0.511 | 0.815 | 0.788 |
| judge v2 on Claude Haiku 5.5, gate action, as frozen | 0.831 | 0.767 | 0.934 | 0.918 |
| the same, with the static-findings floor added afterwards | 0.833 | 0.770 | 0.934 | 0.918 |

The floor (static findings that would block always ask) was applied to the
saved verdicts with no new model calls and changed one decision. Per-case
results and provenance are in `results/`. The 556 subset is spent: tune on the
rest of the benchmark only.

## Steps

1. Download into the cache: SkillTrustBench (`cuhk-zhuque/SkillTrustBench`,
   revision `ef338a5`: `skilltrustbench_556_v1_1.zip`,
   `benchmark_full_v1.0.zip`, `subsets/skilltrustbench_556_v1_1/ground_truth.jsonl`,
   `metadata/case_metadata.jsonl`), licensed CC BY-NC-SA 4.0, and for Security
   Signals `OpenClaw/clawhub-security-signals` revision `69dcbd3`,
   `data/eval_holdout.jsonl`.
2. Unpack with `extract-zip.py`, which refuses paths that leave the folder and
   symlinks. Build the tuning set with `make-tuning-set.py`: the full set minus
   the 556 subset and minus any case sharing a skill name with it. Write
   Security Signals cases as folders with `materialize-security-signals.py`,
   the way ClawScan's benchmark does.
3. Static decisions: `SKILLS=<cases> OUT=<out> ./sandbox.sh npx tsx benchmarks/security-signals/run.mts /skills /out/run.jsonl`.
4. Judge v2 without giving the sandbox the network:
   `judge2-replay.mts capture` writes the exact prompt for each case;
   `ask-claude.py <out> haiku 8` sends each prompt to Claude through the Claude
   Code CLI with every tool, setting, hook and CLAUDE.md off, from an empty
   directory; `judge2-replay.mts replay` parses and grounds each reply with
   ClawVet's own parser and classifies it. With an API key instead,
   `sandbox-api.sh` runs `run-semantic.mts` with the network on and only the
   `CLAWVET_LLM_*` variables passed in.
5. Score: `python3 -I score-skilltrustbench.py <ground_truth.jsonl> <replay.jsonl>`.

`claude-shim.py` is a localhost OpenAI-compatible endpoint backed by the same
isolated CLI call, for running `clawvet gate --semantic` itself on trusted
fixtures without a key. `judge-replay.mts` does steps 4 and 5 for the earlier
judge, and `findings-block.mts` computes the static-findings floor.
