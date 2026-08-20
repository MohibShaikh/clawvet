# corpus500 — Real-World Skill Benchmark

A 500-skill benchmark built from real ClawHub data, not synthetic fixtures.

## Composition

| Tier | Count | Source | Label |
|---|---|---|---|
| benign | 400 | ClawHub skills the platform's own scan labels `clean` | 0 |
| malicious | 50 | ClawHavoc campaign (49 auto-updater + clawhub variants) + 1 ClawHub-blocked fake-identity browser skill | 1 |
| hard-negatives | 50 | Real ClawHub `clean` skills that trip static rules but are benign | 0 |

Built from the `tomhu/ClawSkills` HuggingFace snapshot of ClawHub (1.2GB, 26,502
skills with full SKILL.md content) and the SkillSieve paper's reconstructed
ClawHavoc set. 1,200+ distinct authors in the source pool.

## Why this corpus

The existing 101-fixture benchmark is hand-curated. corpus500 is real-world:
skills authors actually published on ClawHub, with the platform's own scan as
the benign label. That makes the numbers defensible to researchers in a way a
synthetic set never is.

## Hard negatives

The 50 hard negatives are the honest part. Every one is a legitimate skill that
trips credential/exec/persistence rules: security vetting tools, API clients,
installers, cloud tunnels, VPN managers. They carry label 0, so their scores
count against the false-positive rate. At the warn threshold all 50 score above
the line, which is correct behavior — they are the skills a human should glance
at before installing, and the reason the context pass exists.

## Key finding

The 50 ClawHavoc skills score 20-24. ClawVet's warn threshold is 26. So at the
warn threshold recall on real-world ClawHavoc malware is 0. At the paper's
threshold of 20 (their "suspicious" band) recall is 0.58, matching the SkillSieve
paper's published ClawVet figure of 0.584. The malware sits just under the warn
line: the dedup fix restored full weight to repeated findings, but the score
still lands below where ClawVet starts warning.

## Run

```bash
npx tsx benchmarks/scan-corpus500.mjs
python3 benchmarks/eval.py benchmarks/corpus500/results.csv --threshold 20
```

Results: 500 scanned, 0 failed. The whole corpus scans in under a minute.