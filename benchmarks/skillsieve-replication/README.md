# SkillSieve replication

Re-runs the ClawVet baseline from SkillSieve (Hou and Yang, arXiv 2604.06550;
code at github.com/xiaohou521/skillsieve, MIT) on old and current ClawVet with
the paper's own decision rule, so version differences can be told apart from
rule differences.

## Their protocol

From `experiments/run_clawvet_baseline.py` and `rescan_clawvet_390.py`:

- `clawvet scan <dir> --format json` per skill folder.
- A skill counts as flagged if it has any critical or high finding, or a risk
  score of 20 or more ("suspicious" counts as flagged). This is stricter than
  ClawVet's own verdict, which warns at 26 and blocks at 76.
- Their current numbers (`results/paper_metrics.json`) pin `clawvet@0.6.3` on
  390 skills (55 malicious, 335 benign): precision 0.162, recall 0.527, F1
  0.248, false-positive rate 0.448.
- `clawvet@0.6.3` reports its own version as `0.6.0`, a hard-coded `--version`
  bug fixed in 0.7.0. That is why their output is labelled 0.6.0.

## Data

They publish labels (`labeled_dataset_final.json`, copied here under their MIT
license, see `LICENSE-skillsieve`, copyright 2026 SkillSieve authors) but not
the skill files. The files were rebuilt from the `tomhu/ClawSkills` snapshot of
ClawHub (MIT, Hugging Face) by `extract.mjs`, which writes every file of each
skill and refuses paths that leave the skill folder. Extracted skills stay
outside the repository, as in their release.

Only part of the benchmark is recoverable from public data:

| | Malicious | Benign |
|---|---|---|
| In the paper | 55 | 335 |
| Found in the snapshot | 2 | 145 |
| Added from `../corpus500` (SKILL.md only) | 49 | |
| Usable (has a SKILL.md) | 50 | 89 |

ClawHub removed the ClawHavoc skills before the snapshot, so 49 malicious
skills come from corpus500. 52 missing slugs exist under a different owner and
were excluded rather than guessed. 57 snapshot entries have no SKILL.md, 49 of
them no files at all, including one of the two malicious ones. So the absolute
numbers below are not comparable to the paper's 390-skill table. The two
versions are compared on the same 139 skills.

## Results

Measured 2026-10-07 with `run.mjs`, published `clawvet@0.6.3` and
`clawvet@0.13.1`. Same 139 skills for every row.

| Version, rule | Precision | Recall | F1 | False-positive rate |
|---|---|---|---|---|
| 0.6.3, SkillSieve rule | 0.426 | 0.58 | 0.492 | 0.438 |
| 0.6.3, ClawVet block | 0 | 0 | 0 | 0.135 |
| 0.13.1, SkillSieve rule | 0.676 | 0.96 | 0.793 | 0.261 |
| 0.13.1, ClawVet block | 0.653 | 0.98 | 0.784 | 0.295 |

0.13.1 had one error: a 173 KB report truncated by the piped-output bug fixed
after 0.13.1 (see CHANGELOG). `results.json` holds every per-skill result.

## Running

```bash
node extract.mjs <clawhub_all_normalized.jsonl> labeled_dataset_final.json ~/datasets/skillsieve-390
node run.mjs ~/datasets/skillsieve-390 0.6.3=<path>/dist/index.js 0.13.1=<path>/dist/index.js > results.json
```

Install each version in its own directory (`npm install clawvet@<version>`)
and pass its `node_modules/clawvet/dist/index.js`. Adding the corpus500
ClawHavoc samples was done by hand; see the table above.
