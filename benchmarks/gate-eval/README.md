# Gate evaluation

Measures what `clawvet gate` decides, not what `scanSkill()` scores. A gate is
judged on two numbers side by side: malicious skills it stops, and legitimate
skills it stops. Report both every time.

Every skill is only read. The gate never executes a skill, and nothing here
runs, installs or sources any file from a sample.

## Datasets

**MalSkillBench** (arXiv 2606.07131, `lxyeternal/MalSkillBench`): 3,944
malicious and 4,000 benign skills. Not copied here: it is about 800 MB and
licensed for academic research only. Check that license before publishing
numbers from it. Attack types come from its `malware/_source_inventory.txt`:
CI code injection (1,346), PI prompt injection (1,300), MIXED (568), WILD
collected in the wild (703), TEST (27).

**corpus500** (`../corpus500`): 50 ClawHavoc, 400 benign, 50 hard negatives.
`SKILL.md` only.

## Measurement rules

- **Decisions come from the gate's own code.** `evaluate.mts` calls
  `evaluateSkill` (`packages/cli/src/commands/gate.ts`) in-process and records
  structured coverage issues, not the reason string the host sees, which is
  truncated at 1,000 characters.
- **Two cohorts.** "all" counts every skill. "complete" keeps skills whose
  referenced files are all present. 2,887 of the 4,000 benign folders ship only
  `SKILL.md` and `_meta.json`, so coverage blocks them for missing scripts,
  which says nothing about the gate. Assembly reports at most 20 issues; a
  capped list is not counted as complete.
- **Masked findings are checked.** A coverage block stops the gate before it
  scores. For those skills `evaluate.mts` also scores the inspected content,
  and `report.mjs` prints how many would have blocked on findings alone.
- **Families, not skills, are split.** Generated attacks are variants of real
  skills (`<skill>__CI_B4`, `<skill>__PI_B2`), and 135 benign skills share a
  name with malicious variants. The family key strips that suffix and the
  random id on wild copies; `sha256(family)` even goes to tune, odd to test.
  No family spans both halves. Whole campaigns (for example one author's 353
  wild copies) are not grouped.
- **Provenance.** Each run records the git HEAD and a hash of the uncommitted
  source, so a number can be tied to the code that produced it.

Tune policy while looking only at the tune half. Run the test half once per
policy, report it, and do not tune against it. The test half of this split was
reported once, for the frozen default profile below. An earlier per-skill split
was reported once; those skills are reshuffled here but were seen in aggregate.

## Running

```bash
npx turbo build --filter=@clawvet/shared
npx tsx benchmarks/gate-eval/evaluate.mts <MalSkillBench>/Dataset/Skills /tmp/msb.jsonl   # about 1 minute
node benchmarks/gate-eval/report.mjs /tmp/msb.jsonl tune 0.12.4=benchmarks/gate-eval/results/msb-0.12.4.tsv
node benchmarks/gate-eval/simulate.mjs /tmp/msb.jsonl tune
```

A published version has no `evaluateSkill`, so measure it through the command:
install it into its own directory (`npm install clawvet@0.12.4`), then

```bash
node benchmarks/gate-eval/prepare-msb.mjs <MalSkillBench>/Dataset/Skills > /tmp/msb-dirs.txt
xargs -P 14 -I{} benchmarks/gate-eval/run-gate.sh <install>/node_modules/clawvet/dist/index.js {} \
  < /tmp/msb-dirs.txt > /tmp/msb-0.12.4.tsv      # about 7 minutes
```

For corpus500, `node prepare-corpus500.mjs /tmp/c500` writes skill folders and
`/tmp/c500/corpus500-dirs.txt` for `run-gate.sh`.

## Results

Default profile, complete skills, blocked / stopped, where stopped includes
`warn`, which in OpenClaw also halts the install.

The test half was reported once, for the frozen default profile at worktree
`0a9f4ab07bd9`. Two reviews followed (one of them by Codex) and closed
bypasses and false-block bugs; those changes were measured on the tune half
only, so the test column describes the earlier build.

| Complete skills | 0.12.4, test | Default `0a9f4ab07bd9`, test | Default `97bdc38ee6d5`, tune |
|---|---|---|---|
| CI | 1.8% / 13.7% | 62.1% / 65.3% | 56.7% / 61.0% |
| PI | 2.4% / 10.3% | 10.6% / 12.9% | 9.6% / 10.7% |
| MIXED | 0.0% / 10.7% | 58.9% / 62.5% | 83.6% / 85.5% |
| WILD | 15.6% / 90.1% | 94.3% / 94.7% | 94.2% / 94.9% |
| Benign | 0.6% / 4.1% | 5.1% / 8.0% | 4.0% / 6.6% |

`results/msb-eval.jsonl` is the `97bdc38ee6d5` run. The `results/msb-*` files
are gitignored because of the dataset's license; regenerate them locally. Under `--strict`
(`simulate.mjs`) benign stops rose to 15.1% on the test half at `0a9f4ab07bd9`.

corpus500, excluding skills blocked only for missing files
(`results/corpus500-now.tsv`): 49 of 49 ClawHavoc blocked; 3 of 258 benign
blocked and none warned. 0.12.4 blocked none of the malware and stopped none
of the benign skills.

Other files in `results/`: `msb-0.12.4.tsv` and `corpus500-0.12.4.tsv` from
`clawvet@0.12.4` on npm; `msb-before-tiers.tsv` and `corpus500-before-tiers.tsv`
from the working tree before the warn tiers; `corpus500-now.tsv` from the same
build as `msb-eval.jsonl`. All through `run-gate.sh`.
