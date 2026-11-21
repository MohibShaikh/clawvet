# ClawVet Benchmarks

All untrusted skill evaluations run inside the no-network Docker sandbox ([benchmarks/capability-diff/sandbox.sh](../benchmarks/capability-diff/sandbox.sh)).

## SkillTrustBench v1.1 (held out)

[SkillTrustBench](https://huggingface.co/datasets/cuhk-zhuque/SkillTrustBench) v1.1 defines a fixed 556-case leaderboard subset: 316 malicious, 74 suspicious, and 166 normal skills, with full bundles. Measured once on that subset, with the design frozen beforehand and the judge tuned only on cases outside the leaderboard subset:

| Configuration | Accuracy | Macro F1 | Malicious F1 | Malicious recall |
|---|---|---|---|---|
| `clawvet gate` (static) | 0.660 | 0.511 | 0.815 | 0.788 |
| `clawvet gate --semantic` (Claude Haiku 5.5) | 0.833 | 0.770 | 0.934 | 0.918 |

The second row maps gate verdicts (`allow` / `warn` / `block`) to `normal` / `suspicious` / `malicious` with the gate floors active. The floor ensuring that static findings which would block always at least ask was added after the run and applied to saved verdicts without new model calls; it changed one decision (the frozen run scored `0.831` / `0.767`). For comparison, the published leaderboard lists Cisco Skill Scanner at `0.775` / `0.614`, NVIDIA SkillSpector at `0.712` / `0.511`, and Tencent A.I.G at `0.874` / `0.832` with the same Haiku model. Reproduction steps are in [benchmarks/security-signals/README.md](../benchmarks/security-signals/README.md).

## Update rug-pull and ClawHub friction (`v0.17.0`)

Measured in the no-network sandbox on 748 benign ClawHub update pairs, 219 MalSkillBench rug-pull pairs, and 945 cached ClawHub skill versions (212 unique skills). See [benchmarks/capability-diff/README.md](../benchmarks/capability-diff/README.md).

### Update rug-pull benchmark (`v0.16.2` vs `v0.17.0`)

| Metric | Tune half | Held-out test half |
|---|---|---|
| Benign ClawHub updates stopped (gate alone) | 67.0% -> **38.0%** | 64.7% -> **33.6%** |
| Benign ClawHub updates stopped (gate + diff) | 67.6% -> **39.4%** | 65.5% -> **34.1%** |
| Benign updates where permission diff asks | **3.6%** (12.0% `--strict`) | **5.1%** (12.8% `--strict`) |
| Code injection stopped (gate alone -> gate + diff) | 81.8% -> **90.9%** | 83.9% -> **95.2%** |
| Mixed attacks stopped (gate + diff) | **100.0%** | **95.2%** |
| Prompt injection stopped (gate + diff) | 55.0% -> **50.0%** (1 of 20) | 39.4% -> **36.4%** (1 of 33) |

### ClawHub friction & static trade-off (`v0.16.2` -> `v0.17.0`)

- **ClawHub (945 versions / 212 unique skills):** hard blocks dropped **374 -> 160** versions (**-57.2%**) and **79 -> 37** unique skills (**-53.2%**); clean allows rose **384 -> 622** versions (**+238**) and **87 -> 139** unique (**41.0% -> 65.6%**), with **0** regressions.
- **Speed (212 unique ClawHub skills):** total scan time dropped **40.6 s -> 27.1 s** (**1.50x faster**; 2 MiB skills such as `byungkyu/api-gateway` dropped **4.46 s -> 1.98 s**; `extractCapabilities` is **8.4x faster**).
- **MalSkillBench static gate (tune half, vs `v0.16.2`):** benign hard blocks dropped **152 -> 124** (-28, **0** benign regressions) and benign clean allows rose **1,295 -> 1,331** (+36). Malware hard blocks rose **1,184 -> 1,215** (+31, including +34 CI hard blocks) while total stopped stayed at **1,435 / 2,023** (9 newly caught CI attacks offsetting 9 skills, mostly prompt injection, that moved `warn -> allow` because they had been stopped only by coverage false positives such as missing `./references/*.md`; `--semantic` is the check for prompt injection).

## Earlier corpora (`0.9.0` to `0.15.0`)

For the install gate across earlier releases, see [benchmarks/gate-eval/README.md](../benchmarks/gate-eval/README.md). Its one held-out run, on `0.13.2` and the MalSkillBench test half, blocked 45.7% of malicious skills and 9.5% of benign ones (12.5% of the prompt-injection group). `0.14.0` and `0.15.0` were measured on the tune half only (`0.14.0` stopped 63.1% of malicious skills and 12.0% of benign ones; `0.15.0` changed no malicious decisions and moved four benign skills from block to allow).

`benchmarks/` also holds two earlier corpora assembled for `0.11.x` and `eval.py`, a stdlib-only harness reporting precision, recall, F1, MCC, ROC-AUC, and bootstrap confidence intervals. Hard negatives are legitimate skills that trip credential or exec rules (an SSH helper reading `~/.ssh/config`, a base64 utility, a `curl | bash` installer); they carry label 0 so they count against the false-positive rate.

Static-only baseline at threshold 26 from the committed `0.11.1` results:

```text
101 in-text corpus   P 0.909  R 0.980  F1 0.943  FPR 0.100
500 real-world       P 0.774  R 0.960  F1 0.857  FPR 0.031  ROC-AUC 0.977
397 live clean       FPR 0.023  (false positives only, no positive class available)
95% CI (real)        F1 [0.780, 0.921]   MCC [0.769, 0.912]
```

Regenerate and re-run:

```bash
npx tsx benchmarks/scan-all.mjs
python3 benchmarks/eval.py benchmarks/results.csv --threshold 26

npx tsx benchmarks/scan-corpus500.mjs
python3 benchmarks/eval.py benchmarks/corpus500/results.csv --threshold 26
```

### Historical progression (`0.9.0` to `0.11.1`)

The 101-skill corpus is hand-authored with payloads inline in `SKILL.md` (best read as a regression suite). The 500-skill corpus is 50 ClawHavoc skills, 400 clean ClawHub skills, and 50 hard negatives, where payloads usually sit in a referenced script.

| ClawVet | Corpus | P | R | F1 | FPR |
|---|---|---|---|---|---|
| 0.9.0 (linear scoring) | 101 in-text | 0.820 | 0.980 | 0.893 | 0.220 |
| 0.11.0 | 101 in-text | 0.909 | 0.980 | 0.943 | 0.100 |
| 0.10.0 | 500 real-world | 0.000 | 0.000 | 0.000 | 0.111 |
| 0.11.0 | 500 real-world | 0.727 | 0.960 | 0.828 | 0.040 |
| 0.11.1 | 500 real-world | 0.774 | 0.960 | 0.857 | 0.031 |

Through `0.10.0`, every ClawHavoc skill in the 500-skill corpus scored 14-24 (just below the warn threshold of 26) because both halves of the install-me envelope were medium severity. `0.11.0` closed that by promoting the co-occurring envelope pair (48 of 50 malicious, 0 of 450 benign) and promoting credential-read plus outbound-send co-occurrence, while removing metadata hygiene from the numeric score.

### Cold check on 397 live clean ClawHub skills (`0.11.x`)

397 skills labelled clean by ClawHub (from `tomhu/ClawSkills`) were scanned cold:

```text
397 live clean skills   flagged at >=26: 9   FPR 0.023   median score 0   p90 11
```

Eight of the nine genuinely ran `python3 -c`, `node -e`, `curl | sh`, or read `~/.openclaw/`; the ninth was a security-auditing skill naming `.ssh`, `.aws`, and `.env`. Note that the `0.11.0 -> 0.11.1` F1 jump landed entirely on the hard-negatives tier (0/400 on clean, 9/397 unchanged on live clean), and 49 of the 50 malicious entries in the 500-skill corpus share the ClawHavoc campaign shape. Two malicious skills remained statically missed (for example, a pure-English browser-automation skill describing fabricated sign-ups and bot-check evasion), which is what `--semantic` addresses.

## Prior work

Related systems and measurement studies (numbers are not reproduced head-to-head since each uses its own corpus and labelling):

- SkillSieve, a hierarchical triage framework combining static checks with LLM analysis: [arXiv:2604.06550](https://arxiv.org/abs/2604.06550) (includes a measurement of an earlier ClawVet release).
- Empirical study of malicious agent skills in the wild: [arXiv:2602.06547](https://arxiv.org/abs/2602.06547).
- SkillFortify, formal analysis and supply chain security for agent skills: [arXiv:2603.00195](https://arxiv.org/abs/2603.00195).
- ClawHub security signals across multiple scanners: [arXiv:2606.01494](https://arxiv.org/abs/2606.01494) and [OpenClaw/clawhub-security-signals](https://huggingface.co/datasets/OpenClaw/clawhub-security-signals) (note: this dataset strips newlines from `skill_md_content`, which breaks frontmatter and code-fence parsing for structure-aware scanners).
