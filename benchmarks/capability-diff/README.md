# Capability diff benchmark

Measures how often an update's capability diff asks the user, on real benign
updates and on benign-to-malicious "rug-pull" updates.

- Benign: consecutive versions of the most-downloaded ClawHub skills, fetched
  by `fetch-clawhub.mts` into `~/.cache/clawvet-bench/clawhub`.
- Malicious: MalSkillBench generated attacks paired with the benign skill each
  was built from (`benign/<seed>` to `malware/<seed>[__<VECTOR>_B<n>]`).

Pairs split into tune and test halves by a hash of the skill family. Tune only
on the tune half. Read the test half once per change, after tuning, and report
it as it comes out.

## Running

Fetching only writes files, so it runs on the host. Scanning untrusted skills
runs only in the no-network sandbox:

```bash
npx tsx benchmarks/capability-diff/fetch-clawhub.mts 400 6
SKILLS=~/.cache/clawvet-bench/clawhub MSB=<MalSkillBench>/Dataset/Skills \
OUT=$PWD/benchmarks/capability-diff/results \
  benchmarks/capability-diff/sandbox.sh npx tsx benchmarks/capability-diff/measure.mts /skills /msb /out/run.jsonl
python3 -I benchmarks/capability-diff/summarize.py benchmarks/capability-diff/results/run.jsonl tune
```

`results/` is gitignored: its rows are derived from MalSkillBench, which is
licensed for research only. Never commit them or the downloaded skills.

Each row keeps every finding and capability of both versions, so another ask
rule can be tried offline without rescanning. A scan that throws is recorded
with its message, never counted as an unreadable skill.

## Measured, 0.17.0 (`feat/capability-diff`)

| | Tune | Test |
|---|---|---|
| Benign updates that ask, quiet default | 3.6% | 5.3% |
| Benign updates that ask, `--strict` | 12.0% | 13.1% |
| Code injection stopped, gate alone | 81.8% | 83.9% |
| Code injection stopped, gate plus diff | 90.9% | 95.2% |
| Mixed stopped, gate alone / plus diff | 96.4% / 100% | 95.2% / 95.2% |
| Prompt injection stopped, gate alone / plus diff | 50.0% / 55.0% | 39.4% / 39.4% |

748 benign pairs from 215 skills (one version had no content), 219 malicious
pairs. The diff adds little against prompt injection: those attacks change
instructions, not what the code can do.
