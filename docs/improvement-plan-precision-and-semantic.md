# Plan: Improvement Tracks 5 (Precision / FP Hunt) & 6 (Semantic Pass Measurement)

Both use `benchmarks/eval.py` as the measuring instrument. Track 5 is doable now
(no email needed). Track 6 is partially blocked on a malicious-content corpus.

---

## Track 5 — False-Positive Hunt (attack precision 0.157)

**Goal:** find which of the 54 static patterns misfire on real benign skills, fix
the top offenders, and prove the false-positive rate dropped. Precision is
ClawVet's weakest metric, and every flag on a benign skill is a pure false
positive — so a benign-only corpus is exactly the right tool.

**Data:** `MaliciousAgentSkillsBench/data/skills_dataset.csv` — 94,093 `safe`
rows carry real GitHub archive URLs. (Malicious rows are redacted; irrelevant
here — we only need benign.)

**Steps:**
1. **Sample** ~500 `safe` rows (stratify across `source`/`repo` so it's not one
   author). Keep the list reproducible (fixed seed).
2. **Fetch + extract** each archive URL → pull its `SKILL.md`. Cache locally;
   skip dead links, log the fetch-success rate.
   - `# ponytail: naive fetch+unzip, add ret/backoff only if link-rot is bad.`
3. **Scan** each with `clawvet scan <dir> --format json`, collect `findings[]`.
   Every finding here is a false positive (all inputs are benign).
4. **Aggregate** FP counts grouped by finding `title` / pattern id → ranked
   table. Expect a few patterns to dominate (e.g. `curl | bash` shown as docs,
   base64 in examples).
5. **Fix top offenders** — one at a time, TDD:
   - tighten `isInCodeBlock` / `isInHeading` suppression, or
   - lower the pattern's confidence weight, or
   - narrow the regex.
   Each fix: add a benign fixture that currently false-positives, make it pass.
6. **Re-scan the same 500**, compare FP counts before/after. Report FPR drop.

**Measurement:** for a benign-only set, feed `eval.py` all `label=0` rows and read
the flag rate = FPR at the chosen threshold. (Precision/MCC need positives, so
those wait for Track 6's corpus — FPR alone is the right metric here.)

**Deliverables:**
- Ranked FP-by-pattern table (the error-analysis artifact).
- N pattern fixes, each with a regression fixture.
- Before/after FPR on the 500-skill benign sample.

**Caveats:**
- Skills are from `skills.rest` / `skillsmp.com`, **not ClawHub** — format may
  differ; may need a tiny `SKILL.md` locator (some repos nest it).
- Network-dependent; some archive URLs will be dead. Report coverage.
- Fixes tuned on this benign set must not be validated *only* here — re-check
  recall on fixtures so precision gains don't silently cost detections.

---

## Track 6 — Turn On Semantic Pass & Measure Its Lift

**Goal:** quantify what the LLM pass (pass 6) adds over static-only — the
"reads prose" gap the paper names — as an honest ablation row.

**Prereq:** a user-supplied LLM key (Anthropic / OpenAI / Zhipu / Ollama — already
BYO; see `.env.example`). No key ships with ClawVet.

**Steps:**
1. Assemble a labeled set with **both** classes:
   - malicious *content*: the repo's own fixtures + `benchmarks/malicious`
     (base64, decoded) + any hand-built prose-injection cases static misses.
   - benign: the Track-5 sample.
2. Produce two score CSVs over the same set:
   - `static.csv` — semantic **off**.
   - `semantic.csv` — semantic **on** (via the injected `semanticAnalyzer`).
3. `python3 eval.py semantic.csv --compare static.csv` →
   - MCC / F-β / PR-AUC each with bootstrap CIs,
   - **McNemar**: does semantic fix more than it breaks, significantly?
4. Record **cost + latency** per skill (the paper reports $0.006/skill) so the
   lift is judged against its price.

**Deliverables:**
- Ablation table: static-only vs static+semantic (MCC, F-β, PR-AUC, CIs).
- McNemar verdict on the difference.
- Cost/latency-per-skill note.
- A prose-injection fixture that static misses and semantic catches (the
  qualitative proof).

**Caveats / partial block:**
- **Recall measurement needs malicious content.** Until the SkillSieve set (or
  another content-bearing malicious corpus) lands, recall is measured only on
  fixtures — a demonstration, not a benchmark-grade number. What *is* fully
  measurable now: semantic doesn't hurt precision on the 500 benign skills, and
  it catches specific prose-injection fixtures static-only misses.
- Non-determinism: LLM outputs vary. Pin temperature=0, run each skill N times,
  report agreement, and keep the semantic-analysis prompt fixed across runs.

---

## Sequencing
1. Track 5 first — bigger, unblocked, attacks the weakest metric, needs no key.
2. Track 6 after — reuses Track 5's benign set as the precision half; recall half
   grows as malicious content becomes available.
3. Both feed the same eventual results table (and any write-up).
