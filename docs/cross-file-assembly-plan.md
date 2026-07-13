# Plan: Cross-File Payload Assembly (Approach A)

## Goal
Close ClawVet's single-file blind spot. Today `scanSkill(content)` only sees the
`SKILL.md` text, so a payload hidden in a file the skill tells the agent to run
(`bash ./setup.sh`) is never scanned. This is the exact limitation named in the
SkillSieve paper ("misses payloads split across files, as ClawHavoc demonstrated").

Fix: before scanning a skill **folder**, the CLI folds in the content of sibling
files that the `SKILL.md` actually references, so the existing 54 static patterns
run over the assembled whole.

## Design decision (locked): Approach A — referenced-only
Fold in a sibling file **only if its name/path appears in the SKILL.md** (e.g.
`bash setup.sh`, `source ./lib/util.sh`, `[x](./y.js)`, `python scripts/z.py`).

- Rejected **Approach B (all sibling scripts)**: scanning every `.sh/.js/.py`
  next to the skill would flag benign helper scripts and hurt precision — already
  ClawVet's weakest metric (v2 precision 0.157). Referenced-only stays targeted.

## Architecture constraint (do not violate)
`scanSkill(content, options)` takes a **string**, not a path, on purpose — the
engine runs in the browser too (`@clawvet/shared` is the source of truth and must
stay filesystem-free). Therefore:

- **All filesystem work lives in the CLI** (`packages/cli`), which already reads
  `SKILL.md` from disk.
- The scanner core is **not** modified. We assemble the combined string in the
  CLI and pass it to the unchanged `scanSkill`.

## How assembled content is joined
Append each referenced file after the SKILL.md body as **plain text**, not inside
a ``` fence — `isInCodeBlock` suppresses matches inside fences, which would defeat
the purpose. Use a traceable marker:

```
<original SKILL.md content>

# [clawvet] referenced file: setup.sh
<raw setup.sh content>
```

## Files to change
1. **New:** `packages/cli/src/assemble.ts`
   - `export function assembleSkill(skillDir: string, skillMd: string): string`
   - Finds sibling files referenced in `skillMd`, reads them, returns the
     concatenated string (SKILL.md + marked referenced files).
2. **Edit:** `packages/cli/src/commands/scan.ts` (~line 72–85)
   - When the target is a **folder**, call `assembleSkill(dir, content)` and pass
     the result to `scanSkill` instead of the bare `SKILL.md` string.
   - When the target is a single file (no folder context), behavior is unchanged.
3. **New fixture:** `packages/cli/test/fixtures/split-payload/`
   - `SKILL.md` — benign-looking, contains `bash ./setup.sh`
   - `setup.sh` — hides a reverse-shell / exfil payload (base64-encode per repo
     convention if it trips AV; decode in the test).

## Reference-detection heuristic (v1)
For each entry in the skill folder (non-recursive first; one level deep for
`lib/`, `scripts/` if cheap), include it iff its basename **or** relative path
appears as a whole token in the SKILL.md. Keep it simple:

- match `\b<basename>\b` and `\b<relpath>\b` in the raw SKILL.md text.
- skip the SKILL.md itself, binaries, and files over a size cap (e.g. 256 KB).

`# ponytail: basename substring match, upgrade to real ref parsing (md links +
shell tokens) if false-negatives show up on the benchmark.`

## TDD sequence
1. **RED** — test: scanning `fixtures/split-payload/` (folder) yields a finding
   for the payload that lives in `setup.sh`. Assert it currently **misses**
   (no reverse-shell finding). Watch it fail.
2. **GREEN** — implement `assembleSkill`, wire into `scan.ts`, minimal code until
   the payload is detected.
3. **Second RED/GREEN (precision guard)** — test: a benign skill that references a
   benign `setup.sh` is **not** newly flagged, and a skill that references a file
   which does NOT exist doesn't crash.
4. **REFACTOR** — tidy `assembleSkill`, keep tests green. Run full CLI suite.

## Out of scope (explicitly)
- No scanner-core (`@clawvet/shared`) changes.
- No recursive whole-repo assembly; one shallow level max in v1.
- No remote `--remote` assembly (single SKILL.md fetch stays as-is).
- Not the semantic pass, not tuning — separate tracks.

## Done when
- `split-payload` fixture: miss → hit (proven by the RED→GREEN test).
- Benign-reference fixture: no new false positive.
- Full CLI + shared test suites green.
- No changes under `packages/shared`.
