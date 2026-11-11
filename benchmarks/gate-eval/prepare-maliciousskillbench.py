#!/usr/bin/env python3
"""Writes the frozen Source-Disjoint test split of MaliciousSkillBench
(ProtectSkills/MaliciousSkillBench on Hugging Face, arXiv 2608.19901) as one
SKILL.md folder per identity, for run-gate.sh.

Uses `skill_text`, the exact frozen text the benchmark evaluates on. The five
records with only a sanitized `public_skill_text` are skipped, as the
benchmark asks. Splits come from splits/source_disjoint.csv and are not
regenerated. Nothing is executed.

Usage: python3 prepare-maliciousskillbench.py <dataset dir> <out dir>
Writes <out>/<malicious|benign>/<benchmark_id>/SKILL.md, <out>/dirs.txt, <out>/manifest.tsv.
"""

import sys
from pathlib import Path

import pandas as pd

src, out = Path(sys.argv[1]), Path(sys.argv[2])
primary = pd.read_parquet(src / "primary.parquet")
split = pd.read_csv(src / "splits" / "source_disjoint.csv")
test = primary.merge(split[split.split == "test"][["benchmark_id"]], on="benchmark_id")

dirs, manifest, skipped = [], ["tier\tid\tlabel\tsource_id\tfamily\tattack_categories"], 0
for row in test.itertuples():
    if row.skill_text is None:
        skipped += 1
        continue
    tier = "malicious" if str(row.label) == "1" else "benign"  # stored as the string "1"
    skill = out / tier / row.benchmark_id
    skill.mkdir(parents=True, exist_ok=True)
    (skill / "SKILL.md").write_text(row.skill_text, encoding="utf-8")
    dirs.append(str(skill))
    categories = "|".join(row.attack_categories) if row.attack_categories is not None else ""
    manifest.append(f"{tier}\t{row.benchmark_id}\t{row.label}\t{row.source_id}\t{row.structural_family_id}\t{categories}")

(out / "dirs.txt").write_text("\n".join(dirs) + "\n")
(out / "manifest.tsv").write_text("\n".join(manifest) + "\n")
print(f"{len(dirs)} skills -> {out}; skipped {skipped} without exact text")
