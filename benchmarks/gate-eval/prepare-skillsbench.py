#!/usr/bin/env python3
"""Writes SkillsBench-1650 (zenith6888/SkillsBench-1650 on Hugging Face) as
skill folders for run-gate.sh, plus a manifest of labels.

The dataset stores SKILL.md in `content` and every companion script
concatenated in `script_content`, each introduced by a `--- <name> ---` line.
A script goes where SKILL.md refers to it (`scripts/<name>` if SKILL.md
mentions that path), otherwise beside SKILL.md. Nothing is executed.

Usage: python3 prepare-skillsbench.py <dataset dir> <out dir>
Writes <out>/<tier>/<id>/..., <out>/dirs.txt and <out>/manifest.tsv.
"""

import json
import re
import sys
from pathlib import Path

import pandas as pd

src, out = Path(sys.argv[1]), Path(sys.argv[2])
dirs, manifest = [], ["tier\tid\tlabel\tattack_type\tdifficulty\tscripts_placed"]
for tier in ("benign", "malicious"):
    frame = pd.read_parquet(src / f"{tier}.parquet")
    for index, row in frame.iterrows():
        skill_id = f"{index:04d}-{row.content_hash[:12]}"
        skill = out / tier / skill_id
        skill.mkdir(parents=True, exist_ok=True)
        (skill / "SKILL.md").write_text(row.content, encoding="utf-8")
        placed = 0
        if row.has_scripts and row.script_content:
            names = json.loads(row.script_files)
            parts = re.split(r"^--- (.+?) ---$\n?", row.script_content, flags=re.M)
            for name, body in zip(parts[1::2], parts[2::2]):
                if name not in names or "/" in name or name.startswith("."):
                    continue
                # Prefer the path SKILL.md uses for the script, if it names one.
                match = re.search(r"([\w.-]+/)*" + re.escape(name), row.content)
                rel = match.group(0) if match and ".." not in match.group(0) else name
                target = skill / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(body.rstrip("\n") + "\n", encoding="utf-8")
                placed += 1
        dirs.append(str(skill))
        manifest.append(f"{tier}\t{skill_id}\t{row.label}\t{row.attack_type}\t{row.difficulty}\t{placed}")

(out / "dirs.txt").write_text("\n".join(dirs) + "\n")
(out / "manifest.tsv").write_text("\n".join(manifest) + "\n")
print(f"{len(dirs)} skills -> {out}")
