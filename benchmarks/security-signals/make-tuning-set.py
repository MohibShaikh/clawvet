# The SkillTrustBench cases that may be used for tuning: the full v1.0 set minus
# the 556-case leaderboard subset, and minus any case whose skill name appears in
# that subset (injected variants share a base skill). Hard links, no copies.
# Usage: python3 -I make-tuning-set.py <cache dir>   (expects full/, extract/, dl/metadata/)
import json, os, re, shutil, sys, collections
S = sys.argv[1]
full = f"{S}/full/benchmark_full_v1.0"; sub = f"{S}/extract/skilltrustbench_556_v1_1/cases"
def name(d):
    try: t = open(os.path.join(d, "SKILL.md"), errors="replace").read(4000)
    except OSError: return None
    m = re.search(r"^name:\s*['\"]?([^'\"\n]+)", t, re.M); return m.group(1).strip().lower() if m else None
sub_ids = set(os.listdir(sub)); sub_names = {name(os.path.join(sub, i)) for i in sub_ids} - {None}
meta = {m["id"]: m for m in map(json.loads, open(f"{S}/dl/metadata/case_metadata.jsonl"))}
keep, why = [], collections.Counter()
for i in sorted(os.listdir(full)):
    if i in sub_ids: why["leaderboard id"] += 1; continue
    if name(os.path.join(full, i)) in sub_names: why["leaderboard skill name"] += 1; continue
    if i not in meta: why["no label"] += 1; continue
    keep.append(i)
tune = f"{S}/tune"; shutil.rmtree(tune, ignore_errors=True); os.makedirs(tune)
for i in keep: shutil.copytree(os.path.join(full, i), os.path.join(tune, i), copy_function=os.link, symlinks=True)
json.dump({i: meta[i]["judgment"] for i in keep}, open(f"{S}/tune-labels.json", "w"))
print("excluded:", dict(why), "| tuning cases:", len(keep))
