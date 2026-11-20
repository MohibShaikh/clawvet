"""Summarize measure.mts output: how often a diff asks, per set, label and half.

    python3 -I benchmarks/capability-diff/summarize.py out.jsonl [half=tune] [--asks]
"""
import collections
import json
import sys

path = sys.argv[1]
want = sys.argv[2] if len(sys.argv) > 2 and not sys.argv[2].startswith("--") else "tune"
show = "--asks" in sys.argv
rows = [json.loads(line) for line in open(path) if line.strip()]
rows = [r for r in rows if want == "all" or r["half"] == want]

groups = collections.defaultdict(list)
for r in rows:
    groups[(r["set"], r["label"] if r["set"] == "malicious" else "updates")].append(r)

print(f"half={want}")
for (s, label), rs in sorted(groups.items()):
    ok = [r for r in rs if "error" not in r]
    asked = [r for r in ok if r["asks"]]
    pct = 100 * len(asked) / len(ok) if ok else 0
    print(f"{s:9} {label:8} pairs={len(rs):4} scanned={len(ok):4} asked={len(asked):4} ({pct:5.1f}%)")
    kinds = collections.Counter(a.split(":", 1)[0] for r in asked for a in set(x.split(":", 1)[0] + ":" for x in r["asks"]))
    print("          by kind:", dict(kinds))

if show:
    for r in rows:
        if r.get("asks") and r["set"] == "benign":
            print(r["family"], r["label"], r["asks"])
