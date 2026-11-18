# Held-out SkillTrustBench v1.1 556 subset: exact three-class metrics, as the leaderboard reports them.
import json, sys, collections
truth = {r["id"]: r["judgment"] for r in map(json.loads, open(sys.argv[1]))}
rows = {r["id"]: r for r in map(json.loads, open(sys.argv[2]))}
def score(name, pred):
    cls = ["normal", "suspicious", "malicious"]; f1 = {}
    for c in cls:
        tp = sum(pred[i] == c and t == c for i, t in truth.items()); fp = sum(pred[i] == c and t != c for i, t in truth.items()); fn = sum(pred[i] != c and t == c for i, t in truth.items())
        p = tp / (tp + fp) if tp + fp else 0; r = tp / (tp + fn) if tp + fn else 0; f1[c] = 2 * p * r / (p + r) if p + r else 0
    acc = sum(pred[i] == t for i, t in truth.items()) / len(truth)
    mr = sum(pred[i] == "malicious" for i, t in truth.items() if t == "malicious") / sum(t == "malicious" for t in truth.values())
    nf = sum(pred[i] != "normal" for i, t in truth.items() if t == "normal") / sum(t == "normal" for t in truth.values())
    print(f"{name:28s} acc {acc:.4f}  macroF1 {sum(f1.values())/3:.4f}  normalF1 {f1['normal']:.4f}  suspF1 {f1['suspicious']:.4f}  malF1 {f1['malicious']:.4f}  malRecall {mr:.4f}  normal flagged {nf:.3f}")
am = {"allow": "normal", "warn": "suspicious", "block": "malicious"}
vm = {"benign": "normal", "suspicious": "suspicious", "malicious": "malicious"}
score("clawvet static (this tree)", {i: am[rows[i]["staticAction"]] for i in truth})
score("clawvet + judge v2 verdict", {i: vm[rows[i]["verdict"]] for i in truth})
score("clawvet + judge v2 gate", {i: am[rows[i]["action"]] for i in truth})
print("cases:", len(truth), "| judge errors:", sum(1 for r in rows.values() if r.get("error")), "| why:", collections.Counter(r["why"].split(":")[0].split(";")[0] for r in rows.values()).most_common(5))
