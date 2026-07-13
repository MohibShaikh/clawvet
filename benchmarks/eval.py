#!/usr/bin/env python3
"""
Scanner evaluation harness — stdlib only, no numpy/sklearn.

Turns "I think it's better" into "MCC +0.06, 95% CI [0.01, 0.11], McNemar p=0.02".

Input: a CSV with header `id,label,score` where
  label = 1 (malicious) / 0 (benign), score = ClawVet risk score 0-100.

Usage:
  python eval.py results.csv                       # full report at default threshold
  python eval.py results.csv --threshold 26        # pick the malicious cutoff
  python eval.py new.csv --compare old.csv          # McNemar: did new beat old?

Generate a results CSV from the CLI, e.g.:
  clawvet scan path/to/skill --format json | jq '.riskScore'   # -> score per skill
  # label from your ground truth (benchmarks/malicious -> 1, benchmarks/benign -> 0)
"""
import csv
import math
import random
import sys
from argparse import ArgumentParser

random.seed(0)  # reproducible bootstrap


def load(path):
    rows = []
    with open(path, newline="") as f:
        for r in csv.DictReader(f):
            rows.append((r["id"], int(r["label"]), float(r["score"])))
    if not rows:
        sys.exit(f"{path}: no rows")
    return rows


# ---- confusion + point metrics -------------------------------------------------

def confusion(labels, preds):
    tp = fp = tn = fn = 0
    for y, p in zip(labels, preds):
        if p and y:
            tp += 1
        elif p and not y:
            fp += 1
        elif not p and y:
            fn += 1
        else:
            tn += 1
    return tp, fp, tn, fn


def _safe(n, d):
    return n / d if d else 0.0


def metrics_at(labels, scores, threshold, beta=1.0):
    preds = [1 if s >= threshold else 0 for s in scores]
    tp, fp, tn, fn = confusion(labels, preds)
    prec = _safe(tp, tp + fp)
    rec = _safe(tp, tp + fn)
    fpr = _safe(fp, fp + tn)
    b2 = beta * beta
    fbeta = _safe((1 + b2) * prec * rec, b2 * prec + rec)
    acc = _safe(tp + tn, tp + fp + tn + fn)
    bal_acc = (rec + _safe(tn, tn + fp)) / 2
    # Matthews correlation coefficient — the honest single number under imbalance.
    denom = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    mcc = _safe(tp * tn - fp * fn, denom)
    return {
        "TP": tp, "FP": fp, "TN": tn, "FN": fn,
        "precision": prec, "recall": rec, "FPR": fpr,
        f"F{beta:g}": fbeta, "accuracy": acc,
        "balanced_acc": bal_acc, "MCC": mcc,
    }


# ---- threshold-independent -----------------------------------------------------

def roc_auc(labels, scores):
    """AUC = P(score(pos) > score(neg)), ties count 0.5 (Mann-Whitney)."""
    pos = [s for y, s in zip(labels, scores) if y]
    neg = [s for y, s in zip(labels, scores) if not y]
    if not pos or not neg:
        return float("nan")
    wins = 0.0
    for p in pos:
        for n in neg:
            wins += 1.0 if p > n else 0.5 if p == n else 0.0
    return wins / (len(pos) * len(neg))


def average_precision(labels, scores):
    """Area under the precision-recall curve (AP). Better than ROC under imbalance."""
    order = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)
    total_pos = sum(labels)
    if total_pos == 0:
        return float("nan")
    tp = fp = 0
    ap = 0.0
    prev_recall = 0.0
    for i in order:
        if labels[i]:
            tp += 1
        else:
            fp += 1
        recall = tp / total_pos
        precision = tp / (tp + fp)
        ap += (recall - prev_recall) * precision
        prev_recall = recall
    return ap


def brier(labels, scores):
    """Calibration: mean squared error of score/100 as a probability."""
    return sum((s / 100.0 - y) ** 2 for y, s in zip(labels, scores)) / len(labels)


# ---- uncertainty ---------------------------------------------------------------

def bootstrap_ci(labels, scores, fn, n=10000, alpha=0.05):
    """Percentile bootstrap CI for any metric fn(labels, scores)."""
    idx = range(len(labels))
    vals = []
    for _ in range(n):
        sample = [random.choice(idx) for _ in idx]
        bl = [labels[i] for i in sample]
        bs = [scores[i] for i in sample]
        v = fn(bl, bs)
        if v == v:  # skip NaN (degenerate resample)
            vals.append(v)
    vals.sort()
    lo = vals[int(alpha / 2 * len(vals))]
    hi = vals[int((1 - alpha / 2) * len(vals)) - 1]
    return lo, hi


def _binom_tail_p(b, c):
    """Exact two-sided McNemar p-value via the binomial(min(b,c); b+c, 0.5) tail."""
    nd = b + c
    if nd == 0:
        return 1.0
    k = min(b, c)
    tail = sum(math.comb(nd, i) for i in range(0, k + 1)) / (2 ** nd)
    return min(1.0, 2 * tail)


def mcnemar(labels, preds_a, preds_b):
    """Paired comparison of two classifiers on the SAME samples.
    b = A wrong & B right, c = A right & B wrong. Only discordant pairs matter."""
    b = c = 0
    for y, a, bb in zip(labels, preds_a, preds_b):
        a_ok, b_ok = (a == y), (bb == y)
        if not a_ok and b_ok:
            b += 1
        elif a_ok and not b_ok:
            c += 1
    return b, c, _binom_tail_p(b, c)


# ---- report --------------------------------------------------------------------

def report(rows, threshold, beta):
    labels = [r[1] for r in rows]
    scores = [r[2] for r in rows]
    m = metrics_at(labels, scores, threshold, beta)
    n_pos, n_neg = sum(labels), len(labels) - sum(labels)

    print(f"\n=== {len(rows)} skills  ({n_pos} malicious / {n_neg} benign)  "
          f"threshold={threshold} ===")
    print(f"  confusion:  TP={m['TP']}  FP={m['FP']}  TN={m['TN']}  FN={m['FN']}")
    for key in ("precision", "recall", "FPR", f"F{beta:g}",
                "accuracy", "balanced_acc", "MCC"):
        print(f"  {key:14s} {m[key]:.3f}")

    print("\n  threshold-independent:")
    print(f"  {'ROC-AUC':14s} {roc_auc(labels, scores):.3f}")
    print(f"  {'PR-AUC (AP)':14s} {average_precision(labels, scores):.3f}")
    print(f"  {'Brier':14s} {brier(labels, scores):.3f}  (lower = better calibrated)")

    print("\n  95% bootstrap CIs (10k resamples):")
    for name, fn in (
        (f"F{beta:g}", lambda l, s: metrics_at(l, s, threshold, beta)[f"F{beta:g}"]),
        ("MCC", lambda l, s: metrics_at(l, s, threshold, beta)["MCC"]),
        ("PR-AUC", average_precision),
    ):
        lo, hi = bootstrap_ci(labels, scores, fn)
        print(f"  {name:14s} [{lo:.3f}, {hi:.3f}]")


def compare(new_rows, old_rows, threshold):
    key = lambda rows: {r[0]: r for r in rows}
    a, b = key(old_rows), key(new_rows)
    shared = sorted(set(a) & set(b))
    if not shared:
        sys.exit("--compare: the two files share no ids")
    labels = [a[i][1] for i in shared]
    old_pred = [1 if a[i][2] >= threshold else 0 for i in shared]
    new_pred = [1 if b[i][2] >= threshold else 0 for i in shared]
    bb, cc, p = mcnemar(labels, old_pred, new_pred)
    print(f"\n=== McNemar (old vs new, {len(shared)} shared skills, "
          f"threshold={threshold}) ===")
    print(f"  new fixes {bb} old errors, breaks {cc} — p={p:.4f}"
          + ("  (significant)" if p < 0.05 else "  (not significant)"))


def main():
    ap = ArgumentParser()
    ap.add_argument("results")
    ap.add_argument("--compare", metavar="OLD.csv")
    ap.add_argument("--threshold", type=float, default=26.0,
                    help="risk score >= this is 'malicious' (default 26 = grade C)")
    ap.add_argument("--beta", type=float, default=1.0,
                    help="F-beta weighting (0.5 favors precision, 2 favors recall)")
    a = ap.parse_args()
    rows = load(a.results)
    report(rows, a.threshold, a.beta)
    if a.compare:
        compare(rows, load(a.compare), a.threshold)


# ---- self-check: verify the math against ClawVet's published matrix ------------

def _selfcheck():
    # Reconstructed from the SkillSieve paper: P=0.329, R=0.584, on 89/311.
    # -> TP=52, FP=106, TN=205, FN=37 -> MCC ~ 0.21, F1 ~ 0.421.
    labels = [1] * 89 + [0] * 311
    # scores: put 52 malicious above threshold, 37 below; 106 benign above, 205 below.
    scores = ([100] * 52 + [0] * 37) + ([100] * 106 + [0] * 205)
    m = metrics_at(labels, scores, threshold=50)
    assert (m["TP"], m["FP"], m["TN"], m["FN"]) == (52, 106, 205, 37)
    assert abs(m["precision"] - 0.329) < 0.01, m["precision"]
    assert abs(m["recall"] - 0.584) < 0.01, m["recall"]
    assert abs(m["F1"] - 0.421) < 0.01, m["F1"]
    assert abs(m["MCC"] - 0.207) < 0.01, m["MCC"]
    assert abs(m["accuracy"] - 0.642) < 0.01, m["accuracy"]
    # perfect classifier -> MCC 1; McNemar on identical preds -> p=1
    perfect = metrics_at([1, 0, 1, 0], [9, 1, 9, 1], threshold=5)
    assert abs(perfect["MCC"] - 1.0) < 1e-9
    assert _binom_tail_p(0, 0) == 1.0
    assert abs(roc_auc([1, 1, 0, 0], [9, 8, 2, 1]) - 1.0) < 1e-9
    print("selfcheck OK — metrics reproduce ClawVet's published 0.421 F1 / 0.21 MCC")


if __name__ == "__main__":
    if len(sys.argv) == 1:
        _selfcheck()
    else:
        main()
