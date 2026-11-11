#!/usr/bin/env python3
"""Per-skill verdicts of MalSkillBench's published baselines.

The benchmark ships per-skill tool outputs (Experiment/Results) and three
scripts that turn them into binary verdicts and aggregate metrics. Those
scripts are loaded unchanged, so every tool is judged by its authors' own
parser, overrides included. Two of their functions are wrapped to record which
skill each verdict belongs to, instead of only counting it.

Usage: python3 -I baselines.py <MalSkillBench checkout> > msb-baselines.tsv
Output: tool, tier, skill name, verdict (malicious / benign / unknown).
"""

import contextlib
import importlib.util
import sys
from pathlib import Path

root = Path(sys.argv[1]).resolve()
SCRIPTS = {
    "skillsecurity": root / "Experiment/RQ3/baseline_accuracy.py",
    "supplychain": root / "Experiment/RQ4/supplychain_baseline_accuracy.py",
    "promptinjection": root / "Experiment/RQ4/promptinjection_baseline_accuracy.py",
}

print("tool\ttier\tname\tverdict")
for group, path in SCRIPTS.items():
    spec = importlib.util.spec_from_file_location(f"msb_{group}", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # their dataclasses look themselves up here
    spec.loader.exec_module(module)
    module.DATASET_ROOT = root / "Dataset" / "Skills"
    module.RESULTS_ROOT = root / "Experiment" / "Results" / group

    # Every evaluator loops over iter_dataset_skills() and calls
    # update_confusion() at most once per skill, so the skill most recently
    # yielded is the one a verdict belongs to. Skills with no call are unknown.
    current = {}
    verdicts = {}
    original_iter, original_update = module.iter_dataset_skills, module.update_confusion

    def iter_skills():
        for label, name, expected in original_iter():
            current["skill"] = (label, name)
            yield label, name, expected

    def update(metrics, predicted, expected):
        verdicts.setdefault(metrics.tool, {})[current["skill"]] = predicted
        original_update(metrics, predicted, expected)

    module.iter_dataset_skills, module.update_confusion = iter_skills, update
    # main() runs every evaluator and prints the authors' metrics table. Send
    # it to stderr, where it serves as a check on the per-skill counts.
    with contextlib.redirect_stdout(sys.stderr):
        module.main()

    for tool, seen in verdicts.items():
        for label, name, _ in original_iter():
            v = seen.get((label, name))
            verdict = "unknown" if v is None else "malicious" if v else "benign"
            print(f"{tool}\t{'malware' if label == 'malware' else 'benign'}\t{name}\t{verdict}")
