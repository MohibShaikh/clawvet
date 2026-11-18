# Write each Security Signals row as a skill folder, the way ClawScan's
# materializeOpenClawBenchmarkRow does: SKILL.md as stored, bundle files beside it.
# Only writes files; nothing from a skill is executed.
import json, os, sys
src, out = sys.argv[1], sys.argv[2]
def safe(p):
    p = os.path.normpath(p.replace("\\", "/"))
    if p in (".", "..") or os.path.isabs(p) or p.startswith("../"):
        return None
    return p
n = skipped = 0
labels = {}
for line in open(src):
    r = json.loads(line)
    d = os.path.join(out, "skills", r["id"])
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "SKILL.md"), "w") as f:
        f.write(r["skill_md_content"] or "")
    for item in r["skill_bundle_content"] or []:
        rel = safe(item["path"])
        if rel is None:
            skipped += 1; continue
        if rel.lower() == "skill.md":
            continue
        p = os.path.join(d, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(item["content"] or "")
    labels[r["id"]] = {k: r[k] for k in ("clawscan_verdict", "static_status", "skillspector_status", "virustotal_status", "skill_slug", "skill_version")}
    n += 1
json.dump(labels, open(os.path.join(out, "labels.json"), "w"))
print(n, "cases;", skipped, "unsafe bundle paths skipped")
