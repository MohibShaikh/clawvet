#!/usr/bin/env node
// Scores ClawVet versions on SkillSieve's 390-skill benchmark under three
// decision rules, so the effect of the rule can be separated from the tool:
//
//   skillsieve  their harness: any critical or high finding, or riskScore >= 20
//               (experiments/run_clawvet_baseline.py, unchanged)
//   block       ClawVet's own verdict: the gate's decision for versions that
//               have a gate (0.12+), otherwise scan `recommendation`
//   stopped     ClawVet's own block or warn; in OpenClaw a warn also halts
//
// Usage: node run.mjs <extracted dir> <name=path/to/dist/index.js>... > results.json
import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const [dir, ...versions] = process.argv.slice(2);
const manifest = JSON.parse(readFileSync(join(dir, "manifest.json"), "utf8"));
const ids = Object.keys(manifest.skills).filter((id) => manifest.skills[id].hasSkillMd);

function run(bin, args, input) {
  return new Promise((done) => {
    const child = spawn("node", [bin, ...args], { env: { ...process.env, CLAWVET_TELEMETRY: "off" } });
    let out = "";
    child.stdout.on("data", (d) => (out += d));
    child.on("close", () => done(out));
    child.stdin.on("error", () => {});
    if (input) child.stdin.write(input);
    child.stdin.end();
  });
}

async function score(bin, id) {
  const path = join(dir, id);
  let scan;
  try { scan = JSON.parse(await run(bin, ["scan", path, "--format", "json"])); } catch { return { error: "scan output unparseable" }; }
  const findings = scan.findingsCount ?? {};
  const skillsieve = (findings.critical ?? 0) > 0 || (findings.high ?? 0) > 0 || (scan.riskScore ?? 0) >= 20;
  let decision = scan.recommendation === "block" ? "block" : scan.recommendation === "warn" ? "warn" : "allow";
  const gate = await run(bin, ["gate"], JSON.stringify({ protocolVersion: 1, targetType: "skill", targetName: id, sourcePath: path, sourcePathKind: "directory" }));
  try { decision = JSON.parse(gate).decision ?? decision; } catch { /* no gate in this version */ }
  return { riskScore: scan.riskScore, findings, skillsieve, decision };
}

const results = {};
for (const spec of versions) {
  const [name, bin] = spec.split("=");
  const rows = {};
  for (let i = 0; i < ids.length; i += 12) {
    await Promise.all(ids.slice(i, i + 12).map(async (id) => { rows[id] = await score(bin, id); }));
  }
  results[name] = rows;
}

const metrics = (predicted) => {
  const m = { tp: 0, fp: 0, tn: 0, fn: 0, errors: 0 };
  for (const id of ids) {
    const truth = manifest.skills[id].label === "malicious";
    const p = predicted(id);
    if (p === undefined) { m.errors++; continue; }
    m[p ? (truth ? "tp" : "fp") : (truth ? "fn" : "tn")]++;
  }
  const precision = m.tp / (m.tp + m.fp || 1), recall = m.tp / (m.tp + m.fn || 1);
  return { ...m, precision: +precision.toFixed(3), recall: +recall.toFixed(3),
    f1: +(precision + recall ? (2 * precision * recall) / (precision + recall) : 0).toFixed(3),
    fpr: +(m.fp / (m.fp + m.tn || 1)).toFixed(3) };
};

const summary = {};
for (const [name, rows] of Object.entries(results)) {
  const get = (id, f) => (rows[id]?.error ? undefined : f(rows[id]));
  summary[name] = {
    skillsieve: metrics((id) => get(id, (r) => r.skillsieve)),
    block: metrics((id) => get(id, (r) => r.decision === "block")),
    stopped: metrics((id) => get(id, (r) => r.decision !== "allow")),
  };
}
console.log(JSON.stringify({ skills: ids.length, missing: manifest.missing.length, summary, results }, null, 2));
