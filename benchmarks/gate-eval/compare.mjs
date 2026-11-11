#!/usr/bin/env node
// Puts the gate beside MalSkillBench's published baselines on the same skills:
// one half of the family split, one cohort, every tool. Rates carry 95%
// intervals from a bootstrap over clusters, since variants of one skill are not
// independent; every tool sees the same resamples, so differences are paired.
//
// A cluster joins skills that share a family or a byte-identical SKILL.md. The
// family key misses wild copies whose random suffix has no digit, so most wild
// test skills have a SKILL.md identical to one in the tune half. The split is
// kept as tuned against; --decontaminated drops those test skills instead.
//
// Cohort membership comes from the evaluated build (see report.mjs) and is
// applied to every tool. Baseline verdicts of "unknown" are left out of that
// tool's denominators and counted.
//
// Usage: node compare.mjs <eval.jsonl> <baselines.tsv> <Dataset/Skills> <tune|test> <all|complete> [--decontaminated] [--json]
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const [evalFile, baselineFile, skillsDir, half, cohort, ...flags] = process.argv.slice(2);
const json = flags.includes("--json");
const decontaminated = flags.includes("--decontaminated");
const missing = (issue) => /missing or unsupported/.test(issue.reason);
const complete = (row) => row.issues.length < 20 && !row.issues.some(missing);

const lines = readFileSync(evalFile, "utf8").trim().split("\n").map((line) => JSON.parse(line));
const { provenance } = lines.shift();
const body = (row) => {
  try { return createHash("sha256").update(readFileSync(join(skillsDir, row.tier, row.name, "SKILL.md"))).digest("hex"); }
  catch { return `none:${row.tier}/${row.name}`; }
};
for (const row of lines) row.body = body(row);
const otherHalf = new Set(lines.filter((row) => row.half !== half).map((row) => row.body));
const skills = lines.filter((row) => row.half === half && (cohort === "all" || complete(row)) && row.label !== "unlabelled"
  && !(decontaminated && otherHalf.has(row.body)));
const key = (tier, name) => `${tier}/${name}`;

// tool -> skill -> true (flagged) / false (passed). Missing means unknown.
const tools = new Map();
const flag = (tool, skill, value) => {
  if (!tools.has(tool)) tools.set(tool, new Map());
  tools.get(tool).set(skill, value);
};
for (const row of skills) {
  const k = key(row.tier, row.name);
  flag("ClawVet gate, block", k, row.decision === "block");
  flag("ClawVet gate, block or warn", k, row.decision !== "allow");
  // The same build's findings without coverage rules: what the scanner alone
  // decides. Content that could not be read has no score and passes.
  flag("ClawVet findings only, block", k, row.score === "block");
  flag("ClawVet findings only, block or warn", k, row.score === "block" || row.score === "warn");
}
const inHalf = new Set(skills.map((row) => key(row.tier, row.name)));
for (const line of readFileSync(baselineFile, "utf8").trim().split("\n").slice(1)) {
  const [tool, tier, name, verdict] = line.split("\t");
  const k = key(tier, name);
  if (!inHalf.has(k)) continue;
  if (!tools.has(tool)) tools.set(tool, new Map());
  if (verdict !== "unknown") flag(tool, k, verdict === "malicious");
}

const GROUPS = ["CI", "PI", "MIXED", "WILD", "TEST", "malicious", "benign"];
const inGroup = (row, group) => group === "malicious" ? row.label !== "benign" : row.label === group;

// Clusters by union-find over family and SKILL.md body, and a seeded generator
// so the intervals reproduce exactly.
const parent = new Map();
const find = (x) => { while (parent.get(x) !== x) x = parent.get(x); return x; };
const union = (a, b) => {
  for (const x of [a, b]) if (!parent.has(x)) parent.set(x, x);
  parent.set(find(a), find(b));
};
for (const row of skills) union(`f:${row.family}`, `b:${row.body}`);
const byFamily = new Map();
for (const row of skills) {
  const c = find(`f:${row.family}`);
  if (!byFamily.has(c)) byFamily.set(c, []);
  byFamily.get(c).push(row);
}
const families = [...byFamily.keys()];
let seed = 20261009;
const random = () => ((seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0) / 2 ** 32);
const REPS = 2000;
// Each resample is a list of skill indices, so one pass per resample and tool
// counts every group at once.
const index = new Map(skills.map((row, i) => [row, i]));
const resamples = Array.from({ length: REPS }, () =>
  Int32Array.from(Array.from({ length: families.length }, () => byFamily.get(families[Math.floor(random() * families.length)])).flat().map((row) => index.get(row))));
const all = Int32Array.from(skills.keys());
const memberOf = skills.map((row) => GROUPS.map((group) => inGroup(row, group)));

// decision per skill index: 1 flagged, 0 passed, -1 unknown.
function rates(decided, rows) {
  const hit = new Array(GROUPS.length).fill(0), n = new Array(GROUPS.length).fill(0);
  for (const i of rows) {
    const d = decided[i];
    if (d < 0) continue;
    const member = memberOf[i];
    for (let g = 0; g < GROUPS.length; g++) if (member[g]) { n[g]++; hit[g] += d; }
  }
  return GROUPS.map((_, g) => ({ hit: hit[g], n: n[g], value: n[g] ? hit[g] / n[g] : NaN }));
}
const quantile = (xs, q) => {
  const s = xs.filter((x) => !Number.isNaN(x)).sort((a, b) => a - b);
  return s.length ? s[Math.min(s.length - 1, Math.floor(q * s.length))] : NaN;
};

const results = [];
const boots = new Map();
for (const [tool, decisions] of tools) {
  const decided = Int8Array.from(skills, (row) => {
    const d = decisions.get(key(row.tier, row.name));
    return d === undefined ? -1 : d ? 1 : 0;
  });
  const unknown = decided.filter((d) => d < 0).length;
  const point = rates(decided, all);
  const boot = resamples.map((rows) => rates(decided, rows));
  const cells = {};
  GROUPS.forEach((group, g) => {
    const values = boot.map((r) => r[g].value);
    cells[group] = { ...point[g], low: quantile(values, 0.025), high: quantile(values, 0.975) };
    if (group === "malicious" || group === "benign") boots.set(`${tool}\0${group}`, values);
  });
  results.push({ tool, unknown, cells });
}
// Paired difference from the gate's block decision, per resample: positive
// means the tool flags more than the gate.
const REFERENCE = "ClawVet gate, block";
for (const r of results) {
  r.versusGate = {};
  for (const group of ["malicious", "benign"]) {
    const a = boots.get(`${r.tool}\0${group}`), b = boots.get(`${REFERENCE}\0${group}`);
    const d = a.map((x, i) => x - b[i]);
    r.versusGate[group] = { value: r.cells[group].value - results.find((x) => x.tool === REFERENCE).cells[group].value, low: quantile(d, 0.025), high: quantile(d, 0.975) };
  }
}

if (json) {
  console.log(JSON.stringify({ provenance, half, cohort, decontaminated, skills: skills.length, clusters: families.length, reps: REPS, results }, null, 1));
} else {
  const pct = (x) => (Number.isNaN(x) ? "-" : (100 * x).toFixed(1));
  console.log(`half ${half}${decontaminated ? " decontaminated" : ""}, ${cohort} skills (${skills.length}, ${families.length} clusters); build ${provenance.head.slice(0, 7)}+${provenance.worktree.slice(0, 12)}`);
  console.log("tool".padEnd(40), "unk".padStart(5), ...GROUPS.map((g) => `${g} (n)`.padStart(22)));
  for (const { tool, unknown, cells } of results.sort((a, b) => b.cells.malicious.value - a.cells.malicious.value)) {
    console.log(tool.padEnd(40), String(unknown).padStart(5), ...GROUPS.map((g) => {
      const c = cells[g];
      return `${pct(c.value)} [${pct(c.low)},${pct(c.high)}] ${c.n}`.padStart(22);
    }));
  }
}
