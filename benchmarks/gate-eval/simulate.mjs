#!/usr/bin/env node
// Replays an evaluate.mts run under alternative gate policies, without
// rerunning the scanner: which coverage rules block, which only warn. Findings
// keep their score decision in every policy. Complete skills only (see
// report.mjs), one half of the family split.
//
// Usage: node simulate.mjs <eval.jsonl> <tune|test>
import { readFileSync } from "node:fs";

const [evalFile, half] = process.argv.slice(2);
const rows = readFileSync(evalFile, "utf8").trim().split("\n").slice(1).map((line) => JSON.parse(line))
  .filter((row) => row.half === half && row.issues.length < 20 && !row.issues.some((i) => /missing or unsupported/.test(i.reason)));

// Failures that mean the gate could not see the code at all, or saw it being
// swapped. These block in every policy.
const INTEGRITY = /exceeds|Cannot read|Symlinks|Binary|limit|Unsafe|Not a readable|Path resolves inside the skill|depth limit/;
const RULES = {
  substitution: /Downloaded file is (executed|used as instructions)/,
  downloadExecute: /Instructions to download and execute/,
  escape: /escapes the skill root/,
  remote: /Remote (execution target|module)/,
  encoded: /Encoded execution/,
  pipeline: /Download-to-execution pipeline/,
  process: /Process or loader arguments/,
  evaluation: /Runtime evaluation/,
  dynamicModule: /Dynamic (code or module loading|module name)/,
  pythonDownload: /Python download destination/,
};
const POLICIES = {
  "strict (current)": Object.keys(RULES),
  "default A: substitution, download+execute, escape, remote": ["substitution", "downloadExecute", "escape", "remote", "encoded"],
  "default B: A + untrusted curl|sh": ["substitution", "downloadExecute", "escape", "remote", "encoded", "pipeline"],
  "default C: B + eval": ["substitution", "downloadExecute", "escape", "remote", "encoded", "pipeline", "evaluation"],
};

function decide(row, blocking) {
  const blocks = (issue) => INTEGRITY.test(issue.reason) || blocking.some((rule) => RULES[rule].test(issue.reason));
  if (row.issues.some(blocks) || row.score === "block") return "block";
  if (row.issues.length || row.warnings.length || row.score === "warn") return "warn";
  return "allow";
}

const groups = ["CI", "PI", "MIXED", "WILD", "benign"];
const pct = (x, n) => `${(100 * x / n).toFixed(1)}%`.padStart(6);
console.log(`half ${half}, complete skills: blocked / stopped`);
console.log("policy".padEnd(58), ...groups.map((g) => `${g} (${rows.filter((r) => r.label === g).length})`.padStart(16)));
for (const [name, blocking] of Object.entries(POLICIES)) {
  const cells = groups.map((group) => {
    const ds = rows.filter((row) => row.label === group).map((row) => decide(row, blocking));
    return `${pct(ds.filter((d) => d === "block").length, ds.length)} /${pct(ds.filter((d) => d !== "allow").length, ds.length)}`;
  });
  console.log(name.padEnd(58), ...cells.map((c) => c.padStart(16)));
}
