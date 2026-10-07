#!/usr/bin/env node
// Summarizes an evaluate.mts run, optionally beside run-gate.sh results from a
// published version, for one half of the family split.
//
// Two cohorts. "all" counts every skill as it is. "complete" keeps only skills
// whose referenced files are all present: both datasets often ship SKILL.md
// without its scripts, which makes coverage block for a reason that says
// nothing about the gate. Membership comes from the evaluated build's
// structured coverage and is applied to every column.
//
// Usage: node report.mjs <eval.jsonl> <tune|test> [label=run-gate.tsv ...]
import { readFileSync } from "node:fs";

const [evalFile, half, ...baselines] = process.argv.slice(2);
const rows = readFileSync(evalFile, "utf8").trim().split("\n").map((line) => JSON.parse(line));
const { provenance } = rows.shift();
const skills = rows.filter((row) => row.half === half);

const missing = (issue) => /missing or unsupported/.test(issue.reason);
// Assembly reports at most 20 issues, so a capped list cannot prove that every
// referenced file was present.
const complete = (row) => row.issues.length < 20 && !row.issues.some(missing);

const columns = [["this build", Object.fromEntries(skills.map((row) => [`${row.tier}/${row.name}`, row.decision]))]];
for (const arg of baselines) {
  const [label, file] = arg.split("=");
  const decisions = Object.fromEntries(readFileSync(file, "utf8").trim().split("\n")
    .map((line) => line.split("\t")).map((r) => [`${r[0]}/${r[1]}`, r[2]]));
  columns.unshift([label, decisions]);
}

const groups = ["CI", "PI", "MIXED", "WILD", "benign"];
const pct = (x, n) => (n ? `${(100 * x / n).toFixed(1)}%` : "-").padStart(6);
console.log(`half ${half}; build ${provenance.head.slice(0, 7)} + worktree ${provenance.worktree.slice(0, 12)}; measured ${provenance.measured}`);
for (const [cohort, keep] of [["all", () => true], ["complete", complete]]) {
  console.log(`\n${cohort} skills: blocked / stopped (block or warn)`);
  console.log("group".padEnd(8), "n".padStart(5), ...columns.map(([label]) => label.padStart(17)));
  for (const group of groups) {
    const members = skills.filter((row) => row.label === group && keep(row));
    const cells = columns.map(([, decisions]) => {
      const ds = members.map((row) => decisions[`${row.tier}/${row.name}`]);
      return `${pct(ds.filter((d) => d === "block").length, ds.length)} / ${pct(ds.filter((d) => d && d !== "allow").length, ds.length)}`;
    });
    console.log(group.padEnd(8), String(members.length).padStart(5), ...cells);
  }
}

// Of skills blocked only for missing files, how many would block on findings
// alone? Coverage stops the gate before scoring, so this is the hidden part.
const masked = skills.filter((row) => row.decision === "block" && row.issues.length && row.issues.every(missing));
for (const group of groups) {
  const m = masked.filter((row) => row.label === group);
  if (m.length) console.log(`${group}: ${m.length} blocked only for missing files; ${m.filter((row) => row.score === "block").length} would also block on findings`);
}
