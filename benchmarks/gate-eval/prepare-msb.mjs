#!/usr/bin/env node
// Lists MalSkillBench skill folders, one per line, for run-gate.sh. Labels and
// the tune/test split come from evaluate.mts, not from this list.
// Usage: node prepare-msb.mjs <MalSkillBench>/Dataset/Skills > msb-dirs.txt
import { readdirSync, statSync } from "node:fs";
import { join } from "node:path";

const skills = process.argv[2];
for (const tier of ["malware", "benign"]) {
  for (const name of readdirSync(join(skills, tier)).sort()) {
    if (statSync(join(skills, tier, name)).isDirectory()) console.log(join(skills, tier, name));
  }
}
