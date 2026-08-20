#!/usr/bin/env node
// Scans the 500-skill real-world benchmark and writes results.csv for eval.py.
// Run from the repo root with: npx tsx benchmarks/scan-corpus500.mjs
//
// Composition: 400 real ClawHub clean-labeled skills (benign), 50 real
// ClawHavoc malicious skills, 50 real ClawHub skills that trip static rules
// but are benign (hard-negatives). Labels: malicious = 1, else 0.
// Corpus built from the tomhu/ClawSkills HuggingFace snapshot of ClawHub
// (1.2GB, 26,502 skills) + the SkillSieve paper's reconstructed ClawHavoc set.
import { readFileSync, readdirSync, writeFileSync, existsSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { scanSkill } from "@clawvet/shared";

const HERE = dirname(fileURLToPath(import.meta.url));
const DIRS = [
  { dir: "malicious", label: 1 },
  { dir: "benign", label: 0 },
  { dir: "hard-negatives", label: 0 },
];

const rows = [["id", "label", "score", "dir"]];
let done = 0, failed = 0;

for (const { dir, label } of DIRS) {
  const tierDir = resolve(HERE, "corpus500", dir);
  for (const author of readdirSync(tierDir).sort()) {
    const authorDir = resolve(tierDir, author);
    for (const skill of readdirSync(authorDir).sort()) {
      const md = resolve(authorDir, skill, "SKILL.md");
      let content;
      if (existsSync(md)) {
        content = readFileSync(md, "utf8");
      } else {
        const b64 = readFileSync(md + ".b64", "utf8");
        content = Buffer.from(b64, "base64").toString("utf8");
      }
      try {
        const r = await scanSkill(content, { skipCache: true });
        rows.push([`${author}/${skill}`, String(label), String(r.riskScore), dir]);
        done++;
      } catch (e) {
        failed++;
        rows.push([`${author}/${skill}`, String(label), "-1", dir]);
      }
    }
  }
}

writeFileSync(resolve(HERE, "corpus500", "results.csv"), rows.map((r) => r.join(",")).join("\n") + "\n");
process.stderr.write(`scanned ${done}, failed ${failed}\n`);
