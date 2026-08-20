#!/usr/bin/env node
// Scans every benchmark fixture and writes results.csv (id,label,score) for eval.py.
// Run from the repo root with: npx tsx benchmarks/scan-all.mjs
//
// Labels: malicious = 1, benign + hard-negatives = 0.
// Hard negatives are legit skills that trip credential/exec rules, so their
// scores count against the false-positive rate.
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

function loadSkill(dir, name) {
  const plain = resolve(HERE, dir, name, "SKILL.md");
  if (existsSync(plain)) return readFileSync(plain, "utf8");
  const b64 = readFileSync(plain + ".b64", "utf8");
  return Buffer.from(b64, "base64").toString("utf8");
}

const rows = [["id", "label", "score", "dir"]];
for (const { dir, label } of DIRS) {
  const base = resolve(HERE, dir);
  if (!existsSync(base)) continue;
  for (const name of readdirSync(base).sort()) {
    const content = loadSkill(dir, name);
    const r = await scanSkill(content, { skipCache: true });
    rows.push([name, String(label), String(r.riskScore), dir]);
  }
}

const csv = rows.map((r) => r.join(",")).join("\n") + "\n";
writeFileSync(resolve(HERE, "results.csv"), csv);
process.stdout.write(csv);
