#!/usr/bin/env -S npx tsx
// Runs the gate's own decision (evaluateSkill) over MalSkillBench in-process and
// writes one JSON line per skill with structured, untruncated coverage. Skills
// are only read; nothing in a sample is executed.
//
// Usage: npx tsx evaluate.mts <MalSkillBench>/Dataset/Skills <out.jsonl>
import { execSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { scanSkill } from "@clawvet/shared";
import { evaluateSkill } from "../../packages/cli/src/commands/gate.js";

const [skills, out] = process.argv.slice(2);
const repo = join(dirname(fileURLToPath(import.meta.url)), "../..");

// Attack type per malicious entry, from the benchmark's own inventory. Names
// can contain spaces, so match up to the arrow rather than to whitespace.
const labels: Record<string, string> = {};
for (const line of readFileSync(join(skills, "malware/_source_inventory.txt"), "utf8").split("\n")) {
  let m = line.match(/^GENERATED\s+(.+?)\s+<-\s+generated_malicious\/(CI|PI|MIXED)\//);
  if (m) { labels[m[1]] = m[2]; continue; }
  m = line.match(/^(WILD|TEST\S*)\s+(.+?)\s+<-\s+/);
  if (m) labels[m[2]] = m[1] === "WILD" ? "WILD" : "TEST";
}

// Variants of one skill share a family: generated attacks carry a
// __<VECTOR>_B<n> suffix on the benign skill they were built from, and wild
// copies a random id suffix. Families, not skills, are split, so no variant of
// a test skill is seen while tuning. Whole campaigns are not grouped.
const family = (name: string) =>
  name.replace(/__(?:CI|PI|MIXED)_B\d+$/, "").replace(/-(?=[a-z0-9]*\d)[a-z0-9]{10,}$/, "").toLowerCase();
const half = (name: string) =>
  createHash("sha256").update(family(name)).digest()[0] % 2 === 0 ? "tune" : "test";

const git = (cmd: string) => execSync(cmd, { cwd: repo, encoding: "utf8" });
const provenance = {
  head: git("git rev-parse HEAD").trim(),
  // Hash of the uncommitted tracked diff plus untracked source, so a result
  // can be tied to the exact code that produced it.
  worktree: createHash("sha256")
    .update(git("git diff HEAD -- packages apps/api/src"))
    .update(git("git ls-files --others --exclude-standard -- packages apps/api/src")
      .split("\n").filter(Boolean).map((file) => readFileSync(join(repo, file), "utf8")).join("\0"))
    .digest("hex"),
  measured: new Date().toISOString(),
};

const lines = [JSON.stringify({ provenance })];
for (const tier of ["malware", "benign"]) {
  for (const name of readdirSync(join(skills, tier)).sort()) {
    const dir = join(skills, tier, name);
    if (!statSync(dir).isDirectory()) continue;
    const { response, coverage, content } = await evaluateSkill(dir, { skillName: name });
    // Coverage failure stops the gate before scoring. Score the inspected
    // content for every skill, so a decision can be attributed to coverage or
    // to findings, and other policies can be simulated from this file.
    let score: "block" | "warn" | "allow" | undefined;
    if (content) {
      const scan = await scanSkill(content, { skillName: name });
      score = scan.findings.some((f) => f.disqualifying) || scan.riskScore >= 76
        ? "block" : scan.recommendation === "approve" ? "allow" : "warn";
    }
    lines.push(JSON.stringify({
      tier, name, label: tier === "benign" ? "benign" : labels[name] ?? "unlabelled",
      family: family(name), half: half(name),
      decision: response.decision, reason: response.reason,
      issues: coverage?.issues ?? [], warnings: coverage?.warnings ?? [],
      score,
    }));
  }
}
writeFileSync(out, lines.join("\n") + "\n");
console.log(`${lines.length - 1} skills -> ${out}`);
