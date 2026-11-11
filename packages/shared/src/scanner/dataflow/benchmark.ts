// Read-only benchmark runner; it never imports or executes corpus code.
import { execFileSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { homedir } from "node:os";
import { join, relative } from "node:path";
import { analyzeDataflow } from "./index.js";
import type { SourceFile } from "../../types.js";

const root = process.argv[2] ?? join(homedir(), "personal-projects/jev-skillbench/data/MalSkillBench/Dataset/Skills");
const files = execFileSync("rg", ["--files", "--hidden", "-g", "*.py", "-g", "*.pyw", root], { maxBuffer: 64 * 1024 * 1024 }).toString().trim().split("\n").filter(Boolean).sort();
const pythonBySkill = new Map<string, string[]>();
for (const file of files) {
  const name = relative(root, file).split("/").slice(0, 2).join("/");
  const paths = pythonBySkill.get(name) ?? [];
  paths.push(file); pythonBySkill.set(name, paths);
}
function sample(names: string[], seed: number): string[] {
  const result = [...names].sort();
  let state = seed;
  for (let i = result.length - 1; i > 0; i--) {
    state ^= state << 13; state ^= state >>> 17; state ^= state << 5;
    const j = (state >>> 0) % (i + 1);
    [result[i], result[j]] = [result[j], result[i]];
  }
  return result.slice(0, 500);
}
async function sourcesFor(name: string): Promise<SourceFile[]> {
  const sources: SourceFile[] = [];
  let total = 0;
  for (const path of pythonBySkill.get(name) ?? []) {
    const bytes = await readFile(path);
    if (bytes.length > 256 * 1024 || total + bytes.length > 2 * 1024 * 1024) continue;
    const text = bytes.toString("utf8"); total += bytes.length;
    sources.push({ path: relative(join(root, name), path), text, language: "python", startLine: 1, endLine: text.split("\n").length });
  }
  return sources;
}
const cohort = sample([...pythonBySkill.keys()], 0xc1a047);
const latencies: number[] = [];
const coldSources: SourceFile[] = [{ path: "warmup.py", language: "python", text: "pass", startLine: 1, endLine: 1 }];
const coldStart = performance.now();
await analyzeDataflow(coldSources);
const coldMs = performance.now() - coldStart;
let sourceCount = 0, truncatedSkills = 0;
for (const name of cohort) {
  const sources = await sourcesFor(name);
  sourceCount += sources.length;
  const started = performance.now();
  const findings = await analyzeDataflow(sources);
  latencies.push(performance.now() - started);
  if (findings.some((f) => f.title === "Dataflow analysis truncated")) truncatedSkills++;
}
latencies.sort((a, b) => a - b);
const benignNames = execFileSync("rg", ["--files", "--hidden", "-g", "SKILL.md", join(root, "benign")], { maxBuffer: 64 * 1024 * 1024 }).toString().trim().split("\n").filter(Boolean).map((f) => relative(root, f).split("/").slice(0, 2).join("/"));
const benign = sample([...new Set(benignNames)], 0xb3616e);
const flagged: { name: string; categories: string[] }[] = [];
let benignWithPython = 0;
for (const name of benign) {
  const sources = await sourcesFor(name);
  if (sources.length) benignWithPython++;
  const findings = await analyzeDataflow(sources);
  const high = findings.filter((f) => f.severity === "high" || f.severity === "critical");
  if (high.length) flagged.push({ name, categories: [...new Set(high.map((f) => f.category))] });
}
const hash = (names: string[]) => createHash("sha256").update(names.join("\n")).digest("hex");
// No skill names or paths: MalSkillBench is academic-research-only, so only
// aggregates are committed. Print `flagged` locally to review them.
console.log(JSON.stringify({
  measurement: "measured", runtime: process.version, date: new Date().toISOString(),
  latency: { skills: cohort.length, pythonFiles: sourceCount, coldMs, medianMs: latencies[Math.floor(latencies.length / 2)], p95Ms: latencies[Math.ceil(latencies.length * 0.95) - 1], maxMs: latencies.at(-1), truncatedSkills, sampleSeed: "0xc1a047", cohortSha256: hash(cohort) },
  benign: { skills: benign.length, withPython: benignWithPython, highOrCritical: flagged.length, sampleSeed: "0xb3616e", cohortSha256: hash(benign) },
}, null, 2));
