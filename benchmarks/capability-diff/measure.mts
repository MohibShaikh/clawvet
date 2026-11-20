#!/usr/bin/env -S npx tsx
// How often an update's capability diff asks the user anything.
//
//   benign:    consecutive versions of popular ClawHub skills (fetch-clawhub.mts)
//   malicious: MalSkillBench generated attacks paired with the benign skill each
//              was built from (benign/<seed> -> malware/<seed>[__<VECTOR>_B<n>])
//
// Pairs split into tune and test halves by a hash of the skill family, as in
// gate-eval. Only read: nothing in a sample is executed.
//
//   npx tsx benchmarks/capability-diff/measure.mts <clawhub-cache> <MSB>/Dataset/Skills <out.jsonl>
import { createHash } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { diffCapabilities, newPermissions, scanSkill, type Capability } from "@clawvet/shared";
import { evaluateSkill } from "../../packages/cli/src/commands/gate.js";

const [cache, msb, out] = process.argv.slice(2);
const half = (family: string) => createHash("sha256").update(family.toLowerCase()).digest()[0] % 2 === 0 ? "tune" : "test";

// Every finding is kept too, so other alert rules can be simulated offline.
type Scan = { capabilities: Capability[]; findings: string[]; files: string[]; decision?: string; error?: string };
const memo = new Map<string, Scan | null>();
async function scan(dir: string): Promise<Scan | null> {
  if (memo.has(dir)) return memo.get(dir)!;
  let result: Scan | null = null;
  const started = performance.now();
  if (process.env.TRACE) console.error(`start ${dir}`);
  try {
    const { response, coverage, content } = await evaluateSkill(dir, { skillName: dir.split("/").pop() });
    if (content) {
      const r = await scanSkill(content, { files: coverage?.files, skipCache: true });
      result = { capabilities: r.capabilities ?? [], findings: [...new Set(r.findings.map((f) => `${f.severity}:${f.category}:${f.title}`))],
        files: (coverage?.files ?? []).map((f) => f.path), decision: response.decision };
    }
  } catch (err) {
    // A throw is a scanner bug until shown otherwise: record it, never hide it.
    result = { capabilities: [], findings: [], files: [], error: err instanceof Error ? err.message : String(err) };
    console.error(`error ${dir}: ${result.error}`);
  }
  const ms = performance.now() - started;
  if (ms > 2000) console.error(`slow ${Math.round(ms)} ms ${dir}`);
  memo.set(dir, result);
  return result;
}

const pairs: { set: "benign" | "malicious"; family: string; label: string; before: string; after: string }[] = [];
const manifest: { slug: string; versions: string[] }[] = existsSync(join(cache, "manifest.json")) ? JSON.parse(readFileSync(join(cache, "manifest.json"), "utf8")) : [];
for (const { slug, versions } of manifest) {
  for (let i = 0; i + 1 < versions.length; i++) {
    const before = join(cache, slug, versions[i]), after = join(cache, slug, versions[i + 1]);
    if (existsSync(join(before, "SKILL.md")) && existsSync(join(after, "SKILL.md"))) pairs.push({ set: "benign", family: slug, label: `${versions[i]}->${versions[i + 1]}`, before, after });
  }
}
for (const line of readFileSync(join(msb, "malware/_source_inventory.txt"), "utf8").split("\n")) {
  const m = line.match(/^GENERATED\s+(.+?)\s+<-\s+generated_malicious\/(CI|PI|MIXED)\//);
  if (!m) continue;
  const seed = m[1].replace(/__(?:CI|PI|MIXED)_B\d+$/, "");
  const before = join(msb, "benign", seed), after = join(msb, "malware", m[1]);
  if (existsSync(join(before, "SKILL.md")) && existsSync(join(after, "SKILL.md"))) pairs.push({ set: "malicious", family: seed, label: m[2], before, after });
}

const rows: string[] = [];
for (const pair of pairs) {
  const [a, b] = [await scan(pair.before), await scan(pair.after)];
  if (!a || !b || a.error || b.error) { rows.push(JSON.stringify({ ...pair, half: half(pair.family), error: a?.error ?? b?.error ?? "no content" })); continue; }
  const change = diffCapabilities(a.capabilities, b.capabilities);
  const key = (c: Capability) => `${c.kind}:${c.value}${c.declared ? ":declared" : ""}`;
  rows.push(JSON.stringify({ ...pair, half: half(pair.family), asks: newPermissions(change, "quiet", { owner: pair.set === "benign" ? pair.family.split("/")[0] : undefined }).map(key), asksAll: newPermissions(change, "all").map(key), added: change.added.map(key),
    removed: change.removed.length, caps: [a.capabilities.map(key), b.capabilities.map(key)], findings: [a.findings, b.findings],
    files: [a.files, b.files], decisions: [a.decision, b.decision] }));
}
writeFileSync(out, rows.join("\n") + "\n");
console.log(`${rows.length} pairs -> ${out}`);
