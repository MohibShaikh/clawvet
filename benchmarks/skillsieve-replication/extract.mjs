#!/usr/bin/env node
// Rebuilds the skill folders of SkillSieve's 390-skill benchmark from the
// tomhu/ClawSkills snapshot of ClawHub. Every file in a skill is written, not
// only SKILL.md, because SkillSieve scanned folders.
//
// The snapshot is third-party data. File paths inside it are untrusted, so a
// path that is absolute or climbs out of the skill folder is refused. Nothing
// extracted is ever executed.
//
// Usage: node extract.mjs <clawhub_all_normalized.jsonl> <labeled_dataset_final.json> <out dir>
import { createReadStream, mkdirSync, rmSync, writeFileSync, readFileSync } from "node:fs";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import readline from "node:readline";

const [snapshot, labelsFile, out] = process.argv.slice(2);
const samples = JSON.parse(readFileSync(labelsFile, "utf8")).samples.filter((s) => s.evaluated_in_390_benchmark === true);
const wanted = new Map(samples.map((s) => [s.path, s.label]));

const safe = (value) => String(value || "anon").replace(/[^\w.-]/g, "_");
rmSync(out, { recursive: true, force: true });
mkdirSync(out, { recursive: true });

const manifest = {};
const rl = readline.createInterface({ input: createReadStream(snapshot), crlfDelay: Infinity });
for await (const line of rl) {
  if (!line.trim()) continue;
  let record;
  try { record = JSON.parse(line); } catch { continue; }
  const id = `${safe(record.detail?.owner?.handle)}/${safe(record.slug)}`;
  if (!wanted.has(id) || manifest[id]) continue;
  const root = resolve(out, id);
  const files = record.latest_files ? (Array.isArray(record.latest_files) ? record.latest_files : Object.values(record.latest_files)) : [];
  const entry = { label: wanted.get(id), written: 0, skipped: 0, refused: 0, hasSkillMd: false };
  for (const file of files) {
    if (!file || typeof file !== "object") continue;
    const path = String(file.path || "");
    if (file.skipped) { entry.skipped++; continue; }
    const target = resolve(root, path);
    const rel = relative(root, target);
    if (!path || isAbsolute(path) || rel === "" || rel.startsWith(`..${sep}`) || rel === "..") { entry.refused++; continue; }
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, String(file.content ?? file.text ?? ""));
    entry.written++;
    if (rel === "SKILL.md") entry.hasSkillMd = true;
  }
  manifest[id] = entry;
}

const missing = [...wanted.keys()].filter((id) => !manifest[id]);
writeFileSync(join(out, "manifest.json"), JSON.stringify({ found: Object.keys(manifest).length, missing, skills: manifest }, null, 2));
const count = (label) => Object.values(manifest).filter((e) => e.label === label).length;
console.log(`found ${Object.keys(manifest).length} of ${wanted.size} (malicious ${count("malicious")}, benign ${count("benign")}); missing ${missing.length}`);
console.log(`files written ${Object.values(manifest).reduce((n, e) => n + e.written, 0)}, skipped in snapshot ${Object.values(manifest).reduce((n, e) => n + e.skipped, 0)}, refused paths ${Object.values(manifest).reduce((n, e) => n + e.refused, 0)}`);
