import fs from "node:fs";
import path from "node:path";
import readline from "node:readline";
import { createReadStream } from "node:fs";

const SRC = process.argv[2] ?? "/tmp/opencode/clawskills.jsonl";
const OUT = process.argv[3] ?? "/tmp/opencode/clawhub-stage";
const ONLY_LABEL = process.argv[4] ?? null;

fs.rmSync(OUT, { recursive: true, force: true });
fs.mkdirSync(OUT, { recursive: true });

const manifest = [];
let scanned = 0;
let extracted = 0;

function safeAuthor(handle) {
  return String(handle || "anon").replace(/[^\w.-]/g, "_");
}

async function extractContent(rec) {
  const lf = rec.latest_files;
  if (!lf) return null;
  const files = Array.isArray(lf) ? lf : Object.values(lf);
  for (const fl of files) {
    if (!fl || typeof fl !== "object") continue;
    const p = String(fl.path || "");
    const isSkill = p === "SKILL.md" || p.endsWith("/SKILL.md");
    if (!isSkill) continue;
    if (fl.skipped) return { content: null, skipReason: fl.skip_reason, path: p };
    const content = fl.content || fl.text || "";
    if (content.trim().length < 200) return { content: null, skipReason: "too short", path: p };
    return { content, skipReason: null, path: p };
  }
  return null;
}

const rl = readline.createInterface({ input: createReadStream(SRC), crlfDelay: Infinity });

for await (const line of rl) {
  if (!line.trim()) continue;
  scanned++;
  let rec;
  try {
    rec = JSON.parse(line);
  } catch {
    continue;
  }
  const label = (rec.risk && rec.risk.label) || "";
  if (ONLY_LABEL === "__none__") {
    if (label) continue;
  } else if (ONLY_LABEL && label !== ONLY_LABEL) continue;
  const res = await extractContent(rec);
  if (!res || !res.content) continue;

  const author = safeAuthor(rec.detail?.owner?.handle);
  const slug = String(rec.slug || "").replace(/[^\w.-]/g, "_");
  if (!slug) continue;

  const dir = path.join(OUT, label || "nolabel", author, slug);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, "SKILL.md"), res.content);
  manifest.push({ slug, author, label: label || "nolabel", size: res.content.length, hasContent: true });
  extracted++;
}

fs.writeFileSync(path.join(OUT, "manifest.json"), JSON.stringify(manifest, null, 2));
console.log(`scanned=${scanned} extracted=${extracted} label=${ONLY_LABEL ?? "all"} -> ${OUT}`);