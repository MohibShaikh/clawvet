// Whether static findings alone would block each skill (score at the block line,
// or a critical finding): the input to judge v2's floor. Reads files only.
// Usage: npx tsx findings-block.mts <skills dir> <out.jsonl>
import { readdirSync, writeFileSync } from "node:fs";
import { basename, join } from "node:path";
import { scanSkill } from "@clawvet/shared";
import { assembleSkill } from "../../packages/cli/src/assemble.js";

const [dir, out] = process.argv.slice(2);
const rows: string[] = [];
for (const id of readdirSync(dir).sort()) {
  const assembly = assembleSkill(join(dir, id));
  const result = await scanSkill(assembly.content, { skillName: basename(id), files: assembly.coverage.files });
  rows.push(JSON.stringify({ id, findingsBlock: result.riskScore >= 76 || result.findings.some((f) => f.severity === "critical"), riskScore: result.riskScore }));
}
writeFileSync(out, rows.join("\n") + "\n");
