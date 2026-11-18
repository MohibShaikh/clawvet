// Gate decision for each ClawHub Security Signals case, materialised the way
// ClawScan's benchmark does. Reads files only. Run inside sandbox.sh.
// Usage: npx tsx run.mts <skills dir> <out.jsonl>
import { readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { evaluateSkill } from "../../packages/cli/src/commands/gate.js";

const [dir, out] = process.argv.slice(2);
process.env.CLAWVET_TELEMETRY = "off";
const rows: string[] = [];
const ids = readdirSync(dir).sort();
let i = 0;
for (const id of ids) {
  let row: Record<string, unknown>;
  try {
    const { response, coverage } = await evaluateSkill(join(dir, id));
    row = { id, decision: response.decision, reason: (response.reason ?? "").slice(0, 200),
      gaps: [...new Set([...(coverage?.issues ?? []), ...(coverage?.warnings ?? [])].map((g) => g.rule))] };
  } catch (err) {
    row = { id, decision: "error", reason: String(err).slice(0, 200) };
  }
  rows.push(JSON.stringify(row));
  if (++i % 500 === 0) process.stderr.write(`${i}/${ids.length}\n`);
}
writeFileSync(out, rows.join("\n") + "\n");
