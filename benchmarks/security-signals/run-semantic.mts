// Gate decision with the semantic judge, built the way `clawvet gate --semantic`
// builds it, plus the judge's own verdict for analysis. Reads files only; the
// judge is configured from CLAWVET_LLM_* and caches responses under
// XDG_CACHE_HOME. Run inside sandbox.sh with the network on.
// Usage: npx tsx run-semantic.mts <skills dir> <out.jsonl> [concurrency]
import { readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { evaluateSkill, type SemanticGate } from "../../packages/cli/src/commands/gate.js";
import { createSemanticJudge, resolveSemanticConfig, type SemanticJudgment } from "../../packages/cli/src/semantic/judge.js";

const [dir, out, width = "8"] = process.argv.slice(2);
process.env.CLAWVET_TELEMETRY = "off";
const config = resolveSemanticConfig(process.env, { timeoutMs: 120_000, cache: true });
const judge = createSemanticJudge(config);
const ids = readdirSync(dir).sort();
const rows: string[] = new Array(ids.length);
let next = 0, done = 0;

async function worker() {
  for (;;) {
    const index = next++;
    if (index >= ids.length) return;
    const id = ids[index];
    let judged: SemanticJudgment | undefined;
    let judgeError: string | undefined;
    const semantic: SemanticGate = {
      timeoutMs: 120_000, onError: "warn",
      judge: async (content, timeoutMs) => {
        try { judged = await judge(content, timeoutMs); return judged; }
        catch (err) { judgeError = String(err).slice(0, 160); throw err; }
      },
    };
    let row: Record<string, unknown>;
    try {
      const { response, coverage } = await evaluateSkill(join(dir, id), { semantic });
      row = { id, decision: response.decision, reason: (response.reason ?? "").slice(0, 200),
        gaps: [...new Set([...(coverage?.issues ?? []), ...(coverage?.warnings ?? [])].map((g) => g.rule))],
        verdict: judged?.verdict, confidence: judged?.confidence, truncated: judged?.truncated,
        ungrounded: judged?.ungrounded, judgeFindings: judged?.findings.length, judgeError };
    } catch (err) {
      row = { id, decision: "error", reason: String(err).slice(0, 200), judgeError };
    }
    rows[index] = JSON.stringify(row);
    if (++done % 100 === 0) process.stderr.write(`${done}/${ids.length}\n`);
  }
}
await Promise.all(Array.from({ length: Number(width) }, worker));
writeFileSync(out, rows.join("\n") + "\n");
