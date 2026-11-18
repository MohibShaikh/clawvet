// Judge a sample through an outside model without giving it the network here.
//   capture: write the exact request clawvet's judge would send, per skill.
//   replay:  answer that request with the stored reply, so clawvet parses and
//            grounds it exactly as in production, and record the gate decision.
// Reads files only. Run both modes inside the no-network sandbox.
// Usage: npx tsx judge-replay.mts capture|replay <skills dir> <out dir>
import { mkdirSync, readFileSync, readdirSync, writeFileSync, existsSync } from "node:fs";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { assembleSkill } from "../../packages/cli/src/assemble.js";
import { evaluateSkill } from "../../packages/cli/src/commands/gate.js";
import { createSemanticJudge, resolveSemanticConfig, type SemanticJudgment } from "../../packages/cli/src/semantic/judge.js";

const [mode, dir, out] = process.argv.slice(2);
process.env.CLAWVET_TELEMETRY = "off";
mkdirSync(join(out, "prompts"), { recursive: true });
// The judge puts a fresh random boundary in every prompt; match without it.
const key = (user: string) => createHash("sha256").update(user.replace(/CLAWVET_UNTRUSTED_[0-9a-f]{32}/g, "B")).digest("hex");
const replies = new Map<string, string>();
if (mode === "replay") for (const f of readdirSync(join(out, "replies"))) {
  const r = JSON.parse(readFileSync(join(out, "replies", f), "utf8"));
  const prompt = JSON.parse(readFileSync(join(out, "prompts", f), "utf8"));
  replies.set(key(prompt.user), r.text);
}
let current = "";
globalThis.fetch = (async (_url: string, init: { body: string }) => {
  const body = JSON.parse(init.body);
  const system = body.messages.find((m: { role: string }) => m.role === "system").content;
  const user = body.messages.find((m: { role: string }) => m.role === "user").content;
  if (mode === "capture") {
    writeFileSync(join(out, "prompts", `${current}.json`), JSON.stringify({ id: current, key: key(user), system, user }));
    return new Response("captured", { status: 503 });
  }
  const text = replies.get(key(user));
  if (!text) return new Response("no reply", { status: 503 });
  return new Response(JSON.stringify({ choices: [{ message: { content: text } }] }), { status: 200, headers: { "content-type": "application/json" } });
}) as typeof fetch;

const config = resolveSemanticConfig({}, { provider: "openai", model: "replay", baseUrl: "http://localhost:1/v1", timeoutMs: 60_000 });
const judge = createSemanticJudge(config);
const rows: string[] = [];
for (const id of readdirSync(dir).sort()) {
  current = id;
  const content = assembleSkill(join(dir, id)).content;
  if (mode === "capture") { await judge(content).catch(() => {}); continue; }
  let raw: SemanticJudgment | undefined, rawError: string | undefined;
  try { raw = await judge(content); } catch (err) { rawError = String(err).slice(0, 120); }
  const { response } = await evaluateSkill(join(dir, id), { semantic: { judge, timeoutMs: 60_000, onError: "warn" } });
  rows.push(JSON.stringify({ id, decision: response.decision, reason: (response.reason ?? "").slice(0, 160),
    verdict: raw?.verdict, confidence: raw?.confidence, truncated: raw?.truncated, ungrounded: raw?.ungrounded, findings: raw?.findings.length, rawError }));
}
if (mode === "replay") writeFileSync(join(out, "replay.jsonl"), rows.join("\n") + "\n");
