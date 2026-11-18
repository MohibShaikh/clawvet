// Judge v2 on a sample, without giving this process the network.
//   capture: static scan, evidence packet, and the exact v2 prompt per skill.
//   replay:  parse the stored reply with ClawVet's v2 parser and classify.
// Reads files only. Run both modes inside the no-network sandbox.
// Usage: npx tsx judge2-replay.mts capture|replay <skills dir> <out dir>
import { mkdirSync, readFileSync, readdirSync, writeFileSync, existsSync } from "node:fs";
import { createHash } from "node:crypto";
import { basename, join } from "node:path";
import { scanSkill } from "@clawvet/shared";
import { assembleSkill } from "../../packages/cli/src/assemble.js";
import { evaluateSkill } from "../../packages/cli/src/commands/gate.js";
import { budgetContent } from "../../packages/cli/src/semantic/prompt.js";
import { buildEvidence, buildPromptV2, classifyV2, parseVerdictV2, type Action } from "../../packages/cli/src/semantic/judge2.js";

const [mode, dir, out] = process.argv.slice(2);
process.env.CLAWVET_TELEMETRY = "off";
mkdirSync(join(out, "prompts"), { recursive: true });
const key = (user: string) => createHash("sha256").update(user.replace(/CLAWVET_UNTRUSTED_[0-9a-f]{32}/g, "B")).digest("hex");
const rows: string[] = [];
for (const id of readdirSync(dir).sort()) {
  const path = join(dir, id);
  const assembly = assembleSkill(path);
  const result = await scanSkill(assembly.content, { skillName: basename(path), files: assembly.coverage.files });
  const gaps = [...assembly.coverage.issues, ...assembly.coverage.warnings];
  const evidence = buildEvidence(result, gaps);
  const budget = budgetContent(assembly.content, 60_000);
  if (mode === "capture") {
    const prompt = buildPromptV2(budget.content, budget.truncated, evidence);
    writeFileSync(join(out, "prompts", `${id}.json`), JSON.stringify({ id, key: key(prompt.user), system: prompt.system, user: prompt.user }));
    continue;
  }
  const staticAction = (await evaluateSkill(path)).response.decision as Action;
  const disqualified = result.findings.some((f) => f.disqualifying);
  let judgment, error: string | undefined;
  const reply = join(out, "replies", `${id}.json`);
  if (existsSync(reply)) {
    try { judgment = parseVerdictV2(JSON.parse(readFileSync(reply, "utf8")).text, budget.content, evidence); }
    catch (err) { error = String(err).slice(0, 120); }
  } else error = "no reply";
  const findingsBlock = result.riskScore >= 76 || result.findings.some((f) => f.severity === "critical");
  const c = classifyV2({ judgment, truncated: budget.truncated, staticAction, disqualified, gaps, evidence, findingsBlock });
  rows.push(JSON.stringify({ id, verdict: c.verdict, action: c.action, why: c.why, raw: judgment?.verdict, staticAction,
    evidence: evidence.length, reviews: judgment?.reviews.length, cleared: judgment?.reviews.filter((r) => r.expected && r.grounded).length,
    grounded: judgment?.grounded, truncated: budget.truncated, error }));
}
if (mode === "replay") writeFileSync(join(out, "replay.jsonl"), rows.join("\n") + "\n");
