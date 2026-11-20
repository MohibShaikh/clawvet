import type { Finding, SourceFile } from "../../types.js";
import { DataflowDeadline, type DataflowFrontend, type DataflowState } from "./ir.js";
import { analyzeProgram } from "./engine.js";
import { createParser } from "./parser.js";
import { pythonFrontend } from "./frontends/python.js";
import { javascriptFrontend, typescriptFrontend, tsxFrontend } from "./frontends/javascript.js";
import { shellFrontend } from "./frontends/shell.js";

export { DataflowDeadline } from "./ir.js";
export type { DataflowFrontend, DataflowState, IRProgram, IRFunction, IRNode, LanguageSpecs, CallRule, AccessRule, TaintKind, TaintFlag } from "./ir.js";
export { analyzeProgram } from "./engine.js";

// One entry per language; the engine has no language cases.
const frontends: Partial<Record<SourceFile["language"], DataflowFrontend>> = {
  python: pythonFrontend, javascript: javascriptFrontend, typescript: typescriptFrontend, shell: shellFrontend,
};
// .tsx needs its own grammar; a fenced block has no extension and stays typescript.
const frontendFor = (source: SourceFile) =>
  source.language === "typescript" && /\.tsx$/i.test(source.path) ? tsxFrontend : frontends[source.language];

export async function analyzeDataflow(sources: SourceFile[], options: { budgetMs?: number } = {}): Promise<Finding[]> {
  const budget = options.budgetMs ?? 250;
  let remaining = Number.isFinite(budget) ? Math.max(0, budget) : 250;
  const findings: Finding[] = [];
  let truncated = false;
  const state: DataflowState = { incomplete: false };
  for (const source of sources) {
    const frontend = frontendFor(source);
    if (!frontend) continue;
    // Most fenced snippets name no API a finding needs; parsing them is the bulk of the cost.
    if (frontend.mayFind && !frontend.mayFind(source.text)) continue;
    if (remaining <= 0) { truncated = true; break; }
    // One-time WASM runtime and grammar loading happen outside the per-skill
    // analysis budget so a cold process does not silently truncate its first skill.
    const parser = await createParser(frontend.grammar);
    const stepStart = performance.now();
    const deadline = stepStart + remaining;
    let tree;
    try {
      // Cancel a parse that crosses the deadline, so one huge file cannot hold
      // the install hook past its budget. Returning true cancels (web-tree-sitter).
      const progressCallback = (() => performance.now() >= deadline) as unknown as NonNullable<Parameters<typeof parser.parse>[2]>["progressCallback"];
      tree = parser.parse(source.text, null, { progressCallback });
      if (!tree) { truncated = true; break; }
      const program = frontend.lower(tree.rootNode, source, deadline, state);
      findings.push(...analyzeProgram(program, frontend.specs, deadline, state));
    } catch (err) {
      // Out of budget mid-file: report truncation. Anything else is an
      // unexpected partial-tree shape and must not stop the rest of the scan,
      // but the file went unanalysed, so it is reported as incomplete.
      if (err instanceof DataflowDeadline) truncated = true;
      else state.incomplete = true;
    } finally {
      remaining -= performance.now() - stepStart;
      tree?.delete();
      parser.delete();
    }
    if (truncated) break;
    if (remaining <= 0) { truncated = true; break; }
  }
  // Across sources too: SKILL.md shows one API key in a dozen fenced examples.
  const keysSent = new Set<string>();
  const unique = findings.filter((f) => {
    const key = f.severity === "medium" && f.category === "data_exfiltration" ? / env (\w+)/.exec(f.evidence ?? "")?.[1] : undefined;
    if (!key) return true;
    if (keysSent.has(key)) return false;
    keysSent.add(key);
    return true;
  });
  findings.length = 0;
  findings.push(...unique);
  if (truncated) findings.push({ category: "metadata", severity: "low", title: "Dataflow analysis truncated", description: "The per-skill dataflow time budget was exhausted; remaining code was not analysed.", analysisPass: "dataflow" });
  else if (state.incomplete) findings.push({ category: "metadata", severity: "low", title: "Dataflow analysis truncated", description: "Code nested too deeply or too large for the dataflow limits was not fully analysed.", analysisPass: "dataflow" });
  return findings;
}
