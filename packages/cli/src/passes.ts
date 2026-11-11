import { collectSources, extractPinnedDependencies, parseSkill, rescore, type BundledFile, type ScanResult } from "@clawvet/shared";
import type { AssemblyResult } from "./assemble.js";
import { queryOsv } from "./osv.js";
import { suppressCoverage, suppressFindings, type Baseline, type SuppressedItem } from "./suppress.js";

// Passes around scanSkill that the CLI owns: the OSV lookup needs the network,
// and baselines are operator files. Both scan and gate run them in this order:
// accepted coverage gaps first, then the scan with OSV alongside, then accepted
// findings, so a suppressed gap never blocks and a suppressed finding never scores.

export interface PassOptions {
  osv?: { timeoutMs?: number; cache?: boolean };
  baseline?: Baseline;
  skillRoot?: string;
}

export function startOsv(content: string, files: BundledFile[], osv: PassOptions["osv"]) {
  if (!osv) return undefined;
  const deps = extractPinnedDependencies(collectSources(parseSkill(content), files));
  return queryOsv(deps, { timeoutMs: osv.timeoutMs ?? 3000, cache: osv.cache });
}

export function acceptCoverage(assembly: AssemblyResult, options: PassOptions): { assembly: AssemblyResult; suppressed: SuppressedItem[] } {
  if (!options.baseline || !options.skillRoot) return { assembly, suppressed: [] };
  return suppressCoverage(assembly, options.baseline, { skillRoot: options.skillRoot });
}

export async function finishScan(
  result: ScanResult,
  assembly: AssemblyResult | undefined,
  osv: ReturnType<typeof startOsv>,
  options: PassOptions,
): Promise<{ result: ScanResult; suppressed: SuppressedItem[]; osvErrors: string[] }> {
  let osvErrors: string[] = [];
  if (osv) {
    const lookup = await osv;
    osvErrors = lookup.errors;
    if (lookup.findings.length) result = rescore(result, [...result.findings, ...lookup.findings]);
  }
  if (!options.baseline || !options.skillRoot || !assembly) return { result, suppressed: [], osvErrors };
  const accepted = suppressFindings(result, assembly, options.baseline, { skillRoot: options.skillRoot });
  return { result: accepted.result, suppressed: accepted.suppressed, osvErrors };
}
