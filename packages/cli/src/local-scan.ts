import { basename, dirname } from "node:path";
import { scanSkill } from "@clawvet/shared";
import type { ScanResult } from "@clawvet/shared";
import { assembleSkill, coverageReason, coverageWarning, type AssemblyResult } from "./assemble.js";
import { applyProfile, type Profile } from "./policy.js";

export type LocalScanResult = ScanResult & { coverage: AssemblyResult["coverage"] };

export function applyCoverage(result: ScanResult, assembly: AssemblyResult, profile: Profile = "default"): LocalScanResult {
  const { block, ask } = applyProfile(assembly.coverage, profile);
  if (block.length) {
    // Coverage failure is not a malware score. Preserve the partial findings but
    // explicitly fail the scan and override its recommendation outside scoring,
    // ignore policies, and cache storage.
    return { ...result, status: "failed", recommendation: "block", summary: coverageReason(block), coverage: assembly.coverage };
  }
  // Some gaps the default profile only asks about (a missing script, a path
  // outside the skill) still leave code uninspected. The install gate asks the
  // operator; a scan has no one to ask, so CI, audit and badges still treat the
  // inspection as failed. A baseline accepts a known gap.
  const status = ask.some((gap) => assembly.coverage.issues.includes(gap)) ? "failed" : result.status;
  // A reviewable gap lowers a clean verdict to warn and leaves a worse one alone.
  if (ask.length && result.recommendation === "approve") {
    return { ...result, status, recommendation: "warn", summary: coverageWarning(ask), coverage: assembly.coverage };
  }
  return { ...result, status, coverage: assembly.coverage };
}

export async function scanLocalSkill(
  skillFile: string,
  options: Parameters<typeof scanSkill>[1] = {},
  profile: Profile = "default",
): Promise<LocalScanResult> {
  const assembly = assembleSkill(dirname(skillFile), undefined, basename(skillFile));
  const result = await scanSkill(assembly.content, { ...options, files: assembly.coverage.files });
  return applyCoverage(result, assembly, profile);
}

export type FailOn = "critical" | "high" | "medium" | "low";
const SEVERITY_ORDER = ["low", "medium", "high", "critical"];

/** Whether any finding is at or above the --fail-on severity. */
export function failsAt(result: ScanResult, failOn: FailOn): boolean {
  const threshold = SEVERITY_ORDER.indexOf(failOn);
  return result.findings.some((f) => SEVERITY_ORDER.indexOf(f.severity) >= threshold);
}
