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
  // A reviewable gap lowers a clean verdict to warn and leaves a worse one alone.
  if (ask.length && result.recommendation === "approve") {
    return { ...result, recommendation: "warn", summary: coverageWarning(ask), coverage: assembly.coverage };
  }
  return { ...result, coverage: assembly.coverage };
}

export async function scanLocalSkill(
  skillFile: string,
  options: Parameters<typeof scanSkill>[1] = {},
  profile: Profile = "default",
): Promise<LocalScanResult> {
  const assembly = assembleSkill(dirname(skillFile), undefined, basename(skillFile));
  const result = await scanSkill(assembly.content, options);
  return applyCoverage(result, assembly, profile);
}
