import type { BundledFile, Finding, Recommendation, ScanResult } from "../types.js";
import { parseSkill } from "./skill-parser.js";
import { runStaticAnalysis } from "./static-analysis.js";
import { validateMetadata } from "./metadata-validator.js";
import { checkDependencies } from "./dependency-checker.js";
import { detectTyposquats } from "./typosquat-detector.js";
import { applyContext, onlyTrustedInstallers } from "./context-classifier.js";
import { calculateRiskScore, getRiskGrade, countFindings } from "./risk-scorer.js";
import { getCached, setCached } from "./cache.js";
import { codeLines, collectSources } from "./sources.js";
import { analyzeDataflow } from "./dataflow/index.js";

export interface ScanOptions {
  semantic?: boolean;
  semanticAnalyzer?: (content: string) => Promise<Finding[]>;
  ignorePatterns?: string[];
  skipCache?: boolean;
  /** Fallback name when SKILL.md frontmatter is missing `name`. Typically the folder basename. */
  skillName?: string;
  /**
   * Files the CLI appended to `content` (AssemblyResult.coverage.files). Their
   * lines are code to the code-only rules and the context pass. Without it only
   * fenced blocks are code, which is right for a bare SKILL.md.
   */
  files?: BundledFile[];
}

// The report's thresholds. A gate may block lower via --block-at.
export function recommend(riskScore: number): Recommendation {
  return riskScore >= 76 ? "block" : riskScore >= 26 ? "warn" : "approve";
}

/**
 * The same result over a different finding set, for passes that run after the
 * scan: network lookups that add findings, baselines that remove them. The
 * context pass is not re-run; added findings are not dual-use capabilities.
 */
export function rescore(result: ScanResult, findings: Finding[]): ScanResult {
  const riskScore = calculateRiskScore(findings);
  return { ...result, findings, riskScore, riskGrade: getRiskGrade(riskScore),
    findingsCount: countFindings(findings), recommendation: recommend(riskScore) };
}

export async function scanSkill(
  content: string,
  options: ScanOptions = {}
): Promise<ScanResult> {
  if (options.semantic && !options.semanticAnalyzer) {
    throw new Error("Semantic analysis requested without a semantic analyzer");
  }
  // Provider identity/configuration may change: semantic results are never cached.
  const cacheable = !options.skipCache && !options.semantic;
  const cacheKey = JSON.stringify([content, options.ignorePatterns ?? [], options.skillName ?? null, options.files ?? []]);
  if (cacheable) {
    const cached = getCached(cacheKey);
    if (cached) {
      return { ...cached, cached: true };
    }
  }

  const skill = parseSkill(content);
  const allFindings: Finding[] = [];

  const files = options.files ?? [];
  allFindings.push(...runStaticAnalysis(skill, files));
  allFindings.push(...validateMetadata(skill));

  if (options.semantic && options.semanticAnalyzer) {
    const semanticFindings = await options.semanticAnalyzer(content);
    allFindings.push(...semanticFindings);
  }

  allFindings.push(...checkDependencies(skill));

  if (skill.frontmatter.name) {
    allFindings.push(...detectTyposquats(skill.frontmatter.name));
  }

  // Filter out ignored patterns
  const filteredFindings = options.ignorePatterns?.length
    ? allFindings.filter(
        (f) => !options.ignorePatterns!.some((ig) => f.title === ig || f.category === ig)
      )
    : allFindings;

  // Context pass: downweight dual-use capabilities that have no exfil/exec sink.
  // It uses code lines to tell a real use of a credential or exfil channel from
  // a mention of one in prose or frontmatter.
  // Dataflow findings join after it: each one is already a proven flow from a
  // source to a sink, which is what that pass looks for between regex hits.
  const ignored = (f: Finding) => options.ignorePatterns?.some((ig) => f.title === ig || f.category === ig) ?? false;
  // A vendor's documented one-line installer is exempt here as it is in the
  // regex and coverage layers, so the three never disagree about `curl | sh`.
  const lines = content.split("\n");
  const vendorInstaller = (f: Finding) => f.category === "remote_code_execution" && f.lineNumber != null && onlyTrustedInstallers(lines[f.lineNumber - 1] ?? "");
  const dataflow = (await analyzeDataflow(collectSources(skill, files))).filter((f) => !ignored(f) && !vendorInstaller(f));
  const contextFindings = [...applyContext(filteredFindings, codeLines(skill, files)), ...dataflow];

  const riskScore = calculateRiskScore(contextFindings);
  const riskGrade = getRiskGrade(riskScore);
  // Report what was scored. Showing the pre-context findings would explain the
  // score wrong: a promoted envelope pair would read as two mediums next to a
  // score only a high can produce.
  const findingsCount = countFindings(contextFindings);

  const recommendation = recommend(riskScore);

  const result: ScanResult = {
    skillName: skill.frontmatter.name || options.skillName || "unknown",
    skillVersion: skill.frontmatter.version,
    skillSource: "local",
    status: "complete",
    riskScore,
    riskGrade,
    findingsCount,
    findings: contextFindings,
    recommendation,
  };

  if (cacheable) {
    setCached(cacheKey, result);
  }

  return result;
}

export { parseSkill } from "./skill-parser.js";
export { collectSources, codeLines, languageOf, isCode } from "./sources.js";
export { extractPinnedDependencies, type PinnedDependency } from "./manifests.js";
export { isTrustedInstallerUrl, onlyTrustedInstallers } from "./context-classifier.js";
export { runStaticAnalysis } from "./static-analysis.js";
export { validateMetadata } from "./metadata-validator.js";
export { checkDependencies } from "./dependency-checker.js";
export { detectTyposquats } from "./typosquat-detector.js";
export { calculateRiskScore, getRiskGrade, countFindings } from "./risk-scorer.js";
