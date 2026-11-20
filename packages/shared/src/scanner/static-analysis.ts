import { THREAT_PATTERNS } from "../patterns.js";
import type { BundledFile, Finding, ParsedSkill, Severity } from "../types.js";
import { codeLines } from "./sources.js";
import { lineIndex } from "./lines.js";

const HEADING = /^\s*#{1,6}\s/;


const BASE_CONFIDENCE: Record<Severity, number> = {
  critical: 0.9,
  high: 0.8,
  medium: 0.6,
  low: 0.5,
};

// Bundled scripts count as code, not only fenced blocks: a payload in
// scripts/run.sh is code whether or not SKILL.md quotes it.
export function runStaticAnalysis(skill: ParsedSkill, files: BundledFile[] = []): Finding[] {
  const findings: Finding[] = [];
  const code = codeLines(skill, files);
  const isInCodeBlock = (line: number) => code.has(line);
  const lines = skill.rawContent.split("\n");
  const lineOf = lineIndex(skill.rawContent);

  for (const threat of THREAT_PATTERNS) {
    const re = new RegExp(threat.pattern.source, threat.pattern.flags);
    let match: RegExpExecArray | null;

    while ((match = re.exec(skill.rawContent)) !== null) {
      const lineNumber = lineOf(match.index);

      if (threat.codeOnly && !isInCodeBlock(lineNumber)) {
        continue;
      }

      const inCode = isInCodeBlock(lineNumber);
      const inHeading = HEADING.test(lines[lineNumber - 1] ?? "");

      let contextMultiplier: number;
      if (inCode && threat.codeOnly) {
        contextMultiplier = 1.0;
      } else if (inCode) {
        contextMultiplier = 0.95;
      } else if (inHeading) {
        contextMultiplier = 0.5;
      } else if (threat.codeOnly) {
        // codeOnly pattern somehow in prose (shouldn't happen due to skip above)
        contextMultiplier = 0.4;
      } else {
        // Non-codeOnly patterns are designed to match in prose
        contextMultiplier = 0.9;
      }

      const baseConfidence = BASE_CONFIDENCE[threat.severity];
      // A curated indicator of compromise is an exact match, not a fuzzy
      // heuristic, where it appears does not make it less certain.
      const confidence = threat.disqualifying
        ? 1.0
        : Math.min(1.0, baseConfidence * contextMultiplier);

      findings.push({
        category: threat.category,
        severity: threat.severity,
        title: threat.title,
        description: threat.description,
        evidence: match[0],
        lineNumber,
        analysisPass: "static-analysis",
        confidence: Math.round(confidence * 100) / 100,
        fix: threat.fix,
        disqualifying: threat.disqualifying,
      });
    }
  }

  return findings;
}
