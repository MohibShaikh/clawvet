import { THREAT_PATTERNS } from "../patterns.js";
import type { Finding, ParsedSkill, Severity } from "../types.js";

function isInCodeBlock(lineNumber: number, skill: ParsedSkill): boolean {
  return skill.codeBlocks.some(
    (block) => lineNumber >= block.lineStart && lineNumber <= block.lineEnd
  );
}

function isInHeading(lineNumber: number, rawContent: string): boolean {
  const lines = rawContent.split("\n");
  const line = lines[lineNumber - 1] || "";
  return /^\s*#{1,6}\s/.test(line);
}

const BASE_CONFIDENCE: Record<Severity, number> = {
  critical: 0.9,
  high: 0.8,
  medium: 0.6,
  low: 0.5,
};

export function runStaticAnalysis(skill: ParsedSkill): Finding[] {
  const findings: Finding[] = [];

  for (const threat of THREAT_PATTERNS) {
    const re = new RegExp(threat.pattern.source, threat.pattern.flags);
    let match: RegExpExecArray | null;

    while ((match = re.exec(skill.rawContent)) !== null) {
      const before = skill.rawContent.slice(0, match.index);
      const lineNumber = before.split("\n").length;

      if (threat.codeOnly && !isInCodeBlock(lineNumber, skill)) {
        continue;
      }

      const inCode = isInCodeBlock(lineNumber, skill);
      const inHeading = isInHeading(lineNumber, skill.rawContent);

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
      // heuristic — where it appears does not make it less certain.
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
