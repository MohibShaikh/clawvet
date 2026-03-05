import { THREAT_PATTERNS } from "../patterns.js";
import type { Finding, ParsedSkill } from "../types.js";

function isInCodeBlock(lineNumber: number, skill: ParsedSkill): boolean {
  return skill.codeBlocks.some(
    (block) => lineNumber >= block.lineStart && lineNumber <= block.lineEnd
  );
}

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

      findings.push({
        category: threat.category,
        severity: threat.severity,
        title: threat.title,
        description: threat.description,
        evidence: match[0],
        lineNumber,
        analysisPass: "static-analysis",
      });
    }
  }

  return findings;
}
