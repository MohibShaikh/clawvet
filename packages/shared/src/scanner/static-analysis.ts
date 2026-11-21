import { THREAT_PATTERNS } from "../patterns.js";
import type { BundledFile, Finding, ParsedSkill, Severity } from "../types.js";
import { codeLines } from "./sources.js";
import { lineIndex } from "./lines.js";

const HEADING = /^\s*#{1,6}\s/;

// Fast literal prefilters (strict supersets) for line-anchored or wide-gap
// patterns that rarely fire, avoiding per-line lookahead scans on 2 MiB skills.
const PATTERN_PREFILTER: Record<string, RegExp> = {
  CURL_PIPE_BASH: /curl\s/i,
  WGET_EXECUTE: /wget\s/i,
  DNS_EXFIL: /dig\s|nslookup\s|exfil|burpcollaborator|oastify/i,
  CRYPTO_MINER_CONFIG: /nicehash|stratum\+|donate-level|xmrig/i,
  PIPED_UPLOAD: /curl\b/i,
  SUBSTITUTED_UPLOAD: /curl\b/,
  DNS_DATA_LABEL: /\b(?:dig|nslookup|host)\b/,
  SYSTEM_ACCOUNTS_UPLOAD: /\/etc\/(?:passwd|shadow)\b/,
  CLOUD_METADATA_CREDENTIALS: /169\.254\.169\.254|metadata\.google\.internal/,
  HTML_COMMENT_INJECTION: /<!--/,
  PYTHON_EXEC_PAYLOAD: /python3?\s+-c/,
  NODE_EVAL_PAYLOAD: /node\s+(?:-e|--eval|-p|--print)/,
};


const BASE_CONFIDENCE: Record<Severity, number> = {
  critical: 0.9,
  high: 0.8,
  medium: 0.6,
  low: 0.5,
};

// Bundled scripts count as code, not only fenced blocks: a payload in
// scripts/run.sh is code whether or not SKILL.md quotes it.
export function runStaticAnalysis(
  skill: ParsedSkill,
  files: BundledFile[] = [],
  precomputed?: { code?: Set<number>; lines?: string[] },
): Finding[] {
  const findings: Finding[] = [];
  const code = precomputed?.code ?? codeLines(skill, files);
  const isInCodeBlock = (line: number) => code.has(line);
  const lines = precomputed?.lines ?? skill.rawContent.split("\n");
  const lineOf = lineIndex(skill.rawContent);

  for (const threat of THREAT_PATTERNS) {
    if (threat.codeOnly && code.size === 0) continue;
    const prefilter = PATTERN_PREFILTER[threat.name];
    if (prefilter && !prefilter.test(skill.rawContent)) continue;
    // Reuse the compiled RegExp rather than recompiling every pattern per scan.
    const re = threat.pattern;
    re.lastIndex = 0;
    let match: RegExpExecArray | null;

    while ((match = re.exec(skill.rawContent)) !== null) {
      if (match[0].length === 0) {
        re.lastIndex++;
        continue;
      }
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
