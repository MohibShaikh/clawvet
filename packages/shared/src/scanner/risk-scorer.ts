import type { Finding, FindingsCount, RiskGrade } from "../types.js";

const SEVERITY_WEIGHTS = {
  critical: 30,
  high: 15,
  medium: 7,
  low: 3,
} as const;

// A disqualifying indicator of compromise pins the score to the bottom of the
// F band regardless of aggregate, enough benign signal must never dilute a
// known-bad match down into a passing grade.
const DISQUALIFYING_FLOOR = 90;

// Identical matches of the same rule count with diminishing returns. A rule
// matching the same evidence on four lines is one concern repeated, and letting
// it stack linearly is what pushes legitimate skills (an ssh helper that reads
// ~/.ssh a few times) into the block band. The first hit counts full; each
// extra identical hit counts at this fraction, so repetition still adds signal
// without dominating.
const REPEAT_FACTOR = 0.25;

function weight(f: Finding): number {
  return SEVERITY_WEIGHTS[f.severity] * (f.confidence ?? 1.0);
}

// Key on title plus evidence, not title alone. Five "prerequisite install"
// matches on five different lines are five separate malicious instructions and
// each must count full; only identical matches on different lines discount.
function repeatKey(f: Finding): string {
  return `${f.title}\u0000${f.evidence ?? ""}`;
}

export function calculateRiskScore(findings: Finding[]): number {
  const byKey = new Map<string, Finding[]>();
  for (const f of findings) {
    // Metadata findings are documentation hygiene, not risk. An undeclared
    // `grep` says the frontmatter is incomplete, not that the skill is
    // dangerous, and a skill using eight ordinary unix tools would otherwise
    // accumulate enough of them to be flagged on its own. They are still
    // reported, they just do not move the score.
    if (f.category === "metadata") continue;
    const key = repeatKey(f);
    const arr = byKey.get(key);
    if (arr) arr.push(f);
    else byKey.set(key, [f]);
  }

  let score = 0;
  for (const group of byKey.values()) {
    group.sort((a, b) => weight(b) - weight(a));
    group.forEach((f, i) => {
      score += i === 0 ? weight(f) : weight(f) * REPEAT_FACTOR;
    });
  }
  if (findings.some((f) => f.disqualifying)) {
    score = Math.max(score, DISQUALIFYING_FLOOR);
  }
  return Math.round(Math.min(score, 100));
}

export function getRiskGrade(score: number): RiskGrade {
  if (score <= 10) return "A";
  if (score <= 25) return "B";
  if (score <= 50) return "C";
  if (score <= 75) return "D";
  return "F";
}

export function countFindings(findings: Finding[]): FindingsCount {
  const counts: FindingsCount = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) {
    counts[f.severity]++;
  }
  return counts;
}
