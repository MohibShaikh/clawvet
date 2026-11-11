import type { Finding, Severity } from "@clawvet/shared";
import { SemanticUnavailableError, validateConfig, type SemanticConfig } from "./config.js";
import { budgetContent, buildSemanticPrompt, CATEGORIES } from "./prompt.js";
import { requestVerdict } from "./providers.js";
import { cachePath, readCache, writeCache } from "./cache.js";
export { SemanticUnavailableError, resolveSemanticConfig } from "./config.js";
export type { SemanticConfig } from "./config.js";

export type Verdict = "benign" | "suspicious" | "malicious";
interface Evidence { category: string; severity: Severity; quote: string; explanation: string }
interface Judgment { verdict: Verdict; confidence: number; findings: Evidence[] }

/**
 * What a caller enforces. Findings alone are not enough: a grounded "malicious"
 * whose findings score under the warn line would otherwise install, so the
 * verdict travels with them, and so does whether the judge saw everything.
 */
export interface SemanticJudgment {
  verdict: Verdict;
  confidence: number;
  findings: Finding[];
  /** The bundle exceeded the content budget; the tail was not assessed. */
  truncated: boolean;
  /** Non-benign verdict, but no quote survived grounding. */
  ungrounded: boolean;
}

const severities: Severity[] = ["low", "medium", "high", "critical"];
// Bounds applied before any per-entry work, so a hostile or broken provider
// cannot make parsing slow enough to hold the deadline timer off.
const MAX_ENTRIES = 50;
const MAX_FINDINGS = 10;
const MAX_QUOTE = 300;
const MAX_EXPLANATION = 500;

export const normalizeWhitespace = (text: string): string => text.replace(/\s+/g, " ").trim();
const invalid = (): never => { throw new SemanticUnavailableError("invalid_response"); };
function hasKeys(value: unknown, keys: string[]): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value) && keys.every(key => Object.hasOwn(value, key));
}
// Models wrap JSON in fences or a sentence often enough that bare JSON.parse
// makes the judge unavailable in practice. Delimiter search, not a regex: an
// unterminated fence must not backtrack.
function extractJson(text: string): unknown {
  let body = text;
  const fence = text.indexOf("```");
  if (fence >= 0) {
    const close = text.indexOf("```", fence + 3);
    if (close > fence) body = text.slice(text.indexOf("\n", fence) + 1 || fence + 3, close);
  }
  const start = body.indexOf("{"), end = body.lastIndexOf("}");
  if (start < 0 || end <= start) return invalid();
  try { return JSON.parse(body.slice(start, end + 1)); } catch { return invalid(); }
}
export function parseVerdict(text: string, content: string, apiKey?: string): Judgment & { offered: number } {
  const value = extractJson(text);
  if (!hasKeys(value, ["verdict", "confidence", "findings"]) ||
      !["benign", "suspicious", "malicious"].includes(value.verdict as string) ||
      typeof value.confidence !== "number" || !Number.isFinite(value.confidence) || value.confidence < 0 || value.confidence > 1 ||
      !Array.isArray(value.findings)) return invalid();
  const findings: Evidence[] = [];
  const normalized = normalizeWhitespace(content);
  const entries = (value.findings as unknown[]).slice(0, MAX_ENTRIES);
  for (const entry of entries) {
    // One malformed entry is dropped, not the verdict: the rest is still evidence.
    if (!hasKeys(entry, ["category", "severity", "quote", "explanation"]) ||
        !CATEGORIES.includes(entry.category as string) || !severities.includes(entry.severity as Severity) ||
        typeof entry.quote !== "string" || entry.quote.length > 4 * MAX_QUOTE || !normalizeWhitespace(entry.quote) ||
        typeof entry.explanation !== "string") continue;
    // Check the entire quote before capping it, so fabricated suffixes cannot pass.
    if (!normalized.includes(normalizeWhitespace(entry.quote)) || (apiKey && entry.quote.includes(apiKey))) continue;
    let explanation = entry.explanation.slice(0, MAX_EXPLANATION);
    if (apiKey) explanation = explanation.split(apiKey).join("[REDACTED]");
    findings.push({ category: entry.category as string, severity: entry.severity as Severity, quote: entry.quote.slice(0, MAX_QUOTE), explanation });
    if (findings.length === MAX_FINDINGS) break;
  }
  return { verdict: value.verdict as Verdict, confidence: value.confidence, findings, offered: entries.length };
}

function majority(judgments: Judgment[]): Verdict {
  const votes = new Map<Verdict, number>();
  for (const judgment of judgments) votes.set(judgment.verdict, (votes.get(judgment.verdict) ?? 0) + 1);
  // Without a strict majority, use suspicious rather than inventing a consensus.
  return [...votes].find(([, count]) => count > judgments.length / 2)?.[0] ?? "suspicious";
}

export function combineVerdicts(judgments: Judgment[], original: string): Finding[] {
  const verdict = majority(judgments);
  const grouped = new Map<string, { evidence: Evidence; confidences: number[]; ranks: number[] }>();
  for (const judgment of judgments) {
    const seen = new Set<string>();
    for (const evidence of judgment.findings) {
      const key = JSON.stringify([evidence.category, normalizeWhitespace(evidence.quote)]);
      if (seen.has(key)) continue;
      seen.add(key);
      const group = grouped.get(key) ?? { evidence, confidences: [], ranks: [] };
      group.confidences.push(judgment.confidence);
      group.ranks.push(severities.indexOf(evidence.severity));
      grouped.set(key, group);
    }
  }
  const source = normalizeWhitespace(original);
  function quoteLine(quote: string): number | null {
    const target = source.indexOf(normalizeWhitespace(quote));
    if (target < 0) return null;
    let offset = 0;
    // Token boundaries retain original offsets without allocating a per-character map.
    for (const match of original.matchAll(/\S+/g)) {
      if (offset + match[0].length > target) {
        const position = match.index! + target - offset;
        return 1 + (original.slice(0, position).match(/\n/g)?.length ?? 0);
      }
      offset += match[0].length + 1;
    }
    return null;
  }
  const findings: Finding[] = [];
  for (const { evidence, confidences, ranks } of grouped.values()) {
    if (confidences.length <= judgments.length / 2) continue;
    const confidence = confidences.reduce((sum, value) => sum + value, 0) / confidences.length;
    // Model severity is capped: benign or confidence < .5 => low; suspicious or
    // confidence < .8 => medium; malicious >= .8 permits the model's full severity.
    const cap = verdict === "benign" || confidence < .5 ? 0 : verdict === "suspicious" || confidence < .8 ? 1 : 3;
    ranks.sort((a, b) => a - b);
    findings.push({ category: evidence.category, severity: severities[Math.min(cap, ranks[Math.floor((ranks.length - 1) / 2)])],
      title: `Semantic judge: ${evidence.category}`, evidence: evidence.quote,
      description: `${evidence.explanation}\nVerdict: ${verdict}. Agreement: ${confidences.length}/${judgments.length} (${(confidences.length / judgments.length).toFixed(2)}).`,
      confidence, lineNumber: quoteLine(evidence.quote), analysisPass: "semantic" });
    if (findings.length === MAX_FINDINGS) break;
  }
  return findings;
}

export function createSemanticJudge(config: SemanticConfig): (content: string, timeoutMs?: number) => Promise<SemanticJudgment> {
  // Snapshot caller-owned configuration, so concurrent runs use the same identity.
  config = { ...config };
  validateConfig(config);
  return async (content: string, timeoutMs = config.timeoutMs): Promise<SemanticJudgment> => {
    if (!(timeoutMs > 0)) throw new SemanticUnavailableError("timeout");
    const started = performance.now();
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout>;
    const deadline = new Promise<never>((_, reject) => {
      timer = setTimeout(() => { controller.abort(); reject(new SemanticUnavailableError("timeout")); }, timeoutMs);
    });
    const work = async (): Promise<SemanticJudgment> => {
      const budget = budgetContent(content, config.maxChars ?? 60_000);
      const judge = (judgments: Judgment[]): SemanticJudgment => {
        const verdict = majority(judgments);
        const findings = combineVerdicts(judgments, content);
        const confidence = judgments.reduce((sum, j) => sum + j.confidence, 0) / judgments.length;
        return { verdict, confidence, findings, truncated: budget.truncated, ungrounded: verdict !== "benign" && findings.length === 0 };
      };
      const path = config.cache ? cachePath(content, config) : undefined;
      if (path) {
        const cached = await readCache(path);
        if (cached?.length === (config.runs ?? 1)) {
          try { return judge(cached.map(text => parseVerdict(text, budget.content, config.apiKey))); }
          catch { /* Treat corrupt cache entries as misses. */ }
        }
      }
      if (controller.signal.aborted) throw new SemanticUnavailableError("timeout");
      const judgments = await Promise.all(Array.from({ length: config.runs ?? 1 }, async () => {
        const prompt = buildSemanticPrompt(budget.content, budget.truncated);
        return parseVerdict(await requestVerdict(config, prompt, controller.signal), budget.content, config.apiKey);
      }));
      const result = judge(judgments);
      if (path && !controller.signal.aborted) await writeCache(path, judgments.map(({ verdict, confidence, findings }) => JSON.stringify({ verdict, confidence, findings })));
      return result;
    };
    try {
      const result = await Promise.race([work(), deadline]);
      // Synchronous validation can cross the deadline before the timer gets a turn.
      if (performance.now() - started >= timeoutMs) throw new SemanticUnavailableError("timeout");
      return result;
    }
    finally { clearTimeout(timer!); controller.abort(); }
  };
}

/** Findings only, for ScanOptions.semanticAnalyzer. Enforcing callers use createSemanticJudge. */
export function createSemanticAnalyzer(config: SemanticConfig): (content: string) => Promise<Finding[]> {
  const judge = createSemanticJudge(config);
  return async (content: string) => (await judge(content)).findings;
}

/**
 * Why a judgment cannot clear a skill, or undefined if it can. A truncated or
 * ungrounded judgment is treated as no judgment, so padding a skill past the
 * budget or getting the judge to cite nothing cannot buy an allow.
 */
export function judgmentGap(judgment: SemanticJudgment): string | undefined {
  if (judgment.truncated) return "the skill exceeded the judge's content budget, so part of it was not assessed.";
  if (judgment.ungrounded) return `the judge said ${judgment.verdict} but cited nothing found in the skill.`;
  return undefined;
}
