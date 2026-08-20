import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync, existsSync } from "node:fs";
import { resolve } from "node:path";
import { scanSkill } from "../src/index.js";

const BENCHMARKS_DIR = resolve(__dirname, "../../../benchmarks");
const WARN_THRESHOLD = 26; // scanSkill recommends "warn" at >= 26, "approve" below

function listSkills(category: string): string[] {
  const base = resolve(BENCHMARKS_DIR, category);
  if (!existsSync(base)) return [];
  return readdirSync(base).sort();
}

function loadSkill(category: string, name: string): string {
  const plain = resolve(BENCHMARKS_DIR, category, name, "SKILL.md");
  if (existsSync(plain)) return readFileSync(plain, "utf-8");
  const encoded = readFileSync(plain + ".b64", "utf-8");
  return Buffer.from(encoded, "base64").toString("utf-8");
}

async function score(category: string, name: string): Promise<number> {
  const result = await scanSkill(loadSkill(category, name), { skipCache: true });
  return result.riskScore;
}

// The full corpus is the evaluation set consumed by benchmarks/eval.py. These
// tests guard the two invariants the eval relies on. Clean skills are never
// flagged, and nearly every malicious skill is.
describe("Benchmark corpus", () => {
  describe("Clearly-benign skills must never be flagged (score < 26)", () => {
    for (const name of listSkills("benign")) {
      it(`${name} scores in the approve band`, async () => {
        expect(await score("benign", name)).toBeLessThan(WARN_THRESHOLD);
      });
    }
  });

  it("catches >= 90% of malicious skills at the warn threshold", async () => {
    const malicious = listSkills("malicious");
    const scores = await Promise.all(malicious.map((n) => score("malicious", n)));
    const flagged = scores.filter((s) => s >= WARN_THRESHOLD).length;
    // A few fixtures such as hex-payload are evasion cases a static scanner
    // cannot catch. They stay in as honest negative-result data.
    expect(flagged / malicious.length).toBeGreaterThanOrEqual(0.9);
  });

  it("hard negatives parse and are (by design) over-flagged", async () => {
    const hardNegatives = listSkills("hard-negatives");
    expect(hardNegatives.length).toBeGreaterThan(0);
    const scores = await Promise.all(hardNegatives.map((n) => score("hard-negatives", n)));
    // These are legit skills that trip credential/exec rules, label 0 in the
    // eval. Their false positives are what the semantic stage should recover.
    // Assert only that the over-flagging still exists, so a regression that
    // hides it here instead of in the classifier stays visible.
    expect(scores.some((s) => s >= WARN_THRESHOLD)).toBe(true);
  });
});
