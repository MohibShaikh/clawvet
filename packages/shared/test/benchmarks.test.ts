import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { scanSkill } from "../src/index.js";

const BENCHMARKS_DIR = resolve(__dirname, "../../../benchmarks");

function loadSkill(category: string, name: string): string {
  const plainPath = resolve(BENCHMARKS_DIR, category, name, "SKILL.md");
  const b64Path = plainPath + ".b64";
  try {
    return readFileSync(plainPath, "utf-8");
  } catch {
    // Malicious fixtures are base64-encoded to avoid AV false positives
    const encoded = readFileSync(b64Path, "utf-8");
    return Buffer.from(encoded, "base64").toString("utf-8");
  }
}

describe("Benchmark suite", () => {
  describe("Malicious skills should score >= 50", () => {
    const malicious = [
      "rce-base64",
      "credential-theft",
      "prompt-injection",
      "obfuscated-shell",
      "typosquat",
    ];

    for (const name of malicious) {
      it(`${name} should be flagged as risky`, async () => {
        const content = loadSkill("malicious", name);
        const result = await scanSkill(content);
        expect(result.riskScore).toBeGreaterThanOrEqual(50);
        expect(result.findings.length).toBeGreaterThan(0);
      });
    }
  });

  describe("Benign skills should score <= 25", () => {
    const benign = [
      "todo-app",
      "git-helper",
      "markdown-formatter",
      "api-client",
      "file-organizer",
    ];

    for (const name of benign) {
      it(`${name} should be considered safe`, async () => {
        const content = loadSkill("benign", name);
        const result = await scanSkill(content);
        expect(result.riskScore).toBeLessThanOrEqual(25);
      });
    }
  });
});
