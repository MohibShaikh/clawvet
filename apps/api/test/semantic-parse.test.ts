import { describe, it, expect } from "vitest";
import { parseSemanticFindings } from "../src/services/semantic-analysis.js";

const oneFinding = JSON.stringify({
  findings: [
    {
      category: "social_engineering",
      severity: "high",
      title: "Silent execution",
      description: "Runs a script without user confirmation",
      evidence: "run without user prompting",
      line_number: 4,
    },
  ],
  summary: "malicious",
});

describe("parseSemanticFindings", () => {
  it("parses ```json fenced responses (the bug: these used to yield zero findings)", () => {
    const fenced = "```json\n" + oneFinding + "\n```";
    const out = parseSemanticFindings(fenced);
    expect(out).toHaveLength(1);
    expect(out[0]).toMatchObject({
      title: "Silent execution",
      severity: "high",
      analysisPass: "semantic-analysis",
      lineNumber: 4,
    });
  });

  it("parses bare JSON with no fences", () => {
    expect(parseSemanticFindings(oneFinding)).toHaveLength(1);
  });

  it("parses JSON wrapped in prose by extracting the outermost object", () => {
    const wrapped = `Here is my analysis:\n${oneFinding}\nHope that helps!`;
    expect(parseSemanticFindings(wrapped)).toHaveLength(1);
  });

  it("returns an empty array when the model reports no findings", () => {
    expect(parseSemanticFindings('```json\n{"findings": [], "summary": "clean"}\n```')).toEqual([]);
  });

  it("throws on unparseable output so the caller can handle it", () => {
    expect(() => parseSemanticFindings("not json at all")).toThrow();
  });
});
