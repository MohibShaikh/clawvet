import { describe, expect, it } from "vitest";
import { normalizeFrontmatter, parseFences } from "../src/scanner/skill-parser.js";
import { codeLines, parseSkill, scanSkill } from "../src/index.js";

describe("parseFences", () => {
  it("reads the language from an info string with attributes", () => {
    const [block] = parseFences('```python title="main.py"\nprint(1)\n```\n');
    expect(block).toMatchObject({ language: "python", content: "print(1)\n", lineStart: 1, lineEnd: 3 });
  });

  it("an info string does not flip the fences after it", () => {
    const text = [
      '```python title="main.py"', "print(1)", "```",
      "Prose between the blocks.",
      "```bash", "echo placeholder", "```",
    ].join("\n");
    const blocks = parseFences(text);
    expect(blocks.map((b) => [b.language, b.lineStart, b.lineEnd])).toEqual([["python", 1, 3], ["bash", 5, 7]]);
    const code = codeLines(parseSkill(text));
    expect(code.has(4)).toBe(false);
    expect(code.has(6)).toBe(true);
  });

  it("reads fences inside blockquotes and strips the quote markers", () => {
    const [block] = parseFences("> ```bash\n> echo placeholder\n> ```\n");
    expect(block).toMatchObject({ language: "bash", content: "echo placeholder\n", lineEnd: 3 });
  });

  it("closes only on the same fence character, at least as long", () => {
    const blocks = parseFences("````md\n```bash\necho placeholder\n```\n````\n~~~sh\necho placeholder\n~~~\n");
    expect(blocks.map((b) => [b.language, b.lineStart, b.lineEnd])).toEqual([["md", 1, 5], ["sh", 6, 8]]);
  });

  it("an unclosed fence runs to the end", () => {
    const [block] = parseFences("```bash\necho placeholder\nmore\n");
    expect(block).toMatchObject({ lineStart: 1, lineEnd: 4 });
  });

  it("inline triple backticks in prose are not a fence", () => {
    expect(parseFences("Use ```code``` inline.\n")).toEqual([]);
  });
});

describe("fences across bundled files", () => {
  it("a fence left open in one file does not swallow the next", () => {
    const content = ["---", "name: demo", "---", "Intro.", '"""', "```py", '"""', "```python", "print(1)", "```"].join("\n");
    // SKILL.md is lines 1-4, a.py 5-7 (code, no fences), b.md 8-10.
    const files = [
      { path: "SKILL.md", startLine: 1, endLine: 4 },
      { path: "a.py", startLine: 5, endLine: 7 },
      { path: "b.md", startLine: 8, endLine: 10 },
    ];
    const blocks = parseSkill(content, files).codeBlocks;
    expect(blocks.map((b) => [b.language, b.lineStart, b.lineEnd])).toEqual([["python", 8, 10]]);
  });

  it("reads fences nested in list items", () => {
    const [block] = parseFences("1. Run it:\n\n     ```bash\n     echo placeholder\n     ```\n");
    expect(block).toMatchObject({ language: "bash", lineStart: 3, lineEnd: 5 });
  });

  it("a labelled fence line inside an open fence is content", () => {
    const blocks = parseFences("```\n```bash\necho placeholder\n```\n");
    expect(blocks.map((b) => [b.lineStart, b.lineEnd, b.content])).toEqual([[1, 4, "```bash\necho placeholder\n"]]);
  });
});

describe("normalizeFrontmatter", () => {
  it.each([null, 3, "text", ["a"]])("%j becomes empty", (raw) => expect(normalizeFrontmatter(raw)).toEqual({}));

  it("keeps strings, stringifies numbers, drops other shapes", () => {
    const fm = normalizeFrontmatter({ name: 123, version: 1.2, description: { a: 1 }, metadata: { openclaw: { requires: { env: ["A", { b: 1 }, 3], bins: "node" } } } });
    expect(fm.name).toBe("123");
    expect(fm.version).toBe("1.2");
    expect(fm.description).toBeUndefined();
    expect(fm.metadata?.openclaw?.requires?.env).toEqual(["A"]);
    expect(fm.metadata?.openclaw?.requires?.bins).toBeUndefined();
  });

  it.each(["---\nnull\n---\nbody", "---\nname: 123\n---\nbody", "---\n- a\n- b\n---\nbody", "---\nmetadata: 5\n---\nbody", "---\nmetadata:\n  openclaw: [1]\n---\nbody"])(
    "scanSkill survives %j", async (content) => {
      await expect(scanSkill(content, { skipCache: true })).resolves.toMatchObject({ status: "complete" });
    });
});
