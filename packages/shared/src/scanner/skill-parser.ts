import { parse as parseYaml } from "yaml";
import type { BundledFile, ParsedSkill, SkillFrontmatter, CodeBlock } from "../types.js";
import { isCode, languageOf } from "./sources.js";

const FRONTMATTER_RE = /^---\r?\n([\s\S]*?)\r?\n---/;
// An opening fence: blockquote markers, any indentation (fences nested in list
// items are indented past CommonMark's three spaces), then three or more
// backticks or tildes and an optional info string. A regex over the whole text
// that wanted ```` ```lang\n ```` skipped ```` ```python title="x" ```` and
// paired the next closing fence as an opener, flipping code and prose for every
// fence after it.
const FENCE_OPEN = /^((?:[ \t]*>)*[ \t]*)(`{3,}|~{3,})([^\n]*)$/;
const URL_RE = /https?:\/\/[^\s"'<>\])+]+/gi;
const IP_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const DOMAIN_RE = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b/gi;

const text = (value: unknown) => (typeof value === "string" ? value : undefined);
const names = (value: unknown) => (Array.isArray(value) ? value.filter((v): v is string => typeof v === "string") : undefined);

/**
 * Frontmatter is untrusted YAML: it can parse to null, a list, or a number
 * where a name belongs. Keep only the shapes the scanner reads, so a skill
 * cannot crash the scan (and fail the gate closed) with `name: 123`.
 */
export function normalizeFrontmatter(raw: unknown): SkillFrontmatter {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return {};
  const fm = { ...(raw as Record<string, unknown>) } as Record<string, unknown>;
  for (const key of ["name", "description", "version"]) {
    // A YAML number such as `version: 1.2` is still the author's version.
    if (typeof fm[key] === "number") fm[key] = String(fm[key]);
    else if (fm[key] !== undefined && typeof fm[key] !== "string") delete fm[key];
  }
  const openclaw = (fm.metadata as { openclaw?: unknown } | undefined)?.openclaw;
  if (fm.metadata !== undefined && (typeof fm.metadata !== "object" || fm.metadata === null || Array.isArray(fm.metadata))) delete fm.metadata;
  else if (openclaw !== undefined) {
    const oc = openclaw && typeof openclaw === "object" && !Array.isArray(openclaw) ? openclaw as Record<string, unknown> : {};
    const requires = oc.requires && typeof oc.requires === "object" && !Array.isArray(oc.requires) ? oc.requires as Record<string, unknown> : undefined;
    const cleaned = { ...oc, ...(requires ? { requires: { ...requires, env: names(requires.env), bins: names(requires.bins) } } : { requires: undefined }) };
    fm.metadata = { ...(fm.metadata as object), openclaw: cleaned };
  }
  return fm as SkillFrontmatter;
}

/**
 * `files` are the bundled files the CLI appended to `content`. Fences are read
 * inside each prose file on its own, so a fence left open in one file cannot
 * swallow the next one, and code files contribute none.
 */
export function parseSkill(content: string, files: BundledFile[] = []): ParsedSkill {
  let frontmatter: SkillFrontmatter = {};
  let body = content;

  const fmMatch = content.match(FRONTMATTER_RE);
  if (fmMatch) {
    try {
      frontmatter = normalizeFrontmatter(parseYaml(fmMatch[1]));
    } catch {
      frontmatter = {};
    }
    body = content.slice(fmMatch[0].length).trim();
  }

  const codeBlocks = files.length ? fencesByFile(content, files) : parseFences(content);

  const urls = [...new Set(content.match(URL_RE) || [])];
  const ipAddresses = [...new Set(content.match(IP_RE) || [])];
  const domains = [...new Set(content.match(DOMAIN_RE) || [])];

  return {
    frontmatter,
    body,
    codeBlocks,
    urls,
    ipAddresses,
    domains,
    rawContent: content,
  };
}

function fencesByFile(content: string, files: BundledFile[]): CodeBlock[] {
  const lines = content.split("\n");
  const blocks: CodeBlock[] = [];
  for (const file of files) {
    const text = lines.slice(file.startLine - 1, file.endLine).join("\n");
    if (file.executed || isCode(languageOf(file.path, text))) continue;
    for (const block of parseFences(text)) {
      blocks.push({ ...block, lineStart: block.lineStart + file.startLine - 1, lineEnd: block.lineEnd + file.startLine - 1 });
    }
  }
  return blocks.sort((a, b) => a.lineStart - b.lineStart);
}

/**
 * Fenced code blocks by line. A block closes at a fence of the same character,
 * at least as long, with nothing after it; an unclosed block runs to the end,
 * as in CommonMark. `lineStart` and `lineEnd` are the fence lines; `info` is
 * the language word as written, empty when there is none.
 */
export function parseFences(content: string): (CodeBlock & { info: string; closed: boolean })[] {
  const lines = content.split("\n").map((l) => l.replace(/\r$/, ""));
  const blocks: (CodeBlock & { info: string; closed: boolean })[] = [];
  for (let i = 0; i < lines.length; i++) {
    const open = FENCE_OPEN.exec(lines[i]);
    if (!open) continue;
    const [, prefix, fence, infoText] = open;
    // A backtick fence's info string cannot contain a backtick: that is inline code.
    if (fence[0] === "`" && infoText.includes("`")) continue;
    const quotes = (prefix.match(/>/g) ?? []).length;
    const strip = (line: string) => {
      let rest = line;
      for (let q = 0; q < quotes; q++) rest = rest.replace(/^[ \t]*> ?/, "");
      return rest;
    };
    const close = new RegExp(`^[ \\t]*${fence[0] === "`" ? "`" : "~"}{${fence.length},}\\s*$`);
    let end = i + 1;
    while (end < lines.length && !close.test(strip(lines[end]))) end++;
    const body = lines.slice(i + 1, end).map(strip);
    const info = infoText.trim().split(/[\s{,]/)[0]?.replace(/^\./, "") ?? "";
    blocks.push({
      language: info || "unknown",
      info,
      closed: end < lines.length,
      content: body.length ? body.join("\n") + "\n" : "",
      lineStart: i + 1,
      lineEnd: Math.min(end, lines.length - 1) + 1,
    });
    i = end;
  }
  return blocks;
}
