import type { BundledFile, ParsedSkill, SourceFile, SourceLanguage } from "../types.js";

// Which text in a scan is code. Fenced blocks in SKILL.md are code, and so is
// every bundled script the CLI appends. The bundle arrives as one string, so the
// file map must come from the assembler: recovering it from the marker lines in
// that string would let a script forge a marker and turn its own tail into prose.

const EXTENSIONS: Record<string, SourceLanguage> = {
  py: "python", pyw: "python",
  js: "javascript", mjs: "javascript", cjs: "javascript", jsx: "javascript",
  ts: "typescript", mts: "typescript", cts: "typescript", tsx: "typescript",
  sh: "shell", bash: "shell", zsh: "shell", ksh: "shell", command: "shell",
  ps1: "powershell", psm1: "powershell",
  rb: "ruby", pl: "perl", php: "php", lua: "lua", go: "go", rs: "rust",
  json: "config", yaml: "config", yml: "config", toml: "config", ini: "config", cfg: "config",
  md: "markdown", markdown: "markdown", mdx: "markdown", txt: "text", rst: "text",
};

const FENCES: Record<string, SourceLanguage> = {
  python: "python", py: "python", python3: "python",
  javascript: "javascript", js: "javascript", node: "javascript", jsx: "javascript",
  typescript: "typescript", ts: "typescript", tsx: "typescript",
  bash: "shell", sh: "shell", shell: "shell", zsh: "shell", console: "shell", terminal: "shell",
  powershell: "powershell", ps1: "powershell", pwsh: "powershell",
  ruby: "ruby", perl: "perl", php: "php", lua: "lua", go: "go", rust: "rust",
  json: "config", yaml: "config", yml: "config", toml: "config", ini: "config",
};

const SHEBANG: Array<[RegExp, SourceLanguage]> = [
  [/\bpython[\d.]*\b/, "python"],
  [/\b(?:node|deno|bun)\b/, "javascript"],
  [/\b(?:ba|z|k|da)?sh\b/, "shell"],
  [/\bpwsh\b/, "powershell"],
  [/\bruby\b/, "ruby"],
  [/\bperl\b/, "perl"],
];

export function languageOf(path: string, text = ""): SourceLanguage {
  const name = path.split("/").pop() ?? path;
  const dot = name.lastIndexOf(".");
  // A shebang wins over the extension: renaming run.sh to run.md must not turn
  // a script into prose for the code-only rules.
  const first = text.slice(0, text.indexOf("\n") === -1 ? undefined : text.indexOf("\n"));
  if (first.startsWith("#!")) {
    for (const [re, language] of SHEBANG) if (re.test(first)) return language;
    return "other";
  }
  if (dot > 0) {
    const known = EXTENSIONS[name.slice(dot + 1).toLowerCase()];
    if (known) return known;
  }
  // An extensionless file with no shebang is most often a helper script run by
  // name, and a payload gains nothing from losing its extension. Treat as code.
  return dot > 0 ? "other" : "shell";
}

// Prose formats are not code. Anything else that ships in a bundle is.
export function isCode(language: SourceLanguage): boolean {
  return language !== "markdown" && language !== "text";
}

// A file the bundle runs is code even with a prose name; shell is the usual runner.
function fileLanguage(file: BundledFile, text: string): SourceLanguage {
  const language = languageOf(file.path, text);
  return file.executed && !isCode(language) ? "shell" : language;
}

export function collectSources(skill: ParsedSkill, files: BundledFile[] = []): SourceFile[] {
  const lines = skill.rawContent.split("\n");
  const sources: SourceFile[] = files.map((file) => {
    const text = lines.slice(file.startLine - 1, file.endLine).join("\n");
    return { path: file.path, language: fileLanguage(file, text), text, startLine: file.startLine, endLine: file.endLine };
  });
  // A fence in a code file is part of that file's source already. A fence in a
  // markdown file, SKILL.md included, is code of its own, named after its file.
  const fileOf = (line: number) => sources.find((f) => line >= f.startLine && line <= f.endLine);
  for (const block of skill.codeBlocks) {
    const owner = fileOf(block.lineStart);
    if (owner && isCode(owner.language)) continue;
    const language = FENCES[block.language.toLowerCase()] ?? "other";
    // The fence's first content line follows the opening ``` line.
    sources.push({ path: owner?.path ?? "SKILL.md", language, text: block.content, startLine: block.lineStart + 1, endLine: block.lineEnd - 1 });
  }
  return sources;
}

export function codeLines(skill: ParsedSkill, files: BundledFile[] = []): Set<number> {
  const result = new Set<number>();
  for (const block of skill.codeBlocks) {
    for (let l = block.lineStart; l <= block.lineEnd; l++) result.add(l);
  }
  const lines = skill.rawContent.split("\n");
  for (const file of files) {
    const text = lines.slice(file.startLine - 1, file.endLine).join("\n");
    if (!isCode(fileLanguage(file, text))) continue;
    for (let l = file.startLine; l <= file.endLine; l++) result.add(l);
  }
  return result;
}
