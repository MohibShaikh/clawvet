import {
  closeSync, constants, fstatSync, lstatSync, openSync, opendirSync,
  readSync, realpathSync,
} from "node:fs";
import { basename, dirname, extname, isAbsolute, join, relative, resolve, sep } from "node:path";

import { inspectRuntimeCoverage } from "./runtime-coverage.js";
import { RULES, type RuleId } from "./policy.js";

export const ASSEMBLY_LIMITS = {
  fileBytes: 256 * 1024,
  totalBytes: 2 * 1024 * 1024,
  entries: 1024,
  depth: 16,
} as const;

export interface AssemblyIssue {
  path: string;
  rule: RuleId;
  reason: string;
  line?: number;
}

// The skill-root spellings real skills use in their commands. Each stands for
// the bundle itself, so the path after it is a bundled file to inspect.
const SKILL_ROOT = /(?:\{\{\s*(?:baseDir|SKILL_DIR)\s*\}\}|\{(?:baseDir|SKILL_DIR)\}|\$\{(?:CLAUDE_SKILL_DIR|SKILL_DIR)\}|\$SKILL_DIR\b|<skill[_-](?:dir|path)>)\//gi;

export interface AssemblyResult {
  content: string;
  coverage: {
    complete: boolean;
    files: Array<{ path: string; startLine: number; endLine: number }>;
    issues: AssemblyIssue[];
    // Reviewable, not uninspectable: dependency installs. They raise an allow
    // to warn but do not make coverage incomplete.
    warnings: AssemblyIssue[];
  };
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function mentions(text: string, path: string): boolean {
  return new RegExp(`(^|[^\\w.-])${escapeRegExp(path)}($|[^\\w.-]|\\.(?=\\s|$))`, "m").test(text);
}

// This is static reference discovery, not a shell/JS interpreter. Existing
// filenames are matched separately, including extensionless helpers. Extract
// concrete script paths and Markdown links as well so missing references are
// reported, rather than disappearing because they weren't in the inventory.
function references(text: string): string[] {
  const refs = new Set<string>();
  let remaining = text.replace(/(?:https?|mailto|data):[^\s<>"'`]+/gi, "");
  remaining = remaining.replace(/\[[^\[\]\n]*\]\(\s*(?:<([^<>\n]+)>|([^\s()[\]<>]+))(?:\s+["\'][^"\'\n]*["\'])?\s*\)/g,
    (_match, angle: string, plain: string) => {
      const ref = angle || plain;
      if (ref && !ref.startsWith("#")) refs.add(ref.split(/[?#]/)[0]);
      return " ";
    });
  // An interpreter/source command can reference an extensionless file too.
  // Only a path-like word is a reference: "the source of truth" is prose. A
  // bundled file run by its bare name is still found by the inventory match.
  for (const match of remaining.matchAll(/\b(?:bash|sh|zsh|source|node|python\d*|ruby|perl)[ \t]+(?!-)(?:"([^"\n]+)"|'([^'\n]+)'|([^\s`"'<>|;&)]+))/g)) {
    const ref = (match[1] || match[2] || match[3]).replace(/[.,:]+$/, "");
    if (/[/.]/.test(ref) && /\w/.test(ref)) refs.add(ref);
  }
  // Remove quoted paths after extraction, so "my helper.sh" doesn't also
  // manufacture a missing reference to "helper.sh".
  remaining = remaining.replace(/["'`]([^"'`\n]+\.(?:sh|bash|zsh|ps1|bat|cmd|py|js|mjs|cjs|ts|rb|pl|lua))["'`]/g,
    (match, ref: string) => {
      if (/^(?:bash|sh|node|python\d*)\s/.test(ref)) return match;
      refs.add(ref);
      return " ";
    });
  for (const match of remaining.matchAll(/(?:^|[\s`"'(=])((?:\.{1,2}\/|\/)?[\w.@+~$\/\\-]+\.(?:sh|bash|zsh|ps1|bat|cmd|py|pyw|js|mjs|cjs|ts|mts|cts|rb|pl|lua))(?=$|[\s`"')\],;:#?]|\.(?=\s|$))/gm)) {
    refs.add(match[1]);
  }
  // `. path` dot-sources a file. The dot must stand alone, so a sentence's
  // trailing period or a numbered list item is not read as a command.
  // The target must look like a path, or "`code`. The next step" reads as one.
  for (const match of remaining.matchAll(/(?:^|[\s;&|(])\.[ \t]+(?!-)(?:"([^"\n]+)"|'([^'\n]+)'|([^\s`"'<>|;&)]+))/gm)) {
    const ref = (match[1] || match[2] || match[3]).replace(/[.,:]+$/, "");
    if (/[/.~]/.test(ref)) refs.add(ref);
  }
  // An absolute path in command position runs code outside the bundle.
  // System binary directories are excluded: `/usr/bin/python3 helper.py`
  // still runs a bundled file, and needs root to tamper with.
  // "/discover" with one segment is an agent slash command, not a path.
  for (const match of remaining.matchAll(/\b(?:run|execute|exec|invoke|launch)\b(?:\s+(?:this|it|that|first|now|next|the\s+following))*\s*:?\s+(\/[^\s`"'<>|;&)]+)/gim)) {
    const ref = match[1].replace(/[.,:]+$/, "");
    if (/^\/[^/]+\/./.test(ref) && !/^\/(?:usr\/(?:local\/)?)?s?bin\//.test(ref)) refs.add(ref);
  }
  // Explicit local paths also cover extensionless executables and imports.
  for (const match of remaining.matchAll(/(?:^|[\s`"'(=])((?:\.{1,2}\/)[^\s`"'<>|;&)\]]+)/gm)) {
    refs.add(match[1].replace(/[.,:]+$/, ""));
  }
  return [...refs];
}

// "/path/to/script.py" is a documentation placeholder, not a location.
const PLACEHOLDER_PATH = /^\/(?:path\/to|your|absolute\/path)\//i;

// Source files that resolve paths from their own location and are read with the
// code-loading rules rather than as shell.
const CODE_FILE = /\.(?:py|pyw|js|mjs|cjs|jsx|ts|mts|cts|tsx|rb|pl|lua|go|rs)$/i;
// The shell idiom for "the directory this script is in". A path after it is
// relative to the script, which is what "./" means to the resolver below.
const DIRNAME_SELF = /\$\(\s*dirname\s+["']?\$\{?(?:0|BASH_SOURCE(?:\[0\])?)\}?["']?\s*\)/g;

// $(dirname "$0") always names the script's directory. $SCRIPT_DIR only does
// when every assignment to it in this file is built from that idiom; otherwise
// a reassigned SCRIPT_DIR could borrow a bundled decoy's name.
function scriptRelative(text: string): string {
  // Every assignment anywhere, including a second one later on the same line;
  // read, for and printf -v can set it without an equals sign at all.
  const assignments = text.match(/\bSCRIPT_DIR\+?=/g)?.length ?? 0;
  const idiomatic = text.match(new RegExp(`\\bSCRIPT_DIR=["']?(?:\\$\\(\\s*cd\\s+["']?)?${DIRNAME_SELF.source}`, "g"))?.length ?? 0;
  const other = /\b(?:read|for|printf\s+-v|mapfile|readarray|declare\s+-n|local\s+-n)\b[^\n;]*\bSCRIPT_DIR\b/.test(text);
  const own = assignments > 0 && assignments === idiomatic && !other;
  const resolved = text.replace(DIRNAME_SELF, ".");
  return own ? resolved.replace(/\$\{?SCRIPT_DIR\}?/g, ".") : resolved;
}
// Rules for a reference ClawVet cannot resolve to one file.
const UNRESOLVED = new Set<RuleId>(["dynamic-loading", "dynamic-module", "dynamic-target", "computed-command"]);
// Media and fonts cannot be loaded as code; inspecting them would only report
// binary content.
const NOT_CODE = /\.(?:png|jpe?g|gif|webp|ico|bmp|svg|pdf|woff2?|ttf|otf|eot|mp3|wav|ogg|flac|m4a|mp4|webm|mov|mkv)$/i;
const EXECUTABLE = /\.(?:sh|bash|zsh|ps1|psm1|bat|cmd|py|pyw|js|mjs|cjs|jsx|ts|mts|cts|tsx|rb|pl|lua|php|go|rs)$/i;

// Linked documents are read, never run. One outside the skill is worth a look
// but cannot hide executable code from the gate.
const DOCUMENT = /\.(?:md|markdown|rst|txt|json|ya?ml|toml|html?|pdf|png|jpe?g|gif|svg|webp|csv)$|(?:^|\/)(?:LICENSE|README|CHANGELOG|NOTICE|COPYING)$|\/$/i;

// `import helper` names no path, yet runs bundled code: Python resolves it from
// the importing script's directory. Returns module paths without an extension;
// the caller keeps only the ones that exist, so `import os` is not a miss.
function pythonModules(text: string): string[] {
  const modules: string[] = [];
  for (const match of text.matchAll(/^[ \t]*import[ \t]+([\w.]+(?:[ \t]+as[ \t]+\w+)?(?:[ \t]*,[ \t]*[\w.]+(?:[ \t]+as[ \t]+\w+)?)*)/gm)) {
    for (const part of match[1].split(",")) modules.push(part.trim().split(/\s+/)[0]);
  }
  for (const match of text.matchAll(/^[ \t]*from[ \t]+\.*([\w.]*)[ \t]+import[ \t]+\(?([\w \t,]+)/gm)) {
    if (match[1]) modules.push(match[1]);
    // `from pkg import name` may import the submodule pkg/name.py.
    for (const name of match[2].split(",").map((part) => part.trim().split(/\s+/)[0]).filter(Boolean)) {
      modules.push(match[1] ? `${match[1]}.${name}` : name);
    }
  }
  return modules.map((module) => module.split(".").join("/")).filter(Boolean);
}

/**
 * Inventory the canonical skill root, then follow recognized references to a
 * fixed point. Limits and unsupported filesystem objects are coverage failures,
 * never evidence that a skill is clean. No referenced program is executed.
 * If skillMd is omitted, read the entry file with the same bounded reader.
 */
export function assembleSkill(
  skillDir: string,
  skillMd?: string,
  entryFile = "SKILL.md",
): AssemblyResult {
  const result: AssemblyResult = {
    content: "",
    coverage: { complete: true, files: [], issues: [], warnings: [] },
  };
  // issues are what strict blocks on, warnings what it asks about; the profile
  // decides what the gate does with each (see policy.ts).
  const issue = (path: string, rule: RuleId, line?: number) => {
    const ask = RULES[rule].strict === "ask";
    const list = ask ? result.coverage.warnings : result.coverage.issues;
    if (!ask) result.coverage.complete = false;
    // Cap repeats of each rule, never the rule set.
    const same = list.filter((i) => i.rule === rule);
    if (same.length < 5 && !same.some((i) => i.path === path)) {
      list.push({ path, rule, reason: RULES[rule].message, ...(line ? { line } : {}) });
    }
  };
  let root: string;
  try { root = realpathSync(skillDir); }
  catch { issue(".", "missing-skill"); return result; }
  const inside = (path: string) => {
    const rel = relative(root, path);
    return rel !== ".." && !rel.startsWith(`..${sep}`) && !isAbsolute(rel);
  };
  const files = new Set<string>();
  const directories = new Set<string>([root]);
  let entries = 0;
  function walk(dir: string, depth: number): void {
    if (depth > ASSEMBLY_LIMITS.depth) {
      issue(relative(root, dir), "depth-limit"); return;
    }
    let handle;
    try {
      if (realpathSync(dir) !== dir || !(lstatSync(dir).mode & 0o444)) {
        issue(relative(root, dir), "unsafe-directory"); return;
      }
      handle = opendirSync(dir);
      for (let entry = handle.readSync(); entry; entry = handle.readSync()) {
        if (++entries > ASSEMBLY_LIMITS.entries) {
          issue(".", "entry-limit"); break;
        }
        const path = join(dir, entry.name);
        const rel = relative(root, path).split(sep).join("/");
        if (entry.isDirectory()) { directories.add(path); walk(path, depth + 1); }
        else if (entry.isFile()) files.add(rel);
        else issue(rel, "special-file");
        if (entries > ASSEMBLY_LIMITS.entries) break;
      }
    } catch { issue(relative(root, dir) || ".", "unreadable-directory"); }
    finally { handle?.closeSync(); }
  }
  walk(root, 0);

  let totalBytes = 0;
  // quiet: a file pulled in only because a dynamic reference could reach it.
  // Binary content and oversized media there cannot be run as a script, so they
  // are skipped instead of reported.
  function read(path: string, quiet = false): string | undefined {
    let fd: number | undefined;
    try {
      const absolute = resolve(root, path);
      if (!inside(absolute) || realpathSync(absolute) !== absolute) {
        issue(path, "symlink-escape"); return;
      }
      fd = openSync(absolute, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
      const stat = fstatSync(fd);
      if (!stat.isFile() || !(stat.mode & 0o444)) {
        issue(path, "not-regular-file"); return;
      }
      if (stat.size > ASSEMBLY_LIMITS.fileBytes) {
        if (!(quiet && NOT_CODE.test(path))) issue(path, "file-limit");
        return;
      }
      // Read at most the limit + 1 even if the file grows after fstat.
      const buffer = Buffer.alloc(ASSEMBLY_LIMITS.fileBytes + 1);
      let length = 0;
      while (length < buffer.length) {
        const count = readSync(fd, buffer, length, buffer.length - length, null);
        if (!count) break;
        length += count;
      }
      if (length > ASSEMBLY_LIMITS.fileBytes) {
        issue(path, "file-limit"); return;
      }
      totalBytes += length;
      if (totalBytes > ASSEMBLY_LIMITS.totalBytes) {
        issue(path, "total-limit"); return;
      }
      const bytes = buffer.subarray(0, length);
      if (bytes.includes(0)) { if (!quiet) issue(path, "binary"); return; }
      return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    } catch { if (!quiet) issue(path, "unreadable"); return; }
    finally { if (fd !== undefined) closeSync(fd); }
  }

  // Whether a file starts with #!, read without following symlinks. Anything
  // unreadable is left to read() to report if it is ever selected.
  function shebang(path: string): boolean {
    let fd: number | undefined;
    try {
      fd = openSync(resolve(root, path), constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
      const head = Buffer.alloc(2);
      return readSync(fd, head, 0, 2, 0) === 2 && head.toString() === "#!";
    } catch { return false; }
    finally { if (fd !== undefined) closeSync(fd); }
  }

  if (skillMd !== undefined) {
    totalBytes = Buffer.byteLength(skillMd);
    if (totalBytes > ASSEMBLY_LIMITS.fileBytes || skillMd.includes("\0")) {
      issue(entryFile, "manifest-limit"); return result;
    }
  }
  const manifest = skillMd ?? read(entryFile);
  if (manifest === undefined) return result;
  result.content = manifest;
  result.coverage.files.push({ path: entryFile, startLine: 1, endLine: manifest.split("\n").length });
  const visited = new Set([entryFile]);
  const queue = [{ path: entryFile, text: manifest }];
  const candidates = [...files].sort();
  const downloads: Array<{ path: string; target: string; line: number }> = [];
  const executedFiles: Array<{ path: string; target: string }> = [];
  const quietFiles = new Set<string>();
  // Where a target may land: relative to its file or, for shell, to the root.
  const places = (path: string, target: string) => isAbsolute(target)
    ? [resolve(target)] : [resolve(root, dirname(path), target), resolve(root, target)];
  const same = (a: { path: string; target: string }, b: { path: string; target: string }) =>
    places(a.path, a.target).some((place) => places(b.path, b.target).includes(place));
  const instructionFiles: Array<{ path: string; target: string }> = [];
  let unresolved = false;
  // Only a path into an installed copy of this skill maps back to the bundle.
  const skillNames = new Set([basename(root), manifest.match(/^name:\s*["']?([\w.-]+)/m)?.[1] ?? ""]
    .filter(Boolean).map((name) => name.toLowerCase()));
  // An agent can find and run any script installed with the skill, so bundled
  // code is inspected whether or not the manifest names it.
  const bundledCode = candidates.filter((file) => EXECUTABLE.test(file) || shebang(file));
  for (let index = 0; index < queue.length; index++) {
    const source = queue[index];
    const text = scriptRelative(source.text.replace(SKILL_ROOT, ""));
    const runtime = inspectRuntimeCoverage(text, /\.md$/i.test(source.path), 0, CODE_FILE.test(source.path));
    for (const problem of runtime.issues) issue(source.path, problem.rule, problem.line);
    unresolved ||= runtime.issues.some((problem) => UNRESOLVED.has(problem.rule));
    for (const download of runtime.downloads) downloads.push({ path: source.path, ...download });
    executedFiles.push(...runtime.executedFiles.map((target) => ({ path: source.path, target })));
    instructionFiles.push(...runtime.instructionFiles.map(target => ({ path: source.path, target })));
    const selected = new Set<string>();
    for (const candidate of candidates) {
      if (mentions(text, candidate) || mentions(text, basename(candidate))) {
        selected.add(candidate);
      }
    }
    const modules = /\.py$/i.test(source.path)
      ? pythonModules(text)
        .flatMap((module) => [`${module}.py`, `${module}/__init__.py`])
        .map((file) => relative(root, resolve(root, dirname(source.path), file)).split(sep).join("/"))
        .filter((file) => files.has(file))
      : [];
    // An imported module runs, so a download written over it is executed code.
    executedFiles.push(...modules.map((target) => ({ path: entryFile, target })));
    for (let ref of new Set([...references(text), ...runtime.executedFiles, ...modules])) {
      if (PLACEHOLDER_PATH.test(ref)) continue;
      // An absolute path into an installed copy of this skill, such as
      // /home/u/skills/<name>/scripts/run.py, names the bundled file.
      const installed = isAbsolute(ref) ? ref.match(/\/skills\/([^/]+)\/(.+)$/) : undefined;
      if (installed && skillNames.has(installed[1].toLowerCase()) && files.has(installed[2])) ref = installed[2];
      // Code resolves its imports from its own file. Shell and the manifest
      // resolve from a working directory ClawVet cannot know, so a reference
      // there may be relative to the helper or to the skill root: check both.
      const paths = CODE_FILE.test(source.path)
        ? [resolve(root, dirname(source.path), ref)]
        : [...new Set([resolve(root, dirname(source.path), ref), resolve(root, ref)])];
      const hasFile = (path: string) => files.has(relative(root, path).split(sep).join("/"));
      const matches = paths.flatMap((path) => {
        if (!inside(path)) return [];
        if (hasFile(path) || directories.has(path)) return [path];
        // Local imports can omit their source extension. Inspect every matching
        // bundled source rather than guessing which runtime will resolve it.
        return extname(path) ? [] : [".js", ".mjs", ".cjs", ".ts", ".py"]
          .map((extension) => path + extension).filter(hasFile);
      });
      // A quoted sentence that happens to end in a filename is prose, unless a
      // file by that whole name exists.
      const runs = runtime.executedFiles.includes(ref);
      if (/\s/.test(ref) && !matches.length && !runs) continue;
      if (DOCUMENT.test(ref) && !runs && paths.every((path) => !inside(path))) {
        issue(ref, "outside-document");
        continue;
      }
      if (paths.some((path) => !inside(path))) {
        // The runtime working directory is unknown: bash resolves ../ against
        // the cwd, not the script's directory. A path is only covered if every
        // plausible interpretation stays inside the skill, so an in-bundle
        // decoy cannot hide an interpretation that escapes it.
        issue(ref, matches.length ? "decoy-path" : "escape");
      }
      // A path that is not bundled and that nothing runs, such as an output
      // folder or a dotfile, cannot hide code and needs no operator decision.
      // A file the skill downloads is not missing from the bundle; whether it
      // is run or followed is checked against the download below.
      const downloaded = downloads.some((download) => same(download, { path: source.path, target: ref }));
      if (!matches.length && !downloaded && (EXECUTABLE.test(ref) || runtime.executedFiles.includes(ref))) {
        issue(ref, "missing-file");
      }
      for (const path of matches) {
        if (directories.has(path)) {
          const prefix = relative(root, path).split(sep).join("/");
          for (const file of candidates) {
            if (!prefix || file.startsWith(prefix + "/")) selected.add(file);
          }
        } else selected.add(relative(root, path).split(sep).join("/"));
      }
    }
    // A dynamic reference could run any bundled file, and the default profile
    // does not block on it. So inspect every file that could be the target.
    if (unresolved) {
      for (const file of candidates) {
        if (!selected.has(file) && !visited.has(file)) quietFiles.add(file);
        selected.add(file);
      }
    }
    if (index === 0) for (const file of bundledCode) selected.add(file);
    for (const path of [...selected].sort()) {
      if (visited.has(path)) continue;
      visited.add(path);
      if (totalBytes > ASSEMBLY_LIMITS.totalBytes) break;
      const text = read(path, quietFiles.has(path));
      if (text === undefined) continue;
      const separator = result.content.endsWith("\n") ? "\n" : "\n\n";
      const prefix = `${separator}# [clawvet] referenced file: ${path}\n`;
      const startLine = (result.content + prefix).split("\n").length;
      result.content += prefix + text;
      result.coverage.files.push({ path, startLine, endLine: startLine + text.split("\n").length - 1 });
      queue.push({ path, text });
    }
  }
  for (const download of downloads) {
    if (executedFiles.some((executed) => same(executed, download))) {
      issue(download.path, "download-executed", download.line);
    }
    const destinations = [resolve(root, download.target), resolve(root, dirname(download.path), download.target)];
    if (instructionFiles.some(instruction =>
      [resolve(root, instruction.target), resolve(root, dirname(instruction.path), instruction.target)]
        .some(path => destinations.includes(path)))) {
      issue(download.path, "download-followed", download.line);
    }
  }
  return result;
}

export function coverageWarning(issues: AssemblyIssue[]): string {
  return `ClawVet: review before installing: ${describe(issues)}`.slice(0, 1000);
}

export function coverageReason(issues: AssemblyIssue[]): string {
  return `ClawVet inspection incomplete: ${describe(issues)}`.slice(0, 1000);
}

function describe(issues: AssemblyIssue[]): string {
  return issues.map((i) => `${i.path}${i.line ? `:${i.line}` : ""}: ${i.reason}`).join("; ");
}
