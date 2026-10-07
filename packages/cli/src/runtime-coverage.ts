import { basename } from "node:path";
import { onlyTrustedInstallers } from "@clawvet/shared";
import { RULES, type RuleId } from "./policy.js";

export interface RuntimeIssue {
  line: number;
  rule: RuleId;
  reason: string;
  // A warning asks the operator to review; it does not make coverage incomplete.
  level?: "warn";
}

export interface RuntimeCoverage {
  issues: RuntimeIssue[];
  downloads: Array<{ target: string; line: number }>;
  executedFiles: string[];
  instructionFiles: string[];
}

interface Token {
  value: string;
  dynamic: boolean;
  operator?: boolean;
}

const INTERPRETERS = /^(?:ba|da|z|k)?sh$|^\.$|^(?:source|cmd|node|nodejs|python\d*(?:\.\d+)?|ruby|perl|pwsh|powershell)$/i;
const DATA_EXTENSION = /\.(?:json|csv|tsv|txt|xml|ya?ml|png|jpe?g|gif|webp|svg|pdf|wav|mp3|ogg|flac|m4a|aac|mp4|webm|mov|mkv)$/i;
// Packaged installers and archives. Downloading one is reviewable, not hidden
// code: nothing in the skill runs it unless a later command does.
const INSTALLER_EXTENSION = /\.(?:dmg|pkg|msi|exe|deb|rpm|appimage|zip|tar|tgz|gz|bz2|xz|7z|whl|vsix)$/i;
const PIPED_INTERPRETER = "(?:ba|da|z|k)?sh|node|python\\d*(?:\\.\\d+)?|perl|ruby|pwsh|powershell|iex|invoke-expression";
// After the pipe: optional wrappers (sudo, env with VAR=value), then the
// interpreter, possibly quoted or given as a path such as /bin/bash.
const PIPE_TO_INTERPRETER = new RegExp(`\\|\\s*(?:(?:sudo|env|command|exec|nohup|doas)\\s+(?:-\\S+\\s+|\\w+=\\S*\\s+)*)*["']?(?:[\\w.~/-]*\\/)?(?:${PIPED_INTERPRETER})\\b`, "i");
const INTERPRETER_SUBSTITUTION = new RegExp(`(?:\\b(?:${PIPED_INTERPRETER}|source)|(?:^|\\s)\\.)\\s+<\\(`, "i");
// `bash -c "$(curl ...)"`: a download handed to an interpreter as its inline
// code. The same thing as curl | sh, written as a command substitution.
const INTERPRETER_COMMAND_SUBSTITUTION = new RegExp(`(?:^|[\\s;&|(/])(?:${PIPED_INTERPRETER})\\s+(?:-\\S+\\s+)*["']?(?:\\$\\(|\`)`, "i");
// Fence languages read with shell rules, and with prose rules. Any other
// labelled fence is code: only the code API rules apply.
const SHELL_FENCE = /^(?:bash|sh|shell|zsh|console|shellsession|powershell|ps1|pwsh|cmd|bat|batch|fish|ksh)$/i;
const TEXT_FENCE = /^(?:|text|txt|plain|plaintext|markdown|md|json|jsonc|json5|ya?ml|toml|ini|env|xml|html?|css|csv|mermaid|diff|log|output|gitignore|dockerignore)$/i;
const REMOTE = /^(?:https?|ftp|data):/i;
// Commands that make a prose fragment worth reading as shell. Lowercase only:
// "Python 3 is required" and "Node version 18" are sentences, not commands.
const PROSE_COMMAND = /^(?:curl|wget|iwr|irm|bash|sh|zsh|dash|ksh|source|node|nodejs|deno|bun|bunx|npx|npm|pnpm|yarn|pip\d*|uv|uvx|python\d*(?:\.\d+)?|ruby|perl|pwsh|powershell|cmd|eval|iex|sudo|env|exec|chmod)$|^(?:Invoke-WebRequest|Invoke-RestMethod|Invoke-Expression)$|^\.{1,2}\//;
const IMPERATIVE = /^(?:run|execute|exec|type|paste|enter|invoke)\b\s*(?:(?:this|it|that|first|now|next|the\s+following|command)\s+)*:?\s*/i;
// Network reads in a script. A file it writes with a literal name is treated as
// downloaded, and correlated with later execution or instruction use.
const NETWORK_READ = /\b(?:requests|httpx|urllib3?|aiohttp)\.\w+\s*\(|\burlopen\s*\(|\bfetch\s*\(|\baxios\b|\bhttps?\.get\s*\(/;
const CODE_WRITES = [
  /\bopen\s*\(\s*(["'])([^"'\n]+)\1\s*,\s*["'][wax]b?\+?["']/g,
  /\bPath\s*\(\s*(["'])([^"'\n]+)\1\s*\)\s*\.write_(?:text|bytes)\s*\(/g,
  /\b(?:writeFileSync|writeFile|createWriteStream)\s*\(\s*(["'`])([^"'`\n]+)\1/g,
];
const INSTRUCTION_USE = /\b(?:follow|obey|execute|apply|carry\s+out)\s+(?:(?:all|the|its|their|these|those|any|remote|downloaded|retrieved|provided|returned|setup|installation)\s+){0,4}(?:instructions?|directions?|steps|commands?|procedures?)\b|\b(?:follow|obey)\s+what\s+(?:it|the\s+(?:page|document|response))\s+says\b/i;

// Split bounded Python call arguments without evaluating expressions. Nested
// expressions are retained as text; only an entire literal destination counts
// as resolved. Also handles calls spread over several source lines.
function callArguments(text: string, start: number): string[] | undefined {
  const args: string[] = [];
  let argument = "";
  let depth = 0;
  let quote = "";
  for (let i = start; i < Math.min(text.length, start + 4096); i++) {
    const char = text[i];
    if (quote) {
      argument += char;
      if (char === "\\") { argument += text[++i] || ""; continue; }
      if (char === quote) quote = "";
      continue;
    }
    if (char === "#") {
      while (i < text.length && text[i] !== "\n") i++;
      argument += " "; continue;
    }
    if (char === '"' || char === "'") quote = char;
    else if ("([{".includes(char)) depth++;
    else if (char === ")" && depth === 0) { args.push(argument.trim()); return args; }
    else if (")]}".includes(char)) { if (--depth < 0) return; }
    else if (char === "," && depth === 0) {
      args.push(argument.trim()); argument = "";
      if (args.length > 16) return;
      continue;
    }
    argument += char;
  }
}

// Read the resource immediately associated with a prose verb, rather than
// treating every filename in the sentence as an instruction source.
function proseReference(text: string): string | undefined {
  const rest = text.trimStart();
  const link = rest.match(/^\[[^\]\n]*\]\(\s*<?([^\s<>)]*)>?\s*\)/);
  if (link) return link[1];
  const quoted = literalAt(rest, 0);
  const value = quoted?.value ?? rest.match(/^[^\s<>()[\];,]+/)?.[0];
  return value?.replace(/[.,:!?]+$/, "").replace(/^\*{1,2}|\*{1,2}$/g, "");
}

function instructionResource(value: string | undefined): value is string {
  return !!value && (REMOTE.test(value) || /\.(?:md|markdown|rst|html?|txt|json|ya?ml|xml|csv|tsv|sh|py|js)$/i.test(value));
}

// A bounded lexical pass: concatenate adjacent quoted shell words and retain
// expansion markers, but never expand variables, substitutions or globs.
function tokenize(line: string): Token[] {
  const tokens: Token[] = [];
  let value = "";
  let quote = "";
  let dynamic = false;
  const flush = () => {
    if (value) tokens.push({ value, dynamic: dynamic || /%[^%\s]+%|![^!\s]+!/.test(value) });
    value = ""; dynamic = false;
  };
  for (let i = 0; i < line.length; i++) {
    const char = line[i];
    if (char === "\\" && quote !== "'" && i + 1 < line.length) {
      value += line[++i]; continue;
    }
    if (quote) {
      if (char === quote) { quote = ""; continue; }
      if (quote !== "'" && (char === "$" || char === "`")) dynamic = true;
      value += char; continue;
    }
    if (char === "'" || char === '"') { quote = char; continue; }
    if (char === "`" || char === "$" || char === "*" || char === "?" || char === "[") dynamic = true;
    if (/\s/.test(char)) { flush(); continue; }
    if ("|;&<>()".includes(char)) {
      flush(); tokens.push({ value: char, dynamic: false, operator: true }); continue;
    }
    value += char;
  }
  flush();
  return tokens;
}

// Whether a shell line ends inside a quoted string.
function unclosedQuote(line: string): boolean {
  let quote = "";
  for (let i = 0; i < line.length; i++) {
    const char = line[i];
    if (char === "\\" && quote !== "'") { i++; continue; }
    if (quote) { if (char === quote) quote = ""; }
    else if (char === "'" || char === '"') quote = char;
    else if (char === "#" && (i === 0 || /\s/.test(line[i - 1]))) return false;
  }
  return quote !== "";
}

// Read one literal argument without evaluating JavaScript, Python or shell.
// Escapes are deliberately unresolved: an escaped module path needs review.
function literalAt(text: string, start: number): { value: string; end: number } | undefined {
  let i = start;
  while (/\s/.test(text[i] || "") && i < text.length) i++;
  const quote = text[i];
  if (quote !== '"' && quote !== "'") return;
  const begin = ++i;
  while (i < text.length && text[i] !== quote && text[i] !== "\\" && text[i] !== "\n") i++;
  if (text[i] !== quote) return;
  return { value: text.slice(begin, i), end: i + 1 };
}

// The parts of a markdown prose line that are commands: inline code spans and
// the remainder of the line, each only when it starts with a recognized
// command, optionally after an imperative such as "Run". Tables, bullets and
// sentences are not shell, so "$145" in a price table is not a computed command.
function proseCommands(line: string): string[] {
  const commands: string[] = [];
  const starts = (text: string) => PROSE_COMMAND.test((text.trim().split(/\s+/)[0] ?? "").replace(/^["']|["']$/g, ""));
  for (const span of line.matchAll(/`([^`\n]+)`/g)) if (starts(span[1])) commands.push(span[1]);
  const rest = line.replace(/`[^`\n]+`/g, (span) => span.slice(1, -1))
    .replace(/^\s*(?:#{1,6}\s+|>\s*|[-*+]\s+|\d+[.)]\s+)*/, "")
    .replace(/^(?:step\s+\d+\s*:\s*)?/i, "")
    // Sequencing words lead into a command as often as an imperative does.
    .replace(/^(?:(?:and\s+)?then|next|finally|afterwards|now)\b,?\s*/i, "")
    .replace(IMPERATIVE, "");
  if (starts(rest) && !commands.includes(rest)) commands.push(rest);
  return commands;
}

/** Recognized runtime loading boundaries that static file assembly cannot inspect. */
export function inspectRuntimeCoverage(content: string, markdown = false, depth = 0, code = false): RuntimeCoverage {
  const result: RuntimeCoverage = { issues: [], downloads: [], executedFiles: [], instructionFiles: [] };
  const add = (line: number, rule: RuleId) => {
    const reason = RULES[rule].message;
    // Cap repeats of each rule, never the rule set: a run of quiet findings must
    // not crowd out a blocking one.
    const same = result.issues.filter((i) => i.rule === rule);
    if (same.length < 5 && !same.some((i) => i.line === line)) {
      result.issues.push({ line, rule, reason, ...(RULES[rule].strict === "ask" ? { level: "warn" as const } : {}) });
    }
  };
  if (depth > 4) {
    add(1, "nesting-limit");
    return result;
  }
  // Normalize line continuations, preserving their original line numbers.
  const lines = content.split(/\r?\n/);
  let fence: string | undefined;
  let fenceLanguage = "";
  let heredoc: string | undefined;
  const download = (target: string, line: number) => {
    if (target === "-") return;
    result.downloads.push({ target, line });
    // A computed name still counts as data when its extension says so. Any
    // other download matters when something runs or follows it, and assembly
    // blocks that by correlating the download with its use.
    if (INSTALLER_EXTENSION.test(target)) {
      add(line, "download-installer");
    } else if (!DATA_EXTENSION.test(target)) {
      add(line, "download-unknown");
    }
  };
  if (!markdown && NETWORK_READ.test(content)) {
    for (const pattern of CODE_WRITES) {
      for (const write of content.matchAll(pattern)) {
        result.downloads.push({ target: write[2], line: content.slice(0, write.index).split("\n").length });
      }
    }
  }
  // Resolve explicit instruction delegation within a bounded prose paragraph,
  // including a fetch and a follow instruction on different lines. Reading or
  // summarizing remote data alone does not make it an instruction source.
  let prose: string[] = [];
  let proseLength = 0;
  let previousSource: string | undefined;
  const inspectProse = () => {
    // Markdown soft wraps do not end a sentence. Keep the last explicit source
    // across paragraph boundaries so a blank line cannot reset a fetch/follow.
    const text = prose.join(" ");
    for (const sentence of text.split(/(?<=[.!?])\s+|;/)) {
      const reads = [...sentence.matchAll(/\b(?:read|open|retrieve|fetch|download|visit|consult|load|get)\s+(?:(?:the|file|page|document|contents|of|from|at)\s+){0,4}/gi)]
        .map(match => ({ index: match.index!, target: proseReference(sentence.slice(match.index! + match[0].length)) }))
        .filter((read): read is { index: number; target: string } => instructionResource(read.target));
      for (const use of sentence.matchAll(new RegExp(INSTRUCTION_USE.source, "gi"))) {
        const location = sentence.slice(use.index! + use[0].length).match(/^\s+(?:in|from|at|inside)\s+/i);
        const explicit = location ? proseReference(sentence.slice(use.index! + use[0].length + location[0].length)) : undefined;
        const priorRead = reads.filter(read => read.index < use.index!).at(-1)?.target;
        const source = instructionResource(explicit) ? explicit : priorRead ?? previousSource;
        // A remote source is left alone: whether prose hands control to a page is
        // a question of meaning, and a word list both missed paraphrases and
        // blocked ordinary setup docs. Only a staged file can be correlated.
        if (source && !REMOTE.test(source)) result.instructionFiles.push(source);
      }
      if (reads.length) previousSource = reads.at(-1)!.target;
    }
    prose = []; proseLength = 0;
  };
  const inspectCommand = (text: string, lineNumber: number, prose: boolean, index: number, shell = true, lenient = code) => {
    const tokens = shell ? tokenize(text) : [];
    for (let i = 0; i < tokens.length; i++) {
      const token = tokens[i];
      const command = basename(token.value).toLowerCase().replace(/\.exe$/, "");
      if (/^(?:curl|wget|iwr|invoke-webrequest|irm|invoke-restmethod)$/.test(command)) {
        const args: Token[] = [];
        let end = i + 1;
        for (; end < tokens.length && !tokens[end].operator; end++) args.push(tokens[end]);
        let target: string | undefined;
        // curl writes with -o (-O keeps the remote name); wget writes with -O
        // (its -o is a log file). Short flags cluster and take attached values:
        // -sSLo FILE, -oFILE, -qOFILE.
        const output = command === "wget" ? "O" : "o";
        for (let a = 0; a < args.length; a++) {
          const value = args[a].value;
          const short = value.match(new RegExp(`^-([A-Za-z]*?)${output}(.*)$`));
          if (/^(?:--output|--output-document|-outfile)$/i.test(value)) {
            target = args[a + 1]?.value;
          } else if (/^--(?:output|output-document)=/.test(value)) {
            target = value.slice(value.indexOf("=") + 1);
          } else if (short && !value.startsWith("--")) {
            target = short[2] || args[a + 1]?.value;
          }
        }
        if (tokens[end]?.value === ">") target = tokens[end + 1]?.value;
        // curl -O and wget's default output use the URL's last path segment.
        if (!target && (command === "wget" || args.some((a) => /^-[A-Za-z]*O[A-Za-z]*$/.test(a.value)))) {
          const url = args.find((a) => REMOTE.test(a.value));
          try { target = url ? basename(new URL(url.value).pathname) : undefined; } catch { /* unresolved below */ }
          if (!target) add(lineNumber, "download-destination");
        }
        if (target && target !== "-") {
          download(target, lineNumber);
        }
      }
      // Installing named packages from a registry is the ordinary supply chain,
      // and the dependency checker scores those names. Running a package fetched
      // on the spot, or installing from a URL or archive, is not reviewable.
      const next = tokens[i + 1]?.value || "";
      if (/^(?:npx|bunx|uvx)$/.test(command) ||
          (/^(?:npm|pnpm|yarn|bun)$/.test(command) && /^(?:dlx|exec|x)$/.test(next)) ||
          (command === "pipx" && next === "run")) {
        add(lineNumber, "fetch-and-run-package");
      } else if (/^(?:npm|pnpm|yarn|bun|pip\d*)$/.test(command) && /^(?:install|add|i)$/.test(next)) {
        for (let a = i + 2; a < tokens.length && !tokens[a].operator; a++) {
          if (/^(?:git\+|git:|github:|https?:|ftp:)|\.(?:tgz|tar\.gz|whl|zip)$/i.test(tokens[a].value)) {
            add(lineNumber, "install-from-url");
            break;
          }
        }
      }
      if (INTERPRETERS.test(command)) {
        let arg = i + 1;
        let inline = false;
        let module = false;
        while (tokens[arg] && !tokens[arg].operator && (tokens[arg].value.startsWith("-") || (command === "cmd" && /^\/[ck]$/i.test(tokens[arg].value)))) {
          const flag = tokens[arg++].value;
          if (/^(?:-EncodedCommand|-enc)$/i.test(flag)) {
            add(lineNumber, "encoded");
          }
          if (/^-[^-]*c[^-]*$/.test(flag) || /^(?:-e|--eval|-p|--print|-command|\/[ck])$/i.test(flag)) { inline = true; break; }
          if (flag === "-o" || flag === "-O") arg++;
          if (/^(?:-m|--module)$/.test(flag)) {
            if (tokens[arg]?.dynamic) add(lineNumber, "dynamic-module");
            module = true; break;
          }
        }
        // Arguments after `-m module` belong to the module, and a heredoc's
        // body is inline text that is inspected where it stands.
        const input = module ? undefined : tokens[arg];
        const heredoc = input?.value === "<" && tokens[arg + 1]?.value === "<";
        if (heredoc) {
          // Nothing to resolve.
        } else if (input?.dynamic || input?.value === "<") {
          add(lineNumber, "dynamic-target");
        } else if (input && REMOTE.test(input.value)) {
          add(lineNumber, "remote-target");
        } else if (input && !input.operator && inline) {
          const nested = inspectRuntimeCoverage(input.value, false, depth + 1);
          for (const problem of nested.issues) add(lineNumber, problem.rule);
          result.downloads.push(...nested.downloads.map((download) => ({ ...download, line: lineNumber })));
          result.executedFiles.push(...nested.executedFiles);
          result.instructionFiles.push(...nested.instructionFiles);
        } else if (input && !input.operator && (!prose || (/[/.]/.test(input.value) && /\w/.test(input.value)))) {
          result.executedFiles.push(input.value.replace(/[.,:]+$/, ""));
        }
      }
      // A redirect target follows an operator but is a file, not a command.
      const commandPosition = i === 0 || (tokens[i - 1].operator && !"<>".includes(tokens[i - 1].value)) ||
        /^(?:run|execute|sudo|command|exec|env)$/i.test(tokens[i - 1].value);
      // `$env:TOKEN="x"` and `$url = "..."` assign; `$PYTHON scripts/run.py`
      // runs a literal bundled script through an interpreter variable.
      const assignment = /^\$[\w:{}]+=/.test(token.value) || tokens[i + 1]?.value.startsWith("=");
      const script = tokens[i + 1] && !tokens[i + 1].dynamic && /\.(?:py|js|mjs|cjs|ts|sh|rb|pl)$/.test(tokens[i + 1].value);
      if (commandPosition && token.dynamic && /^\$\w+$/.test(token.value) && script) {
        result.executedFiles.push(tokens[i + 1].value);
      } else if (commandPosition && token.dynamic && !assignment && !lenient && /^(?:["']?\$|\.\.?\/|`)/.test(token.value)) {
        add(lineNumber, "computed-command");
      }
      if (commandPosition && /^\.\.?\//.test(token.value) && !token.dynamic) result.executedFiles.push(token.value);
      // An absolute command runs a file outside the bundle, except the system
      // binary directories, which need root to change. A single segment such as
      // /deploy is an agent slash command, not a path.
      if (commandPosition && !prose && /^\/[^/\s]+\/[^/\s]/.test(token.value) && !token.dynamic &&
          !/^\/(?:usr\/(?:local\/)?)?s?bin\/|^\/opt\/homebrew\/bin\//.test(token.value)) {
        result.executedFiles.push(token.value);
      }
      if (commandPosition && /^(?:eval|iex|invoke-expression)$/i.test(command)) {
        add(lineNumber, "eval");
      }
    }
    // urlretrieve writes the response directly to a file, even when a harmless
    // copy of that destination is bundled. Never treat that staged copy as the
    // downloaded code. Data destinations are correlated with later use below.
    for (const call of text.matchAll(/\burlretrieve\s*\(/g)) {
      const context = [text, ...lines.slice(index + 1, index + 9)].join("\n");
      const args = callArguments(context, call.index! + call[0].length);
      const argument = args?.find((arg) => /^filename\s*=/.test(arg))?.replace(/^filename\s*=\s*/, "") ?? args?.[1];
      const target = argument && literalAt(argument, 0);
      if (!argument || !target || argument.slice(target.end).trim()) {
        add(lineNumber, "python-download");
      } else download(target.value, lineNumber);
    }
    // JS/Python loading and code-evaluation APIs. A nonliteral first argument,
    // concatenation or template cannot establish which code will run.
    // `itemRe.exec(text)` is a method, not the builtin, and `olcli compile (x)`
    // is a shell word, so the bare builtins need a call with no gap.
    // In code, `eval ("x")` and `eval/*c*/("x")` are calls too. Python's
    // `from x import (a, b)` is not, so import keeps the strict form.
    const calls = lenient
      ? /(?<![.\w$])(import|require|eval|exec|compile|Function)(?:\(|(?<!import)(?:\s|\/\*[\s\S]*?\*\/)+\()|\b(import_module|run_path|run_module|runInNewContext|runInThisContext)\s*\(/g
      : /(?<![.\w$])(import|require|eval|exec|compile|Function)\(|\b(import_module|run_path|run_module|runInNewContext|runInThisContext)\s*\(/g;
    for (const call of text.matchAll(calls)) {
      call[1] ??= call[2];
      const argument = literalAt(text, call.index! + call[0].length);
      let end = argument?.end ?? 0;
      while (end < text.length && /\s/.test(text[end])) end++;
      const next = argument ? text[end] : undefined;
      if (/^(?:eval|exec|compile|Function|runInNewContext|runInThisContext)$/.test(call[1])) {
        add(lineNumber, "eval");
      } else if (!argument || (next !== ")" && next !== ",")) {
        add(lineNumber, "dynamic-loading");
      } else if (REMOTE.test(argument.value)) {
        add(lineNumber, "remote-module");
      }
    }
    if (/\bfrom\s*["'](?:https?|data):/i.test(text) ||
        /\bimport\s*["'](?:https?|data):/i.test(text)) {
      add(lineNumber, "remote-import");
    }
    if (/\b(?:spawn|execFile|execFileSync|Popen|spec_from_file_location)\s*\(/.test(text) ||
        /\b(?:subprocess\.(?:run|call|check_call|check_output)|os\.(?:system|execv|execve))\s*\(/.test(text)) {
      // These APIs accept arrays/options/loader parameters. We do not pretend
      // to resolve those expressions with a shell tokenizer.
      add(lineNumber, "process");
    }
  };
  for (let index = 0; index < lines.length; index++) {
    const lineNumber = index + 1;
    let line = lines[index];
    // The shell removes backslash-newline outright, so `ba\` + `sh` is bash.
    // In markdown prose a trailing backslash is a line break between words.
    const join = markdown && !fence ? " " : "";
    while (/\\$/.test(line) && index + 1 < lines.length) line = line.slice(0, -1) + join + lines[++index];
    // A leading # is a comment in code, but a heading in markdown prose, and a
    // heading can still tell the agent to run something.
    if ((!markdown || fence) && /^\s*(?:#|\/\/)/.test(line)) continue;
    if (markdown) {
      // Fences nested in list items are indented, so allow any indentation.
      const marker = line.match(/^\s*(`{3,}|~{3,})\s*([\w+.-]*)/);
      if (marker) {
        inspectProse();
        if (!fence) { fence = marker[1][0]; fenceLanguage = marker[2]; }
        else if (fence === marker[1][0]) fence = undefined;
        heredoc = undefined;
        continue;
      }
    }
    if (heredoc) {
      if (line.trim() === heredoc) { heredoc = undefined; continue; }
      // A heredoc body is the interpreter's input: code, not shell commands.
      inspectCommand(line, lineNumber, false, index, false);
      continue;
    }
    // Prose is read as shell only where it contains a command. Fences are read
    // by language: shell fences and script files as shell, text and data
    // fences like prose, other code fences with the code rules only.
    // Text and data fences read like prose. Shell fences and script files are
    // shell. Unlabelled and code-labelled fences get both the shell rules and the
    // code-loading rules, since a label cannot be trusted to hide commands; there
    // an executed target must look like a path, so words are not taken as files.
    const isProse = markdown && (!fence || (fenceLanguage !== "" && TEXT_FENCE.test(fenceLanguage)));
    const shell = !isProse && !code;
    const loose = markdown && !!fence && !SHELL_FENCE.test(fenceLanguage);
    // JSON bodies and HTTP request lines appear in shell fences; neither is a
    // command, and both stay subject to the line-level rules below.
    // A line cannot start with a pipe in shell, so one that does is a table row.
    const data = shell && /^\s*(?:[{}[\],|]|"[^"\n]*"\s*:|(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+\/|[\w-]+:\s)/.test(line);
    if (shell && !data) {
      line = line.replace(/^\s*(?:\$|>|PS [^>\n]*>)\s+/, "");
      // A quoted argument can span lines, such as a JSON request body.
      while (unclosedQuote(line) && index + 1 < lines.length && !/^\s*(`{3,}|~{3,})/.test(lines[index + 1])) {
        line += "\n" + lines[++index];
      }
      heredoc = line.match(/<<-?\s*(["']?)([A-Za-z_]\w*)\1/)?.[2];
    }
    const segments = isProse ? proseCommands(line) : [line];
    if (isProse && !fence) {
      // Markdown delimiters are not shell substitution, so the line-level rules
      // and the instruction tracker read prose with its code spans unwrapped.
      line = line.replace(/`([^`\n]+)`/g, "$1");
      if (!line.trim()) inspectProse();
      else {
        if (proseLength + line.length > 4096) inspectProse();
        prose.push(line); proseLength += line.length;
      }
    }
    for (const segment of data ? [] : segments) inspectCommand(segment, lineNumber, isProse || loose, index, isProse || shell, code || (loose && fenceLanguage !== ""));
    // The interpreter must receive the download: `| bash` or `bash <(...)`.
    // A domain like opsy.sh or a pipe into jq is not execution.
    const hasDownload = /\b(?:curl|wget|iwr|invoke-webrequest|irm|invoke-restmethod)\b/i.test(line);
    // `ba""sh` is bash to the shell: drop empty quote pairs before matching.
    const plain = line.replace(/(["'])\1/g, "");
    if (hasDownload && (PIPE_TO_INTERPRETER.test(plain) || INTERPRETER_SUBSTITUTION.test(plain) ||
        INTERPRETER_COMMAND_SUBSTITUTION.test(plain))) {
      // A vendor's own one-line installer, from an exact trusted host, is
      // reviewable. Any other host, or a mix, stays a block.
      if (onlyTrustedInstallers(line)) add(lineNumber, "trusted-installer");
      else add(lineNumber, "pipe-to-shell");
    }
    if (/\b(?:download|fetch)\b/i.test(line) && /(?<![-\w])(?:run|execute|source|eval)\b/i.test(line) && /https?:\/\//i.test(line)) {
      add(lineNumber, "download-and-run");
    }
  }
  inspectProse();
  return result;
}

