import { Parser, type Node } from "web-tree-sitter";
import type { SourceFile } from "../../../types.js";
import { DataflowDeadline, type Argument, type DataflowFrontend, type IRFunction, type IRNode, type IRProgram, type ValueId, coverage } from "../ir.js";
import { shellMayFind, shellSpecs, SHELL_OPTIONS, SHELL_SINKS } from "../specs/shell.js";
import { SECRET_ENV } from "../specs/common.js";

const MAX_CONSTANT = 4096;
const field = (node: Node, name: string) => node.childForFieldName(name);
const plain = (node: Node) => node.type === "raw_string" || node.type === "string" ? node.text.slice(1, -1) : node.text.replace(/\\(.)/g, "$1");
const redirect = (node: Node) => /^(?:file|herestring|heredoc)_redirect$/.test(node.type);
interface Word { node: Node; text: string; value: ValueId }
interface State { env: Map<string, ValueId>; files: Map<string, ValueId>; executable: Set<string> }

class Lowerer {
  readonly module: IRFunction = { name: "<module>", parameters: [], nodes: [], returns: [] };
  readonly functions: IRFunction[] = [];
  private fn = this.module;
  private state: State = { env: new Map(), files: new Map(), executable: new Set() };
  private loops: number[] = [];
  private loopId = 0;
  private depth = 0;
  private stdin: ValueId | undefined;
  // Where `cp` put a file, so loading it afterwards is not counted as a second job.
  private readonly installed = new Set<string>();
  private readonly functionNames: Set<string>;
  private readonly globalNames: Set<string>;

  constructor(root: Node, private readonly deadline = Infinity) {
    this.functionNames = new Set(root.descendantsOfType("function_definition").map((n) => field(n, "name")?.text ?? ""));
    this.globalNames = new Set(root.descendantsOfType("variable_assignment").filter((n) => {
      for (let parent = n.parent; parent; parent = parent.parent) if (parent.type === "function_definition") return false;
      return true;
    }).map((n) => field(n, "name")?.text ?? ""));
  }
  get globals(): Record<string, ValueId> { return Object.fromEntries(this.state.env); }
  private add(node: Node, op: IRNode["op"], inputs: ValueId[] = [], extra: Partial<IRNode> = {}): ValueId {
    const id = this.fn.nodes.length;
    // Lowering is not free: a huge script must stop at the budget, as the engine does.
    if ((id & 127) === 0 && performance.now() >= this.deadline) throw new DataflowDeadline();
    this.fn.nodes.push({ id, op, inputs, line: node.startPosition.row + 1, loops: [...this.loops], ...extra });
    return id;
  }
  private literal(node: Node, text = ""): ValueId { return this.add(node, "literal", [], { text }); }
  private merge(node: Node, inputs: ValueId[]): ValueId { return this.add(node, "merge", inputs); }
  private call(node: Node, name: string, values: ValueId[], names: (string | undefined)[] = []): ValueId {
    const callee = this.add(node, "symbol", [], { name });
    const args: Argument[] = values.map((value, index) => ({ value, name: names[index] }));
    return this.add(node, "call", [callee, ...values], { args });
  }
  // `x=$x$x` repeated doubles the string each line and shares every node, so
  // folding is memoised per function (nodes never change once added) and gives
  // up past MAX_CONSTANT characters. null caches "not a constant"; a cut-off by
  // depth is not cached, since the same node may be shallower from elsewhere.
  private readonly constants = new WeakMap<IRFunction, Map<ValueId, string | null>>();
  private constant(value: ValueId, depth = 0): string | undefined {
    if (depth > 24) return undefined;
    let memo = this.constants.get(this.fn);
    if (!memo) this.constants.set(this.fn, memo = new Map());
    const known = memo.get(value);
    if (known !== undefined) return known ?? undefined;
    const node = this.fn.nodes[value];
    let result: string | null = null;
    if (node.op === "literal") result = node.text ?? null;
    else if (node.op === "concat") {
      const parts: string[] = [];
      let size = 0;
      for (const id of node.inputs) {
        const part = this.constant(id, depth + 1);
        if (part === undefined) {
          // Unknown below a depth cut-off: answer, but do not remember it.
          if (memo.get(id) !== null) return undefined;
          parts.length = 0;
          break;
        }
        parts.push(part);
        size += part.length;
        // Paths and URLs are short; a longer fold is a body of text, not a name.
        if (size > MAX_CONSTANT) { parts.length = 0; break; }
      }
      if (parts.length === node.inputs.length) result = parts.join(node.text ?? "");
    }
    memo.set(value, result);
    return result ?? undefined;
  }
  private key(value: ValueId): string | undefined {
    const path = this.constant(value);
    return path === undefined ? undefined : path.replace(/^\$\{?HOME\}?(?=\/|$)/, "~").replace(/^\.\//, "");
  }
  private lookup(node: Node, name: string): ValueId {
    const bound = this.state.env.get(name);
    if (bound !== undefined) return bound;
    if (name === "HOME") return this.literal(node, "~");
    if (name === "@" || name === "*") return this.merge(node, [...this.state.env].filter(([key]) => /^\d+$/.test(key)).map(([, id]) => id));
    if (this.fn !== this.module && this.globalNames.has(name)) return this.add(node, "symbol", [], { name });
    return /PASS(?:$|_)/i.test(name) ? this.add(node, "symbol", [], { name: `shell.secret.${name}` }) : this.call(node, "shell.env", [this.literal(node, name)]);
  }
  private read(node: Node, path: ValueId): ValueId {
    // Bash opens a socket for this path, so what is read came from the network.
    if (SHELL_OPTIONS.socket.test(this.constant(path) ?? "")) return this.call(node, "shell.response", [path]);
    const loaded = this.call(node, "shell.read", [path]);
    const key = this.key(path), stored = key === undefined ? undefined : this.state.files.get(key);
    return stored === undefined ? loaded : this.merge(node, [loaded, stored]);
  }
  private write(node: Node, path: ValueId, data: ValueId, append = false): void {
    if (SHELL_OPTIONS.socket.test(this.constant(path) ?? "")) { this.call(node, "shell.send", [path, data], ["url"]); return; }
    this.call(node, "shell.write", [path, data]);
    const key = this.key(path);
    if (key !== undefined) {
      const old = this.state.files.get(key);
      this.state.files.set(key, append && old !== undefined ? this.merge(node, [old, data]) : data);
    }
  }
  private snapshot(): State { return { env: new Map(this.state.env), files: new Map(this.state.files), executable: new Set(this.state.executable) }; }
  private join(node: Node, states: State[]): void {
    const mergeMaps = (maps: Map<string, ValueId>[]) => {
      const result = new Map<string, ValueId>();
      for (const key of new Set(maps.flatMap((map) => [...map.keys()]))) {
        const values = maps.map((map) => map.get(key) ?? this.literal(node));
        result.set(key, values.every((id) => id === values[0]) ? values[0] : this.merge(node, values));
      }
      return result;
    };
    this.state = { env: mergeMaps(states.map((s) => s.env)), files: mergeMaps(states.map((s) => s.files)), executable: new Set(states.flatMap((s) => [...s.executable])) };
  }
  private scoped(node: Node): ValueId {
    const saved = this.snapshot();
    const result = this.sequence(node.namedChildren, node);
    this.state.env = saved.env;
    return result;
  }
  private sequence(nodes: Node[], owner: Node): ValueId {
    return nodes.length ? this.merge(owner, nodes.filter((c) => c.type !== "comment").map((c) => this.lower(c))) : this.literal(owner);
  }
  lower(node: Node, input = this.stdin): ValueId {
    if (this.depth >= 128) { coverage.incomplete = true; return this.literal(node); }
    this.depth++;
    const saved = this.stdin;
    this.stdin = input;
    try { return this.inner(node); } finally { this.stdin = saved; this.depth--; }
  }
  private inner(node: Node): ValueId {
    switch (node.type) {
      case "comment": return this.literal(node);
      case "word": case "number": case "string_content": case "heredoc_content": case "heredoc_start":
        return this.literal(node, plain(node));
      case "raw_string": return this.literal(node, node.text.slice(1, -1));
      case "string": case "concatenation": case "heredoc_body":
        return node.namedChildCount ? this.add(node, "concat", node.namedChildren.map((c) => this.lower(c))) : this.literal(node, plain(node));
      case "simple_expansion": case "expansion": {
        const name = node.namedChildren.find((c) => /^(?:variable_name|special_variable_name)$/.test(c.type));
        const operator = node.childrenForFieldName("operator").map((c) => c.text).join("");
        const values = name && operator !== ":+" && operator !== "+" ? [this.lookup(name, name.text)] : [];
        values.push(...node.namedChildren.filter((c) => c.id !== name?.id && c.type !== "variable_name").map((c) => this.lower(c)));
        return values.length === 1 ? values[0] : this.merge(node, values);
      }
      case "variable_assignment": {
        const name = field(node, "name")?.text, valueNode = field(node, "value");
        let value = valueNode ? this.lower(valueNode) : this.literal(node);
        if (name) {
          if (node.text.startsWith(`${name}+=`)) value = this.add(node, "concat", [this.lookup(node, name), value]);
          this.state.env.set(name, value);
        }
        return this.literal(node);
      }
      case "declaration_command": {
        for (const child of node.namedChildren.filter((c) => c.type === "variable_assignment")) this.lower(child);
        return /^export\s+-p(?:\s|$)/.test(node.text) ? this.add(node, "symbol", [], { name: "shell.environment" }) : this.literal(node);
      }
      case "command_substitution": case "process_substitution": case "subshell": return this.scoped(node);
      case "pipeline": {
        let output = this.stdin;
        for (const child of node.namedChildren) output = this.lower(child, output);
        return output ?? this.literal(node);
      }
      case "list": {
        const left = node.namedChildren[0], right = node.namedChildren[1];
        if (!left || !right) return this.sequence(node.namedChildren, node);
        const first = this.lower(left), before = this.snapshot(), second = this.lower(right), after = this.snapshot();
        this.join(node, [before, after]);
        return this.merge(node, [first, second]);
      }
      case "if_statement": return this.branch(node);
      case "for_statement": case "while_statement": case "c_style_for_statement": return this.loop(node);
      case "function_definition": this.function(node); return this.literal(node);
      case "redirected_statement": return this.redirected(node, field(node, "body"));
      case "command": return this.redirected(node, node);
      case "program": case "compound_statement": case "do_group": case "else_clause": case "elif_clause": return this.sequence(node.namedChildren, node);
      default: return this.merge(node, node.namedChildren.map((c) => this.lower(c)));
    }
  }
  private branch(node: Node): ValueId {
    const conditions = node.childrenForFieldName("condition");
    for (const condition of conditions) if (condition.isNamed) this.lower(condition);
    const base = this.snapshot(), arms: State[] = [], outputs: ValueId[] = [];
    const body = node.namedChildren.filter((c) => !conditions.some((n) => n.id === c.id));
    const then = body.filter((c) => c.type !== "else_clause" && c.type !== "elif_clause");
    outputs.push(this.sequence(then, node)); arms.push(this.snapshot());
    for (const arm of body.filter((c) => c.type === "else_clause" || c.type === "elif_clause")) {
      this.state = { env: new Map(base.env), files: new Map(base.files), executable: new Set(base.executable) };
      outputs.push(this.lower(arm)); arms.push(this.snapshot());
    }
    if (!body.some((c) => c.type === "else_clause")) arms.push(base);
    this.join(node, arms);
    return this.merge(node, outputs);
  }
  private loop(node: Node): ValueId {
    const before = this.snapshot();
    this.loops.push(++this.loopId);
    // Back edges preserve values assigned on a later iteration.
    const phis = new Map<string, ValueId>();
    for (const assignment of node.descendantsOfType("variable_assignment")) {
      const name = field(assignment, "name")?.text;
      if (name && !phis.has(name)) {
        const old = this.state.env.get(name) ?? this.lookup(assignment, name);
        const phi = this.merge(assignment, [old]); phis.set(name, phi); this.state.env.set(name, phi);
      }
    }
    const variable = field(node, "variable");
    if (variable) {
      const values = node.childrenForFieldName("value").map((c) => this.word(c));
      this.state.env.set(variable.text, this.merge(node, values.map((w) => w.value)));
    }
    for (const condition of node.childrenForFieldName("condition")) if (condition.isNamed) this.lower(condition);
    const body = field(node, "body"), result = body ? this.lower(body) : this.literal(node);
    for (const [name, phi] of phis) {
      const end = this.state.env.get(name);
      if (end !== undefined && end !== phi) this.fn.nodes[phi].inputs.push(end);
    }
    this.join(node, [before, this.snapshot()]);
    this.loops.pop();
    return result;
  }
  private function(node: Node): void {
    const name = field(node, "name")?.text, body = field(node, "body");
    if (!name || !body) return;
    const saved = { fn: this.fn, state: this.state, stdin: this.stdin, loops: this.loops };
    this.fn = { name, parameters: [...Array.from({ length: 9 }, (_, i) => `${i + 1}`), "__stdin"], nodes: [], returns: [] };
    this.functions.push(this.fn);
    this.state = { env: new Map(), files: new Map(), executable: new Set() }; this.loops = [];
    for (const [parameter, key] of this.fn.parameters.entries()) this.state.env.set(key, this.add(node, "parameter", [], { parameter }));
    this.stdin = this.state.env.get("__stdin");
    this.fn.returns.push(this.lower(body));
    Object.assign(this, saved);
  }
  private word(node: Node): Word {
    let value = this.lower(node);
    const text = plain(node);
    const glob = node.type === "word" ? /[*?\[]/.test(text) : node.type === "concatenation" && node.namedChildren.some((c) => c.type === "word" && /[*?\[]/.test(c.text));
    if (glob && SHELL_OPTIONS.home.test(this.constant(value) ?? text)) value = this.call(node, "shell.walk", [value]);
    return { node, text, value };
  }
  private redirected(node: Node, body: Node | null): ValueId {
    const redirects = node.namedChildren.filter(redirect).flatMap((r) => [r, ...r.childrenForFieldName("redirect")]);
    let input = this.stdin;
    const outputs: { node: Node; path: ValueId; append: boolean; stdout: boolean }[] = [];
    const suffixes: Node[] = [];
    for (const r of redirects) {
      if (r.type === "heredoc_redirect") {
        const content = r.namedChildren.find((c) => c.type === "heredoc_body");
        if (content) input = /['"\\]/.test(r.namedChildren.find((c) => c.type === "heredoc_start")?.text ?? "") ? this.literal(content, content.text) : this.lower(content);
        suffixes.push(...r.namedChildren.filter((c) => c.type === "pipeline"));
      } else if (r.type === "herestring_redirect") {
        const content = r.namedChildren.find((c) => c.type !== "file_descriptor");
        if (content) input = this.lower(content);
      } else {
        const dest = field(r, "destination");
        if (!dest || /(?:>&|<&)/.test(r.text)) continue;
        const path = this.lower(dest);
        if (/^\d*</.test(r.text)) input = dest.type === "process_substitution" ? path : this.read(r, path);
        else outputs.push({ node: r, path, append: r.text.includes(">>"), stdout: !/^[2-9]/.test(r.text) });
      }
    }
    const saved = this.stdin; this.stdin = input;
    const prefix = body?.id === node.id ? new Map(node.namedChildren.filter((c) => c.type === "variable_assignment").map((c) => { const name = field(c, "name")?.text ?? ""; return [name, this.state.env.get(name)] as const; })) : undefined;
    let value = body ? body.id === node.id ? this.command(body) : this.lower(body, input) : this.literal(node);
    for (const [name, prior] of prefix ?? []) { if (prior === undefined) this.state.env.delete(name); else this.state.env.set(name, prior); }
    this.stdin = saved;
    for (const suffix of suffixes) value = this.lower(suffix, value);
    for (const out of outputs) this.write(out.node, out.path, out.stdout ? value : this.literal(out.node), out.append);
    return outputs.some((out) => out.stdout) ? this.literal(node) : value;
  }
  private command(node: Node): ValueId {
    const nameNode = field(node, "name");
    if (!nameNode) return this.literal(node);
    const nameValue = this.lower(nameNode.namedChildren[0] ?? nameNode);
    const rawName = this.constant(nameValue) ?? nameNode.text;
    let name = rawName.split("/").pop() ?? rawName;
    for (const assignment of node.namedChildren.filter((c) => c.type === "variable_assignment")) this.lower(assignment);
    const args = node.childrenForFieldName("argument").filter((c) => c.isNamed).flatMap((c) => {
      const replacement = c.type === "expansion" && c.childrenForFieldName("operator").some((op) => op.text === ":+") ? c.namedChildren.find((n) => n.type === "concatenation") : undefined;
      return replacement && replacement.text.startsWith("-") ? replacement.namedChildren.map((n) => this.word(n)) : [this.word(c)];
    });
    // Bash's grammar separates the process substitution in x=@<(...) from x=@.
    const words: Word[] = [];
    for (const arg of args) {
      const prior = words.at(-1);
      if (prior && prior.node.endIndex === arg.node.startIndex && arg.node.type === "process_substitution") {
        prior.value = this.merge(arg.node, [prior.value, arg.value]); prior.text += arg.text;
      } else words.push({ ...arg });
    }
    // `curl ... | sudo -E bash -` runs bash: a wrapper names the real command after its own options.
    while (SHELL_OPTIONS.wrappers.test(name)) {
      let skip = 0;
      if (name === "sudo" || name === "doas") while (words[skip]?.text.startsWith("-")) skip += SHELL_OPTIONS.sudoValue.test(words[skip].text) ? 2 : 1;
      // `env -u X A=1 sh`: options and assignments come before the command.
      if (name === "env") while (words[skip] && (words[skip].text.startsWith("-") || /^[A-Za-z_]\w*=/.test(words[skip].text))) skip += /^(?:-u|--unset|-C|--chdir)$/.test(words[skip].text) ? 2 : 1;
      if (name === "nice") while (words[skip]?.text.startsWith("-")) skip += /^(?:-n|--adjustment)$/.test(words[skip].text) ? 2 : 1;
      const next = words[skip];
      if (!next || next.text.startsWith("-")) break;
      words.splice(0, skip + 1);
      name = next.text.split("/").pop()!;
    }
    // Sinks are dispatched by kind, never by name: specs/shell.ts owns the names.
    const sink = SHELL_SINKS.get(name);
    const empty = () => this.literal(node);
    const stdin = () => this.stdin ?? empty();
    const values = () => words.map((w) => w.value);
    const inputs = () => this.merge(node, [stdin(), ...values()]);
    const nonOptions = () => words.filter((w) => !w.text.startsWith("-"));
    const fileInputs = () => {
      const paths = words.filter((w, i) => !w.text.startsWith("-") && !(i > 0 && (name === "head" || name === "tail" ? /^(?:-n|-c|--lines|--bytes)$/ : /^(?:-w|--wrap)$/).test(words[i - 1].text)));
      return paths.length ? this.merge(node, paths.map((w) => w.text === "-" ? stdin() : w.node.type === "process_substitution" ? w.value : this.read(w.node, w.value))) : stdin();
    };
    if (this.functionNames.has(rawName)) {
      return this.call(node, rawName, [...Array.from({ length: 9 }, (_, i) => words[i]?.value ?? empty()), stdin()]);
    }
    if (name === "read") {
      for (const word of words) if (/^[a-zA-Z_]\w*$/.test(word.text)) this.state.env.set(word.text, stdin());
      return empty();
    }
    if (name === "echo" || name === "printf") return this.merge(node, values());
    if (name === "cat" || name === "head" || name === "tail") return fileInputs();
    if (name === "env" || name === "set" && !words.length) return this.add(node, "symbol", [], { name: "shell.environment" });
    if (name === "printenv") return words.length ? this.merge(node, words.map((w) => this.call(node, "shell.env", [w.value]))) : this.add(node, "symbol", [], { name: "shell.environment" });
    if (name === "pbpaste" || name === "xsel" || name === "xclip" && words.some((w) => /^-(?:o|out)$/.test(w.text))) return this.call(node, "shell.clipboard", []);
    if (name === "whoami" || name === "hostname" && !words.some((w) => !w.text.startsWith("-")) || name === "id" && words.some((w) => /^-[a-z]*n/.test(w.text)) || name === "uname" && words.some((w) => /^-[a-z]*[an]/.test(w.text))) return this.call(node, "shell.host", []);
    if (name === "find") return this.find(node, words);
    if (name === "ls" && words.some((w) => /^-[^-]*R/.test(w.text))) return this.call(node, "shell.walk", values());
    if (sink === "codec") {
      const decode = words.some((w) => /^(?:--decode|-[^-]*[dD])$/.test(w.text) || name === "xxd" && w.text === "-r");
      return this.call(node, decode ? "shell.decode" : "shell.encode", [fileInputs()]);
    }
    if (sink === "archive") {
      // An archive written to a file carries what went into it to a later upload.
      const paths = nonOptions(), flags = words.findIndex((w, i) => /^-?[a-zA-Z]*f$/.test(w.text) && (i === 0 || w.text.startsWith("-")));
      const target = name === "zip" ? paths[0] : name === "tar" && flags >= 0 && /c/.test(words.slice(0, flags + 1).map((w) => w.text).join("")) ? words[flags + 1] : undefined;
      if (target && target.text !== "-") {
        const members = name === "zip" ? paths.slice(1) : words.slice(flags + 2).filter((w) => !w.text.startsWith("-"));
        this.write(node, target.value, this.call(node, "shell.encode", [this.merge(node, members.map((w) => this.read(w.node, w.value)))]));
        return empty();
      }
      if (name === "zip") return this.call(node, "shell.encode", [this.merge(node, paths.slice(1).map((w) => this.read(w.node, w.value)))]);
      const stdout = words.some((w) => w.text === "--stdout" || (name === "tar" ? /^-?[a-zA-Z]*c[a-zA-Z]*$/ : /^-[^-]*c/).test(w.text)) && (name !== "tar" || words.some((w) => /^(?:-?[^-]*f-|-)$/.test(w.text)));
      return stdout ? this.call(node, words.some((w) => w.text === "-d" || w.text === "--decompress") ? "shell.decode" : "shell.encode", [fileInputs()]) : empty();
    }
    if (sink === "cipher" && (name === "openssl" ? words[0]?.text === "enc" : name === "gpg" ? words.some((w) => /^(?:-c|--symmetric)$/.test(w.text)) : words.length >= 2)) {
      const inIndex = words.findIndex((w) => w.text === "-in"), outIndex = words.findIndex((w) => /^(?:-out|-o|--output)$/.test(w.text));
      let data = inIndex >= 0 && words[inIndex + 1] ? this.read(node, words[inIndex + 1].value) : stdin();
      if (name === "gpg") {
        const path = words.at(-1);
        if (path && !path.text.startsWith("-") && outIndex !== words.length - 2) data = this.read(path.node, path.value);
      }
      const encrypted = this.call(node, words.some((w) => w.text === "-d") ? "shell.decode" : "shell.encrypt", [data]);
      if (outIndex >= 0 && words[outIndex + 1]) {
        if (words[outIndex + 1].text === "-") return encrypted;
        this.write(node, words[outIndex + 1].value, encrypted); return empty();
      }
      if (name === "gpg") {
        const path = words.at(-1);
        if (path && !path.text.startsWith("-")) {
          this.write(node, this.add(node, "concat", [path.value, this.literal(node, ".gpg")]), encrypted);
          return empty();
        }
      }
      return encrypted;
    }
    if (sink === "transfer") return this.transfer(node, name === "curl" ? "curl" : "wget", words);
    if (sink === "send") {
      this.call(node, "shell.send", [words[0]?.value ?? empty(), stdin(), ...values()], ["url"]);
      return empty();
    }
    if (sink === "copy") {
      const paths = words.filter((w, i) => !w.text.startsWith("-") && !(i > 0 && SHELL_OPTIONS.remoteValue.test(words[i - 1].text))), destination = paths.at(-1);
      if (destination && SHELL_OPTIONS.remote.test(destination.text)) this.call(node, "shell.send", [destination.value, ...paths.slice(0, -1).map((w) => this.read(w.node, w.value))], ["url"]);
      return empty();
    }
    if (sink === "dns") { this.call(node, "shell.dns", values()); return empty(); }
    if (SHELL_OPTIONS.interpreters.test(name) || name === "eval" || name === "source" || name === "." || /^(?:python[\d.]*|node)$/.test(name)) {
      let code = stdin();
      const inline = words.findIndex((w) => /^(?:-c|-e|--eval)$/.test(w.text));
      if (inline >= 0) code = words[inline + 1]?.value ?? empty();
      else if (name === "eval") code = this.merge(node, values());
      else {
        const path = nonOptions()[0];
        if (path) code = path.node.type === "process_substitution" ? path.value : this.read(path.node, path.value);
      }
      this.call(node, "shell.execute", [code]); return empty();
    }
    if (name === "chmod") {
      if (words.some((w) => /(?:\+x|^[0-7]*[1357][0-7]{2}$)/.test(w.text))) for (const word of words.slice(1)) { const key = this.key(word.value); if (key) this.state.executable.add(key); }
      return empty();
    }
    if (name === "rm" || name === "mv") {
      this.call(node, "shell.mutate", values());
      const source = nonOptions()[0], destination = nonOptions()[1];
      const sourceKey = source && this.key(source.value), destKey = destination && this.key(destination.value);
      if (sourceKey !== undefined) {
        const contents = this.state.files.get(sourceKey);
        if (name === "mv" && destKey !== undefined && contents !== undefined) this.state.files.set(destKey, contents);
        this.state.files.delete(sourceKey);
      }
      return empty();
    }
    if (sink === "crontab") {
      if (!words.some((w) => /^(?:-l|-r)$/.test(w.text))) this.write(node, this.literal(node, "crontab"), words[0]?.text === "-" ? stdin() : words[0] ? this.read(node, words[0].value) : stdin());
      return empty();
    }
    if (sink === "launchctl" && words[0]?.text === "load" && words[1]) {
      // Copying a plist into place and then loading it is one job, reported at the copy.
      const plist = this.key(words[1].value);
      if (plist !== undefined && [...this.installed].some((place) => plist === place || plist.startsWith(`${place}/`))) return empty();
      // Loading registers a launchd job even for a plist outside LaunchAgents.
      this.call(node, "shell.write", [this.literal(node, "~/Library/LaunchAgents"), words[1].value]);
      return empty();
    }
    if (sink === "store") {
      const paths = nonOptions(), destination = paths.at(-1);
      if (destination && paths.length > 1) {
        this.write(node, destination.value, this.merge(node, paths.slice(0, -1).map((w) => this.read(w.node, w.value))));
        const place = this.key(destination.value);
        if (place !== undefined) this.installed.add(place.replace(/\/$/, ""));
      }
      return empty();
    }
    if (sink === "tee") {
      for (const path of nonOptions()) this.write(node, path.value, stdin(), words.some((w) => w.text === "-a"));
      return stdin();
    }
    const key = this.key(nameValue);
    if (key && this.state.executable.has(key) && this.state.files.has(key)) this.call(node, "shell.execute", [this.state.files.get(key)!]);
    if (nameNode.namedChildren.some((c) => c.type !== "word")) this.call(node, "shell.execute", [nameValue]);
    return inputs();
  }
  private find(node: Node, words: Word[]): ValueId {
    const walked = this.call(node, "shell.walk", words.filter((w) => !w.text.startsWith("-")).map((w) => w.value));
    const exec = words.findIndex((w) => w.text === "-exec" || w.text === "-execdir");
    if (exec >= 0 && /(?:^|\/)openssl$/.test(words[exec + 1]?.text ?? "") && words[exec + 2]?.text === "enc") {
      const input = words.findIndex((w, i) => i > exec && w.text === "-in"), output = words.findIndex((w, i) => i > exec && w.text === "-out");
      if (input >= 0 && words[input + 1]?.text.includes("{}")) {
        this.loops.push(++this.loopId);
        const data = this.read(node, walked), encrypted = this.call(node, "shell.encrypt", [data]);
        if (output >= 0) this.write(node, this.merge(node, [walked, words[output + 1]?.value ?? walked]), encrypted);
        this.loops.pop();
      }
    }
    return walked;
  }
  private environmentNames(values: ValueId[]): Set<string> {
    const names = new Set<string>(), visited = new Set<ValueId>(), queue = [...values];
    while (queue.length && visited.size < 512) {
      const id = queue.pop()!;
      if (visited.has(id)) continue;
      visited.add(id);
      const node = this.fn.nodes[id];
      if (node.op === "symbol" && node.name?.startsWith("shell.secret.")) names.add(node.name);
      if (node.op === "parameter") names.add(`parameter:${node.parameter}`);
      if (node.op === "call" && this.fn.nodes[node.inputs[0]]?.name === "shell.env") {
        const key = node.args?.[0] && this.constant(node.args[0].value);
        if (key && SECRET_ENV.test(key)) names.add(key);
      }
      queue.push(...node.inputs);
    }
    if (queue.length) names.add("unknown");
    return names;
  }
  private transfer(node: Node, name: "curl" | "wget", words: Word[]): ValueId {
    let url = this.literal(node), output: Word | undefined, prefix: string | undefined, remoteName = false;
    const payloads: ValueId[] = [], headers: ValueId[] = [];
    const stdin = () => this.stdin ?? this.literal(node);
    const upload = (word: Word, file: boolean, form = false, urlencode = false) => {
      const text = word.text;
      const at = (form ? /(?:^|=)@/ : urlencode ? /(?:^|^[^=@]+)@/ : /^@/).exec(text);
      if (file || at) {
        const path = file ? text : text.slice(at!.index + at![0].length);
        if (path === "-" || path === "@-") return stdin();
        if (word.node.type === "process_substitution" || text.includes("<(") || text.includes(">(")) return word.value;
        // Remove the upload marker while retaining a dynamic path's provenance.
        const value = this.constant(word.value);
        const marker = value === undefined ? undefined : (form ? /(?:^|=)@/ : urlencode ? /(?:^|^[^=@]+)@/ : /^@/).exec(value);
        const resolved = value === undefined ? word.value : this.literal(word.node, file ? value.replace(/^@/, "") : value.slice(marker ? marker.index + marker[0].length : 0));
        return this.read(word.node, resolved);
      }
      return word.value;
    };
    for (let i = 0; i < words.length; i++) {
      let word = words[i], option = word.text, attached: string | undefined;
      const long = /^(--[^=]+)=(.*)$/.exec(option);
      // -qO- and -sSLo are clusters: flags, then the first letter that takes a value, then the value if attached.
      const cluster = long || option.startsWith("--") ? null : (name === "curl" ? /^-[A-Za-z#]*?([dFTHuoXAemxbc])(.*)$/ : /^-[A-Za-z]*?(O)(.*)$/).exec(option);
      if (long) { option = long[1]; attached = long[2]; }
      else if (cluster) { option = `-${cluster[1]}`; attached = cluster[2] || undefined; }
      const takesValue = name === "curl" ? SHELL_OPTIONS.curlData.test(option) || SHELL_OPTIONS.curlValue.test(option) : SHELL_OPTIONS.wgetValue.test(option);
      if (takesValue) {
        if (attached !== undefined) word = { ...word, text: attached, value: this.constant(word.value) !== undefined ? this.literal(word.node, attached) : word.value };
        else { const next = words[++i]; if (!next) break; word = next; }
        if (name === "curl" && SHELL_OPTIONS.curlData.test(option)) payloads.push(option === "--data-raw" || option === "--form-string" ? word.value : upload(word, option === "-T" || option === "--upload-file", option === "-F" || option === "--form", option === "--data-urlencode"));
        else if (option === "--post-data" || option === "--post-file") payloads.push(upload(word, option === "--post-file"));
        else if (option === "-H" || option === "--header") {
          const expansions = word.node.descendantsOfType(["simple_expansion", "expansion"]);
          if (/^(?:Authorization:\s*Bearer\s+|X-API-Key:\s*)\$\{?\w+\}?$/i.test(word.text) && expansions.length === 1) headers.push(word.value);
          else payloads.push(word.value);
        } else if (option === "-u" || option === "--user") payloads.push(word.value);
        else if (/^(?:-o|--output|-O|--output-document)$/.test(option)) output = word;
        else if (option === "--url") url = word.value;
        else if (option === "-P" || option === "--directory-prefix") prefix = this.constant(word.value);
      } else if (name === "curl" && /^(?:-[A-Za-z#]*O[A-Za-z#]*|--remote-name)$/.test(option)) remoteName = true;
      else if (!option.startsWith("-")) url = word.value;
    }
    const authOnly = this.environmentNames(headers).size <= 1;
    this.call(node, name === "curl" ? "shell.curl" : "shell.wget", [url, ...payloads, ...headers], ["url", ...payloads.map(() => undefined), ...headers.map(() => authOnly ? "headers" : undefined)]);
    const response = this.call(node, "shell.response", [url]);
    if (output && output.text !== "-") { this.write(node, output.value, response); return this.literal(node); }
    // wget, and curl -O, save under the URL's last path segment, so `sh file`
    // afterwards runs the download.
    if (!output && (name === "wget" || remoteName)) {
      const href = this.constant(url);
      const base = href === undefined ? undefined : /^(?:[a-z][\w+.-]*:\/\/)?[^/?#]*(?:[^?#]*\/)?([^/?#]*)/i.exec(href)?.[1] || (name === "wget" ? "index.html" : undefined);
      if (base) this.write(node, this.literal(node, prefix ? `${prefix.replace(/\/+$/, "")}/${base}` : base), response);
      return this.literal(node);
    }
    return response;
  }
}

export const shellFrontend: DataflowFrontend = {
  grammar: "bash",
  specs: shellSpecs,
  mayFind: shellMayFind,
  lower(root: Node, source: SourceFile, deadline?: number): IRProgram {
    // Prompt removal is restricted to uniformly prompted documentation blocks.
    const lines = source.text.split("\n"), nonempty = lines.filter((line) => line.trim());
    const prompt = /\.(?:md|markdown|mdown)$/i.test(source.path) && nonempty.length ? /^(\$ |# )/.exec(nonempty[0])?.[0] : undefined;
    let parser: Parser | undefined, tree;
    try {
      if (prompt && nonempty.every((line) => line.startsWith(prompt))) {
        parser = new Parser(); parser.setLanguage(root.tree.language);
        tree = parser.parse(lines.map((line) => line.startsWith(prompt) ? line.slice(prompt.length) : line).join("\n"));
        if (tree) root = tree.rootNode;
      }
      const lowerer = new Lowerer(root, deadline);
      lowerer.lower(root);
      return { source, module: lowerer.module, functions: lowerer.functions, globals: lowerer.globals };
    } finally { tree?.delete(); parser?.delete(); }
  },
};
