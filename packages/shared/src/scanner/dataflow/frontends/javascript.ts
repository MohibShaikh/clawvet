import type { Node } from "web-tree-sitter";
import type { SourceFile } from "../../../types.js";
import type { Argument, DataflowFrontend, IRFunction, IRNode, IRProgram, ValueId } from "../ir.js";
import { persistencePath, sinkHint } from "../specs/common.js";
import { DataflowDeadline, coverage } from "../ir.js";
import { javascriptApis as apis, javascriptSpecs } from "../specs/javascript.js";

const field = (node: Node, name: string) => node.childForFieldName(name);
const children = (node: Node) => node.namedChildren;
const isFunction = (node: Node) => /^(?:arrow_function|function_expression|function_declaration|generator_function|generator_function_declaration)$/.test(node.type);
const unquote = (text: string) => text.slice(1, -1).replace(/\\(?:u\{([\da-f]+)\}|u([\da-f]{4})|x([\da-f]{2})|([\s\S]))/gi, (_match, wide: string, unicode: string, hex: string, char: string) => {
  if (wide || unicode || hex) { const code = parseInt(wide || unicode || hex, 16); return code <= 0x10ffff ? String.fromCodePoint(code) : ""; }
  return ({ n: "\n", r: "\r", t: "\t", b: "\b", f: "\f", v: "\v", "0": "\0", "\n": "" } as Record<string, string>)[char] ?? char;
});
const keyName = (node: Node) => node.type === "string" ? unquote(node.text) : node.text;
const moduleName = (name: string) => name.replace(/^node:/, "").replaceAll("/promises", ".promises");

class Lowerer {
  constructor(private readonly deadline = Infinity) {}
  readonly module: IRFunction = { name: "<module>", parameters: [], nodes: [], returns: [] };
  readonly functions: IRFunction[] = [];
  private fn = this.module;
  private env = new Map<string, ValueId>();
  private shapes = new Map<ValueId, Map<string, ValueId>>();
  private api = new Map<ValueId, string>();
  private files = new Map<string, ValueId>();
  private readonly moduleEnv = this.env;
  private readonly moduleApi = this.api;
  readonly apis = new Map<IRFunction, Map<ValueId, string>>([[this.module, this.api]]);
  private loops: number[] = [];
  private loopId = 0;
  private depth = 0;
  private journals: Map<string, ValueId | undefined>[] = [];
  get globals(): Record<string, ValueId> { return Object.fromEntries(this.env); }

  private add(node: Node, op: IRNode["op"], inputs: ValueId[] = [], extra: Partial<IRNode> = {}): ValueId {
    const id = this.fn.nodes.length;
    if ((id & 127) === 0 && performance.now() >= this.deadline) throw new DataflowDeadline();
    this.fn.nodes.push({ id, op, inputs, line: node.startPosition.row + 1, loops: [...this.loops], ...extra });
    if (op === "symbol" && extra.name) this.api.set(id, extra.name);
    if (op === "merge") {
      const canonical = inputs.map((input) => this.api.get(input)).find(Boolean);
      if (canonical) this.api.set(id, canonical);
      if (inputs.length === 1 && this.shapes.has(inputs[0])) this.shapes.set(id, this.shapes.get(inputs[0])!);
    }
    return id;
  }
  private symbol(node: Node, name: string): ValueId { return this.add(node, "symbol", [], { name }); }
  private bind(name: string, value: ValueId): void {
    for (const journal of this.journals) if (!journal.has(name)) journal.set(name, this.env.get(name));
    this.env.set(name, value);
  }
  private lookup(node: Node): ValueId {
    const local = this.env.get(node.text); if (local !== undefined) return local;
    const value = this.symbol(node, node.text), global = this.moduleEnv.get(node.text);
    if (global !== undefined && this.moduleApi.has(global)) this.api.set(value, this.moduleApi.get(global)!);
    return value;
  }
  private property(node: Node, base: ValueId, name: string): ValueId {
    const known = this.shapes.get(base)?.get(name);
    if (known !== undefined) return known;
    // An env member selects one variable; ordinary attributes preserve the receiver.
    if (apis.env.test(this.api.get(base) ?? "")) return this.add(node, "index", [base, this.add(node, "literal", [], { text: name })]);
    const value = this.add(node, "attribute", [base], { name });
    this.api.set(value, `${this.api.get(base) ?? ""}.${name}`);
    return value;
  }
  private assign(target: Node | null, value: ValueId): void {
    if (!target) return;
    if (/^(?:identifier|shorthand_property_identifier_pattern)$/.test(target.type)) { this.bind(target.text, value); return; }
    if (target.type === "required_parameter" || target.type === "optional_parameter") { this.assign(field(target, "pattern"), value); return; }
    if (target.type === "assignment_pattern" || target.type === "object_assignment_pattern") { this.assign(field(target, "left"), value); return; }
    if (target.type === "object_pattern") {
      for (const item of children(target)) {
        if (item.type === "pair_pattern") {
          const key = field(item, "key"), dest = field(item, "value");
          if (key) this.assign(dest, this.property(item, value, keyName(key)));
        } else if (item.type === "rest_pattern") this.assign(children(item)[0], value);
        else if (item.type === "object_assignment_pattern") {
          const left = field(item, "left"); if (left) this.assign(left, this.property(item, value, left.text));
        } else this.assign(item, this.property(item, value, item.text));
      }
      return;
    }
    if (target.type === "member_expression" || target.type === "subscript_expression") {
      const object = field(target, "object");
      if (object) {
        const base = this.expr(object);
        (this.fn.nodes[base].mutations ??= []).push(value);
        const key = field(target, "property") ?? field(target, "index");
        if (key && (key.type !== "identifier" || target.type === "member_expression")) {
          const shape = this.shapes.get(base) ?? new Map<string, ValueId>();
          shape.set(keyName(key), value); this.shapes.set(base, shape);
        }
      }
      return;
    }
    for (const child of children(target)) if (!child.type.includes("type")) this.assign(child, value);
  }
  private importNode(node: Node): void {
    const source = field(node, "source");
    if (!source || children(node).some((c) => c.text === "type")) return;
    const canonical = moduleName(unquote(source.text));
    const clause = children(node).find((c) => c.type === "import_clause");
    for (const item of clause ? children(clause) : []) {
      if (item.type === "identifier") this.bind(item.text, this.symbol(item, canonical));
      if (item.type === "namespace_import") {
        const alias = children(item).at(-1); if (alias) this.bind(alias.text, this.symbol(alias, canonical));
      }
      if (item.type === "named_imports") for (const specifier of children(item)) {
        const name = field(specifier, "name"), alias = field(specifier, "alias") ?? name;
        if (name && alias) this.bind(alias.text, this.symbol(alias, `${canonical}.${name.text}`));
      }
    }
  }
  private functionNode(node: Node, name: string): ValueId {
    const binding = this.symbol(node, name);
    const saved = { fn: this.fn, env: this.env, shapes: this.shapes, api: this.api, files: this.files, loops: this.loops, journals: this.journals, lookup: this.lookup };
    this.fn = { name, parameters: [], nodes: [], returns: [] }; this.functions.push(this.fn);
    this.env = new Map(); this.shapes = new Map(); this.api = new Map(); this.files = new Map(); this.loops = []; this.journals = [];
    this.apis.set(this.fn, this.api);
    this.lookup = Lowerer.prototype.lookup;
    const params = field(node, "parameters");
    const parameters = params ? children(params) : [field(node, "parameter")].filter((p): p is Node => !!p);
    for (const param of parameters) {
      if (param.type.includes("type")) continue;
      const parameter = this.fn.parameters.length;
      this.fn.parameters.push(param.text);
      this.assign(param, this.add(param, "parameter", [], { parameter }));
    }
    const body = field(node, "body");
    if (body?.type === "statement_block") this.statement(body);
    else if (body) this.fn.returns.push(this.expr(body));
    Object.assign(this, saved);
    return binding;
  }
  private branch(node: Node, arms: Node[], exhaustive = false): void {
    const changed = new Map<string, ValueId | undefined>(), outputs = new Map<string, ValueId[]>();
    for (const arm of arms) {
      const journal = new Map<string, ValueId | undefined>(); this.journals.push(journal);
      this.statement(arm); this.journals.pop();
      for (const [name, prior] of journal) {
        if (!this.env.has(name)) continue;
        if (!changed.has(name)) changed.set(name, prior);
        const values = outputs.get(name) ?? []; values.push(this.env.get(name)!); outputs.set(name, values);
        if (prior === undefined) this.env.delete(name); else this.env.set(name, prior);
      }
    }
    for (const [name, prior] of changed) {
      const values = outputs.get(name)!;
      if (prior !== undefined && !(exhaustive && values.length === arms.length)) values.push(prior);
      this.bind(name, this.add(node, "merge", values));
    }
  }
  private loop(node: Node, run: () => void): void {
    this.loops.push(++this.loopId);
    const journal = new Map<string, ValueId | undefined>(), phis = new Map<string, ValueId>();
    this.journals.push(journal);
    const outerLookup = this.lookup;
    this.lookup = (ref: Node) => {
      const old = this.env.get(ref.text);
      if (old !== undefined && !journal.has(ref.text) && !phis.has(ref.text)) {
        const phi = this.add(ref, "merge", [old]); phis.set(ref.text, phi); this.bind(ref.text, phi);
        if (this.api.has(old)) this.api.set(phi, this.api.get(old)!);
      }
      return outerLookup.call(this, ref);
    };
    run(); this.lookup = outerLookup; this.journals.pop();
    for (const [name, phi] of phis) { const end = this.env.get(name); if (end !== undefined && end !== phi) this.fn.nodes[phi].inputs.push(end); }
    for (const [name, prior] of journal) {
      const end = this.env.get(name);
      if (prior !== undefined && end !== undefined && !phis.has(name)) this.bind(name, this.add(node, "merge", [prior, end]));
    }
    this.loops.pop();
  }
  statement(node: Node): void {
    if (this.depth >= 128) { coverage.incomplete = true; return; }
    this.depth++;
    try { this.statementInner(node); } finally { this.depth--; }
  }
  private statementInner(node: Node): void {
    switch (node.type) {
      case "import_statement": this.importNode(node); return;
      case "function_declaration": case "generator_function_declaration": {
        const name = field(node, "name"); if (name) this.bind(name.text, this.functionNode(node, name.text)); return;
      }
      case "variable_declarator": {
        const name = field(node, "name"), value = field(node, "value");
        if (name && value) this.assign(name, isFunction(value) ? this.functionNode(value, name.text) : this.expr(value));
        return;
      }
      case "return_statement": for (const child of children(node)) this.fn.returns.push(this.expr(child)); return;
      case "if_statement": {
        const condition = field(node, "condition"); if (condition) this.expr(condition);
        const consequence = field(node, "consequence"), alternative = field(node, "alternative");
        this.branch(node, [consequence, alternative].filter((n): n is Node => !!n), !!alternative); return;
      }
      case "try_statement": this.branch(node, children(node).filter((c) => ["statement_block", "catch_clause"].includes(c.type))); {
        const final = field(node, "finalizer"); if (final) this.statement(final); return;
      }
      case "for_in_statement": this.loop(node, () => {
        const right = field(node, "right"), left = field(node, "left"), body = field(node, "body");
        if (right) this.assign(left, this.expr(right)); if (body) this.statement(body);
      }); return;
      case "for_statement": case "while_statement": case "do_statement": this.loop(node, () => {
        for (const name of ["initializer", "condition", "body", "increment"]) { const part = field(node, name); if (part) this.statement(part); }
      }); return;
      case "program": case "statement_block": case "expression_statement": case "lexical_declaration": case "variable_declaration": case "else_clause": case "catch_clause": case "finally_clause": case "export_statement":
        for (const child of children(node)) this.statement(child); return;
      case "interface_declaration": case "type_alias_declaration": return;
      default: this.expr(node);
    }
  }
  private options(value: ValueId): Argument[] {
    const shape = this.shapes.get(value);
    return shape ? [...shape].map(([name, value]) => ({ name: name === "apiKey" ? "api_key" : name, value })) : [{ value }];
  }
  private literalPieces(value: ValueId, seen = new Set<ValueId>()): string[] {
    if (seen.has(value) || seen.size >= 128) return [];
    seen.add(value); const node = this.fn.nodes[value];
    if (node.op === "literal") return [node.text ?? ""];
    if (node.op !== "merge" && node.op !== "concat") return [];
    const parts = node.inputs.flatMap((id) => this.literalPieces(id, seen));
    return node.op === "concat" ? [parts.join(node.text ?? "")] : parts.slice(0, 16);
  }
  private fileKey(value: ValueId): string { const node = this.fn.nodes[value]; return node.op === "literal" ? `path:${node.text?.replace(/^\.\//, "")}` : `value:${value}`; }
  private executedValue(node: Node, value: ValueId, seen = new Set<ValueId>()): ValueId {
    if (seen.has(value) || seen.size >= 128) return value;
    seen.add(value);
    const stored = this.files.get(this.fileKey(value));
    if (stored !== undefined) return this.add(node, "merge", [value, stored]);
    const ir = this.fn.nodes[value];
    const inputs = ir.op === "concat" || ir.op === "merge" ? ir.inputs.map((id) => this.executedValue(node, id, seen)) : [];
    if (ir.op === "literal") for (const [path, data] of this.files) {
      if (path.startsWith("path:") && path.length > 5 && ir.text?.split(/[\s'";|&]+/).includes(path.slice(5))) inputs.push(data);
    }
    return inputs.length ? this.add(node, "merge", [value, ...inputs]) : value;
  }
  private inline(node: Node, values: ValueId[]): ValueId {
    const params = field(node, "parameters"), parameter = field(node, "parameter");
    const parameters = params ? children(params) : parameter ? [parameter] : [];
    const prior = new Map(this.env), returns = this.fn.returns;
    this.fn.returns = [];
    parameters.forEach((param, index) => this.assign(param, values[index] ?? this.add(param, "merge")));
    const body = field(node, "body");
    if (body?.type === "statement_block") this.statement(body);
    else if (body) this.fn.returns.push(this.expr(body));
    const result = this.add(node, "merge", this.fn.returns);
    this.fn.returns = returns;
    // Callback parameters are local; captured assignments remain visible outside.
    for (const param of parameters) for (const [name] of this.env) {
      if (name === param.text) { const old = prior.get(name); if (old === undefined) this.env.delete(name); else this.env.set(name, old); }
    }
    return result;
  }
  private call(node: Node): ValueId {
    const callee = field(node, "function") ?? field(node, "constructor"), argumentList = field(node, "arguments");
    // A tagged template ($`cmd ${x}`) passes one string built from its parts.
    const syntaxArgs = argumentList ? argumentList.type === "template_string" ? [argumentList] : children(argumentList) : [];
    let target = callee ? this.expr(callee) : this.symbol(node, "");
    let name = this.api.get(target) ?? "";
    const receiver = callee && ["member_expression", "subscript_expression"].includes(callee.type) ? this.fn.nodes[target].inputs[0] : undefined;
    const values = syntaxArgs.map((arg) => isFunction(arg) ? this.add(arg, "merge") : this.expr(arg));
    // Static requires are imports; a dynamic require remains an execution sink.
    if (name === "require" && syntaxArgs[0]?.type === "string" && !this.files.has(this.fileKey(values[0]))) return this.symbol(node, moduleName(unquote(syntaxArgs[0].text)));
    if (name === "Buffer.from" && this.fn.nodes[values[1]]?.text === "base64") name += ".base64";
    if (name.endsWith(".toString") && this.fn.nodes[values[0]]?.text === "base64") name += ".base64";
    if (apis.command.test(name)) {
      // Bun.spawn(["sh", "-c", code]) takes argv as one array: split it into the executable and its arguments.
      if (/^Bun\.spawn/.test(name) && syntaxArgs[0]?.type === "array") {
        const argv = this.fn.nodes[values[0]].inputs;
        if (argv.length) values.splice(0, 1, argv[0], this.add(node, "merge", argv.slice(1)));
      }
      if (!apis.shell.test(name) && values.length) {
        const executable = this.executedValue(node, values[0]);
        const code = [executable];
        if (/(?:^|\/)(?:node|nodejs|bun|deno|python[\d.]*|sh|bash|zsh|pwsh|powershell)(?:\.exe)?$/.test(this.fn.nodes[values[0]].text ?? "")) {
          const argv = this.fn.nodes[values[1]]?.inputs ?? [];
          const script = argv.find((id) => !this.fn.nodes[id].text?.startsWith("-"));
          if (script !== undefined) code.push(this.executedValue(node, script));
        }
        const value = this.add(node, "merge", code);
        this.add(node, "call", [this.symbol(node, "clawvet.execute"), value], { args: [{ value }] });
      }
      const command = values.slice(0, syntaxArgs.findIndex((a) => isFunction(a)) < 0 ? values.length : syntaxArgs.findIndex((a) => isFunction(a)));
      const combined = this.add(node, "merge", command);
      values[0] = this.executedValue(node, combined);
      const text = this.literalPieces(combined).join(" ");
      if (apis.clipboard.test(text)) {
        const clip = this.add(node, "call", [this.symbol(node, "clawvet.clipboard")], { args: [] });
        // exec callbacks receive stdout in position one.
        syntaxArgs.forEach((arg) => { if (isFunction(arg)) this.inline(arg, [this.add(arg, "merge"), clip]); });
        return clip;
      }
      let persistence: string | undefined;
      if (/\breg(?:\.exe)?\b[\s\S]*\badd\b/i.test(text) && /Software\\Microsoft\\Windows\\CurrentVersion\\Run(?:Once)?(?:\s|$)/i.test(text)) persistence = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
      if (/(?:^|[|;&]\s*)(?:[^\s]*\/)?crontab(?:\s|$)/.test(text) && !/\bcrontab\s+-[lr]\b/.test(text)) persistence = "crontab";
      for (const redirect of text.matchAll(/(?:^|\s)\d?>{1,2}\s*['"]?([^\s;|&'"]+)/g)) if (persistencePath(redirect[1])) persistence = redirect[1];
      if (persistence) {
        const key = this.add(node, "literal", [], { text: persistence });
        this.add(node, "call", [this.symbol(node, "clawvet.persistence"), key], { args: [{ value: key }] });
      }
    } else if (/^(?:eval|Function|require|import)$|^vm\./.test(name) && values.length) {
      values[0] = this.executedValue(node, name === "Function" ? this.add(node, "merge", values) : values[0]);
    }
    let args: Argument[] = values.map((value) => ({ value }));
    if (apis.request.test(name)) {
      if (name === "axios" || name === "axios.request") args = values.length === 1 && this.shapes.has(values[0]) ? this.options(values[0]) : [{ name: "url", value: values[0] }, ...values.slice(1).flatMap((v) => this.options(v))];
      else if (apis.axiosBody.test(name)) args = [{ name: "url", value: values[0] }, ...values.slice(1).flatMap((value, index) => index === 0 ? [{ name: "data", value }] : this.options(value))];
      else args = values.flatMap((value, index) => index === 0 && !this.shapes.has(value) ? [{ name: "url", value }] : this.options(value));
    } else if (apis.command.test(name)) args = [{ value: values[0] }, ...values.slice(1).flatMap((value) => this.options(value))];
    else if (apis.sdk.test(name)) args = values.flatMap((value) => this.options(value));
    if (name !== this.api.get(target)) target = this.symbol(node, name);
    args = args.filter((arg) => arg.value !== undefined);
    const result = this.add(node, "call", [target, ...args.map((arg) => arg.value), ...(receiver === undefined ? [] : [receiver])], { args, receiver });
    for (const rule of javascriptSpecs.calls) if (rule.names.test(name) && rule.resultApi) this.api.set(result, rule.resultApi);
    if (apis.write.test(name) && values.length > 1) this.files.set(this.fileKey(values[0]), values[1]);
    if (receiver !== undefined && /\.(?:push|unshift|splice|set|add)$/.test(name)) (this.fn.nodes[receiver].mutations ??= []).push(...values);
    const callbackResults: ValueId[] = [];
    syntaxArgs.forEach((arg) => {
      if (!isFunction(arg)) return;
      if (apis.iteration.test(name) && receiver !== undefined) this.loop(node, () => callbackResults.push(this.inline(arg, [receiver, receiver])));
      else if (/\.then$/.test(name) && receiver !== undefined) callbackResults.push(this.inline(arg, [receiver]));
      else if (apis.callbackRead.test(name)) callbackResults.push(this.inline(arg, [this.add(arg, "merge"), result]));
      else if (/^https?\.(?:get|request)$/.test(name)) {
        const response = this.add(node, "call", [this.symbol(node, "fetch")], { args: [] }); this.api.set(response, "response");
        callbackResults.push(this.inline(arg, [response]));
      } else if (/\.on$/.test(name) && receiver !== undefined && syntaxArgs[0]?.text.match(/^["']data["']$/)) callbackResults.push(this.inline(arg, [receiver]));
      else this.inline(arg, []);
    });
    if ((/\.then$/.test(name) || apis.iteration.test(name)) && callbackResults.length) return this.add(node, "merge", callbackResults);
    return result;
  }
  private expr(node: Node): ValueId {
    if (this.depth >= 128) { coverage.incomplete = true; return this.add(node, "merge"); }
    this.depth++;
    try { return this.exprInner(node); } finally { this.depth--; }
  }
  private exprInner(node: Node): ValueId {
    switch (node.type) {
      case "identifier": case "shorthand_property_identifier": return this.lookup(node);
      case "string": return this.add(node, "literal", [], { text: unquote(node.text) });
      case "number": case "true": case "false": case "null": case "undefined": return this.add(node, "literal", [], { text: node.text });
      case "member_expression": {
        const object = field(node, "object"), property = field(node, "property");
        return object && property ? this.property(node, this.expr(object), property.text) : this.add(node, "merge");
      }
      case "subscript_expression": {
        const object = field(node, "object"), index = field(node, "index");
        if (!object || !index) return this.add(node, "merge");
        const base = this.expr(object);
        if (index.type === "string" && !apis.env.test(this.api.get(base) ?? "")) return this.property(node, base, unquote(index.text));
        return this.add(node, "index", [base, this.expr(index)]);
      }
      case "call_expression": case "new_expression": return this.call(node);
      case "import": return this.symbol(node, "import");
      case "object": {
        const shape = new Map<string, ValueId>(), inputs: ValueId[] = [];
        for (const item of children(node)) {
          if (item.type === "pair") {
            const key = field(item, "key"), value = field(item, "value");
            if (key && value) { const id = this.expr(value); shape.set(keyName(key), id); inputs.push(id); }
          } else {
            const value = this.expr(item); inputs.push(value);
            if (item.type === "shorthand_property_identifier") shape.set(item.text, value);
            else if (item.type === "spread_element") {
              const spread = this.shapes.get(value); if (spread) for (const [key, val] of spread) shape.set(key, val);
              else shape.set(`...${item.startIndex}`, value);
            }
          }
        }
        const result = this.add(node, "merge", inputs); this.shapes.set(result, shape); return result;
      }
      case "spread_element": case "await_expression": case "parenthesized_expression": case "non_null_expression": case "as_expression": case "satisfies_expression": case "type_assertion": {
        const value = children(node).find((c) => !c.type.includes("type")); return value ? this.expr(value) : this.add(node, "merge");
      }
      case "template_string": return this.add(node, "concat", children(node).map((c) => c.type === "string_fragment" || c.type === "escape_sequence" ? this.add(c, "literal", [], { text: unquote(`'${c.text}'`) }) : this.expr(c)));
      case "assignment_expression": case "augmented_assignment_expression": {
        const left = field(node, "left"), right = field(node, "right");
        if (!right) return this.add(node, "merge");
        let value = this.expr(right);
        if (left && node.type === "augmented_assignment_expression") value = this.add(node, field(node, "operator")?.text === "^=" ? "xor" : "concat", [this.expr(left), value]);
        this.assign(left, value); return value;
      }
      case "binary_expression": {
        const left = field(node, "left"), right = field(node, "right"), op = field(node, "operator")?.text;
        return this.add(node, op === "^" ? "xor" : op === "+" ? "concat" : "merge", [left, right].filter((n): n is Node => !!n).map((n) => this.expr(n)));
      }
      case "ternary_expression": {
        const condition = field(node, "condition"); if (condition) this.expr(condition);
        return this.add(node, "merge", [field(node, "consequence"), field(node, "alternative")].filter((n): n is Node => !!n).map((n) => this.expr(n)));
      }
      case "arrow_function": case "function_expression": return this.functionNode(node, `<callback:${this.functions.length}>`);
      case "comment": case "regex": case "type_annotation": return this.add(node, "merge");
      default: return this.add(node, "merge", children(node).map((child) => this.expr(child)));
    }
  }
}

// Slice away bookkeeping that cannot reach an effect or a used helper return.
// This also avoids solving unrelated UI and formatting helpers in bundled scripts.
function compact(program: IRProgram, api: Map<IRFunction, Map<ValueId, string>>, deadline: number): IRProgram {
  const functions = [program.module, ...program.functions];
  const byName = new Map<string, IRFunction[]>();
  for (const fn of program.functions) byName.set(fn.name, [...(byName.get(fn.name) ?? []), fn]);
  const roots = new Map<IRFunction, ValueId[]>(), effectful = new Set<string>();
  const calls = new Map<IRFunction, { node: IRNode; name: string }[]>();
  for (const fn of functions) {
    if (performance.now() >= deadline) throw new DataflowDeadline();
    const entries = fn.nodes.filter((node) => node.op === "call").map((node) => ({ node, name: api.get(fn)?.get(node.inputs[0]) ?? "" }));
    calls.set(fn, entries); roots.set(fn, []);
    for (const { node, name } of entries) {
      if (!name || name.startsWith(".") || javascriptSpecs.calls.some((rule) => rule.names.test(name) && rule.effects.some((effect) => ["network", "dns", "execute", "command", "write", "mutate"].includes(effect)))) {
        roots.get(fn)!.push(node.id); effectful.add(fn.name);
      }
    }
  }
  for (let round = 0; round < 12; round++) {
    let changed = false;
    for (const fn of functions) if (!effectful.has(fn.name) && calls.get(fn)!.some(({ name }) => effectful.has(name))) { effectful.add(fn.name); changed = true; }
    if (!changed) break;
  }
  for (const fn of functions) for (const { node, name } of calls.get(fn)!) if (effectful.has(name)) roots.get(fn)!.push(node.id);
  const needed = new Set<IRFunction>();
  const kept = new Map(functions.map((fn) => [fn, new Set<ValueId>()]));
  const work: [IRFunction, ValueId][] = [];
  for (const [fn, ids] of roots) for (const id of ids) work.push([fn, id]);
  for (let head = 0; head < work.length; head++) {
    if ((head & 127) === 0 && performance.now() >= deadline) throw new DataflowDeadline();
    const [fn, id] = work[head], seen = kept.get(fn)!;
    if (seen.has(id)) continue;
    seen.add(id); const node = fn.nodes[id];
    for (const input of [...node.inputs, ...(node.mutations ?? []), ...(node.receiver === undefined ? [] : [node.receiver]), ...(node.args ?? []).map((arg) => arg.value)]) work.push([fn, input]);
    if (node.op === "call") for (const helper of byName.get(api.get(fn)?.get(node.inputs[0]) ?? "") ?? []) { needed.add(helper); for (const result of helper.returns) work.push([helper, result]); }
    if (node.op === "symbol" && fn !== program.module) {
      const global = program.globals?.[node.name ?? ""]; if (global !== undefined) work.push([program.module, global]);
    }
  }
  const maps = new Map<IRFunction, Map<ValueId, ValueId>>();
  for (const fn of functions) maps.set(fn, new Map(fn.nodes.filter((n) => kept.get(fn)!.has(n.id)).map((node, id) => [node.id, id])));
  const moduleIds = maps.get(program.module)!;
  program.globals = Object.fromEntries(Object.entries(program.globals ?? {}).filter(([, id]) => moduleIds.has(id)).map(([name, id]) => [name, moduleIds.get(id)!]));
  program.functions = program.functions.filter((fn) => needed.has(fn) || kept.get(fn)!.size > 0);
  for (const fn of functions) {
    const ids = maps.get(fn)!;
    fn.nodes = fn.nodes.filter((node) => ids.has(node.id)).map((node) => ({ ...node, id: ids.get(node.id)!, inputs: node.inputs.map((id) => ids.get(id)!), mutations: node.mutations?.map((id) => ids.get(id)!), receiver: node.receiver === undefined ? undefined : ids.get(node.receiver), args: node.args?.map((arg) => ({ ...arg, value: ids.get(arg.value)! })) }));
    fn.returns = fn.returns.filter((id) => ids.has(id)).map((id) => ids.get(id)!);
  }
  return program;
}

function lower(root: Node, source: SourceFile, deadline = Infinity): IRProgram {
  const lowerer = new Lowerer(deadline); lowerer.statement(root);
  return compact({ source, module: lowerer.module, functions: lowerer.functions, globals: lowerer.globals }, lowerer.apis, deadline);
}
// A string escape can spell a module name the hint cannot see: 'f\\x73' is 'fs'
// to require() and to unquote() above. Any backslash keeps the source.
const hint = sinkHint(javascriptSpecs);
const mayFind = (text: string) => !hint || text.includes("\\") || hint.test(text);
export const javascriptFrontend: DataflowFrontend = { grammar: "javascript", specs: javascriptSpecs, mayFind, lower };
export const typescriptFrontend: DataflowFrontend = { grammar: "typescript", specs: javascriptSpecs, mayFind, lower };

export const tsxFrontend: DataflowFrontend = { grammar: "tsx", specs: javascriptSpecs, mayFind, lower };
