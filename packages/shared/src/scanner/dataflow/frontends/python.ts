import type { Node } from "web-tree-sitter";
import type { SourceFile } from "../../../types.js";
import { DataflowDeadline, type DataflowFrontend, type IRFunction, type IRNode, type IRProgram, type ValueId, coverage } from "../ir.js";
import { pythonSpecs } from "../specs/python.js";
import { sinkHint } from "../specs/common.js";

const field = (node: Node, name: string) => node.childForFieldName(name);
const children = (node: Node) => node.namedChildren;

class Lowerer {
  readonly functions: IRFunction[] = [];
  readonly module: IRFunction = { name: "<module>", parameters: [], nodes: [], returns: [] };
  private fn = this.module;
  private env = new Map<string, ValueId>();
  get globals(): Record<string, ValueId> { return Object.fromEntries(this.env); }
  private imports = new Map<string, string>();
  private readonly moduleImports = this.imports;
  private depth = 0;
  private loops: number[] = [];
  private loopId = 0;
  private journals: Map<string, ValueId | undefined>[] = [];
  // Methods are named Class.method, so declaring a method never shadows the
  // module function of the same name that a plain call reaches.
  private classes: string[] = [];
  private steps = 0;
  constructor(private readonly deadline = Infinity) {}
  private tick(): void {
    if ((++this.steps & 255) === 0 && performance.now() >= this.deadline) throw new DataflowDeadline();
  }

  private add(node: Node, op: IRNode["op"], inputs: ValueId[] = [], extra: Partial<IRNode> = {}): ValueId {
    const id = this.fn.nodes.length;
    this.fn.nodes.push({ id, op, inputs, line: node.startPosition.row + 1, loops: [...this.loops], ...extra });
    return id;
  }
  private bind(name: string, value: ValueId): void {
    for (const journal of this.journals) if (!journal.has(name)) journal.set(name, this.env.get(name));
    this.env.set(name, value);
  }
  private lookup(node: Node): ValueId {
    const value = this.env.get(node.text);
    if (value !== undefined) return value;
    return this.add(node, "symbol", [], { name: this.imports.get(node.text) ?? this.moduleImports.get(node.text) ?? node.text });
  }
  private assign(target: Node | null, value: ValueId): void {
    if (!target) return;
    if (target.type === "identifier") { this.bind(target.text, value); return; }
    if (target.type === "attribute" || target.type === "subscript") {
      const base = field(target, "object") ?? field(target, "value");
      if (base) {
        const old = this.expr(base);
        const container = this.fn.nodes[old];
        (container.mutations ??= []).push(value);
      }
      return;
    }
    for (const child of children(target)) this.assign(child, value);
  }
  private branch(node: Node, arms: Node[]): void {
    const changed = new Map<string, ValueId | undefined>();
    const outputs = new Map<string, ValueId[]>();
    for (const arm of arms) {
      const journal = new Map<string, ValueId | undefined>();
      this.journals.push(journal);
      this.statement(arm);
      this.journals.pop();
      for (const [name, prior] of journal) {
        if (!changed.has(name)) changed.set(name, prior);
        const values = outputs.get(name) ?? [];
        values.push(this.env.get(name)!); outputs.set(name, values);
        if (prior === undefined) this.env.delete(name); else this.env.set(name, prior);
      }
    }
    for (const [name, prior] of changed) {
      const inputs = outputs.get(name)!;
      if (prior !== undefined && !(node.type === "if_statement" && arms.some((a) => a.type === "else_clause") && inputs.length === arms.length)) inputs.push(prior);
      this.bind(name, this.add(node, "merge", inputs));
    }
  }
  private loop(node: Node, iterable: Node | null, target: Node | null, body: Node | null): void {
    this.loops.push(++this.loopId);
    const input = iterable ? this.expr(iterable) : undefined;
    // Loop-carried values use phi nodes. Only names touched by the body are joined.
    const journal = new Map<string, ValueId | undefined>();
    this.journals.push(journal);
    const phis = new Map<string, ValueId>();
    // Lazy phis avoid copying the entire environment at every control-flow join.
    const outerLookup = this.lookup;
    this.lookup = (ref: Node) => {
      const old = this.env.get(ref.text);
      if (old !== undefined && !journal.has(ref.text) && !phis.has(ref.text)) {
        const phi = this.add(ref, "merge", [old]);
        phis.set(ref.text, phi); this.bind(ref.text, phi);
      }
      return outerLookup.call(this, ref);
    };
    if (target && input !== undefined) this.assign(target, input);
    if (body) this.statement(body);
    this.lookup = outerLookup;
    this.journals.pop();
    for (const [name, phi] of phis) {
      const end = this.env.get(name);
      if (end !== undefined && end !== phi) this.fn.nodes[phi].inputs.push(end);
    }
    for (const [name, prior] of journal) {
      const end = this.env.get(name);
      if (prior !== undefined && end !== undefined && !phis.has(name)) this.bind(name, this.add(node, "merge", [prior, end]));
    }
    this.loops.pop();
  }
  private importNode(node: Node): void {
    const module = field(node, "module_name")?.text;
    for (const item of children(node)) {
      if (item.id === field(node, "module_name")?.id || item.type === "wildcard_import") continue;
      const name = field(item, "name")?.text ?? item.text;
      const alias = field(item, "alias")?.text ?? (module ? name : name.split(".")[0]);
      const canonical = module ? `${module}.${name}` : field(item, "alias") ? name : name.split(".")[0];
      this.imports.set(alias, canonical);
      this.bind(alias, this.add(item, "symbol", [], { name: canonical }));
    }
  }
  private functionNode(node: Node): void {
    const name = field(node, "name")?.text;
    const body = field(node, "body");
    if (!name || !body) return;
    const saved = { fn: this.fn, env: this.env, imports: this.imports, loops: this.loops, journals: this.journals, lookup: this.lookup };
    const params = field(node, "parameters");
    this.fn = { name: this.classes.length ? `${this.classes.join(".")}.${name}` : name, parameters: [], nodes: [], returns: [] };
    this.functions.push(this.fn);
    this.env = new Map(); this.imports = new Map(); this.loops = []; this.journals = [];
    this.lookup = Lowerer.prototype.lookup;
    for (const param of params ? children(params) : []) {
      const id = param.type === "identifier" ? param : field(param, "name") ?? children(param).find((c) => c.type === "identifier");
      if (!id) continue;
      const parameter = this.fn.parameters.length;
      this.fn.parameters.push(id.text);
      this.bind(id.text, this.add(id, "parameter", [], { parameter }));
    }
    this.statement(body);
    Object.assign(this, saved);
  }
  statement(node: Node): void {
    this.tick();
    if (this.depth >= 128) { coverage.incomplete = true; return; }
    this.depth++;
    try { this.statementInner(node); } finally { this.depth--; }
  }
  private statementInner(node: Node): void {
    switch (node.type) {
      case "import_statement": case "import_from_statement": this.importNode(node); return;
      case "function_definition": this.functionNode(node); return;
      case "class_definition": {
        const name = field(node, "name")?.text ?? "<class>";
        this.classes.push(name);
        try { for (const child of children(node)) this.statement(child); } finally { this.classes.pop(); }
        return;
      }
      case "return_statement":
        for (const child of children(node)) this.fn.returns.push(this.expr(child));
        return;
      case "assignment": {
        const right = field(node, "right");
        if (right) {
          if (right.type === "assignment") this.statement(right);
          this.assign(field(node, "left"), right.type === "assignment" ? this.expr(field(right, "left")!) : this.expr(right));
        }
        return;
      }
      case "augmented_assignment": {
        const left = field(node, "left"), right = field(node, "right");
        if (left && right) this.assign(left, this.add(node, node.text.includes("^=") ? "xor" : "concat", [this.expr(left), this.expr(right)]));
        return;
      }
      case "with_statement": {
        const clause = children(node).find((c) => c.type === "with_clause");
        for (const item of clause ? children(clause) : []) {
          const value = field(item, "value") ?? children(item)[0];
          if (!value) continue;
          if (value.type === "as_pattern") this.assign(field(value, "alias"), this.expr(children(value)[0]));
          else this.expr(value);
        }
        const body = field(node, "body"); if (body) this.statement(body);
        return;
      }
      case "for_statement": case "while_statement":
        this.loop(node, field(node, "right") ?? field(node, "condition"), field(node, "left"), field(node, "body"));
        return;
      case "if_statement": case "try_statement": case "match_statement": {
        const condition = field(node, "condition"); if (condition) this.expr(condition);
        this.branch(node, children(node).filter((c) => ["block", "elif_clause", "else_clause", "except_clause", "finally_clause", "case_clause"].includes(c.type)));
        return;
      }
      case "module": case "block": case "expression_statement": case "else_clause": case "elif_clause": case "except_clause": case "finally_clause": case "decorated_definition":
        for (const child of children(node)) this.statement(child);
        return;
      default: this.expr(node);
    }
  }
  private expr(node: Node): ValueId {
    this.tick();
    if (this.depth >= 128) { coverage.incomplete = true; return this.add(node, "merge"); }
    this.depth++;
    try { return this.exprInner(node); } finally { this.depth--; }
  }
  private exprInner(node: Node): ValueId {
    switch (node.type) {
      case "identifier": return this.lookup(node);
      case "string": {
        const parts = children(node);
        const interpolation = parts.some((p) => p.type === "interpolation");
        if (interpolation) return this.add(node, "concat", parts.filter((p) => p.type === "string_content" || p.type === "interpolation").map((p) => p.type === "string_content" ? this.add(p, "literal", [], { text: p.text }) : this.expr(field(p, "expression") ?? p)));
        const start = parts.find((p) => p.type === "string_start")?.text ?? '"';
        const end = parts.find((p) => p.type === "string_end")?.text ?? '"';
        const text = node.text.slice(start.length, -end.length).replace(/\\([\\'"nrt])/g, (_, c: string) => ({ n: "\n", r: "\r", t: "\t" }[c] ?? c));
        return this.add(node, "literal", [], { text });
      }
      case "integer": case "float": case "true": case "false": case "none": return this.add(node, "literal", [], { text: node.text });
      case "attribute": {
        const object = field(node, "object"), attribute = field(node, "attribute");
        return this.add(node, "attribute", object ? [this.expr(object)] : [], { name: attribute?.text });
      }
      case "subscript": {
        const value = field(node, "value"), subscript = field(node, "subscript");
        return this.add(node, "index", [value && this.expr(value), subscript && this.expr(subscript)].filter((id): id is number => typeof id === "number"));
      }
      case "call": {
        const callee = field(node, "function"), args = field(node, "arguments");
        const target = callee ? this.expr(callee) : this.add(node, "symbol");
        const receiver = callee?.type === "attribute" ? this.fn.nodes[target].inputs[0] : undefined;
        const argumentsIR = (args ? children(args) : []).map((arg) => ({
          name: arg.type === "keyword_argument" ? field(arg, "name")?.text : undefined,
          value: this.expr(arg.type === "keyword_argument" ? field(arg, "value")! : arg),
        }));
        const result = this.add(node, "call", [target, ...argumentsIR.map((a) => a.value)], { args: argumentsIR, receiver });
        // Mutating a container taints every alias to it, without field sensitivity.
        if (callee?.type === "attribute" && /^(?:append|extend|insert|update|setdefault|add)$/.test(field(callee, "attribute")?.text ?? "") && receiver !== undefined) {
          const container = this.fn.nodes[receiver];
          (container.mutations ??= []).push(...argumentsIR.map((a) => a.value));
        }
        return result;
      }
      case "binary_operator": {
        const left = field(node, "left"), right = field(node, "right");
        const op = field(node, "operator")?.text;
        return this.add(node, op === "^" ? "xor" : op === "+" || op === "/" ? "concat" : "merge", [left && this.expr(left), right && this.expr(right)].filter((id): id is number => typeof id === "number"), { text: op === "/" ? "/" : "" });
      }
      case "list_comprehension": case "set_comprehension": case "dictionary_comprehension": case "generator_expression": {
        const inputs: ValueId[] = [];
        for (const clause of children(node).filter((c) => c.type === "for_in_clause")) {
          const right = field(clause, "right"), left = field(clause, "left");
          if (right) { const value = this.expr(right); inputs.push(value); this.assign(left, value); }
        }
        const body = field(node, "body"); if (body) inputs.push(this.expr(body));
        return this.add(node, "merge", inputs);
      }
      case "assignment": case "augmented_assignment": this.statement(node); return this.add(node, "merge");
      default: return this.add(node, node.type === "concatenated_string" ? "concat" : "merge", children(node).map((child) => this.expr(child)));
    }
  }
}

const hint = sinkHint(pythonSpecs);
export const pythonFrontend: DataflowFrontend = {
  grammar: "python",
  specs: pythonSpecs,
  mayFind: (text) => !hint || hint.test(text),
  lower(root: Node, source: SourceFile, deadline?: number): IRProgram {
    const lowerer = new Lowerer(deadline);
    lowerer.statement(root);
    return { source, module: lowerer.module, functions: lowerer.functions, globals: lowerer.globals };
  },
};
