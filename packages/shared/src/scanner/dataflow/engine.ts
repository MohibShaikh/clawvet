import type { Finding, SourceFile } from "../../types.js";
import { coverage, DataflowDeadline, type AccessRule, type CallRule, type IRFunction, type IRNode, type IRProgram, type LanguageSpecs, type TaintFlag, type TaintKind } from "./ir.js";
import { credentialPath, persistencePath, projectSecretPath, SECRET_ENV, TRANSFER_COMMAND } from "./specs/common.js";

interface Trace { kind: TaintKind; line: number; detail: string; parameter?: number; authOnly?: boolean }
interface Value { traces: Trace[]; flags: TaintFlag[]; strings: string[]; api?: string; readLine?: number }
type EventKind = "network" | "execute" | "write" | "mutate" | "read" | "encrypt";
interface Event { kind: EventKind; data: Value; target: Value; line: number; name: string; loops: number[]; dns?: boolean }
// mutates[i]: what the function stores into its i-th parameter, so a helper
// that fills a caller's dict taints the caller's dict.
interface Summary { result: Value; events: Event[]; mutates: Value[]; parameters: string[]; positions: Map<string, number>; globals?: Map<string, Value> }
// Read-only views, so a solve can record which summaries and globals it consulted.
type Summaries = Pick<Map<string, Summary>, "get">;
type Globals = Pick<Map<string, Value>, "get">;
const EMPTY: Value = { traces: [], flags: [], strings: [] };
const MAX_TRACES = 24;
const MAX_EVENTS = 64;
const MAX_ROUNDS = 12;
const MAX_UPDATES = 24;
// Per function, across all helper expansions: a helper called thousands of
// times must not expand into millions of events after the worklist stops.
const MAX_FUNCTION_EVENTS = 512;
const SHELL_RC = /(?:^|\/)(?:\.(?:bashrc|bash_profile|profile|zshrc|zprofile)|profile\.d)(?:$|\/)/i;
// export X=..., alias x=..., PATH=..., a comment: configuration, not commands.
const CONFIG_LINE = /^\s*(?:#.*|export\s+[A-Za-z_]\w*=[^;&|`$()]*|alias\s+[\w.-]+=[^;&|`$()]*|(?:export\s+)?PATH=[^;&|`()]*)\s*$/;
const LOGIN_KEYS = /(?:^|\/)\.ssh\/authorized_keys2?$/i;
const READER_COMMAND = /^(?:cat|head|tail|base64|xxd|type)$/;
// Literal text that ends in a registrable domain: "<label>.<tld>".
const FIXED_DOMAIN = /\.[a-z0-9-]+\.[a-z]{2,}\.?$/i;
const traceKey = (t: Trace) => `${t.kind}:${t.parameter ?? ""}:${t.authOnly ?? false}`;
const has = (v: Value, ...kinds: TaintKind[]) => v.traces.some((t) => kinds.includes(t.kind));
// Field-wise equality: serializing both values on every worklist step was the
// single largest cost in the solver.
function same(a: Value, b: Value): boolean {
  if (a === b) return true;
  if (a.api !== b.api || a.readLine !== b.readLine || a.traces.length !== b.traces.length || a.flags.length !== b.flags.length || a.strings.length !== b.strings.length) return false;
  for (let i = 0; i < a.flags.length; i++) if (a.flags[i] !== b.flags[i]) return false;
  for (let i = 0; i < a.strings.length; i++) if (a.strings[i] !== b.strings[i]) return false;
  for (let i = 0; i < a.traces.length; i++) {
    const x = a.traces[i], y = b.traces[i];
    if (x.kind !== y.kind || x.line !== y.line || x.detail !== y.detail || x.parameter !== y.parameter || x.authOnly !== y.authOnly) return false;
  }
  return true;
}
// Values merge() built, or that are too small to need it: merging one of these
// with nothing returns it unchanged, so the common one-input join allocates nothing.
const merged = new WeakSet<Value>();
const settled = (v: Value) => merged.has(v) || v.traces.length <= 1 && v.flags.length <= 1 && v.strings.length <= 1 && (v.strings[0]?.length ?? 0) <= 2048;

function merge(values: Value[]): Value {
  let only: Value | undefined, live = 0;
  for (const value of values) if (value.traces.length || value.flags.length || value.strings.length || value.api !== undefined || value.readLine !== undefined) { only = value; live++; }
  if (live === 0) return EMPTY;
  if (live === 1 && settled(only!)) return only!;
  const traces = new Map<string, Trace>();
  const flags = new Set<TaintFlag>();
  const strings = new Set<string>();
  let api: string | undefined;
  let readLine: number | undefined;
  for (const value of values) {
    for (const trace of value.traces) {
      const key = traceKey(trace);
      if (traces.has(key)) continue;
      if (traces.size < MAX_TRACES) traces.set(key, trace);
      else coverage.incomplete = true;
    }
    for (const flag of value.flags) flags.add(flag);
    for (const str of value.strings) if (strings.size < 4) strings.add(str.slice(0, 2048));
    api ??= value.api;
    readLine ??= value.readLine;
  }
  const result = { traces: [...traces.values()], flags: [...flags].sort(), strings: [...strings], api, readLine };
  merged.add(result);
  return result;
}
function source(kind: TaintKind, node: IRNode, detail: string): Value {
  return { ...EMPTY, traces: [{ kind, line: node.line, detail }] };
}
function flag(value: Value, name: TaintFlag): Value {
  return { ...value, flags: [...new Set([...value.flags, name])].sort() };
}
function replaceParameters(value: Value, args: Value[]): Value {
  const ordinary = { ...value, traces: value.traces.filter((t) => t.kind !== "parameter") };
  const inputs = value.traces.filter((t) => t.kind === "parameter").map((t) => {
    const arg = args[t.parameter!] ?? EMPTY;
    return t.authOnly ? { ...arg, traces: arg.traces.filter((trace) => trace.kind !== "environment").map((trace) => trace.kind === "parameter" ? { ...trace, authOnly: true } : trace) } : arg;
  });
  let result = merge([ordinary, ...inputs]);
  if (result.readLine !== undefined && !has(result, "environment_all") && result.strings.some(projectSecretPath)) result = merge([result, { ...EMPTY, traces: [{ kind: "environment_all", line: result.readLine, detail: "read project .env" }] }]);
  const sensitive = result.strings.find(credentialPath);
  if (result.readLine !== undefined && sensitive && !has(result, "credential")) result = merge([result, { ...EMPTY, traces: [{ kind: "credential", line: result.readLine, detail: `read ${sensitive}` }] }]);
  if (result.readLine !== undefined && has(result, "walk") && !has(result, "file")) result = merge([result, { ...EMPTY, traces: [{ kind: "file", line: result.readLine, detail: "read walked file" }] }]);
  return result;
}
function canonical(node: IRNode, values: Value[]): string {
  return values[node.inputs[0]]?.api ?? "";
}
// Rule lookup runs every regex in the spec, and a solve asks for the same few
// names thousands of times. The spec tables are constants, so cache per table.
const ruleCache = new WeakMap<LanguageSpecs, Map<string, Omit<CallRule, "names">>>();
const accessCache = new WeakMap<LanguageSpecs, Map<string, AccessRule | null>>();
function cached<T>(cache: WeakMap<LanguageSpecs, Map<string, T>>, specs: LanguageSpecs, name: string, compute: () => T): T {
  let names = cache.get(specs);
  if (!names) cache.set(specs, names = new Map());
  let value = names.get(name);
  if (value === undefined) {
    // Names come from scanned code: bound the table so a long-lived process cannot grow it forever.
    if (names.size >= 8192) names.clear();
    names.set(name, value = compute());
  }
  return value;
}
function effects(name: string, specs: LanguageSpecs): Omit<CallRule, "names"> {
  return cached(ruleCache, specs, name, () => {
    let result: Omit<CallRule, "names"> = { effects: [] };
    for (const rule of specs.calls) if (rule.names.test(name)) result = { ...result, ...rule, effects: [...result.effects, ...rule.effects] };
    return result;
  });
}
function access(name: string, specs: LanguageSpecs): AccessRule | null {
  return cached(accessCache, specs, name, () => specs.accesses.find((a) => a.names.test(name)) ?? null);
}
function targetValue(rule: Omit<CallRule, "names">, args: Value[], receiver: Value): Value {
  return rule.target === "receiver" ? receiver : args[rule.target ?? 0] ?? EMPTY;
}
function callArguments(node: IRNode, values: Value[]): Value[] {
  return (node.args ?? []).map((a) => values[a.value] ?? EMPTY);
}
function boundArguments(node: IRNode, values: Value[], summary: Summary): Value[] {
  const result: Value[] = [];
  let position = 0;
  for (const arg of node.args ?? []) {
    const index = arg.name ? summary.positions.get(arg.name) ?? -1 : position++;
    if (index >= 0) result[index] = values[arg.value] ?? EMPTY;
  }
  return result;
}
function callValue(node: IRNode, values: Value[], specs: LanguageSpecs, summaries: Summaries): Value {
  const name = canonical(node, values);
  const args = callArguments(node, values);
  const receiver = node.receiver === undefined ? EMPTY : values[node.receiver] ?? EMPTY;
  const summary = summaries.get(name);
  if (summary) return replaceParameters(summary.result, boundArguments(node, values, summary));
  const rule = effects(name, specs);
  const all = merge([...args, receiver]);
  let result = all;
  if (rule.effects.includes("path")) {
    const separator = rule.pathSeparator ?? "";
    result = { ...all, strings: [args.map((v) => v.strings[0] ?? "").join(separator)].filter(Boolean) };
    if (rule.pathReceiver) result = { ...result, strings: receiver.strings };
  }
  if (rule.effects.includes("open") || rule.effects.includes("read")) {
    const path = targetValue(rule, args, receiver);
    const modeArg = (node.args ?? []).find((a) => a.name === "mode");
    const modes = modeArg ? values[modeArg.value]?.strings : args[1]?.strings;
    const writeOnly = rule.effects.includes("open") && modes?.some((m) => /[wax]/.test(m) && !m.includes("+"));
    const sensitive = !writeOnly && path.strings.find(credentialPath);
    const project = !writeOnly && !sensitive && path.strings.find(projectSecretPath);
    result = sensitive ? merge([path, source("credential", node, `read ${sensitive}`)])
      // The whole file is every secret in it, like dumping the environment;
      // indexing one key out of it narrows that to a single secret (see "index").
      : project ? merge([path, source("environment_all", node, `read ${project}`)]) : path;
    if (!writeOnly && has(path, "walk")) result = merge([result, source("file", node, "read walked file")]);
    if (!writeOnly) result = { ...result, readLine: node.line };
  }
  if (rule.effects.includes("environment")) {
    result = args[0]?.strings.some((s) => SECRET_ENV.test(s)) ? source("environment", node, `env ${args[0].strings[0]}`) : EMPTY;
  }
  if (rule.effects.includes("command")) {
    // What a command prints is what it read: `cat ~/.ssh/id_rsa` returns the key, `env` the environment.
    const words = (args[0]?.strings ?? []).join(" ").trim().split(/[\s'"]+/);
    const sensitive = READER_COMMAND.test(words[0] ?? "") ? words.find(credentialPath) : undefined;
    if (sensitive) result = merge([result, source("credential", node, `read ${sensitive}`)]);
    else if (words.length === 1 && /^(?:env|printenv)$/.test(words[0])) result = merge([result, source("environment_all", node, words[0])]);
  }
  if (rule.effects.includes("clipboard")) result = source("clipboard", node, "clipboard read");
  if (rule.effects.includes("host")) result = source("host", node, name);
  // len(), bool(), isinstance() and the like return a count or a flag: no content
  // or location survives, so a file count sent as telemetry is not exfiltration.
  if (rule.effects.includes("aggregate")) result = EMPTY;
  if (rule.effects.includes("walk")) result = merge([all, source("walk", node, "filesystem walk")]);
  if (rule.effects.includes("request")) result = filteredNetworkData(node, values);
  if (rule.effects.includes("network_read")) result = source("network", node, `${name} response`);
  if (rule.effects.includes("encode")) result = flag(result, "encoded");
  if (rule.effects.includes("decode")) result = flag(result, "decoded");
  if (rule.effects.includes("encrypt")) result = flag(flag(result, "encoded"), "encrypted");
  if (rule.effects.includes("join")) result = { ...result, strings: args[0]?.strings.length ? [args[0].strings.join(receiver.strings[0] ?? "").slice(0, 2048)] : [] };
  if (rule.effects.includes("format")) {
    let index = 0;
    result = { ...result, strings: receiver.strings.map((str) => str.replace(/\{([^{}]*)\}/g, (_match, key: string) => {
      const argIndex = key === "" ? index++ : /^\d+$/.test(key) ? Number(key) : (node.args ?? []).findIndex((a) => a.name === key);
      return args[argIndex]?.strings[0] ?? "";
    })) };
  }
  // Unknown calls do not invent sources, but preserve data passed through wrappers.
  return { ...result, api: rule.resultApi ?? (rule.clearApi ? undefined : result.api) };
}
function evaluate(node: IRNode, values: Value[], specs: LanguageSpecs, summaries: Summaries, globals: Globals): Value {
  const inputs = node.inputs.map((id) => values[id] ?? EMPTY);
  switch (node.op) {
    case "literal": return { ...EMPTY, strings: [(node.text ?? "").slice(0, 2048)] };
    case "symbol": {
      const global = globals.get(node.name ?? "");
      if (global) return global;
      const rule = access(node.name ?? "", specs);
      return { ...(rule ? source(rule.source, node, node.name!) : EMPTY), api: node.name };
    }
    case "parameter": return { ...EMPTY, traces: [{ kind: "parameter", line: node.line, detail: "parameter", parameter: node.parameter }] };
    case "merge": return merge(inputs);
    case "concat": {
      const value = merge(inputs);
      // Keep literal path pieces even when another component is computed.
      return { ...value, strings: [inputs.map((v) => v.strings[0] ?? "").join(node.text ?? "").slice(0, 2048)], api: undefined };
    }
    case "xor": return flag(flag(merge(inputs), "encoded"), "encrypted");
    case "attribute": {
      const base = inputs[0] ?? EMPTY;
      const name = base.api ? `${base.api}.${node.name}` : `.${node.name}`;
      const rule = access(name, specs);
      return { ...(rule ? source(rule.source, node, name) : base), api: name };
    }
    case "index": {
      const base = inputs[0] ?? EMPTY, key = inputs[1] ?? EMPTY;
      if (has(base, "environment_all")) return key.strings.some((s) => SECRET_ENV.test(s)) ? source("environment", node, `env ${key.strings[0]}`) : has(key, "environment_all") ? source("environment_all", node, "iterated environment") : EMPTY;
      return merge([base, key]);
    }
    case "call": return callValue(node, values, specs, summaries);
  }
}
function filteredNetworkData(node: IRNode, values: Value[]): Value {
  return merge((node.args ?? []).map((arg) => {
    const value = values[arg.value] ?? EMPTY;
    const auth = arg.name === "api_key" || arg.name === "headers";
    return auth ? { ...value, traces: value.traces.filter((t) => t.kind !== "environment").map((t) => t.kind === "parameter" ? { ...t, authOnly: true } : t) } : value;
  }));
}
// Past a cap, keep one of each equivalent event (same kind, call and values,
// differing only in line) before cutting, so 64 identical sends cannot push a
// different one off the end. Anything still cut marks the analysis incomplete.
function capEvents(events: Event[], max: number): Event[] {
  if (events.length <= max) return events;
  const seen = new Set<string>();
  const kept: Event[] = [];
  for (const e of events) {
    const key = `${e.kind}|${e.name}|${e.dns ?? ""}|${JSON.stringify(e.data)}|${JSON.stringify(e.target)}`;
    if (!seen.has(key)) { seen.add(key); kept.push(e); }
  }
  if (kept.length <= max) return kept;
  coverage.incomplete = true;
  return kept.slice(0, max);
}
function collectEvents(fn: IRFunction, values: Value[], specs: LanguageSpecs, summaries: Summaries, deadline: number): Event[] {
  const events: Event[] = [];
  for (const node of fn.nodes) {
    if (events.length >= MAX_FUNCTION_EVENTS) { coverage.incomplete = true; break; }
    if ((node.id & 127) === 0 && performance.now() >= deadline) throw new DataflowDeadline();
    if (node.op === "xor" && has(values[node.id], "file")) events.push({ kind: "encrypt", data: values[node.id], target: EMPTY, line: node.line, name: "XOR", loops: node.loops });
    if (node.op !== "call") continue;
    const name = canonical(node, values);
    const summary = summaries.get(name);
    if (summary) {
      const args = boundArguments(node, values, summary);
      for (const event of capEvents(summary.events, Math.min(MAX_EVENTS, MAX_FUNCTION_EVENTS - events.length))) {
        events.push({ ...event, data: replaceParameters(event.data, args), target: replaceParameters(event.target, args), loops: node.loops, name: `${name} -> ${event.name}` });
      }
      continue;
    }
    const rule = effects(name, specs);
    const args = callArguments(node, values);
    const receiver = node.receiver === undefined ? EMPTY : values[node.receiver] ?? EMPTY;
    const all = merge([...args, receiver]);
    const target = targetValue(rule, args, receiver);
    const add = (kind: EventKind, data = all, dest = target, dns = false) => {
      // Public sends and unrelated local writes cannot contribute to a flow.
      if (kind === "network" && !has(data, "credential", "environment", "environment_all", "clipboard", "file", "walk", "host", "parameter")) return;
      if (kind === "execute" && !has(data, "network", "parameter") && !data.flags.includes("decoded")) return;
      if (kind === "read" && !has(data, "walk", "file", "parameter")) return;
      if (kind === "encrypt" && !has(data, "walk", "file", "parameter")) return;
      if ((kind === "write" || kind === "mutate") && !has(data, "walk", "file", "parameter") && !has(dest, "walk", "file", "parameter") && !dest.strings.some(persistencePath)) return;
      events.push({ kind, data, target: dest, line: node.line, name, loops: node.loops, ...(dns ? { dns } : {}) });
    };
    if (rule.effects.includes("network") || rule.effects.includes("dns")) {
      const url = (node.args ?? []).find((a) => a.name === "url");
      const destination = url ? values[url.value] : args[rule.urlPosition ?? 0];
      add("network", filteredNetworkData(node, values), destination ?? EMPTY, rule.effects.includes("dns"));
    }
    if (rule.effects.includes("execute")) add("execute", args[0] ?? EMPTY);
    if (rule.effects.includes("command")) {
      const command = args[0] ?? EMPTY;
      if (command.strings.some((s) => TRANSFER_COMMAND.test(s)) || TRANSFER_COMMAND.test(command.strings.join(" "))) add("network", command);
      const shell = (node.args ?? []).find((a) => a.name === (rule.shellOption ?? "shell"));
      if (rule.commandShell === "always" || shell && values[shell.value]?.strings.some((s) => rule.truthy?.includes(s))) add("execute", command);
    }
    if (rule.effects.includes("read") || rule.effects.includes("open")) add("read", values[node.id]);
    if (rule.effects.includes("encrypt")) add("encrypt", values[node.id]);
    if (rule.effects.includes("write")) add("write");
    if (rule.effects.includes("mutate")) add("mutate");
    if (rule.effects.includes("open") && (args[1]?.strings.some((s) => /[wax+]/.test(s)) || (node.args ?? []).some((a) => a.name === "mode" && values[a.value]?.strings.some((s) => /[wax+]/.test(s))))) add("write", all, args[0]);
  }
  return events;
}
function solve(fn: IRFunction, specs: LanguageSpecs, summaries: Summaries, deadline: number, globals: Globals = new Map<string, Value>(), exports?: Record<string, number>): Summary {
  const values = fn.nodes.map(() => EMPTY);
  const dependents: number[][] = fn.nodes.map(() => []);
  for (const node of fn.nodes) for (const input of [...node.inputs, ...(node.mutations ?? [])]) dependents[input]?.push(node.id);
  const queue = fn.nodes.map((n) => n.id);
  const queued = fn.nodes.map(() => true);
  const updates = fn.nodes.map(() => 0);
  // Taint a callee stored into an argument, keyed by the argument's value id.
  const stored: Value[] = fn.nodes.map(() => EMPTY);
  let head = 0;
  while (head < queue.length) {
    if ((head & 255) === 0 && performance.now() >= deadline) break;
    const id = queue[head++]; queued[id] = false;
    if (updates[id]++ >= MAX_UPDATES) { coverage.incomplete = true; continue; }
    const node = fn.nodes[id];
    const computed = evaluate(node, values, specs, summaries, globals);
    const extra = [...(node.mutations ?? []).map((input) => values[input] ?? EMPTY), ...(stored[id].traces.length ? [stored[id]] : [])];
    const result = extra.length ? merge([computed, ...extra]) : computed;
    const enqueue = (target: number) => { if (!queued[target]) { queued[target] = true; queue.push(target); } };
    if (node.op === "call") {
      const summary = summaries.get(canonical(node, values));
      if (summary?.mutates.some((m) => m.traces.length)) {
        const args = boundArguments(node, values, summary);
        let position = 0;
        for (const arg of node.args ?? []) {
          const index = arg.name ? summary.positions.get(arg.name) ?? -1 : position++;
          const mutation = index >= 0 ? summary.mutates[index] : undefined;
          if (!mutation?.traces.length) continue;
          const next = merge([stored[arg.value] ?? EMPTY, replaceParameters(mutation, args)]);
          if (!same(next, stored[arg.value] ?? EMPTY)) { stored[arg.value] = next; enqueue(arg.value); }
        }
      }
    }
    if (same(result, values[id])) continue;
    values[id] = result;
    for (const dependent of dependents[id]) enqueue(dependent);
  }
  // What the body stored into each parameter, without the parameter itself.
  const mutates = fn.parameters.map(() => EMPTY);
  for (const node of fn.nodes) {
    if (node.op !== "parameter" || node.parameter === undefined) continue;
    const own = values[node.id];
    const extra = own.traces.filter((t) => !(t.kind === "parameter" && t.parameter === node.parameter));
    if (extra.length) mutates[node.parameter] = { ...own, traces: extra };
  }
  return { result: merge(fn.returns.map((id) => values[id])), events: capEvents(collectEvents(fn, values, specs, summaries, deadline), MAX_FUNCTION_EVENTS), mutates,
    parameters: fn.parameters, positions: new Map(fn.parameters.map((name, index) => [name, index])), globals: exports ? new Map(Object.entries(exports).map(([name, id]) => [name, values[id]])) : undefined };
}
// Two definitions with one name (a redefinition, or a frontend that cannot tell
// scopes apart) share one summary holding both. Keeping only the last would let
// a later harmless definition hide the one a call actually reaches.
function combine(a: Summary | undefined, b: Summary): Summary {
  if (!a) return b;
  return { ...a, result: merge([a.result, b.result]), events: capEvents([...a.events, ...b.events], MAX_FUNCTION_EVENTS),
    mutates: a.mutates.map((m, i) => merge([m, b.mutates[i] ?? EMPTY])) };
}
function finding(sourceFile: SourceFile, event: Event, category: string, severity: Finding["severity"], title: string, trace?: Trace): Finding {
  const evidence = trace ? `${sourceFile.path}:${trace.line} ${trace.detail} -> :${event.line} ${event.name}` : `${sourceFile.path}:${event.line} ${event.name}`;
  return { category, severity, title, description: title, evidence: evidence.slice(0, 500), lineNumber: sourceFile.startLine + event.line - 1, analysisPass: "dataflow" };
}
function findingsForEvents(events: Event[], sourceFile: SourceFile): Finding[] {
  const findings: Finding[] = [];
  // One API key used in many requests is one fact. Without this a client with
  // ten endpoints scores ten mediums and blocks on its own authentication.
  const keysSent = new Set<string>();
  const hostsSent = new Set<string>();
  const loopFacts = new Map<number, { read?: Event; encrypt?: Event; mutations: Event[] }>();
  for (const event of events) {
    if (event.kind === "network") {
      const credential = event.data.traces.find((t) => t.kind === "credential");
      const other = event.data.traces.find((t) => ["environment", "environment_all", "clipboard", "file", "walk"].includes(t.kind));
      const trace = credential ?? other;
      if (trace) {
        // One named secret reaching the network is how API clients authenticate:
        // in a header, a query string, a body, through a helper. It counts, but
        // alone it cannot block. Credential files, the whole environment, the
        // clipboard and walked files stay critical.
        // An unresolved parameter is not a source, so it does not make a key "more".
        // Neither is an earlier response: a job id the server sent, echoed back
        // with the same key, is still one key and nothing local.
        const sources = event.data.traces.filter((t) => t.kind !== "parameter" && t.kind !== "network" && t.kind !== "host");
        const singleEnv = !credential && sources.length > 0 && sources.every((t) => t.kind === "environment");
        if (singleEnv) {
          const key = sources.map((t) => t.detail).sort().join("|");
          if (keysSent.has(key)) continue;
          keysSent.add(key);
        }
        findings.push(finding(sourceFile, event, credential ? "credential_theft" : "data_exfiltration", singleEnv ? "medium" : "critical", credential ? "Credential data flows to a network send" : "Sensitive data flows to a network send", trace));
      }
    }
    // A lookup of `<user>.<host>.fixed.domain` sends those labels to whoever
    // runs the domain's name server. Resolving the machine's own name, with no
    // fixed domain around it, is how a script finds its local address.
    const host = event.kind === "network" ? event.data.traces.find((t) => t.kind === "host") : undefined;
    if (host && event.dns) {
      if ([...event.target.strings, ...event.data.strings].some((text) => FIXED_DOMAIN.test(text))) findings.push(finding(sourceFile, event, "data_exfiltration", "critical", "Host identity is carried in a DNS lookup name", host));
    } else if (host && !has(event.data, "credential", "environment", "environment_all", "clipboard", "file", "walk")) {
      // The host or user name sent to a remote endpoint is what a beacon reports
      // about the machine it landed on. High, not critical: device registration
      // and telemetry send it too. One read sent to many endpoints is one fact.
      const key = `${host.line}:${host.detail}`;
      if (!hostsSent.has(key)) {
        hostsSent.add(key);
        findings.push(finding(sourceFile, event, "data_exfiltration", "high", "Host identity flows to a network send", host));
      }
    }
    if (event.kind === "execute" && (has(event.data, "network") || event.data.flags.includes("decoded"))) {
      findings.push(finding(sourceFile, event, "remote_code_execution", "critical", "Network response or decoded data flows to code execution", event.data.traces.find((t) => t.kind === "network") ?? event.data.traces[0]));
    }
    // Scheduling anything (cron, launchd, systemd, autostart) is persistence,
    // and the payload is usually literal text. A shell rc file is different:
    // `echo 'export PATH=...' >> ~/.bashrc` is an install step. It is medium only
    // when every written line is plain configuration and nothing tainted is in it.
    if (event.kind === "write" && event.target.strings.some(persistencePath)) {
      const rcOnly = event.target.strings.filter(persistencePath).every((path) => SHELL_RC.test(path));
      // A write event's data also carries its own target path; judge only the content.
      const written = event.data.strings.filter((text) => !event.target.strings.includes(text) && !persistencePath(text));
      const configOnly = written.length > 0 && written.every((text) => text.split("\n").every((line) => !line.trim() || CONFIG_LINE.test(line)));
      const carried = event.data.traces.length > 0 || event.data.flags.includes("decoded");
      // A key added to authorized_keys is a login for whoever holds the other
      // half. Nothing softens that the way an rc file's PATH line does.
      const login = event.target.strings.some((path) => LOGIN_KEYS.test(path));
      findings.push(finding(sourceFile, event, "persistence", login ? "critical" : rcOnly && configOnly && !carried ? "medium" : "high", "Code writes to an operating-system persistence location"));
    }
    for (const loop of event.loops) {
      const facts = loopFacts.get(loop) ?? { mutations: [] };
      if (event.kind === "read" && has(event.data, "file") && has(event.data, "walk")) facts.read = event;
      if (event.kind === "encrypt" && has(event.data, "file") && has(event.data, "walk") && event.data.flags.includes("encrypted")) facts.encrypt = event;
      if ((event.kind === "write" || event.kind === "mutate") && (has(event.target, "walk") || has(event.data, "file") && event.data.flags.includes("encrypted"))) facts.mutations.push(event);
      loopFacts.set(loop, facts);
    }
  }
  for (const facts of loopFacts.values()) {
    if (!facts.read || !facts.encrypt) continue;
    const mutation = facts.mutations.find((e) => e.line >= facts.encrypt!.line);
    if (mutation) findings.push(finding(sourceFile, mutation, "file_system", "critical", "Walked files are read, encrypted and changed inside a loop", facts.read.data.traces.find((t) => t.kind === "walk")));
  }
  return findings;
}

/** Bounded worklists and summaries keep work linear in the IR size. */
export function analyzeProgram(program: IRProgram, specs: LanguageSpecs, deadline = Infinity): Finding[] {
  const summaries = new Map<string, Summary>();
  const serialized = new Map<string, string>();
  let module = solve(program.module, specs, summaries, deadline, undefined, program.globals);
  // A function's summary depends only on the summaries it looked up and the
  // module globals it read. When none of those changed since it was last
  // solved, the answer is the same, so a round re-solves only real callers.
  const solved = new Map<IRFunction, { summary: Summary; calls: Set<string>; reads: Map<string, Value | undefined> }>();
  let changedBefore: Set<string> | undefined;
  let converged = false;
  for (let round = 0; round < MAX_ROUNDS && performance.now() < deadline; round++) {
    const changedNow = new Set<string>();
    const next = new Map<string, Summary>();
    const globals = module.globals;
    for (const fn of program.functions) {
      let entry = solved.get(fn);
      const current = entry && changedBefore && ![...entry.calls].some((name) => changedBefore!.has(name))
        && [...entry.reads].every(([name, value]) => { const now = globals?.get(name); return value === now || value !== undefined && now !== undefined && same(value, now); });
      if (!entry || !current) {
        const calls = new Set<string>(), reads = new Map<string, Value | undefined>();
        const summary = solve(fn, specs, { get: (name) => { calls.add(name); return summaries.get(name); } }, deadline,
          { get: (name) => { const value = globals?.get(name); reads.set(name, value); return value; } });
        entry = { summary, calls, reads };
        solved.set(fn, entry);
      }
      next.set(fn.name, combine(next.get(fn.name), entry.summary));
      if (performance.now() >= deadline) break;
    }
    for (const [name, summary] of next) {
      const text = JSON.stringify(summary);
      if (text !== serialized.get(name)) { summaries.set(name, summary); serialized.set(name, text); changedNow.add(name); }
    }
    if (!changedNow.size) { converged = true; break; }
    changedBefore = changedNow;
    module = solve(program.module, specs, summaries, deadline, undefined, program.globals);
  }
  // Out of rounds, not out of time (index.ts reports that): summaries may be stale.
  if (!converged && program.functions.length && performance.now() < deadline) coverage.incomplete = true;
  const events = [...module.events, ...[...summaries.values()].flatMap((s) => s.events)];
  const result = findingsForEvents(events, program.source);
  const seen = new Set<string>();
  return result.filter((f) => { const key = `${f.category}:${f.lineNumber}:${f.severity}`; if (seen.has(key)) return false; seen.add(key); return true; });
}
