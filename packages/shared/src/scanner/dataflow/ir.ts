import type { SourceFile } from "../../types.js";
import type { Node as SyntaxNode } from "web-tree-sitter";

export type ValueId = number;
export type TaintKind = "credential" | "environment" | "environment_all" | "clipboard" | "walk" | "file" | "network" | "host" | "parameter";
export type TaintFlag = "encoded" | "decoded" | "encrypted";
export interface Argument { name?: string; value: ValueId }

/** A bounded value graph per function, with phi nodes at control-flow joins. */
export interface IRNode {
  id: ValueId;
  op: "literal" | "symbol" | "parameter" | "merge" | "concat" | "attribute" | "index" | "call" | "xor";
  inputs: ValueId[];
  /** Coarse writes taint every alias of this value. */
  mutations?: ValueId[];
  line: number;
  loops: number[];
  text?: string;
  name?: string;
  parameter?: number;
  args?: Argument[];
  receiver?: ValueId;
}
export interface IRFunction { name: string; parameters: string[]; nodes: IRNode[]; returns: ValueId[] }
export interface IRProgram { source: SourceFile; functions: IRFunction[]; module: IRFunction; globals?: Record<string, ValueId> }

export type CallEffect = "aggregate" | "host" | "open" | "read" | "network" | "dns" | "walk" | "clipboard" | "environment" | "encode" | "decode" | "encrypt" | "execute" | "command" | "write" | "mutate" | "path" | "identity" | "request" | "network_read" | "join" | "format";
export interface CallRule {
  names: RegExp;
  effects: CallEffect[];
  /** Constructors expose a canonical receiver API to subsequent method calls. */
  resultApi?: string;
  target?: "receiver" | number;
  pathSeparator?: string;
  pathReceiver?: boolean;
  commandShell?: "always" | "option";
  shellOption?: string;
  truthy?: string[];
  urlPosition?: number;
  clearApi?: boolean;
}
export interface AccessRule { names: RegExp; source: Exclude<TaintKind, "parameter"> }
export interface LanguageSpecs { calls: CallRule[]; accesses: AccessRule[] }

/** Register a language here through index.ts; the engine has no language cases. */
export interface DataflowFrontend {
  grammar: string;
  specs: LanguageSpecs;
  /**
   * False only when the text names nothing a finding needs, so it is not parsed.
   * It must never be stricter than the frontend: when unsure, return true.
   */
  mayFind?(text: string): boolean;
  /** Throw DataflowDeadline once `deadline` (performance.now()) passes; lowering is not free. */
  lower(root: SyntaxNode, source: SourceFile, deadline?: number): IRProgram;
}

/**
 * Set by a frontend or the engine when a depth guard or size cap drops part of
 * a file, so the scan reports that the analysis is incomplete instead of
 * presenting a partial answer as a clean one. analyzeDataflow resets it.
 */
export const coverage = { incomplete: false };

/** Thrown by a frontend or the engine when the per-skill budget runs out mid-file. */
export class DataflowDeadline extends Error {
  constructor() { super("dataflow budget exhausted"); this.name = "DataflowDeadline"; }
}
