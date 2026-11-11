import { checkApproval } from "../review.js";
import { existsSync, lstatSync, statSync, realpathSync } from "node:fs";
import { join, basename, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { rescore, scanSkill } from "@clawvet/shared";
import type { Finding, Recommendation } from "@clawvet/shared";
import { assembleSkill, coverageReason, coverageWarning, type AssemblyResult } from "../assemble.js";
import { applyProfile, type Profile } from "../policy.js";
import { createSemanticJudge, judgmentGap, resolveSemanticConfig, SemanticUnavailableError, type SemanticJudgment } from "../semantic/judge.js";
import { acceptCoverage, finishScan, startOsv, type PassOptions } from "../passes.js";
import { loadBaselines } from "../suppress.js";

// OpenClaw's security.installPolicy hook. It writes staged install metadata to
// our stdin and reads a single JSON verdict from our stdout, after the source
// is staged and before the install completes. Anything it cannot parse fails
// closed, so this path must emit exactly one JSON object on stdout and put
// every diagnostic on stderr.
//
// Named `gate`, not `policy`. `openclaw policy` is a different thing in the
// same ecosystem: a workspace-config conformance linter a human runs. This is
// an install-time admission gate the host runs. Two commands called policy
// meaning two different things is a trap, and it would also collide with a
// future declarative `clawvet policy` that reads a rules file.
//
// This is the enforcement half of ClawVet. The clawvet skill asks an agent to
// remember to scan; this runs whether or not it remembers.

const PROTOCOL_VERSION = 1;

// Only the fields we use. OpenClaw sends more and may add more.
interface PolicyRequest {
  protocolVersion?: number;
  targetType?: string;
  targetName?: string;
  sourcePath?: string;
  sourcePathKind?: "directory" | "file";
  origin?: { slug?: string; version?: string; registry?: string };
  // Set when OpenClaw is installing one of the skill's dependencies
  // (metadata.openclaw.install[]): the spec it is about to run.
  skill?: { installId?: string; installSpec?: unknown };
}

type Decision = "allow" | "warn" | "block";

interface PolicyFinding {
  ruleId: string;
  message: string;
  severity: "info" | "warn" | "critical";
  /** The bundled file the finding is in; `line` is within that file. */
  file?: string;
  evidence?: string;
  line?: number;
}

interface PolicyResponse {
  protocolVersion: number;
  decision: Decision;
  reason?: string;
  findings?: PolicyFinding[];
}

// approve/warn/block is already ClawVet's own vocabulary, so the mapping is
// identity. Kept explicit so a change on either side is a compile error here
// rather than a silently wrong verdict.
const DECISION: Record<Recommendation, Decision> = {
  approve: "allow",
  warn: "warn",
  block: "block",
};

// ClawVet grades severity for a human reading a report; installPolicy grades it
// for a gate. medium and low are advisory either way.
const SEVERITY: Record<Finding["severity"], PolicyFinding["severity"]> = {
  critical: "critical",
  high: "critical",
  medium: "warn",
  low: "info",
};

const REASON_MAX = 1000;

// ClawVet carries two thresholds for two jobs. `recommendation` blocks at 76,
// which is the conservative posture for a report a human reads. The scanner's
// warn line is 26, and that is the threshold the paper validates detection at.
// A hard install gate inherits whichever one it is wired to, so the operator
// picks: default to 76 so ordinary dual-use skills still install, and let a
// stricter deployment lower it. See --block-at.
const DEFAULT_BLOCK_AT = 76;

// OpenClaw blocks a warn whose rendered review (title, target, reason, findings,
// recovery guidance) exceeds 4,000 characters, rather than show part of it. Keep
// the reason and findings well inside that, so a warn stays a warn the operator
// can approve. The rest of the detail is one `clawvet scan` away.
const NOTICE_BUDGET = 2800;
export function fitNotice(res: PolicyResponse): PolicyResponse {
  const reason = res.reason?.slice(0, 600);
  let used = reason?.length ?? 0;
  const findings: PolicyFinding[] = [];
  for (const finding of res.findings ?? []) {
    const size = finding.ruleId.length + finding.message.length + (finding.evidence?.length ?? 0) + (finding.file?.length ?? 0) + 24;
    if (findings.length === 10 || used + size > NOTICE_BUDGET) break;
    findings.push(finding);
    used += size;
  }
  return { ...res, ...(reason !== undefined ? { reason } : {}), ...(res.findings ? { findings } : {}) };
}

function emit(res: PolicyResponse): never {
  process.stdout.write(JSON.stringify(fitNotice(res)) + "\n");
  process.exit(0);
}

// A scanner that cannot read the target has not cleared it. Block with a
// reason the user can act on, rather than exiting non-zero and leaving them
// with a bare install failure.
function blockWith(reason: string): never {
  emit({
    protocolVersion: PROTOCOL_VERSION,
    decision: "block",
    reason: reason.slice(0, REASON_MAX),
  });
}

// Install metadata is a few hundred bytes. Bound both size and time, so a host
// that never closes stdin still gets a verdict before its own timeout.
const STDIN_MAX = 1024 * 1024;
const STDIN_DEADLINE_MS = 5000;

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  let size = 0;
  const deadline = setTimeout(() => blockWith("ClawVet gate timed out waiting for install metadata on stdin."), STDIN_DEADLINE_MS);
  try {
    for await (const chunk of process.stdin) {
      size += (chunk as Buffer).length;
      if (size > STDIN_MAX) blockWith("ClawVet gate received install metadata larger than 1 MiB.");
      chunks.push(chunk as Buffer);
    }
  } finally { clearTimeout(deadline); }
  return Buffer.concat(chunks).toString("utf-8");
}

function summarize(
  name: string,
  grade: string,
  score: number,
  findings: Finding[]
): string {
  const worst = findings
    .filter((f) => f.severity === "critical" || f.severity === "high")
    .slice(0, 3)
    .map((f) => f.title);
  const head = `ClawVet graded "${name}" ${grade} (risk ${score}/100).`;
  return worst.length ? `${head} ${worst.join("; ")}.` : head;
}

export interface GateOptions {
  blockAt?: number;
  printConfig?: boolean;
  approval?: string;
  strict?: boolean;
  semantic?: boolean;
  semanticRuns?: number;
  semanticTimeoutMs?: number;
  semanticCache?: boolean;
  semanticOnError?: "warn" | "ignore";
  /** Operator-owned baseline file, or a directory of them. Never inside a skill. */
  baseline?: string;
  /** Opt-in OSV.dev lookup of pinned dependencies. The gate is offline otherwise. */
  osv?: boolean;
  osvCache?: boolean;
}

// The judge must answer inside the host's install timeout, with room left for
// assembly and the static passes.
export const DEFAULT_SEMANTIC_TIMEOUT_MS = 8000;

/**
 * An optional LLM judge for evaluateSkill. `unavailable` is set instead of
 * `analyze` when it could not be configured, so the onError policy applies to a
 * missing key the same way it applies to an outage.
 */
export interface SemanticGate {
  judge?: (content: string, timeoutMs?: number) => Promise<SemanticJudgment>;
  /** Milliseconds left for the judge, from the gate's absolute deadline. */
  timeoutMs?: number;
  unavailable?: string;
  onError: "warn" | "ignore";
}

export function semanticGate(
  options: Pick<GateOptions, "semanticRuns" | "semanticTimeoutMs" | "semanticCache" | "semanticOnError">,
  timeoutMs = options.semanticTimeoutMs ?? DEFAULT_SEMANTIC_TIMEOUT_MS,
): SemanticGate {
  const onError = options.semanticOnError ?? "warn";
  try {
    const config = resolveSemanticConfig(process.env, {
      timeoutMs: options.semanticTimeoutMs ?? DEFAULT_SEMANTIC_TIMEOUT_MS,
      runs: options.semanticRuns ?? 1,
      cache: options.semanticCache ?? false,
    });
    return { judge: createSemanticJudge(config), timeoutMs, onError };
  } catch (err) {
    return { unavailable: err instanceof Error ? err.message : "semantic judge unavailable", onError };
  }
}

// The host timeout --print-config writes for a semantic gate: the judge's own
// budget plus room for stdin, assembly, the static passes and process start.
export function semanticHostTimeout(semanticTimeoutMs: number): number {
  return Math.max(10000, semanticTimeoutMs + 4000);
}
// What the gate keeps back from the host timeout for everything after the judge.
const SEMANTIC_RESERVE_MS = 1500;

// OpenClaw requires the policy command and any interpreter script argument to
// be "direct regular files with trusted ownership, restricted permissions, and
// verifiable parent directories. Symlinks and insecure paths are rejected."
// `npm i -g clawvet` puts a symlink in bin/, so pointing installPolicy at
// `which clawvet` fails. Resolve through to the real file and invoke it via
// node explicitly, so both the command and the script argument are regular
// files.
function printConfig(blockAt: number, options: GateOptions): void {
  const { approval, strict } = options;
  const self = realpathSync(fileURLToPath(import.meta.url));
  const args: string[] = [self, "gate"];
  if (blockAt !== DEFAULT_BLOCK_AT) args.push("--block-at", String(blockAt));
  if (approval) args.push("--approval", resolve(approval));
  if (strict) args.push("--strict");
  const semanticTimeout = options.semanticTimeoutMs ?? DEFAULT_SEMANTIC_TIMEOUT_MS;
  const passEnv = [
    ...(options.semantic ? ["CLAWVET_LLM_PROVIDER", "CLAWVET_LLM_MODEL", "CLAWVET_LLM_BASE_URL", "CLAWVET_LLM_API_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY"] : []),
    // The caches live under the user's cache directory.
    ...(options.semanticCache || options.osvCache ? ["HOME", "XDG_CACHE_HOME"] : []),
  ];
  if (options.baseline) args.push("--baseline", resolve(options.baseline));
  if (options.osv) args.push("--osv", ...(options.osvCache ? ["--osv-cache"] : []));
  if (options.semantic) {
    // The key is read from the gateway's environment, never written here.
    args.push("--semantic");
    if (options.semanticRuns && options.semanticRuns !== 1) args.push("--semantic-runs", String(options.semanticRuns));
    if (options.semanticTimeoutMs) args.push("--semantic-timeout", String(semanticTimeout));
    if (options.semanticCache) args.push("--semantic-cache");
    if (options.semanticOnError === "ignore") args.push("--semantic-on-error", "ignore");
  }
  const config = {
    security: {
      installPolicy: {
        enabled: true,
        // Only "skill". ClawVet reads SKILL.md and the files it references. A
        // plugin with no SKILL.md has no instruction layer to inspect and is
        // allowed through, so listing "plugin" here would claim a protection
        // that does not exist yet.
        targets: ["skill"],
        exec: {
          // OpenClaw requires exec.source == "exec"; omit it and config
          // validation rejects the block as-is.
          source: "exec",
          command: realpathSync(process.execPath),
          args,
          // The judge's own deadline plus room for assembly and the static
          // passes, so the host never kills a gate that is about to answer.
          timeoutMs: options.semantic ? semanticHostTimeout(semanticTimeout) : 10000,
          // OpenClaw starts the policy with an empty environment and copies only
          // the names listed here, so the judge's key must be named or the gate
          // never sees it. Values stay in the gateway's environment.
          ...(passEnv.length ? { passEnv } : {}),
          // The OSV lookup runs alongside the scan with its own 3 s deadline, so
          // it fits inside either budget.
        },
      },
    },
  };
  process.stdout.write(JSON.stringify(config, null, 2) + "\n");
}

export async function gateCommand(options: GateOptions = {}): Promise<void> {
  // One absolute deadline from entry. A slow stdin shrinks the judge's share
  // instead of pushing the verdict past the host's timeout.
  const startedAt = Date.now();
  const blockAt = Number.isFinite(options.blockAt)
    ? (options.blockAt as number)
    : DEFAULT_BLOCK_AT;

  if (options.printConfig) {
    printConfig(blockAt, options);
    return;
  }
  let req: PolicyRequest;
  try {
    const raw = await readStdin();
    if (!raw.trim()) blockWith("ClawVet gate received no install metadata on stdin.");
    req = JSON.parse(raw) as PolicyRequest;
  } catch {
    blockWith("ClawVet gate could not parse the install metadata on stdin.");
  }
  // `null` parses fine but has no properties, so reading one crashed the gate
  // with nothing on stdout. Answer every non-object with a verdict instead.
  if (typeof req !== "object" || req === null || Array.isArray(req)) {
    blockWith("ClawVet gate received install metadata that is not a JSON object.");
  }

  // Host fields are untrusted: an object with a hostile toString must not reach
  // a template string, and anything unexpected below must still get a verdict.
  if ((req.protocolVersion !== undefined && typeof req.protocolVersion !== "number") ||
      (req.sourcePath !== undefined && typeof req.sourcePath !== "string") ||
      (req.targetType !== undefined && typeof req.targetType !== "string") ||
      (req.targetName !== undefined && typeof req.targetName !== "string")) {
    blockWith("ClawVet gate received install metadata with fields of the wrong type.");
  }
  try {
    await gateRequest(req, blockAt, options, startedAt);
  } catch (err) {
    blockWith(`ClawVet gate failed: ${err instanceof Error ? err.message : "unknown error"}`);
  }
}

async function gateRequest(req: PolicyRequest, blockAt: number, options: GateOptions, startedAt = Date.now()): Promise<void> {
  if (req.protocolVersion !== undefined && req.protocolVersion !== PROTOCOL_VERSION) {
    blockWith(
      `ClawVet gate speaks protocol ${PROTOCOL_VERSION}, host sent ${req.protocolVersion}. Upgrade clawvet.`
    );
  }

  const sourcePath = req.sourcePath;
  if (!sourcePath || !existsSync(sourcePath)) {
    blockWith(`ClawVet gate could not read the staged source at ${sourcePath ?? "(none)"}.`);
  }

  // The staged source must be the staged source, not a link to somewhere else.
  if (lstatSync(sourcePath).isSymbolicLink()) {
    blockWith("ClawVet gate refuses a staged source that is a symlink.");
  }
  let skillFile = sourcePath;
  let skillDir: string | undefined;
  if (statSync(sourcePath).isDirectory()) {
    skillDir = sourcePath;
    skillFile = join(sourcePath, "SKILL.md");
  }

  if (!existsSync(skillFile) || statSync(skillFile).isDirectory()) {
    // Plugins can legitimately ship without SKILL.md, so a plugin target passes.
    // installPolicy only targets skills, though, and a skill with no instruction
    // layer is either not a skill or installs its payload without saying what it
    // does. Block on the way through so the gap cannot be leaned on.
    if (req.targetType === "plugin") {
      emit({ protocolVersion: PROTOCOL_VERSION, decision: "allow" });
    }
    blockWith(
      "ClawVet gate found no SKILL.md in the staged skill. A skill install must stage a SKILL.md to scan."
    );
  }

  if (options.approval) {
    try { await checkApproval(skillFile, options.approval, blockAt); }
    catch (err) { blockWith(`ClawVet approval required: ${err instanceof Error ? err.message : "invalid approval"}`); }
  }

  const root = skillDir || dirname(skillFile);
  let passes: PassOptions = { skillRoot: root };
  if (options.baseline) {
    // A baseline the operator configured and the gate cannot read is a
    // misconfiguration, not a pass: block and say why.
    try { passes.baseline = loadBaselines(options.baseline, { skillRoot: root }); }
    catch (err) { blockWith(`ClawVet baseline unusable: ${err instanceof Error ? err.message : "invalid baseline"}`); }
  }
  if (options.osv) passes = { ...passes, osv: { cache: options.osvCache } };
  const { response } = await evaluateSkill(root, {
    blockAt,
    profile: options.strict ? "strict" : "default",
    entryFile: basename(skillFile),
    skillName: req.targetName || req.origin?.slug || basename(dirname(skillFile)),
    semantic: options.semantic ? semanticGate(options, Math.min(
      options.semanticTimeoutMs ?? DEFAULT_SEMANTIC_TIMEOUT_MS,
      startedAt + semanticHostTimeout(options.semanticTimeoutMs ?? DEFAULT_SEMANTIC_TIMEOUT_MS) - SEMANTIC_RESERVE_MS - Date.now(),
    )) : undefined,
    passes,
  });
  emit(dependencyVerdict(response, req.skill?.installSpec));
}

// A dependency install of kind "download" puts a file from the network on the
// host, outside anything the gate read. Pinned by sha256, OpenClaw verifies it;
// unpinned, the bytes are whatever the URL serves that day; over plain http,
// anyone on the path chooses them. Other installer kinds go through a package
// manager and keep the skill's own verdict. An unrecognised shape changes nothing.
export function dependencyVerdict(response: PolicyResponse, spec: unknown): PolicyResponse {
  if (!spec || typeof spec !== "object" || (spec as { kind?: unknown }).kind !== "download" || response.decision === "block") return response;
  const { url, sha256 } = spec as { url?: unknown; sha256?: unknown };
  const where = typeof url === "string" ? url.slice(0, 200) : "an unknown URL";
  if (typeof url !== "string" || !/^https:\/\//i.test(url)) {
    return { ...response, decision: "block", reason: `ClawVet blocks a dependency download that is not over https: ${where}` };
  }
  if (typeof sha256 !== "string" || !/^[a-f0-9]{64}$/i.test(sha256)) {
    return { ...response, decision: "warn", reason: `Dependency download from ${where} is not pinned by sha256; review it, or add sha256 to the skill's install spec.` };
  }
  return response;
}

export interface Evaluation {
  response: PolicyResponse;
  // Present when assembly ran. Benchmarks read it instead of the reason text,
  // which is truncated for the host.
  coverage?: AssemblyResult["coverage"];
  content?: string;
}

/**
 * The gate's verdict for a staged skill folder, without stdin or exit. Never
 * throws: a scanner failure is a block, as on the command line.
 */
export async function evaluateSkill(
  skillDir: string,
  options: { blockAt?: number; entryFile?: string; skillName?: string; profile?: Profile; semantic?: SemanticGate; passes?: PassOptions } = {},
): Promise<Evaluation> {
  const blockAt = options.blockAt ?? DEFAULT_BLOCK_AT;
  const block = (reason: string, assembly?: AssemblyResult): Evaluation => ({
    response: { protocolVersion: PROTOCOL_VERSION, decision: "block", reason: reason.slice(0, REASON_MAX) },
    ...(assembly ? { coverage: assembly.coverage, content: assembly.content } : {}),
  });
  let result: Awaited<ReturnType<typeof scanSkill>> | undefined;
  let assembly: AssemblyResult;
  let ask: AssemblyResult["coverage"]["issues"] = [];
  let semanticFailure: string | undefined;
  let judgment: SemanticJudgment | undefined;
  try {
    if (lstatSync(skillDir).isSymbolicLink()) return block("ClawVet gate refuses a staged source that is a symlink.");
    assembly = assembleSkill(skillDir, undefined, options.entryFile ?? "SKILL.md");
    const passes = options.passes ?? {};
    assembly = acceptCoverage(assembly, passes).assembly;
    const coverage = applyProfile(assembly.coverage, options.profile);
    if (coverage.block.length) return block(coverageReason(coverage.block), assembly);
    ask = coverage.ask;
    // Coverage has already blocked what cannot be read, so the judge only sees
    // skills that would otherwise install. It adds findings; it never removes one.
    // The network passes start first so their waits overlap the static scan.
    const osv = startOsv(assembly.content, assembly.coverage.files, passes.osv);
    const semantic = options.semantic;
    const judging = semantic?.judge ? semantic.judge(assembly.content, semantic.timeoutMs) : undefined;
    judging?.catch(() => {}); // Settled below; never an unhandled rejection meanwhile.
    result = await scanSkill(assembly.content, { skillName: options.skillName ?? basename(skillDir), files: assembly.coverage.files });
    if (judging) {
      try {
        judgment = await judging;
        semanticFailure = judgmentGap(judgment);
        if (judgment.findings.length) result = rescore(result, [...result.findings, ...judgment.findings]);
      } catch (err) {
        if (!(err instanceof SemanticUnavailableError)) throw err;
        semanticFailure = err.message;
      }
    } else if (semantic?.unavailable) semanticFailure = semantic.unavailable;
    const finished = await finishScan(result, assembly, osv, passes);
    result = finished.result;
    if (finished.osvErrors.length) process.stderr.write(`clawvet: OSV lookup incomplete: ${finished.osvErrors.join("; ")}\n`);
  } catch (err) {
    return block(`ClawVet gate failed to scan the staged skill: ${err instanceof Error ? err.message : "unknown error"}`);
  }
  const evaluated = { coverage: assembly.coverage, content: assembly.content };

  // A disqualifying indicator is a verdict on its own, independent of score.
  const disqualified = result.findings.some((f) => f.disqualifying);
  // A grounded non-benign judgment is never an allow, whatever its findings
  // score: a "malicious" with one high finding scores under the warn line.
  const judged = judgment && !semanticFailure && judgment.verdict !== "benign";
  const decision: Decision =
    disqualified || result.riskScore >= blockAt
      ? "block"
      : DECISION[result.recommendation ?? "warn"] === "allow" && !judged
        ? "allow"
        : "warn";
  // Bounded, so the one JSON line on stdout stays small whatever a provider or
  // a skill put in a finding.
  // Lines are positions in the assembled bundle; the operator needs the file and
  // the line inside it. Most severe first, so the notice budget keeps those.
  const rank = { critical: 0, high: 1, medium: 2, low: 3 };
  const locate = (line: number) => assembly.coverage.files.find((f) => line >= f.startLine && line <= f.endLine);
  const findings: PolicyFinding[] = [...result.findings].sort((a, b) => rank[a.severity] - rank[b.severity]).slice(0, 20).map((f) => {
    const file = f.lineNumber ? locate(f.lineNumber) : undefined;
    return {
      ruleId: f.id ?? f.category,
      // String(): a finding built from parsed YAML can carry a non-string value.
      message: String(f.description || f.title).slice(0, 200),
      severity: SEVERITY[f.severity],
      ...(file ? { file: file.path } : {}),
      ...(f.evidence ? { evidence: String(f.evidence).slice(0, 120) } : {}),
      ...(f.lineNumber ? { line: file ? f.lineNumber - file.startLine + 1 : f.lineNumber } : {}),
    };
  });

  if (decision === "allow") {
    // The operator asked for a semantic check and did not get one. Under "warn"
    // that is not a pass: the install waits for them rather than going through
    // on the static verdict alone.
    if (semanticFailure && options.semantic?.onError === "warn") {
      return { ...evaluated, response: { protocolVersion: PROTOCOL_VERSION, decision: "warn", reason: `Semantic check unavailable: ${semanticFailure} Static checks found nothing to block.`.slice(0, REASON_MAX), findings } };
    }
    if (semanticFailure) process.stderr.write(`clawvet: semantic check unavailable, using static verdict: ${semanticFailure}\n`);
    // A reviewable gap is not an uninspectable payload, but nothing here has
    // resolved it. Under the profiles that ask, the operator decides.
    if (ask.length) {
      return { ...evaluated, response: { protocolVersion: PROTOCOL_VERSION, decision: "warn", reason: coverageWarning(ask), findings } };
    }
    return { ...evaluated, response: { protocolVersion: PROTOCOL_VERSION, decision, findings } };
  }

  return {
    ...evaluated,
    response: {
      protocolVersion: PROTOCOL_VERSION,
      decision,
      reason: ((judged ? `Semantic judge: ${judgment!.verdict} (confidence ${judgment!.confidence.toFixed(2)}). ` : "") +
        summarize(result.skillName, result.riskGrade, result.riskScore, result.findings)).slice(0, REASON_MAX),
      findings,
    },
  };
}
