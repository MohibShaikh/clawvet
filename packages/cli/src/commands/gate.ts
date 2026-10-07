import { checkApproval } from "../review.js";
import { existsSync, lstatSync, statSync, realpathSync } from "node:fs";
import { join, basename, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { scanSkill } from "@clawvet/shared";
import type { Finding, Recommendation } from "@clawvet/shared";
import { assembleSkill, coverageReason, coverageWarning, type AssemblyResult } from "../assemble.js";
import { applyProfile, type Profile } from "../policy.js";

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
}

type Decision = "allow" | "warn" | "block";

interface PolicyFinding {
  ruleId: string;
  message: string;
  severity: "info" | "warn" | "critical";
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

function emit(res: PolicyResponse): never {
  process.stdout.write(JSON.stringify(res) + "\n");
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
}

// OpenClaw requires the policy command and any interpreter script argument to
// be "direct regular files with trusted ownership, restricted permissions, and
// verifiable parent directories. Symlinks and insecure paths are rejected."
// `npm i -g clawvet` puts a symlink in bin/, so pointing installPolicy at
// `which clawvet` fails. Resolve through to the real file and invoke it via
// node explicitly, so both the command and the script argument are regular
// files.
function printConfig(blockAt: number, approval?: string, strict?: boolean): void {
  const self = realpathSync(fileURLToPath(import.meta.url));
  const args: string[] = [self, "gate"];
  if (blockAt !== DEFAULT_BLOCK_AT) args.push("--block-at", String(blockAt));
  if (approval) args.push("--approval", resolve(approval));
  if (strict) args.push("--strict");
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
          timeoutMs: 10000,
        },
      },
    },
  };
  process.stdout.write(JSON.stringify(config, null, 2) + "\n");
}

export async function gateCommand(options: GateOptions = {}): Promise<void> {
  const blockAt = Number.isFinite(options.blockAt)
    ? (options.blockAt as number)
    : DEFAULT_BLOCK_AT;

  if (options.printConfig) {
    printConfig(blockAt, options.approval, options.strict);
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
    await gateRequest(req, blockAt, options);
  } catch (err) {
    blockWith(`ClawVet gate failed: ${err instanceof Error ? err.message : "unknown error"}`);
  }
}

async function gateRequest(req: PolicyRequest, blockAt: number, options: GateOptions): Promise<void> {
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

  const { response } = await evaluateSkill(skillDir || dirname(skillFile), {
    blockAt,
    profile: options.strict ? "strict" : "default",
    entryFile: basename(skillFile),
    skillName: req.targetName || req.origin?.slug || basename(dirname(skillFile)),
  });
  emit(response);
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
  options: { blockAt?: number; entryFile?: string; skillName?: string; profile?: Profile } = {},
): Promise<Evaluation> {
  const blockAt = options.blockAt ?? DEFAULT_BLOCK_AT;
  const block = (reason: string, assembly?: AssemblyResult): Evaluation => ({
    response: { protocolVersion: PROTOCOL_VERSION, decision: "block", reason: reason.slice(0, REASON_MAX) },
    ...(assembly ? { coverage: assembly.coverage, content: assembly.content } : {}),
  });
  let result;
  let assembly: AssemblyResult;
  let ask: AssemblyResult["coverage"]["issues"] = [];
  try {
    if (lstatSync(skillDir).isSymbolicLink()) return block("ClawVet gate refuses a staged source that is a symlink.");
    assembly = assembleSkill(skillDir, undefined, options.entryFile ?? "SKILL.md");
    const coverage = applyProfile(assembly.coverage, options.profile);
    if (coverage.block.length) return block(coverageReason(coverage.block), assembly);
    ask = coverage.ask;
    // Static passes only. The semantic pass needs a key and a network round
    // trip, and this runs inside the host's install timeout.
    result = await scanSkill(assembly.content, { skillName: options.skillName ?? basename(skillDir) });
  } catch (err) {
    return block(`ClawVet gate failed to scan the staged skill: ${err instanceof Error ? err.message : "unknown error"}`);
  }
  const evaluated = { coverage: assembly.coverage, content: assembly.content };

  // A disqualifying indicator is a verdict on its own, independent of score.
  const disqualified = result.findings.some((f) => f.disqualifying);
  const decision: Decision =
    disqualified || result.riskScore >= blockAt
      ? "block"
      : DECISION[result.recommendation ?? "warn"] === "allow"
        ? "allow"
        : "warn";
  const findings: PolicyFinding[] = result.findings.slice(0, 20).map((f) => ({
    ruleId: f.id ?? f.category,
    message: f.description || f.title,
    severity: SEVERITY[f.severity],
    ...(f.evidence ? { evidence: f.evidence } : {}),
    ...(f.lineNumber ? { line: f.lineNumber } : {}),
  }));

  if (decision === "allow") {
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
      reason: summarize(result.skillName, result.riskGrade, result.riskScore, result.findings).slice(0, REASON_MAX),
      findings,
    },
  };
}
