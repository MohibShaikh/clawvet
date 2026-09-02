import { readFileSync, existsSync, statSync } from "node:fs";
import { join, basename, dirname } from "node:path";
import { scanSkill } from "@clawvet/shared";
import type { Finding, Recommendation } from "@clawvet/shared";
import { assembleSkill } from "../assemble.js";

// OpenClaw's security.installPolicy hook. It writes staged install metadata to
// our stdin and reads a single JSON verdict from our stdout, after the source
// is staged and before the install completes. Anything it cannot parse fails
// closed, so this path must emit exactly one JSON object on stdout and put
// every diagnostic on stderr.
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

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(chunk as Buffer);
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

export interface PolicyOptions {
  blockAt?: number;
}

export async function policyCommand(options: PolicyOptions = {}): Promise<void> {
  const blockAt = Number.isFinite(options.blockAt)
    ? (options.blockAt as number)
    : DEFAULT_BLOCK_AT;
  let req: PolicyRequest;
  try {
    const raw = await readStdin();
    if (!raw.trim()) blockWith("ClawVet policy received no install metadata on stdin.");
    req = JSON.parse(raw) as PolicyRequest;
  } catch {
    blockWith("ClawVet policy could not parse the install metadata on stdin.");
  }

  if (req.protocolVersion !== undefined && req.protocolVersion !== PROTOCOL_VERSION) {
    blockWith(
      `ClawVet policy speaks protocol ${PROTOCOL_VERSION}, host sent ${req.protocolVersion}. Upgrade clawvet.`
    );
  }

  const sourcePath = req.sourcePath;
  if (!sourcePath || !existsSync(sourcePath)) {
    blockWith(`ClawVet policy could not read the staged source at ${sourcePath ?? "(none)"}.`);
  }

  let skillFile = sourcePath;
  let skillDir: string | undefined;
  if (statSync(sourcePath).isDirectory()) {
    skillDir = sourcePath;
    skillFile = join(sourcePath, "SKILL.md");
  }

  if (!existsSync(skillFile) || statSync(skillFile).isDirectory()) {
    // No SKILL.md means no instruction layer to vet. Plugins can legitimately
    // ship without one, so this is not on its own a reason to fail an install.
    emit({ protocolVersion: PROTOCOL_VERSION, decision: "allow" });
  }

  let result;
  try {
    const skillMd = readFileSync(skillFile, "utf-8");
    // Assemble referenced files so a payload split across them cannot hide.
    const content = skillDir ? assembleSkill(skillDir, skillMd) : skillMd;
    // Static passes only. The semantic pass needs a key and a network round
    // trip, and this runs inside the host's install timeout.
    result = await scanSkill(content, {
      skillName: req.targetName || req.origin?.slug || basename(dirname(skillFile)),
    });
  } catch (err) {
    blockWith(
      `ClawVet policy failed to scan the staged skill: ${err instanceof Error ? err.message : "unknown error"}`
    );
  }

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
    emit({ protocolVersion: PROTOCOL_VERSION, decision, findings });
  }

  emit({
    protocolVersion: PROTOCOL_VERSION,
    decision,
    reason: summarize(
      result.skillName,
      result.riskGrade,
      result.riskScore,
      result.findings
    ).slice(0, REASON_MAX),
    findings,
  });
}
