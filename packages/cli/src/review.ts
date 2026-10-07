import { createHash } from "node:crypto";
import {
  closeSync, constants, fstatSync, lstatSync, openSync, opendirSync,
  readSync, realpathSync, readFileSync, writeFileSync,
} from "node:fs";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { scanSkill, type ScanResult } from "@clawvet/shared";
import { assembleSkill, ASSEMBLY_LIMITS } from "./assemble.js";
import { applyCoverage } from "./local-scan.js";

const hash = (value: string | Buffer) => createHash("sha256").update(value).digest("hex");
const POLICY_VERSION = 1;
export interface FileDigest { path: string; sha256: string; executable: boolean }
export interface Signal { kind: string; value: string; path: string; line: number }
export interface Review {
  schema: "clawvet-review-v1";
  engine: string;
  policy: { version: number; blockAt: number };
  artifact: string;
  files: FileDigest[];
  signals: Signal[];
  scan: ScanResult & { coverage: ReturnType<typeof assembleSkill>["coverage"] };
}
export interface Approval { schema: "clawvet-approval-v1"; approvedAt: string; review: Review }

function inside(root: string, path: string): boolean {
  const rel = relative(root, path);
  return rel === "" || (rel !== ".." && !rel.startsWith(`..${sep}`) && !isAbsolute(rel));
}
function boundedRead(path: string, max: number): Buffer {
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.size > max || !(stat.mode & 0o444)) throw new Error(`Cannot inspect ${path}`);
    const buffer = Buffer.alloc(max + 1);
    let size = 0;
    while (size < buffer.length) {
      const count = readSync(fd, buffer, size, buffer.length - size, null);
      if (!count) break;
      size += count;
    }
    if (size > max) throw new Error(`Inspection limit exceeded: ${path}`);
    return buffer.subarray(0, size);
  } finally { closeSync(fd); }
}

// Fingerprint the actual bundled engine; source-mode development fingerprints
// both source trees. A code change invalidates approvals even before a release.
export function engineFingerprint(): string {
  const self = fileURLToPath(import.meta.url);
  if (!self.endsWith(".ts")) return hash(readFileSync(self));
  const digest = createHash("sha256");
  function visit(dir: string) {
    const handle = opendirSync(dir);
    const entries = [];
    try { for (let entry = handle.readSync(); entry; entry = handle.readSync()) entries.push(entry); }
    finally { handle.closeSync(); }
    for (const entry of entries.sort((a, b) => a.name.localeCompare(b.name))) {
      const path = join(dir, entry.name);
      if (entry.isDirectory()) visit(path);
      else if (entry.name.endsWith(".ts")) digest.update(entry.name).update(readFileSync(path));
    }
  }
  visit(dirname(self));
  visit(resolve(dirname(self), "../../shared/src"));
  return digest.digest("hex");
}

export function skillRoot(target: string): string {
  const path = resolve(target);
  if (lstatSync(path).isSymbolicLink()) throw new Error("Review target must not be a symlink");
  if (lstatSync(path).isDirectory()) return realpathSync(path);
  if (basename(path) !== "SKILL.md") throw new Error("Review requires a skill directory or SKILL.md");
  return realpathSync(dirname(path));
}

function snapshot(root: string) {
  const files: FileDigest[] = [];
  const signals: Signal[] = [];
  let bytes = 0;
  let entries = 0;
  function walk(dir: string, depth: number) {
    if (depth > ASSEMBLY_LIMITS.depth || realpathSync(dir) !== dir) throw new Error("Unsafe or excessively deep skill directory");
    const handle = opendirSync(dir);
    try {
      for (let entry = handle.readSync(); entry; entry = handle.readSync()) {
        if (++entries > ASSEMBLY_LIMITS.entries) throw new Error("Skill inventory limit exceeded");
        const path = join(dir, entry.name);
        if (entry.isDirectory()) { walk(path, depth + 1); continue; }
        if (!entry.isFile() || realpathSync(path) !== path) throw new Error("Symlinks and special files cannot be approved");
        const data = boundedRead(path, ASSEMBLY_LIMITS.fileBytes);
        bytes += data.length;
        if (bytes > ASSEMBLY_LIMITS.totalBytes) throw new Error("Skill snapshot exceeds 2 MiB");
        const rel = relative(root, path).split(sep).join("/");
        files.push({ path: rel, sha256: hash(data), executable: Boolean(lstatSync(path).mode & 0o111) });
        // These are textual indicators, including examples/comments, not proven
        // runtime capabilities. Binary files are hashed but not interpreted.
        if (!data.includes(0)) {
          let text: string;
          try { text = new TextDecoder("utf-8", { fatal: true }).decode(data); } catch { continue; }
          for (const [index, line] of text.split("\n").entries()) {
            const rules: Array<[string, RegExp]> = [
              ["network destination", /https?:\/\/[^\s<>"'`\\)\]]+/gi],
              ["credential reference", /(?:\b[A-Z][A-Z0-9_]*(?:API_KEY|TOKEN|SECRET|PASSWORD)\b|\.ssh\b|\.aws\b|\.env\b)/g],
              ["execution or installation", /\b(?:curl|wget|eval|exec|npx|bunx|npm\s+install|pip\s+install|Invoke-Expression|Invoke-WebRequest)\b/gi],
            ];
            for (const [kind, pattern] of rules) for (const match of line.matchAll(pattern)) {
              let value = match[0];
              if (kind === "network destination") {
                try { value = new URL(value).origin; } catch { continue; }
              }
              signals.push({ kind, value, path: rel, line: index + 1 });
              if (signals.length > 2000) throw new Error("Too many review indicators");
            }
          }
        }
      }
    } finally { handle.closeSync(); }
  }
  walk(root, 0);
  files.sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
  signals.sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
  return { files, signals, artifact: hash(JSON.stringify(files)) };
}

export async function createReview(target: string, blockAt = 76): Promise<Review> {
  if (!Number.isInteger(blockAt) || blockAt < 0 || blockAt > 100) throw new Error("block-at must be 0–100");
  const root = skillRoot(target);
  const before = snapshot(root);
  const assembly = assembleSkill(root);
  // Approving a skill should mean all of it was inspected, so review is strict.
  const scan = applyCoverage(await scanSkill(assembly.content, { skipCache: true, skillName: basename(root) }), assembly, "strict");
  const after = snapshot(root);
  if (before.artifact !== after.artifact) throw new Error("Skill changed during inspection; stage an unchanged copy and retry");
  return { schema: "clawvet-review-v1", engine: engineFingerprint(), policy: { version: POLICY_VERSION, blockAt }, ...before, scan };
}

export function canApprove(review: Review): boolean {
  return review.scan.coverage.complete && review.scan.status === "complete" &&
    review.scan.riskScore < review.policy.blockAt && !review.scan.findings.some((f) => f.disqualifying);
}

export function readDocument(path: string): unknown {
  return JSON.parse(boundedRead(resolve(path), 2 * 1024 * 1024).toString("utf8"));
}
function asReview(value: unknown): Review {
  const review = value as Review;
  if (!review || review.schema !== "clawvet-review-v1" || typeof review.engine !== "string" ||
      !Array.isArray(review.files) || !Array.isArray(review.signals) || !review.policy || !review.scan?.coverage ||
      !Array.isArray(review.scan.findings)) throw new Error("Invalid review document");
  return review;
}
export function readApproval(path: string): Approval {
  const approval = readDocument(path) as Approval;
  if (!approval || approval.schema !== "clawvet-approval-v1") throw new Error("Invalid approval receipt");
  asReview(approval.review);
  return approval;
}

function assertExternal(target: string, path: string) {
  const absolute = resolve(path);
  const physical = join(realpathSync(dirname(absolute)), basename(absolute));
  if (inside(skillRoot(target), physical)) throw new Error("Store review reports and approvals outside the skill directory");
}
export function writeDocument(target: string, path: string, value: unknown): void {
  assertExternal(target, path);
  // Never overwrite an existing approval or follow a destination symlink.
  writeFileSync(resolve(path), JSON.stringify(value, null, 2) + "\n", { flag: "wx", mode: 0o600 });
}

export function compareReviews(previous: Review, current: Review) {
  const old = new Map(previous.files.map((file) => [file.path, file]));
  const fresh = new Map(current.files.map((file) => [file.path, file]));
  const key = (signal: Signal) => JSON.stringify([signal.kind, signal.value, signal.path]);
  const priorSignals = new Set(previous.signals.map(key));
  return {
    added: current.files.filter((file) => !old.has(file.path)).map((file) => file.path),
    removed: previous.files.filter((file) => !fresh.has(file.path)).map((file) => file.path),
    changed: current.files.filter((file) => old.has(file.path) && JSON.stringify(file) !== JSON.stringify(old.get(file.path))).map((file) => file.path),
    newSignals: current.signals.filter((signal) => !priorSignals.has(key(signal))),
    engineChanged: previous.engine !== current.engine,
    policyChanged: JSON.stringify(previous.policy) !== JSON.stringify(current.policy),
  };
}

export async function approveReview(target: string, reportPath: string, output: string): Promise<Approval> {
  assertExternal(target, reportPath);
  const document = readDocument(reportPath) as { review?: unknown };
  const reviewed = asReview(document?.review);
  const fresh = await createReview(target, reviewed.policy.blockAt);
  // Compare the entire analysis too: editing the report to conceal a finding
  // cannot cause approval of a different result. No finding overrides here.
  if (JSON.stringify(fresh) !== JSON.stringify(reviewed)) throw new Error("Review no longer matches files, engine, policy, or analysis; generate a fresh report");
  if (!canApprove(fresh)) throw new Error("Incomplete or policy-blocked skills cannot be approved");
  const approval: Approval = { schema: "clawvet-approval-v1", approvedAt: new Date().toISOString(), review: fresh };
  writeDocument(target, output, approval);
  return approval;
}

export async function checkApproval(target: string, path: string, blockAt: number): Promise<void> {
  assertExternal(target, path);
  const approved = readApproval(path).review;
  const fresh = await createReview(target, blockAt);
  // Directory name is presentation metadata: a staged install may move roots.
  if (approved.engine !== fresh.engine || approved.artifact !== fresh.artifact ||
      JSON.stringify(approved.policy) !== JSON.stringify(fresh.policy) || !canApprove(fresh)) {
    throw new Error("Approval does not match the staged files, current scanner, or gate policy; review and approve again");
  }
}
