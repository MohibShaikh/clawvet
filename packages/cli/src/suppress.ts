import { createHash } from "node:crypto";
import { closeSync, constants, fstatSync, lstatSync, openSync, readdirSync, readSync, realpathSync } from "node:fs";
import { basename, isAbsolute, join, relative, resolve, sep } from "node:path";
import { rescore, type ScanResult } from "@clawvet/shared";
import { ASSEMBLY_LIMITS, type AssemblyIssue, type AssemblyResult } from "./assemble.js";
import { RULES, type RuleId } from "./policy.js";

// An allowlist, not a denylist, so a rule added to policy.ts is not acceptable
// until someone decides it is. Each listed gap is pinned by the hash of the file
// it comes from: the operator read that file and accepts what it does.
// - missing-file: the bundle cannot run a file it does not ship; if the file
//   appears later the gap closes and the file is inspected.
// - binary, file-limit, unreadable, not-regular-file: the file's own bytes are
//   hashed, so any change revives the gap.
// - eval, process and the dynamic-* rules: the code that computes the target is
//   in the pinned file.
// - the review-level ("ask") rules, which only ask an operator to look.
// Left out: anything whose behaviour depends on bytes no hash covers (downloads
// run or followed, pipes to a shell, remote code, escapes outside the skill,
// outside documents, encoded payloads, decoys, symlinks, the bundle-wide limits,
// a remote manifest), and anything that is an attack shape on its own.
export const SUPPRESSIBLE_COVERAGE_RULES: readonly RuleId[] = Object.freeze([
  "missing-file", "binary", "file-limit", "unreadable", "not-regular-file",
  "eval", "process", "dynamic-module", "dynamic-loading", "python-download",
  "dynamic-target", "computed-command", "download-installer", "download-unknown",
  "download-destination", "fetch-and-run-package", "install-from-url", "trusted-installer",
]);
const acceptable = new Set<string>(SUPPRESSIBLE_COVERAGE_RULES);
const BASELINE_LIMIT = 1024 * 1024;
const hash = (value: string | Buffer) => createHash("sha256").update(value).digest("hex");
export interface BaselineEntry {
  kind: "finding" | "coverage";
  rule: string;
  path: string;
  fingerprint: string;
  fileSha256: string;
  reason: string;
  createdAt: string;
  expiresAt?: string;
}
export interface Baseline {
  schema: "clawvet-baseline-v1";
  skill: { name: string; sha256: string };
  entries: BaselineEntry[];
}
export interface SuppressedItem extends BaselineEntry {
  status: "suppressed" | "expired";
}
interface Options { skillRoot: string }
function inside(root: string, path: string): boolean {
  const rel = relative(root, path);
  return rel === "" || (rel !== ".." && !rel.startsWith(`..${sep}`) && !isAbsolute(rel));
}
function boundedRead(path: string, max: number): Buffer {
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile() || !(stat.mode & 0o444)) throw new Error("Not a readable regular file");
    if (stat.size > max) throw new Error("File exceeds size limit");
    const buffer = Buffer.alloc(Math.min(stat.size + 1, max + 1));
    let size = 0;
    while (size < buffer.length) {
      const count = readSync(fd, buffer, size, buffer.length - size, null);
      if (!count) break;
      size += count;
    }
    if (size > stat.size || size > max) throw new Error("File changed or exceeds size limit");
    return buffer.subarray(0, size);
  } finally { closeSync(fd); }
}
function fileHashes(root: string) {
  const cache = new Map<string, string | undefined>();
  return (path: string): string | undefined => {
    if (!cache.has(path)) {
      let digest: string | undefined;
      try {
        const absolute = resolve(root, path);
        if (inside(root, absolute) && realpathSync(absolute) === absolute) {
          digest = hash(boundedRead(absolute, ASSEMBLY_LIMITS.totalBytes));
        }
      } catch { /* Unreadable or unsafe files cannot authorize suppression. */ }
      cache.set(path, digest);
    }
    return cache.get(path);
  };
}
const normalize = (value: string) => value.replace(/\s+/g, " ").trim();
const fingerprint = (kind: string, rule: string, path: string, evidence: string) =>
  hash(JSON.stringify([kind, rule, path, normalize(evidence)]));
function candidates(scan: ScanResult, assembly: AssemblyResult) {
  // Index once so findings do not repeatedly search all source-file ranges.
  const lines = new Map<number, string>();
  for (const file of assembly.coverage.files) {
    for (let line = file.startLine; line <= file.endLine; line++) lines.set(line, file.path);
  }
  // A bare SKILL.md scan has no file map; every located line is SKILL.md.
  const bare = assembly.coverage.files.length === 0;
  const findings = scan.findings.map(f => {
    const located = f.lineNumber ? (lines.get(f.lineNumber) ?? (bare ? "SKILL.md" : undefined)) : undefined;
    const path = located ?? "SKILL.md";
    // An unlocated finding cannot be pinned to the bytes that produced it, so it
    // is never accepted: binding it to SKILL.md would let the real source change.
    return { kind: "finding" as const, rule: f.title, path,
      fingerprint: fingerprint("finding", f.title, path, f.evidence ?? ""), allowed: !f.disqualifying && !!located };
  });
  const issue = (i: AssemblyIssue) => {
    // Pinned to the file the gap comes from: the referencing file for a missing
    // or escaping target, the file itself for an unreadable or oversized one.
    const path = i.source ?? i.path;
    return { kind: "coverage" as const, rule: i.rule, path,
      fingerprint: fingerprint("coverage", i.rule, path, i.path), allowed: acceptable.has(i.rule) };
  };
  return { findings, issues: assembly.coverage.issues.map(issue), warnings: assembly.coverage.warnings.map(issue) };
}
function validDate(value: unknown): value is string {
  return typeof value === "string" && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)$/.test(value) && Number.isFinite(Date.parse(value));
}
function validate(value: unknown): asserts value is Baseline {
  const fail = (detail: string): never => { throw new Error(`Invalid baseline schema: ${detail}`); };
  const record = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);
  const keys = (v: Record<string, unknown>, allowed: string[]) => Object.keys(v).every(k => allowed.includes(k));
  const digest = (v: unknown) => typeof v === "string" && /^[a-f0-9]{64}$/.test(v);
  if (!record(value) || !keys(value, ["schema", "skill", "entries"]) || value.schema !== "clawvet-baseline-v1") fail("expected clawvet-baseline-v1");
  const b = value as Record<string, unknown>;
  if (!record(b.skill) || !keys(b.skill, ["name", "sha256"]) || typeof b.skill.name !== "string" || !b.skill.name.trim() || !digest(b.skill.sha256)) fail("invalid skill");
  if (!Array.isArray(b.entries)) fail("entries must be an array");
  for (const e of b.entries as unknown[]) {
    if (!record(e) || !keys(e, ["kind", "rule", "path", "fingerprint", "fileSha256", "reason", "createdAt", "expiresAt"])) fail("invalid entry fields");
    const entry = e as Record<string, unknown>;
    if (entry.kind !== "finding" && entry.kind !== "coverage") fail("invalid entry kind");
    if (typeof entry.rule !== "string" || !entry.rule.trim() || (entry.kind === "coverage" && !Object.hasOwn(RULES, entry.rule))) fail("invalid rule");
    if (typeof entry.path !== "string" || !entry.path || entry.path.includes("\\") || entry.path.includes("\0") || isAbsolute(entry.path) || entry.path.split("/").some(p => !p || p === "." || p === "..")) fail("path must be inside the skill");
    if (!digest(entry.fingerprint) || !digest(entry.fileSha256)) fail("invalid sha256");
    if (typeof entry.reason !== "string" || !entry.reason.trim() || entry.reason.length > 500) fail("reason must contain 1–500 characters");
    if (!validDate(entry.createdAt) || (entry.expiresAt !== undefined && !validDate(entry.expiresAt))) fail("invalid ISO date");
  }
}
export function createBaseline(scan: ScanResult, assembly: AssemblyResult, options: Options & { reason: string; expiresAt?: string }): Baseline {
  if (typeof options.reason !== "string" || !options.reason.trim() || options.reason.length > 500) throw new Error("Baseline reason must contain 1–500 characters");
  if (options.expiresAt !== undefined && !validDate(options.expiresAt)) throw new Error("Invalid baseline expiry ISO date");
  const root = realpathSync(options.skillRoot);
  const digest = fileHashes(root);
  const manifest = digest("SKILL.md");
  if (!manifest) throw new Error("Cannot baseline unreadable SKILL.md");
  const all = candidates(scan, assembly);
  const entries: BaselineEntry[] = [];
  const createdAt = new Date().toISOString();
  for (const item of [...all.findings, ...all.issues, ...all.warnings]) {
    const fileSha256 = digest(item.path);
    if (!fileSha256) throw new Error(`Cannot baseline unreadable file: ${item.path}`);
    const { allowed: _allowed, ...identity } = item;
    entries.push({ ...identity, fileSha256, reason: options.reason, createdAt,
      ...(options.expiresAt !== undefined ? { expiresAt: options.expiresAt } : {}) });
  }
  const baseline: Baseline = { schema: "clawvet-baseline-v1", skill: { name: scan.skillName || basename(root), sha256: manifest }, entries };
  validate(baseline);
  return baseline;
}
export function loadBaseline(path: string, options: Options): Baseline {
  try {
    const root = realpathSync(options.skillRoot);
    const absolute = resolve(path);
    const physical = realpathSync(absolute);
    if (inside(resolve(options.skillRoot), absolute) || inside(root, physical)) throw new Error("Baseline must be outside the skill root");
    if (physical !== absolute) throw new Error("Baseline path must not traverse symlinks");
    let value: unknown;
    try { value = JSON.parse(boundedRead(absolute, BASELINE_LIMIT).toString("utf8")); }
    catch (error) {
      if (error instanceof SyntaxError) throw new Error("Malformed baseline JSON");
      throw error;
    }
    validate(value);
    return value;
  } catch (error) { throw new Error(`Cannot load baseline: ${(error as Error).message}`); }
}
type Candidate = ReturnType<typeof candidates>["findings"][number] | ReturnType<typeof candidates>["issues"][number];

// One matcher per baseline and skill. Entries match on kind, rule, path,
// fingerprint and the file's current hash, so editing the file revives them.
function matcher(baseline: Baseline, options: Options & { now?: Date }) {
  validate(baseline);
  const now = (options.now ?? new Date()).getTime();
  if (!Number.isFinite(now)) throw new Error("Invalid baseline comparison time");
  const digest = fileHashes(realpathSync(options.skillRoot));
  const key = (entry: Pick<BaselineEntry, "kind" | "rule" | "path" | "fingerprint" | "fileSha256">) =>
    JSON.stringify([entry.kind, entry.rule, entry.path, entry.fingerprint, entry.fileSha256]);
  const expired = (entry: BaselineEntry) => !!entry.expiresAt && Date.parse(entry.expiresAt) <= now;
  const entries = new Map<string, BaselineEntry>();
  const fingerprints = new Set<string>();
  // Collapse duplicates once, preferring a live acceptance over an expired one.
  for (const entry of baseline.entries) {
    const identity = key(entry);
    if (!entries.has(identity) || !expired(entry)) entries.set(identity, entry);
    fingerprints.add(entry.fingerprint);
  }
  const suppressed: SuppressedItem[] = [];
  const keep = (item: Candidate) => {
    if (!item.allowed || !fingerprints.has(item.fingerprint)) return true;
    const fileSha256 = digest(item.path);
    if (!fileSha256) return true;
    const entry = entries.get(key({ ...item, fileSha256 }));
    if (!entry) return true;
    const status = expired(entry) ? "expired" : "suppressed";
    suppressed.push({ ...entry, status });
    return status === "expired";
  };
  return { keep, suppressed };
}

const NO_FINDINGS = { findings: [] } as unknown as ScanResult;

/**
 * Coverage phase. The gate decides coverage blocks before it scans, so accepted
 * coverage gaps must be removed first, or a suppressed gap still blocks.
 */
export function suppressCoverage(assembly: AssemblyResult, baseline: Baseline, options: Options & { now?: Date }): { assembly: AssemblyResult; suppressed: SuppressedItem[] } {
  const { keep, suppressed } = matcher(baseline, options);
  const all = candidates(NO_FINDINGS, assembly);
  const issues = assembly.coverage.issues.filter((_, i) => keep(all.issues[i]));
  const warnings = assembly.coverage.warnings.filter((_, i) => keep(all.warnings[i]));
  return { assembly: { ...assembly, coverage: { ...assembly.coverage, issues, warnings, complete: issues.length === 0 } }, suppressed };
}

/** Findings phase: accepted findings are removed and the result is rescored. */
export function suppressFindings(scan: ScanResult, assembly: AssemblyResult, baseline: Baseline, options: Options & { now?: Date }): { result: ScanResult; suppressed: SuppressedItem[] } {
  const { keep, suppressed } = matcher(baseline, options);
  const all = candidates(scan, assembly);
  const findings = scan.findings.filter((_, i) => keep(all.findings[i]));
  return { result: rescore(scan, findings), suppressed };
}

export function applyBaseline(scan: ScanResult, assembly: AssemblyResult, baseline: Baseline, options: Options & { now?: Date }): { result: ScanResult; assembly: AssemblyResult; suppressed: SuppressedItem[] } {
  const coverage = suppressCoverage(assembly, baseline, options);
  const findings = suppressFindings(scan, assembly, baseline, options);
  const result = findings.result;
  // Callers apply their coverage profile to this fresh score, after suppression.
  if ("coverage" in result) Object.assign(result, { coverage: coverage.assembly.coverage });
  return { result, assembly: coverage.assembly, suppressed: [...coverage.suppressed, ...findings.suppressed] };
}

/**
 * A file, or a directory of baselines merged into one. The gate's config names
 * one path for every install. Merging is safe because an entry only matches a
 * file at the same path with the same bytes, whichever skill it was written for.
 */
export function loadBaselines(path: string, options: Options): Baseline {
  let directory = false;
  try { directory = lstatSync(path).isDirectory(); } catch { /* loadBaseline reports it. */ }
  if (!directory) return loadBaseline(path, options);
  const root = realpathSync(options.skillRoot);
  const absolute = resolve(path);
  if (inside(resolve(options.skillRoot), absolute) || inside(root, realpathSync(absolute))) {
    throw new Error("Cannot load baseline: Baseline must be outside the skill root");
  }
  const files = readdirSync(absolute).filter((name) => name.endsWith(".json")).sort();
  if (files.length > 1000) throw new Error("Cannot load baseline: more than 1000 baselines in directory");
  const baselines = files.map((name) => loadBaseline(join(absolute, name), options));
  if (!baselines.length) throw new Error("Cannot load baseline: no .json baselines in directory");
  return { schema: "clawvet-baseline-v1", skill: baselines[0].skill, entries: baselines.flatMap((b) => b.entries) };
}
