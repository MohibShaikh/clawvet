import { afterEach, describe, expect, it, vi } from "vitest";
import { mkdtempSync, mkdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { performance } from "node:perf_hooks";
import { calculateRiskScore, countFindings, getRiskGrade, type Finding, type ScanResult } from "@clawvet/shared";
import { applyBaseline, createBaseline, loadBaseline, SUPPRESSIBLE_COVERAGE_RULES } from "../../../packages/cli/src/suppress.js";
import { RULES, type RuleId } from "../../../packages/cli/src/policy.js";
import type { AssemblyIssue, AssemblyResult } from "../../../packages/cli/src/assemble.js";

vi.mock("node:fs", async (importOriginal) => ({ ...await importOriginal<typeof import("node:fs")>() }));

const roots: string[] = [];
afterEach(() => { vi.restoreAllMocks(); for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });
function fixture() {
  const root = mkdtempSync(join(tmpdir(), "clawvet-suppress-"));
  roots.push(root);
  const skillRoot = join(root, "skill");
  mkdirSync(skillRoot);
  writeFileSync(join(skillRoot, "SKILL.md"), "name: fixture\necho placeholder\n");
  writeFileSync(join(skillRoot, "later.sh"), "echo placeholder\n");
  const assembly: AssemblyResult = { content: "echo placeholder", coverage: { complete: true,
    files: [{ path: "SKILL.md", startLine: 1, endLine: 3 }, { path: "later.sh", startLine: 6, endLine: 8 }], issues: [], warnings: [] } };
  return { root, skillRoot, assembly, reason: "Reviewed inert fixture" };
}
function finding(index = 0, lineNumber = 2): Finding {
  return { title: `Rule ${index}`, category: "code_execution", severity: "critical", evidence: `echo placeholder ${index}`, description: "Fixture", analysisPass: "static", lineNumber };
}
function scan(findings: Finding[]): ScanResult {
  const riskScore = calculateRiskScore(findings);
  return { skillName: "fixture", skillSource: "local", status: "complete", findings,
    riskScore, riskGrade: getRiskGrade(riskScore), findingsCount: countFindings(findings), recommendation: "block" };
}
function issue(path = "later.sh", rule: AssemblyIssue["rule"] = "dynamic-loading"): AssemblyIssue {
  return { path, rule, reason: "Fixture gap" };
}

describe("suppression baselines", () => {
  it("round trips externally stored baselines and recomputes the clean score", () => {
    const f = fixture();
    const original = scan([finding(), finding(1, 7)]);
    const baseline = createBaseline(original, f.assembly, f);
    const path = join(f.root, "baseline.json");
    writeFileSync(path, JSON.stringify(baseline));
    const applied = applyBaseline(original, f.assembly, loadBaseline(path, f), f);
    expect(applied.result).toMatchObject({ findings: [], riskScore: 0, riskGrade: "A", recommendation: "approve", findingsCount: { critical: 0, high: 0, medium: 0, low: 0 } });
    expect(applied.suppressed.map(s => s.status)).toEqual(["suppressed", "suppressed"]);
    expect(original.findings).toHaveLength(2);
  });
  it("revives only entries bound to a modified file", () => {
    const f = fixture();
    const original = scan([finding(), finding(1, 7)]);
    const baseline = createBaseline(original, f.assembly, f);
    writeFileSync(join(f.skillRoot, "later.sh"), "echo changed placeholder\n");
    expect(applyBaseline(original, f.assembly, baseline, f).result.findings).toEqual([original.findings[1]]);
  });
  it("reports expiry without suppressing at the expiry boundary", () => {
    const f = fixture();
    const original = scan([finding()]);
    const baseline = createBaseline(original, f.assembly, { ...f, expiresAt: "2030-01-01T00:00:00Z" });
    expect(applyBaseline(original, f.assembly, baseline, { ...f, now: new Date("2029-12-31T23:59:59Z") }).result.findings).toEqual([]);
    const expired = applyBaseline(original, f.assembly, baseline, { ...f, now: new Date("2030-01-01T00:00:00Z") });
    expect(expired.result.findings).toHaveLength(1);
    expect(expired.suppressed[0]).toMatchObject({ status: "expired", reason: f.reason });
  });
  it("refuses internal baselines, symlinks, ancestor symlinks and oversized input", () => {
    const f = fixture();
    const baseline = createBaseline(scan([]), f.assembly, f);
    const path = join(f.root, "baseline.json");
    writeFileSync(path, JSON.stringify(baseline));
    const internal = join(f.skillRoot, "baseline.json");
    writeFileSync(internal, JSON.stringify(baseline));
    expect(() => loadBaseline(internal, f)).toThrow(/outside the skill root/);
    symlinkSync(path, join(f.root, "linked.json"));
    expect(() => loadBaseline(join(f.root, "linked.json"), f)).toThrow(/symlink/);
    symlinkSync(f.skillRoot, join(f.root, "alias"));
    expect(() => loadBaseline(join(f.root, "alias", "baseline.json"), f)).toThrow(/outside/);
    writeFileSync(path, " ".repeat(1024 * 1024 + 1));
    expect(() => loadBaseline(path, f)).toThrow(/size limit/);
  });
  it("never suppresses disqualifying findings or prohibited coverage rules", () => {
    const f = fixture();
    const original = scan([{ ...finding(), disqualifying: true }]);
    const prohibited = (Object.keys(RULES) as RuleId[]).filter(rule => !SUPPRESSIBLE_COVERAGE_RULES.includes(rule));
    // The audit's list: unpinnable targets and bundle-wide gaps stay prohibited.
    for (const rule of ["escape", "outside-document", "nesting-limit", "total-limit", "entry-limit", "depth-limit", "manifest-limit", "remote-manifest", "pipe-to-shell", "download-executed"]) {
      expect(prohibited).toContain(rule);
    }
    f.assembly.coverage.issues = prohibited.map(rule => issue("later.sh", rule));
    f.assembly.coverage.complete = false;
    const applied = applyBaseline(original, f.assembly, createBaseline(original, f.assembly, f), f);
    expect(applied.result.findings).toEqual(original.findings);
    expect(applied.result.recommendation).toBe("block");
    expect(applied.assembly.coverage.issues).toEqual(f.assembly.coverage.issues);
    expect(applied.suppressed).toEqual([]);
  });
  it("gives clear errors for malformed JSON and invalid schema fields", () => {
    const f = fixture();
    const path = join(f.root, "baseline.json");
    writeFileSync(path, "{broken");
    expect(() => loadBaseline(path, f)).toThrow(/Malformed baseline JSON/);
    const baseline = createBaseline(scan([finding()]), f.assembly, f);
    const bad = [null, { ...baseline, schema: "other" }, { ...baseline, extra: true },
      ...[{ reason: " " }, { reason: "x".repeat(501) }, { path: "../outside" }, { fileSha256: "no" },
        { expiresAt: "tomorrow" }, { kind: "coverage", rule: "invented" }, { extra: true }]
        .map(change => ({ ...baseline, entries: [{ ...baseline.entries[0], ...change }] }))];
    for (const value of bad) {
      writeFileSync(path, JSON.stringify(value));
      expect(() => loadBaseline(path, f)).toThrow(/Invalid baseline schema/);
    }
    expect(() => createBaseline(scan([]), f.assembly, { ...f, reason: "" })).toThrow(/reason/);
  });
  it.each([
    [["critical", "critical", "high", "low"], 78, "block"],
    [["critical", "critical", "high"], 75, "warn"],
    [["high", "medium", "medium"], 29, "warn"],
    [["high", "medium", "low"], 25, "approve"],
  ] as const)("recomputes recommendations for remaining severities %j", (severities, score, recommendation) => {
    const f = fixture();
    const accepted = finding(99);
    const original = scan([...severities.map((severity, i) => ({ ...finding(i), severity })), accepted]);
    const baseline = createBaseline(scan([accepted]), f.assembly, f);
    const applied = applyBaseline(original, f.assembly, baseline, f);
    expect(applied.result.riskScore).toBe(score);
    expect(applied.result.recommendation).toBe(recommendation);
  });
  it("recomputes completeness after filtering later-file issues and warnings", () => {
    const f = fixture();
    f.assembly.coverage.issues = [issue("SKILL.md"), issue("later.sh")];
    f.assembly.coverage.warnings = [issue("later.sh", "computed-command")];
    f.assembly.coverage.complete = false;
    const original = scan([]);
    const baseline = createBaseline(original, f.assembly, f);
    const partial = { ...baseline, entries: baseline.entries.filter(e => e.path === "later.sh") };
    const applied = applyBaseline(original, f.assembly, partial, f);
    expect(applied.assembly.coverage.complete).toBe(false);
    expect(applied.assembly.coverage.issues).toEqual([issue("SKILL.md")]);
    expect(applied.assembly.coverage.warnings).toEqual([]);
    expect(applyBaseline(original, f.assembly, baseline, f).assembly.coverage.complete).toBe(true);
  });
  it("revives later-file coverage entries when that file changes", () => {
    const f = fixture();
    f.assembly.coverage.issues = [issue()];
    f.assembly.coverage.complete = false;
    const baseline = createBaseline(scan([]), f.assembly, f);
    writeFileSync(join(f.skillRoot, "later.sh"), "echo modified placeholder\n");
    const applied = applyBaseline(scan([]), f.assembly, baseline, f);
    expect(applied.assembly.coverage.issues).toEqual(f.assembly.coverage.issues);
    expect(applied.assembly.coverage.complete).toBe(false);
  });
  it("does not let symlink replacement authorize suppression", () => {
    const f = fixture();
    const original = scan([finding(0, 7)]);
    const baseline = createBaseline(original, f.assembly, f);
    const target = join(f.root, "outside.sh");
    writeFileSync(target, "echo placeholder\n");
    rmSync(join(f.skillRoot, "later.sh"));
    symlinkSync(target, join(f.skillRoot, "later.sh"));
    expect(applyBaseline(original, f.assembly, baseline, f).result.findings).toEqual(original.findings);
  });
  it("applies the exact score boundaries", () => {
    const f = fixture();
    for (const [riskScore, recommendation] of [[76, "block"], [26, "warn"], [25, "approve"]] as const) {
      const findings = riskScore === 76
        ? [finding(0), finding(1), { ...finding(2), severity: "high" as const }, { ...finding(3), severity: "low" as const, confidence: 1 / 3 }]
        : [{ ...finding(), confidence: riskScore / 30 }];
      const original = scan([...findings, finding(99)]);
      const baseline = createBaseline(scan([finding(99)]), f.assembly, f);
      expect(applyBaseline(original, f.assembly, baseline, f).result).toMatchObject({ riskScore, recommendation });
    }
  });
  it("prefers live entries to expired duplicates in either order", () => {
    const f = fixture();
    const original = scan([finding()]);
    const baseline = createBaseline(original, f.assembly, f);
    const expired = { ...baseline.entries[0], expiresAt: "2000-01-01T00:00:00Z" };
    for (const entries of [[expired, baseline.entries[0]], [baseline.entries[0], expired]]) {
      expect(applyBaseline(original, f.assembly, { ...baseline, entries }, f).result.findings).toEqual([]);
    }
  });
  it("normalizes evidence whitespace without accepting a different rule or evidence", () => {
    const f = fixture();
    const original = scan([finding()]);
    const baseline = createBaseline(original, f.assembly, f);
    expect(applyBaseline(scan([{ ...finding(), evidence: " echo  placeholder 0 " }]), f.assembly, baseline, f).result.findings).toEqual([]);
    expect(applyBaseline(scan([{ ...finding(), evidence: "changed" }]), f.assembly, baseline, f).result.findings).toHaveLength(1);
  });
  it("measures processing latency and hashes each file once per call", () => {
    const f = fixture();
    f.assembly.coverage.files = [];
    const findings: Finding[] = [];
    for (let i = 0; i < 50; i++) {
      const path = i === 0 ? "SKILL.md" : `file-${i}.sh`;
      writeFileSync(join(f.skillRoot, path), "echo placeholder\n");
      f.assembly.coverage.files.push({ path, startLine: i * 4 + 1, endLine: i * 4 + 4 });
      for (let j = 0; j < 4; j++) findings.push(finding(i * 4 + j, i * 4 + j + 1));
    }
    const original = scan(findings);
    const baseline = createBaseline(original, f.assembly, f);
    let ioMs = 0;
    const counts = new Map<string, number>();
    for (const name of ["openSync", "readSync", "fstatSync", "closeSync", "realpathSync"] as const) {
      const implementation = fs[name] as (...args: unknown[]) => unknown;
      vi.spyOn(fs, name).mockImplementation(((...args: unknown[]) => {
        const start = performance.now();
        try {
          if (name === "openSync") counts.set(String(args[0]), (counts.get(String(args[0])) ?? 0) + 1);
          return implementation(...args);
        } finally { ioMs += performance.now() - start; }
      }) as never);
    }
    const measured: number[] = [];
    for (let run = 0; run < 30; run++) {
      ioMs = 0;
      counts.clear();
      const start = performance.now();
      const applied = applyBaseline(original, f.assembly, baseline, f);
      const processingMs = performance.now() - start - ioMs;
      expect(applied.result.findings).toHaveLength(0);
      expect([...counts.values()]).toEqual(Array(50).fill(1));
      if (run >= 10) measured.push(processingMs);
    }
    measured.sort((a, b) => a - b);
    console.log(`Measured applyBaseline processing median: ${measured[Math.floor(measured.length / 2)].toFixed(3)} ms (200 findings, 50 files; filesystem-call time excluded)`);
    // Measured about 2 to 4 ms alone. The bound catches an accidental quadratic
    // pass without failing when the full suite loads the machine.
    expect(measured[Math.floor(measured.length / 2)]).toBeLessThan(50);
  });
});
