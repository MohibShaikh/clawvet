import { afterEach, describe, expect, it, vi } from "vitest";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { scanCommand } from "../../../packages/cli/src/commands/scan.js";
import { checkExecutablePermissions, dependencyVerdict, gateCommand } from "../../../packages/cli/src/commands/gate.js";
import { printScanResult, sanitizeTerminal } from "../../../packages/cli/src/output/terminal.js";
import { queryOsv } from "../../../packages/cli/src/osv.js";
import { watchCommand } from "../../../packages/cli/src/commands/watch.js";

const dirs: string[] = [];
const origCwd = process.cwd();
const temp = (prefix = "clawvet-0162-") => {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  dirs.push(dir);
  return dir;
};

afterEach(() => {
  process.chdir(origCwd);
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
  process.exitCode = undefined;
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe("0.16.2 CLI regressions", () => {
  it(".clawvetban blocks a skill even when SKILL.md has no YAML frontmatter", async () => {
    const workspace = temp();
    const skillDir = join(workspace, "banned-tool");
    mkdirSync(skillDir);
    writeFileSync(join(workspace, ".clawvetban"), "banned-tool\n");
    writeFileSync(join(skillDir, "SKILL.md"), "# No frontmatter\nJust plain markdown.\n");

    process.chdir(workspace);
    const exit = vi.spyOn(process, "exit").mockImplementation(((code?: number) => {
      throw new Error(`EXIT:${code}`);
    }) as never);
    const err = vi.spyOn(console, "error").mockImplementation(() => {});

    await expect(scanCommand(skillDir, { format: "json" })).rejects.toThrow("EXIT:1");
    expect(exit).toHaveBeenCalledWith(1);
    expect(err.mock.calls.flat().join("\n")).toContain("banned-tool");
  });

  it(".clawvetignore warns on stderr when inside the skill dir and never suppresses disqualifying IOCs", async () => {
    const skillDir = temp();
    writeFileSync(join(skillDir, "SKILL.md"), "---\nname: ioc-test\ndescription: Test.\n---\nPing 91.92.242.15\n");
    writeFileSync(join(skillDir, ".clawvetignore"), "Known malicious IP\ndata_exfiltration\n");

    process.chdir(skillDir);
    process.env.CLAWVET_TELEMETRY = "off";
    const logs: string[] = [];
    const errs: string[] = [];
    vi.spyOn(console, "log").mockImplementation((...args) => { logs.push(args.join(" ")); });
    vi.spyOn(console, "error").mockImplementation((...args) => { errs.push(args.join(" ")); });

    await scanCommand(".", { format: "json" });
    const parsed = JSON.parse(logs.join("\n"));
    expect(parsed.findings.some((f: { disqualifying?: boolean }) => f.disqualifying)).toBe(true);
    expect(parsed.recommendation).toBe("block");
    expect(errs.join("\n")).toContain("inside the scanned skill directory");
  });

  it("sanitizeTerminal and printScanResult strip ANSI/OSC/CR sequences and show per-file path:line", () => {
    const dirty = "safe\x1b[31mred\x1b[0m\x1b]52;c;YWJj\x07\rFAKE APPROVE";
    const clean = sanitizeTerminal(dirty);
    expect(clean).not.toMatch(/[\x1b\x07\r]/);
    expect(clean).toContain("safered");
    expect(clean).toContain("FAKE APPROVE");

    const logs: string[] = [];
    vi.spyOn(console, "log").mockImplementation((...args) => { logs.push(args.join(" ")); });
    printScanResult({
      skillName: "demo\x1b]0;pwned\x07",
      skillVersion: "1.0.0",
      skillSource: "local",
      status: "complete",
      riskScore: 40,
      riskGrade: "C",
      findingsCount: { critical: 0, high: 1, medium: 0, low: 0 },
      recommendation: "warn",
      coverage: {
        complete: true,
        files: [
          { path: "SKILL.md", startLine: 1, endLine: 10 },
          { path: "scripts/run.sh", startLine: 13, endLine: 20 },
        ],
        issues: [],
        warnings: [],
      },
      findings: [{
        category: "credential_theft",
        severity: "high",
        title: "Sensitive file access",
        description: "Reads secret",
        evidence: "cat ~/.ssh/id_rsa\x1b[2K\rclean",
        lineNumber: 15,
        analysisPass: "static",
      }],
    });
    const output = logs.join("\n");
    expect(output).not.toContain("\x1b]0;pwned");
    expect(output).not.toContain("\x1b[2K");
    expect(output).toContain("Location: scripts/run.sh:3");
  });

  it("checkExecutablePermissions flags group/world-writable paths on POSIX", () => {
    if (process.platform === "win32") return;
    const base = temp();
    const safeDir = join(base, "safe");
    const badDir = join(base, "writable");
    mkdirSync(safeDir, { mode: 0o700 });
    mkdirSync(badDir, { mode: 0o777 });
    chmodSync(safeDir, 0o700);
    chmodSync(badDir, 0o777);
    const badFile = join(badDir, "script.js");
    writeFileSync(badFile, "");
    chmodSync(badFile, 0o644);
    const flagged = checkExecutablePermissions([badFile]);
    expect(flagged).toContain(badDir);
    expect(flagged).not.toContain(badFile);
  });

  it("gate --print-config --semantic keeps stdout valid JSON and warns on stderr when no LLM key is set", async () => {
    let out = "";
    let err = "";
    vi.spyOn(process.stdout, "write").mockImplementation((chunk: string | Uint8Array) => { out += String(chunk); return true; });
    vi.spyOn(process.stderr, "write").mockImplementation((chunk: string | Uint8Array) => { err += String(chunk); return true; });
    vi.stubEnv("ANTHROPIC_API_KEY", "");
    vi.stubEnv("OPENAI_API_KEY", "");
    vi.stubEnv("CLAWVET_LLM_API_KEY", "");
    vi.stubEnv("CLAWVET_LLM_PROVIDER", "");
    await gateCommand({ printConfig: true, semantic: true });
    expect(() => JSON.parse(out)).not.toThrow();
    expect(err).toContain("--semantic requires an LLM API key");
  });

  it("dependencyVerdict preserves an existing warn reason when adding an unpinned download warning", () => {
    const existing = { protocolVersion: 1, decision: "warn" as const, reason: "ClawVet graded \"demo\" C (risk 35/100)." };
    const next = dependencyVerdict(existing, { kind: "download", url: "https://example.invalid/tool.tar.gz" });
    expect(next.decision).toBe("warn");
    expect(next.reason).toContain("ClawVet graded \"demo\" C (risk 35/100).");
    expect(next.reason).toContain("not pinned by sha256");
  });

  it("queryOsv does not emit unhandledRejection when its deadline fires between awaits", async () => {
    const unhandled: unknown[] = [];
    const onUnhandled = (reason: unknown) => { unhandled.push(reason); };
    process.on("unhandledRejection", onUnhandled);
    try {
      const fetchImpl = vi.fn<typeof fetch>(async () => {
        await new Promise((r) => setTimeout(r, 30));
        return new Response(JSON.stringify({ results: [{ vulns: [] }] }), { status: 200 });
      });
      const res = await queryOsv([{ name: "pkg", ecosystem: "npm", version: "1.0.0", path: "package.json", line: 1 }], { timeoutMs: 5, fetchImpl });
      await new Promise((r) => setTimeout(r, 40));
      expect(res.errors.join()).toMatch(/deadline/);
      expect(unhandled).toEqual([]);
    } finally {
      process.off("unhandledRejection", onUnhandled);
    }
  });

  it("watchCommand honors --threshold 0 instead of falling back to 50", async () => {
    const logs: string[] = [];
    vi.spyOn(console, "log").mockImplementation((...args) => { logs.push(args.join(" ")); });
    vi.spyOn(process, "exit").mockImplementation(((code?: number) => {
      throw new Error(`EXIT:${code}`);
    }) as never);
    await expect(watchCommand({ threshold: 0, dir: join(temp(), "does-not-exist") })).rejects.toThrow("EXIT:1");
    expect(logs.join("\n")).toContain("threshold: 0");
  });
});
