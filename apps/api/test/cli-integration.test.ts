import { describe, it, expect } from "vitest";
import { exec } from "node:child_process";
import { promisify } from "node:util";
import { join } from "node:path";
import { readFileSync } from "node:fs";

const execAsync = promisify(exec);

const ROOT = join(__dirname, "..", "..", "..");
const CLI = `npx tsx ${join(ROOT, "packages/cli/src/index.ts")}`;
const FIXTURES = join(__dirname, "fixtures");
const CLI_VERSION = JSON.parse(
  readFileSync(join(ROOT, "packages/cli/package.json"), "utf-8")
).version;

// Async so the spawned CLI process doesn't block the Vitest worker's event
// loop. `execSync` blocks for ~5s per call (and ~60s in the multi-run test),
// which starves the worker's heartbeat RPC and fails the run with a
// "Timeout calling onTaskUpdate" error even when every assertion passes.
async function run(args: string): Promise<{ stdout: string; exitCode: number }> {
  try {
    const { stdout } = await execAsync(`${CLI} ${args}`, {
      cwd: ROOT,
      encoding: "utf-8",
      env: { ...process.env, NODE_NO_WARNINGS: "1" },
    });
    return { stdout, exitCode: 0 };
  } catch (err: any) {
    return { stdout: err.stdout || "", exitCode: err.code ?? 1 };
  }
}

// Each test spawns a cold `npx tsx` CLI process, which on Windows/CI takes
// ~5s for a scan — right at Vitest's 5000ms default. Give the suite headroom
// so these integration tests don't flake on timing alone.
describe("CLI integration", { timeout: 30000 }, () => {
  it("clawvet --version prints version", async () => {
    const { stdout, exitCode } = await run("--version");
    expect(exitCode).toBe(0);
    expect(stdout.trim()).toBe(CLI_VERSION);
  });

  it("clawvet --help shows usage", async () => {
    const { stdout, exitCode } = await run("--help");
    expect(exitCode).toBe(0);
    expect(stdout).toContain("scan");
    expect(stdout).toContain("audit");
    expect(stdout).toContain("watch");
  });

  it("clawvet scan with nonexistent path exits 1", async () => {
    const { exitCode } = await run("scan /nonexistent/path/to/skill");
    expect(exitCode).toBe(1);
  });

  it("clawvet scan benign-weather --format json produces valid JSON", async () => {
    const { stdout, exitCode } = await run(
      `scan ${join(FIXTURES, "benign-weather")} --format json`
    );
    expect(exitCode).toBe(0);
    const result = JSON.parse(stdout);
    expect(result.skillName).toBe("weather-forecast");
    expect(result.riskGrade).toBe("A");
    expect(result.status).toBe("complete");
    expect(Array.isArray(result.findings)).toBe(true);
  });

  it("clawvet scan malicious-stealer --format json --fail-on high exits 1", async () => {
    const { stdout, exitCode } = await run(
      `scan ${join(FIXTURES, "malicious-stealer")} --format json --fail-on high`
    );
    expect(exitCode).toBe(1);
    const result = JSON.parse(stdout);
    expect(result.riskScore).toBe(100);
  });

  it("clawvet scan benign-weather --fail-on critical exits 0", async () => {
    const { stdout, exitCode } = await run(
      `scan ${join(FIXTURES, "benign-weather")} --format json --fail-on critical`
    );
    expect(exitCode).toBe(0);
  });

  it("clawvet scan on a direct SKILL.md file path works", async () => {
    const { stdout, exitCode } = await run(
      `scan ${join(FIXTURES, "benign-weather", "SKILL.md")} --format json`
    );
    expect(exitCode).toBe(0);
    const result = JSON.parse(stdout);
    expect(result.skillName).toBe("weather-forecast");
  });

  it("all 6 fixtures produce consistent results across runs", { timeout: 60000 }, async () => {
    const fixtures = [
      "benign-weather",
      "malicious-stealer",
      "sneaky-injection",
      "typosquat-todoistt",
      "leaky-creds",
      "obfuscated-payload",
    ];

    for (const fixture of fixtures) {
      const r1 = await run(`scan ${join(FIXTURES, fixture)} --format json`);
      const r2 = await run(`scan ${join(FIXTURES, fixture)} --format json`);

      const result1 = JSON.parse(r1.stdout);
      const result2 = JSON.parse(r2.stdout);

      expect(result1.riskScore).toBe(result2.riskScore);
      expect(result1.riskGrade).toBe(result2.riskGrade);
      expect(result1.findings.length).toBe(result2.findings.length);
    }
  });

  it("terminal output contains expected sections", async () => {
    const { stdout, exitCode } = await run(
      `scan ${join(FIXTURES, "malicious-stealer")}`
    );
    expect(exitCode).toBe(0);
    expect(stdout).toContain("ClawVet Scan Report");
    expect(stdout).toContain("productivity-boost");
    expect(stdout).toContain("Risk Score:");
    expect(stdout).toContain("Findings:");
    expect(stdout).toContain("Recommendation:");
    expect(stdout).toContain("BLOCK");
  });
});
