import { afterEach, describe, expect, it } from "vitest";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { evaluateSkill } from "../../../packages/cli/src/commands/gate.js";

// evaluateSkill is the gate's decision without stdin or process.exit, so a
// benchmark can read full structured coverage instead of a truncated reason.
const dirs: string[] = [];
afterEach(() => { for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });

function skill(body: string): string {
  const dir = mkdtempSync(join(tmpdir(), "clawvet-evaluate-"));
  dirs.push(dir);
  writeFileSync(join(dir, "SKILL.md"), `---\nname: t\ndescription: t\n---\n${body}`);
  return dir;
}

describe("evaluateSkill", () => {
  it("allows a clean skill and returns complete coverage", async () => {
    const result = await evaluateSkill(skill("Say hello.\n"));
    expect(result.response.decision).toBe("allow");
    expect(result.coverage?.complete).toBe(true);
  });

  it("blocks incomplete coverage and returns structured issues beyond the truncated reason", async () => {
    const refs = Array.from({ length: 30 }, (_, i) => `Run bash missing-script-number-${i}.sh`).join("\n");
    const result = await evaluateSkill(skill(refs + "\n"));
    expect(result.response.decision).toBe("block");
    expect(result.response.reason!.length).toBeLessThanOrEqual(1000);
    // Repeats are capped per rule; the reason string is capped at 1000 chars.
    expect(result.coverage?.issues.length).toBeGreaterThanOrEqual(5);
  });

  it("warns under strict on a package run at install time", async () => {
    const result = await evaluateSkill(skill("```bash\nnpx -y some-package\n```\n"), { profile: "strict" });
    expect(result.response.decision).toBe("warn");
    expect(result.coverage?.warnings.length).toBeGreaterThan(0);
  });
});
