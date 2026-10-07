import { describe, it, expect, vi, beforeEach } from "vitest";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

const scanSkillMock = vi.fn(async () => ({
  skillName: "test-skill",
  status: "complete",
  riskScore: 0,
  riskGrade: "A",
  findingsCount: { critical: 0, high: 0, medium: 0, low: 0 },
  findings: [],
  recommendation: "approve",
}));

vi.mock("@clawvet/shared", () => ({
  scanSkill: scanSkillMock,
}));

describe("CLI semantic flag wiring", () => {
  beforeEach(() => {
    scanSkillMock.mockClear();
  });

  it("refuses --semantic without calling scanSkill (semantic analysis is API-only)", async () => {
    const { scanCommand } = await import("../../../packages/cli/src/commands/scan.ts");

    const dir = mkdtempSync(join(tmpdir(), "clawvet-semantic-"));
    const skillPath = join(dir, "SKILL.md");
    writeFileSync(skillPath, "---\nname: test\ndescription: test\n---\n");

    try {
      await scanCommand(skillPath, { format: "json", semantic: true });
      expect(process.exitCode).toBe(1);
      expect(scanSkillMock).not.toHaveBeenCalled();
    } finally {
      rmSync(dir, { recursive: true, force: true });
      process.exitCode = 0;
    }
  });

  it("assembles referenced files when the scan target is a folder", async () => {
    const { scanCommand } = await import("../../../packages/cli/src/commands/scan.ts");

    const dir = mkdtempSync(join(tmpdir(), "clawvet-assembly-wiring-"));
    writeFileSync(
      join(dir, "SKILL.md"),
      "---\nname: test\ndescription: test\n---\n\nExecute `bash ./setup.sh`.\n"
    );
    writeFileSync(join(dir, "setup.sh"), "REFERENCED_FILE_CONTENT\n");

    try {
      await scanCommand(dir, { format: "json" });
      expect(scanSkillMock).toHaveBeenCalledTimes(1);
      expect(scanSkillMock).toHaveBeenCalledWith(
        expect.stringContaining(
          "# [clawvet] referenced file: setup.sh\nREFERENCED_FILE_CONTENT"
        ),
        expect.any(Object)
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
