import { afterEach, describe, expect, it } from "vitest";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { assembleSkill } from "../../../packages/cli/src/assemble.js";
import { scanSkill } from "@clawvet/shared";

const ROOT = join(__dirname, "..", "..", "..");
const FIXTURES = join(ROOT, "packages/cli/test/fixtures");
const tempDirs: string[] = [];

function loadFixture(name: string): { dir: string; skillMd: string } {
  const dir = join(FIXTURES, name);
  return {
    dir,
    skillMd: readFileSync(join(dir, "SKILL.md"), "utf-8"),
  };
}

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

describe("CLI referenced-file assembly", () => {
  it("turns a cross-file payload miss into a finding", async () => {
    const { dir, skillMd } = loadFixture("split-payload");
    const bareResult = await scanSkill(skillMd);
    const assembledResult = await scanSkill(assembleSkill(dir, skillMd));

    expect(bareResult.findings).not.toEqual(
      expect.arrayContaining([
        expect.objectContaining({ title: "Known malicious IP" }),
      ])
    );
    expect(assembledResult.findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ title: "Known malicious IP" }),
        expect.objectContaining({ title: "Sensitive file access" }),
      ])
    );
  });

  it("does not introduce findings for a benign referenced sibling", async () => {
    const { dir, skillMd } = loadFixture("benign-reference");
    const bareResult = await scanSkill(skillMd);
    const assembledResult = await scanSkill(assembleSkill(dir, skillMd));

    expect(assembledResult.findings).toEqual(bareResult.findings);
  });

  it("ignores missing references without throwing", () => {
    const dir = mkdtempSync(join(tmpdir(), "clawvet-assembly-"));
    tempDirs.push(dir);
    const skillMd = "# Missing helper\n\nExecute `bash ./missing.sh`.\n";

    expect(assembleSkill(dir, skillMd)).toBe(skillMd);
  });

  it("includes referenced shallow files but skips unreferenced and binary files", () => {
    const dir = mkdtempSync(join(tmpdir(), "clawvet-assembly-"));
    tempDirs.push(dir);
    mkdirSync(join(dir, "scripts"));
    writeFileSync(join(dir, "scripts", "referenced.js"), "REFERENCED_CONTENT");
    writeFileSync(join(dir, "unreferenced.sh"), "UNREFERENCED_CONTENT");
    writeFileSync(join(dir, "binary.dat"), Buffer.from([0, 1, 2, 3]));
    const skillMd = [
      "# Helpers",
      "Execute `node scripts/referenced.js` and inspect binary.dat.",
    ].join("\n");

    const assembled = assembleSkill(dir, skillMd);

    expect(assembled).toContain(
      "# [clawvet] referenced file: scripts/referenced.js\nREFERENCED_CONTENT"
    );
    expect(assembled).not.toContain("UNREFERENCED_CONTENT");
    expect(assembled).not.toContain("# [clawvet] referenced file: binary.dat");
  });
});
