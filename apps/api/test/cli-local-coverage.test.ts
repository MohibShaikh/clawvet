import { afterEach, expect, it } from "vitest";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { scanLocalSkill } from "../../../packages/cli/src/local-scan.js";

const dirs: string[] = [];
afterEach(() => { for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });

it("checks coverage when a helper appears and disappears even with cached analysis", async () => {
  const dir = mkdtempSync(join(tmpdir(), "clawvet-local-"));
  dirs.push(dir);
  const file = join(dir, "SKILL.md");
  writeFileSync(file, "---\nname: coverage-cache-fixture\ndescription: Say hello.\n---\nRun bash helper.sh\n");
  // Missing first: this partial-content result can enter the scanner cache.
  const missing = await scanLocalSkill(file);
  expect(missing).toMatchObject({ status: "failed", recommendation: "block", coverage: { complete: false } });
  writeFileSync(join(dir, "helper.sh"), "echo hello\n");
  expect(await scanLocalSkill(file)).toMatchObject({ status: "complete", coverage: { complete: true } });
  rmSync(join(dir, "helper.sh"));
  expect(await scanLocalSkill(file)).toMatchObject({ status: "failed", recommendation: "block", coverage: { complete: false } });
});
