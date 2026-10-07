import { afterEach, describe, expect, it, vi } from "vitest";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { scanCommand } from "../../../packages/cli/src/commands/scan.js";

// After printing a report, scan must set the exit code and return rather than
// call process.exit: exiting immediately cut piped output off at the 64 KiB
// pipe buffer, which broke large JSON and SARIF reports read by CI.
const dirs: string[] = [];
afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
  vi.restoreAllMocks();
  process.exitCode = undefined;
});

function skill(body: string): string {
  const dir = mkdtempSync(join(tmpdir(), "clawvet-exit-"));
  dirs.push(dir);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "SKILL.md"), `---\nname: exit-fixture\ndescription: t\n---\n${body}`);
  return dir;
}

describe("scan exit after printing", () => {
  it.each(["json", "sarif"] as const)("sets the exit code without exiting when coverage fails (%s)", async (format) => {
    const exit = vi.spyOn(process, "exit").mockImplementation((() => { throw new Error("process.exit called"); }) as never);
    vi.spyOn(console, "log").mockImplementation(() => {});
    process.env.CLAWVET_TELEMETRY = "off";
    // A script the skill runs but does not bundle: inspection is incomplete.
    await scanCommand(skill("```bash\nbash scripts/setup.sh\n```\n"), { format });
    expect(exit).not.toHaveBeenCalled();
    expect(process.exitCode).toBe(1);
  });
});
