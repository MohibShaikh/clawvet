import { afterEach, describe, expect, it } from "vitest";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

// scripts/pre-commit.sh turns pre-commit's `args:` plus file names into one
// `clawvet scan` per skill. A stub npx records where it ran and then runs the
// command after `--`, with a stub clawvet that records where the scan ran.
const HOOK = resolve(dirname(fileURLToPath(import.meta.url)), "../../../scripts/pre-commit.sh");
const HOOK_REPO = resolve(dirname(HOOK), "..");
const VERSION = JSON.parse(readFileSync(join(HOOK_REPO, "packages/cli/package.json"), "utf8")).version;
const dirs: string[] = [];
afterEach(() => { for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });

function run(args: string[], options: { files?: string[]; npxExit?: number } = {}) {
  const repo = realpathSync(mkdtempSync(join(tmpdir(), "clawvet-hook-")));
  dirs.push(repo);
  const files = options.files ?? ["skills/a/SKILL.md", "skills/a/scripts/run.sh", "skills/b/SKILL.md", "notes/readme.txt"];
  for (const file of files) {
    mkdirSync(dirname(join(repo, file)), { recursive: true });
    writeFileSync(join(repo, file), "placeholder\n");
  }
  const log = join(repo, "npx.log");
  mkdirSync(join(repo, "bin"));
  // npx: note the install directory, drop its own options, run the command.
  writeFileSync(join(repo, "bin", "npx"), `#!/bin/sh\necho "$PWD" > "${log}.npx"\nwhile [ "$1" != "--" ]; do shift; done; shift\nexec "$@"\n`);
  writeFileSync(join(repo, "bin", "clawvet"), `#!/bin/sh\necho "$PWD|$*" >> "${log}"\nexit ${options.npxExit ?? 0}\n`);
  chmodSync(join(repo, "bin", "npx"), 0o755);
  chmodSync(join(repo, "bin", "clawvet"), 0o755);
  const result = spawnSync("bash", [HOOK, ...args], { cwd: repo, env: { ...process.env, PATH: `${join(repo, "bin")}:${process.env.PATH}` } });
  let lines: string[] = [];
  try { lines = readFileSync(log, "utf8").trim().split("\n"); } catch { /* clawvet never ran */ }
  const calls = lines.map((line) => {
    const [cwd, command] = line.split("|");
    return { cwd, command };
  });
  let npxCwd: string | undefined;
  try { npxCwd = readFileSync(`${log}.npx`, "utf8").trim(); } catch { /* npx never ran */ }
  return { status: result.status, calls, npxCwd, repo, commands: calls.map((c) => c.command) };
}

describe("pre-commit hook", () => {
  it("scans each touched skill once and skips files outside any skill", () => {
    expect(run(["skills/a/SKILL.md", "skills/a/scripts/run.sh", "skills/b/SKILL.md", "notes/readme.txt"]).commands)
      .toEqual(["scan --fail-on high -- skills/a", "scan --fail-on high -- skills/b"]);
  });

  it.each([
    [["--fail-on", "medium"], "scan --fail-on medium -- skills/a"],
    [["--fail-on=critical"], "scan --fail-on critical -- skills/a"],
    [["--strict"], "scan --strict --fail-on high -- skills/a"],
    [["--format", "json", "--strict"], "scan --format json --strict --fail-on high -- skills/a"],
    [["--baseline", "base.json", "--reason", "reviewed", "--expires", "2027-01-01T00:00:00Z"], "scan --baseline base.json --reason reviewed --expires 2027-01-01T00:00:00Z --fail-on high -- skills/a"],
  ])("passes args %j through and keeps a threshold", (args, expected) => {
    expect(run([...args, "skills/a/SKILL.md"]).commands).toEqual([expected]);
  });

  it.each(["--help", "--version", "--fail-on=low"])("treats a committed file named %s as a file, not an option", (name) => {
    const { commands } = run([name, "SKILL.md"], { files: [name, "SKILL.md"] });
    expect(commands).toEqual(["scan --fail-on high -- ."]);
  });

  it("installs outside the scanned repository, so its .npmrc cannot pick the registry", () => {
    expect(run(["skills/a/SKILL.md"]).npxCwd).toBe(HOOK_REPO);
  });

  it("scans from the repository, where .clawvetban, .clawvetignore and relative baselines live", () => {
    const { calls, repo } = run(["--baseline", "base.json", "skills/a/SKILL.md"]);
    expect(calls).toEqual([{ cwd: repo, command: "scan --baseline base.json --fail-on high -- skills/a" }]);
  });

  it("fails when a scan fails", () => {
    expect(run(["skills/a/SKILL.md"], { npxExit: 1 }).status).toBe(1);
  });
});
