import { afterEach, describe, expect, it, vi } from "vitest";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import {
  buildClaudeHookCommand,
  detectInitTargets,
  initCommand,
  isWatchedAgentFile,
  patchClaudeSettings,
  patchOpenClawConfig,
} from "../../../packages/cli/src/commands/init.js";
import { buildGateConfig } from "../../../packages/cli/src/commands/gate.js";

const dirs: string[] = [];
afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
  vi.restoreAllMocks();
  process.exitCode = undefined;
});

function makeTree(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "clawvet-init-"));
  dirs.push(dir);
  for (const [rel, body] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, rel)), { recursive: true });
    writeFileSync(join(dir, rel), body);
  }
  return dir;
}

describe("clawvet init", () => {
  it("detects OpenClaw and Claude Code directories and config files", () => {
    const home = makeTree({
      ".openclaw/openclaw.json": JSON.stringify({ model: "claude" }),
      ".claude/settings.json": JSON.stringify({ theme: "dark" }),
    });
    const targets = detectInitTargets({ HOME: home });
    expect(targets.openclawConfig).toEqual({ path: join(home, ".openclaw", "openclaw.json"), exists: true });
    expect(targets.claudeSettings).toEqual({ path: join(home, ".claude", "settings.json"), exists: true });
  });

  it("merges OpenClaw security.installPolicy without clobbering existing keys and is idempotent", () => {
    const built = buildGateConfig(76, { strict: true });
    const existing = {
      model: "opus",
      security: { auditLog: true },
    };
    const first = patchOpenClawConfig(existing, built.config);
    expect(first.changed).toBe(true);
    expect(first.updated.model).toBe("opus");
    expect((first.updated.security as Record<string, unknown>).auditLog).toBe(true);
    const installPolicy = (first.updated.security as Record<string, Record<string, unknown>>).installPolicy;
    expect(installPolicy.enabled).toBe(true);
    expect((installPolicy.exec as { args: string[] }).args).toContain("--strict");

    const second = patchOpenClawConfig(first.updated, built.config);
    expect(second.changed).toBe(false);
  });

  it("merges Claude Code PostToolUse hook while preserving unrelated hooks and is idempotent", () => {
    const cmd = buildClaudeHookCommand("/usr/bin/node", "/opt/clawvet/dist/index.js");
    const existing = {
      theme: "dark",
      hooks: {
        PreToolUse: [{ matcher: "Bash", hooks: [{ type: "command", command: "echo hi" }] }],
        PostToolUse: [{ matcher: "Bash", hooks: [{ type: "command", command: "echo done" }] }],
      },
    };
    const first = patchClaudeSettings(existing, cmd);
    expect(first.changed).toBe(true);
    const post = (first.updated.hooks as { PostToolUse: unknown[] }).PostToolUse;
    expect(post.length).toBe(2);
    expect((first.updated.hooks as { PreToolUse: unknown[] }).PreToolUse.length).toBe(1);

    const second = patchClaudeSettings(first.updated, cmd);
    expect(second.changed).toBe(false);
    expect((second.updated.hooks as { PostToolUse: unknown[] }).PostToolUse.length).toBe(2);
  });

  it("--dry-run makes zero changes to disk", async () => {
    const origOc = JSON.stringify({ keepMe: 1 }, null, 2);
    const origCc = JSON.stringify({ theme: "light" }, null, 2);
    const home = makeTree({
      ".openclaw/openclaw.json": origOc,
      ".claude/settings.json": origCc,
    });
    vi.spyOn(console, "log").mockImplementation(() => {});
    vi.spyOn(console, "error").mockImplementation(() => {});

    const res = await initCommand({ dryRun: true, env: { HOME: home }, cwd: home });
    expect(res.dryRun).toBe(true);
    expect(res.openclaw).toBe("dry-run");
    expect(res.claude).toBe("dry-run");
    expect(res.backups).toEqual([]);
    expect(readFileSync(join(home, ".openclaw", "openclaw.json"), "utf-8")).toBe(origOc);
    expect(readFileSync(join(home, ".claude", "settings.json"), "utf-8")).toBe(origCc);
  });

  it("--yes patches both configs with backups and second run is idempotent", async () => {
    const home = makeTree({
      ".openclaw/openclaw.json": JSON.stringify({ gateway: { port: 8080 } }, null, 2),
      ".claude/settings.json": JSON.stringify({ permissions: { allow: ["Read"] } }, null, 2),
    });
    vi.spyOn(console, "log").mockImplementation(() => {});
    vi.spyOn(console, "error").mockImplementation(() => {});
    process.env.CLAWVET_TELEMETRY = "off";

    const res1 = await initCommand({ yes: true, audit: false, semantic: true, blockAt: 50, env: { HOME: home }, cwd: home });
    expect(res1.openclaw).toBe("configured");
    expect(res1.claude).toBe("configured");
    expect(res1.backups.length).toBe(2);
    for (const bak of res1.backups) expect(existsSync(bak)).toBe(true);

    const oc = JSON.parse(readFileSync(join(home, ".openclaw", "openclaw.json"), "utf-8"));
    expect(oc.gateway.port).toBe(8080);
    expect(oc.security.installPolicy.exec.args).toContain("--semantic");
    expect(oc.security.installPolicy.exec.args).toContain("--block-at");
    expect(oc.security.installPolicy.exec.args).toContain("50");
    expect(oc.security.installPolicy.exec.passEnv).toContain("ANTHROPIC_API_KEY");

    const cc = JSON.parse(readFileSync(join(home, ".claude", "settings.json"), "utf-8"));
    expect(cc.permissions.allow).toEqual(["Read"]);
    expect(cc.hooks.PostToolUse.length).toBe(1);

    // Re-running init should leave both unchanged and create no new backups.
    const ocFilesBefore = readdirSync(join(home, ".openclaw")).length;
    const res2 = await initCommand({ yes: true, audit: false, semantic: true, blockAt: 50, env: { HOME: home }, cwd: home });
    expect(res2.openclaw).toBe("unchanged");
    expect(res2.claude).toBe("unchanged");
    expect(res2.backups).toEqual([]);
    expect(readdirSync(join(home, ".openclaw")).length).toBe(ocFilesBefore);
  });

  it("isWatchedAgentFile matches only skills, rules, hooks, and MCP configs", () => {
    expect(isWatchedAgentFile("/repo/skills/foo/SKILL.md")).toBe(true);
    expect(isWatchedAgentFile("/home/u/.claude/commands/deploy.md")).toBe(true);
    expect(isWatchedAgentFile("/repo/.cursor/rules/style.mdc")).toBe(true);
    expect(isWatchedAgentFile("/repo/.cursorrules")).toBe(true);
    expect(isWatchedAgentFile("/repo/AGENTS.md")).toBe(true);
    expect(isWatchedAgentFile("/repo/.mcp.json")).toBe(true);
    expect(isWatchedAgentFile("/home/u/.config/Claude/claude_desktop_config.json")).toBe(true);

    expect(isWatchedAgentFile("/repo/src/index.ts")).toBe(false);
    expect(isWatchedAgentFile("/repo/README.md")).toBe(false);
    expect(isWatchedAgentFile("/repo/package.json")).toBe(false);
  });
});
