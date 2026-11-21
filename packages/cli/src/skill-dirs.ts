import { existsSync, readdirSync, readFileSync, realpathSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { basename, extname, join, resolve } from "node:path";

export type AuditEcosystem = "openclaw" | "claude-code" | "cursor" | "codex" | "windsurf" | "mcp" | "custom";
export type AuditTargetKind = "skill-dir" | "rule-file" | "claude-settings" | "mcp-config";

export interface AuditTarget {
  ecosystem: AuditEcosystem;
  kind: AuditTargetKind;
  name: string;
  path: string;
}

const isDirectory = (path: string): boolean => {
  try { return statSync(path).isDirectory(); } catch { return false; }
};

const isRegularFile = (path: string): boolean => {
  try { return statSync(path).isFile(); } catch { return false; }
};

const canonical = (path: string): string => {
  try { return realpathSync(path); } catch { return resolve(path); }
};

// Where OpenClaw loads skills from, in its precedence order (docs/tools/skills.md
// in openclaw 2026.11.2). `audit` and `watch` must look everywhere an agent
// does, or a skill installed under .agents/skills or a moved state directory
// goes unscanned. skills.load.extraDirs lives in operator config; pass those
// with --dir.
export function skillDirs(env: NodeJS.ProcessEnv = process.env, cwd = process.cwd()): string[] {
  const home = env.HOME || env.USERPROFILE || homedir();
  const state = env.OPENCLAW_STATE_DIR ? resolve(env.OPENCLAW_STATE_DIR) : join(home, ".openclaw");
  const dirs = [
    join(cwd, "skills"),
    join(cwd, ".agents", "skills"),
    join(home, ".agents", "skills"),
    join(state, "skills"),
    join(state, "workspace", "skills"),
    join(state, "workspace", ".agents", "skills"),
    // Claude Code: project and personal skills (CLAUDE_CONFIG_DIR moves the latter).
    join(cwd, ".claude", "skills"),
    join(env.CLAUDE_CONFIG_DIR ? resolve(env.CLAUDE_CONFIG_DIR) : join(home, ".claude"), "skills"),
  ];
  // Skill Workshop keeps each agent's own skills at <state>/agents/<id>/agent/workshop-skills.
  try {
    for (const agent of readdirSync(join(state, "agents"))) dirs.push(join(state, "agents", agent, "agent", "workshop-skills"));
  } catch { /* No agents directory. */ }
  return [...new Set(dirs)].filter((dir) => existsSync(dir));
}

function collectSkillFolders(rootDir: string, ecosystem: AuditEcosystem, out: AuditTarget[], seen: Set<string>): void {
  if (!existsSync(rootDir) || !isDirectory(rootDir)) return;
  const directSkill = join(rootDir, "SKILL.md");
  if (existsSync(directSkill) && isRegularFile(directSkill)) {
    const key = canonical(rootDir);
    if (!seen.has(key)) {
      seen.add(key);
      out.push({ ecosystem, kind: "skill-dir", name: basename(rootDir), path: rootDir });
    }
    return;
  }
  let entries;
  try { entries = readdirSync(rootDir, { withFileTypes: true }); } catch { return; }
  for (const entry of entries) {
    const child = join(rootDir, entry.name);
    if (!entry.isDirectory() && !(entry.isSymbolicLink() && isDirectory(child))) continue;
    const skillFile = join(child, "SKILL.md");
    if (!existsSync(skillFile) || !isRegularFile(skillFile)) continue;
    const key = canonical(child);
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ ecosystem, kind: "skill-dir", name: entry.name, path: child });
  }
}

function collectRuleFiles(
  rootDir: string,
  ecosystem: AuditEcosystem,
  extensions: Set<string>,
  prefix: string,
  out: AuditTarget[],
  seen: Set<string>,
  depth = 0,
): void {
  if (depth > 3 || !existsSync(rootDir) || !isDirectory(rootDir)) return;
  let entries;
  try { entries = readdirSync(rootDir, { withFileTypes: true }); } catch { return; }
  for (const entry of entries) {
    const child = join(rootDir, entry.name);
    if (entry.isDirectory()) {
      collectRuleFiles(child, ecosystem, extensions, `${prefix}${entry.name}/`, out, seen, depth + 1);
      continue;
    }
    if (!entry.isFile() && !(entry.isSymbolicLink() && isRegularFile(child))) continue;
    if (!extensions.has(extname(entry.name).toLowerCase())) continue;
    const key = canonical(child);
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ ecosystem, kind: "rule-file", name: `${prefix}${entry.name}`, path: child });
  }
}

function addSingleRuleFile(filePath: string, ecosystem: AuditEcosystem, name: string, out: AuditTarget[], seen: Set<string>): void {
  if (!existsSync(filePath) || !isRegularFile(filePath)) return;
  const key = canonical(filePath);
  if (seen.has(key)) return;
  seen.add(key);
  out.push({ ecosystem, kind: "rule-file", name, path: filePath });
}

function readSmallJson(filePath: string): Record<string, unknown> | undefined {
  try {
    const st = statSync(filePath);
    if (!st.isFile() || st.size === 0 || st.size > 512 * 1024) return undefined;
    const parsed: unknown = JSON.parse(readFileSync(filePath, "utf-8"));
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? (parsed as Record<string, unknown>) : undefined;
  } catch {
    return undefined;
  }
}

function hasNonEmptyObject(obj: Record<string, unknown> | undefined, key: string): boolean {
  const val = obj?.[key];
  return Boolean(val && typeof val === "object" && !Array.isArray(val) && Object.keys(val as Record<string, unknown>).length > 0);
}

/**
 * Discover installed agent skills, instruction rules, Claude Code hooks, and
 * MCP server configs across OpenClaw, Claude Code, Cursor, Codex, Windsurf,
 * and standard MCP config paths.
 */
export function discoverAuditTargets(
  env: NodeJS.ProcessEnv = process.env,
  cwd = process.cwd(),
  options: { ecosystem?: AuditEcosystem } = {},
): AuditTarget[] {
  const home = env.HOME || env.USERPROFILE || homedir();
  const openclawState = env.OPENCLAW_STATE_DIR ? resolve(env.OPENCLAW_STATE_DIR) : join(home, ".openclaw");
  const claudeDir = env.CLAUDE_CONFIG_DIR ? resolve(env.CLAUDE_CONFIG_DIR) : join(home, ".claude");
  const codexDir = env.CODEX_HOME ? resolve(env.CODEX_HOME) : join(home, ".codex");
  const xdgConfig = env.XDG_CONFIG_HOME ? resolve(env.XDG_CONFIG_HOME) : join(home, ".config");
  const out: AuditTarget[] = [];
  const seen = new Set<string>();
  const want = (eco: AuditEcosystem) => !options.ecosystem || options.ecosystem === eco;

  if (want("openclaw")) {
    const openclawRoots = [
      join(cwd, "skills"),
      join(cwd, ".agents", "skills"),
      join(home, ".agents", "skills"),
      join(openclawState, "skills"),
      join(openclawState, "workspace", "skills"),
      join(openclawState, "workspace", ".agents", "skills"),
    ];
    try {
      for (const agent of readdirSync(join(openclawState, "agents"))) {
        openclawRoots.push(join(openclawState, "agents", agent, "agent", "workshop-skills"));
      }
    } catch { /* No agents directory. */ }
    for (const root of openclawRoots) collectSkillFolders(root, "openclaw", out, seen);
  }

  if (want("claude-code")) {
    collectSkillFolders(join(cwd, ".claude", "skills"), "claude-code", out, seen);
    collectSkillFolders(join(claudeDir, "skills"), "claude-code", out, seen);
    const mdOnly = new Set([".md"]);
    collectRuleFiles(join(cwd, ".claude", "commands"), "claude-code", mdOnly, "claude-cmd:", out, seen);
    collectRuleFiles(join(claudeDir, "commands"), "claude-code", mdOnly, "claude-cmd:", out, seen);
    addSingleRuleFile(join(cwd, "CLAUDE.md"), "claude-code", "CLAUDE.md", out, seen);
    addSingleRuleFile(join(claudeDir, "CLAUDE.md"), "claude-code", "~/.claude/CLAUDE.md", out, seen);

    const settingsCandidates: Array<[string, string]> = [
      [join(cwd, ".claude", "settings.json"), ".claude/settings.json"],
      [join(cwd, ".claude", "settings.local.json"), ".claude/settings.local.json"],
      [join(claudeDir, "settings.json"), "~/.claude/settings.json"],
    ];
    for (const [filePath, label] of settingsCandidates) {
      if (!existsSync(filePath)) continue;
      const key = canonical(filePath);
      if (seen.has(key)) continue;
      const data = readSmallJson(filePath);
      if (hasNonEmptyObject(data, "hooks")) {
        seen.add(key);
        out.push({ ecosystem: "claude-code", kind: "claude-settings", name: `${label} (hooks)`, path: filePath });
      }
    }
  }

  if (want("cursor")) {
    const cursorExts = new Set([".mdc", ".md"]);
    addSingleRuleFile(join(cwd, ".cursorrules"), "cursor", ".cursorrules", out, seen);
    collectRuleFiles(join(cwd, ".cursor", "rules"), "cursor", cursorExts, "cursor:", out, seen);
    collectRuleFiles(join(home, ".cursor", "rules"), "cursor", cursorExts, "cursor:", out, seen);
  }

  if (want("codex")) {
    collectSkillFolders(join(cwd, ".codex", "skills"), "codex", out, seen);
    collectSkillFolders(join(codexDir, "skills"), "codex", out, seen);
    addSingleRuleFile(join(cwd, "AGENTS.md"), "codex", "AGENTS.md", out, seen);
    addSingleRuleFile(join(codexDir, "AGENTS.md"), "codex", "~/.codex/AGENTS.md", out, seen);
  }

  if (want("windsurf")) {
    const windsurfExts = new Set([".md", ".mdc"]);
    addSingleRuleFile(join(cwd, ".windsurfrules"), "windsurf", ".windsurfrules", out, seen);
    collectRuleFiles(join(cwd, ".windsurf", "rules"), "windsurf", windsurfExts, "windsurf:", out, seen);
  }

  if (want("mcp")) {
    const mcpCandidates: Array<[string, string]> = [
      [join(cwd, ".mcp.json"), ".mcp.json"],
      [join(cwd, ".cursor", "mcp.json"), ".cursor/mcp.json"],
      [join(cwd, ".vscode", "mcp.json"), ".vscode/mcp.json"],
      [join(home, ".cursor", "mcp.json"), "~/.cursor/mcp.json"],
      [join(home, ".claude.json"), "~/.claude.json"],
      [join(home, ".codeium", "windsurf", "mcp_config.json"), "windsurf/mcp_config.json"],
      [join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"), "claude_desktop_config.json"],
      [join(xdgConfig, "Claude", "claude_desktop_config.json"), "claude_desktop_config.json"],
    ];
    if (env.APPDATA) {
      mcpCandidates.push([join(env.APPDATA, "Claude", "claude_desktop_config.json"), "claude_desktop_config.json"]);
    }
    for (const [filePath, label] of mcpCandidates) {
      if (!existsSync(filePath)) continue;
      const key = canonical(filePath);
      if (seen.has(key)) continue;
      const data = readSmallJson(filePath);
      if (hasNonEmptyObject(data, "mcpServers") || hasNonEmptyObject(data, "servers")) {
        seen.add(key);
        out.push({ ecosystem: "mcp", kind: "mcp-config", name: `mcp:${label}`, path: filePath });
      }
    }
  }

  return out;
}
