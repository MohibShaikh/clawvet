import { existsSync, readdirSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";

// Where OpenClaw loads skills from, in its precedence order (docs/tools/skills.md
// in openclaw 2026.11.2). `audit` and `watch` must look everywhere an agent
// does, or a skill installed under .agents/skills or a moved state directory
// goes unscanned. skills.load.extraDirs lives in operator config; pass those
// with --dir.
export function skillDirs(env: NodeJS.ProcessEnv = process.env, cwd = process.cwd()): string[] {
  const home = homedir();
  const state = env.OPENCLAW_STATE_DIR ? resolve(env.OPENCLAW_STATE_DIR) : join(home, ".openclaw");
  const dirs = [
    join(cwd, "skills"),
    join(cwd, ".agents", "skills"),
    join(home, ".agents", "skills"),
    join(state, "skills"),
    join(state, "workspace", "skills"),
    join(state, "workspace", ".agents", "skills"),
  ];
  // Skill Workshop keeps each agent's own skills at <state>/agents/<id>/agent/workshop-skills.
  try {
    for (const agent of readdirSync(join(state, "agents"))) dirs.push(join(state, "agents", agent, "agent", "workshop-skills"));
  } catch { /* No agents directory. */ }
  return [...new Set(dirs)].filter((dir) => existsSync(dir));
}
