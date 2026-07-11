import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";

export interface AgentInfo {
  id: string;
  name: string;
  configDir: string;
  skillPaths: string[];
  kind: "skills" | "plugins" | "mcp" | "rules";
}

export interface DiscoveredSkill {
  agentId: string;
  agentName: string;
  skillPath: string;
  skillName: string;
  content: string;
}

const AGENTS: AgentInfo[] = [
  {
    id: "claude-code",
    name: "Claude Code",
    configDir: join(homedir(), ".claude"),
    skillPaths: [
      join(homedir(), ".claude", "skills"),
    ],
    kind: "skills",
  },
  {
    id: "cursor",
    name: "Cursor",
    configDir: join(homedir(), ".cursor"),
    skillPaths: [
      join(homedir(), ".cursor", "skills"),
    ],
    kind: "skills",
  },
  {
    id: "openai-codex",
    name: "OpenAI Codex",
    configDir: join(homedir(), ".codex"),
    skillPaths: [
      join(homedir(), ".codex", "skills"),
    ],
    kind: "skills",
  },
  {
    id: "cline",
    name: "Cline",
    configDir: join(homedir(), ".cline"),
    skillPaths: [
      join(homedir(), ".cline", "skills"),
    ],
    kind: "skills",
  },
  {
    id: "windsurf",
    name: "Windsurf",
    configDir: join(homedir(), ".codeium", "windsurf"),
    skillPaths: [
      join(homedir(), ".codeium", "windsurf", "skills"),
    ],
    kind: "skills",
  },
  {
    id: "continue",
    name: "Continue",
    configDir: join(homedir(), ".continue"),
    skillPaths: [
      join(homedir(), ".continue", "skills"),
    ],
    kind: "skills",
  },
  {
    id: "github-copilot",
    name: "GitHub Copilot",
    configDir: join(homedir(), ".config", "github-copilot"),
    skillPaths: [
      join(homedir(), ".config", "github-copilot", "skills"),
    ],
    kind: "skills",
  },
  {
    id: "gemini-cli",
    name: "Gemini CLI",
    configDir: join(homedir(), ".gemini"),
    skillPaths: [
      join(homedir(), ".gemini", "skills"),
    ],
    kind: "skills",
  },
  {
    id: "opencode",
    name: "OpenCode",
    configDir: join(homedir(), ".config", "opencode"),
    skillPaths: [
      join(homedir(), ".config", "opencode", "skills"),
    ],
    kind: "skills",
  },
  {
    id: "goose",
    name: "Goose",
    configDir: join(homedir(), ".config", "goose"),
    skillPaths: [
      join(homedir(), ".config", "goose", "skills"),
    ],
    kind: "skills",
  },
  {
    id: "openclaw",
    name: "OpenClaw",
    configDir: join(homedir(), ".openclaw"),
    skillPaths: [
      join(homedir(), ".openclaw", "skills"),
      join(homedir(), ".openclaw", "workspace", "skills"),
    ],
    kind: "skills",
  },
  {
    id: "roo",
    name: "Roo",
    configDir: join(homedir(), ".roo"),
    skillPaths: [
      join(homedir(), ".roo", "skills"),
    ],
    kind: "skills",
  },
  {
    id: "antigravity",
    name: "Antigravity",
    configDir: join(homedir(), ".gemini", "antigravity"),
    skillPaths: [
      join(homedir(), ".gemini", "antigravity", "skills"),
    ],
    kind: "skills",
  },
  {
    id: "augment",
    name: "Augment",
    configDir: join(homedir(), ".augment"),
    skillPaths: [
      join(homedir(), ".augment", "skills"),
    ],
    kind: "skills",
  },
  {
    id: "kilo-code",
    name: "Kilo Code",
    configDir: join(homedir(), ".kilocode"),
    skillPaths: [
      join(homedir(), ".kilocode", "skills"),
    ],
    kind: "skills",
  },
  {
    id: "kiro",
    name: "Kiro",
    configDir: join(homedir(), ".kiro"),
    skillPaths: [
      join(homedir(), ".kiro", "skills"),
    ],
    kind: "skills",
  },
  {
    id: "mistral-vibe",
    name: "Mistral Vibe",
    configDir: join(homedir(), ".vibe"),
    skillPaths: [
      join(homedir(), ".vibe", "skills"),
    ],
    kind: "skills",
  },
  {
    id: "openhands",
    name: "OpenHands",
    configDir: join(homedir(), ".openhands"),
    skillPaths: [
      join(homedir(), ".openhands", "skills"),
    ],
    kind: "skills",
  },
  {
    id: "pi",
    name: "Pi",
    configDir: join(homedir(), ".pi", "agent"),
    skillPaths: [
      join(homedir(), ".pi", "agent", "skills"),
    ],
    kind: "skills",
  },
  {
    id: "qwen-code",
    name: "Qwen Code",
    configDir: join(homedir(), ".qwen"),
    skillPaths: [
      join(homedir(), ".qwen", "skills"),
    ],
    kind: "skills",
  },
  {
    id: "trae",
    name: "Trae",
    configDir: join(homedir(), ".trae"),
    skillPaths: [
      join(homedir(), ".trae", "skills"),
    ],
    kind: "skills",
  },
  {
    id: "warp",
    name: "Warp",
    configDir: join(homedir(), ".warp"),
    skillPaths: [
      join(homedir(), ".warp", "skills"),
    ],
    kind: "skills",
  },
];

export function getKnownAgents(): AgentInfo[] {
  return AGENTS;
}

export function detectInstalledAgents(): AgentInfo[] {
  return AGENTS.filter((a) => existsSync(a.configDir));
}

export function discoverAgentSkills(agent: AgentInfo): DiscoveredSkill[] {
  const results: DiscoveredSkill[] = [];

  for (const dir of agent.skillPaths) {
    if (!existsSync(dir)) continue;

    try {
      const entries = readdirSync(dir, { withFileTypes: true });
      for (const entry of entries) {
        if (!entry.isDirectory()) continue;

        const skillFile = join(dir, entry.name, "SKILL.md");
        if (!existsSync(skillFile)) continue;

        const content = readFileSync(skillFile, "utf-8");
        results.push({
          agentId: agent.id,
          agentName: agent.name,
          skillPath: skillFile,
          skillName: entry.name,
          content,
        });
      }
    } catch {
      continue;
    }
  }

  return results;
}

export function discoverAllSkills(): DiscoveredSkill[] {
  const agents = detectInstalledAgents();
  const results: DiscoveredSkill[] = [];

  for (const agent of agents) {
    results.push(...discoverAgentSkills(agent));
  }

  return results;
}
