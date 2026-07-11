import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import type { Finding } from "./types.js";

export interface MCPServer {
  name: string;
  source: string;
  sourceType: "agent_config" | "npm" | "local_directory";
  agentId: string;
  config: Record<string, unknown>;
  packageJson?: Record<string, unknown>;
  manifestPath?: string;
  toolDescriptions?: string[];
}

interface AgentMCPConfig {
  agentId: string;
  configPaths: string[];
  configParser: (content: string) => Record<string, unknown>;
}

const MCP_CONFIGS: AgentMCPConfig[] = [
  {
    agentId: "claude-code",
    configPaths: [
      join(homedir(), ".claude", "mcp.json"),
      join(homedir(), ".claude", "mcp-config.json"),
    ],
    configParser: (content) => JSON.parse(content),
  },
  {
    agentId: "cursor",
    configPaths: [
      join(homedir(), ".cursor", "mcp.json"),
      join(homedir(), ".cursor", "mcp-config.json"),
    ],
    configParser: (content) => JSON.parse(content),
  },
  {
    agentId: "windsurf",
    configPaths: [
      join(homedir(), ".codeium", "windsurf", "mcp.json"),
    ],
    configParser: (content) => JSON.parse(content),
  },
  {
    agentId: "github-copilot",
    configPaths: [
      join(homedir(), ".config", "github-copilot", "mcp.json"),
    ],
    configParser: (content) => JSON.parse(content),
  },
  {
    agentId: "gemini-cli",
    configPaths: [
      join(homedir(), ".gemini", "mcp.json"),
    ],
    configParser: (content) => JSON.parse(content),
  },
];

const MCP_KNOWN_DIRS = [
  join(homedir(), ".claude", "mcp_servers"),
  join(homedir(), ".cursor", "mcp_servers"),
];

export function discoverMCPConfigs(): AgentMCPConfig[] {
  return MCP_CONFIGS.filter((c) => c.configPaths.some((p) => existsSync(p)));
}

export function detectMCPServers(): MCPServer[] {
  const servers: MCPServer[] = [];
  const seen = new Set<string>();

  for (const cfg of MCP_CONFIGS) {
    for (const configPath of cfg.configPaths) {
      if (!existsSync(configPath)) continue;

      try {
        const content = readFileSync(configPath, "utf-8");
        const parsed = cfg.configParser(content);

        if (typeof parsed !== "object" || parsed === null) continue;

        for (const [key, value] of Object.entries(parsed)) {
          if (seen.has(key)) continue;
          seen.add(key);

          const entry = value as Record<string, unknown>;

          servers.push({
            name: key,
            source: configPath,
            sourceType: "agent_config",
            agentId: cfg.agentId,
            config: entry,
            toolDescriptions: extractToolDescriptions(entry),
          });
        }
      } catch {
        continue;
      }
    }
  }

  for (const dir of MCP_KNOWN_DIRS) {
    if (!existsSync(dir)) continue;

    try {
      const entries = readdirSync(dir, { withFileTypes: true });
      for (const entry of entries) {
        if (!entry.isDirectory()) continue;
        if (seen.has(entry.name)) continue;
        seen.add(entry.name);

        const pkgPath = join(dir, entry.name, "package.json");
        let packageJson: Record<string, unknown> | undefined;
        let manifestPath: string | undefined;

        if (existsSync(pkgPath)) {
          try {
            packageJson = JSON.parse(readFileSync(pkgPath, "utf-8"));
            manifestPath = pkgPath;
          } catch {
            // ignore
          }
        }

        servers.push({
          name: entry.name,
          source: join(dir, entry.name),
          sourceType: "local_directory",
          agentId: "unknown",
          config: {},
          packageJson,
          manifestPath,
        });
      }
    } catch {
      continue;
    }
  }

  return servers;
}

function extractToolDescriptions(config: Record<string, unknown>): string[] {
  const descriptions: string[] = [];

  if (config.tools && Array.isArray(config.tools)) {
    for (const tool of config.tools) {
      if (typeof tool === "object" && tool !== null) {
        const t = tool as Record<string, unknown>;
        if (typeof t.description === "string") {
          descriptions.push(t.description);
        }
      }
    }
  }

  if (config.command && typeof config.command === "string") {
    descriptions.push(config.command);
  }

  if (config.args && Array.isArray(config.args)) {
    descriptions.push(config.args.join(" "));
  }

  return descriptions;
}

export function scanMCPServer(server: MCPServer): Finding[] {
  const findings: Finding[] = [];
  const pass = "mcp-analysis";

  const commandStr = JSON.stringify(server.config).toLowerCase();

  // Dangerous command patterns in MCP server config
  const dangerousCmds = [
    { pattern: /curl\s+.*\|/, severity: "critical" as const, title: "MCP server pipes curl to shell", category: "remote_code_execution" },
    { pattern: /(?:sudo|chmod\s+777|chmod\s+a\+x)/, severity: "high" as const, title: "MCP server uses privilege escalation", category: "privilege_escalation" },
    { pattern: /(?:eval|exec)\s*\(/, severity: "critical" as const, title: "MCP server uses dynamic code execution", category: "remote_code_execution" },
    { pattern: /(?:\.env|credentials|secret|token|api_key)/, severity: "high" as const, title: "MCP server references credential files", category: "credential_theft" },
    { pattern: /(?:ngrok|bore|localhost\.run|serveo)/, severity: "high" as const, title: "MCP server uses tunnel service", category: "data_exfiltration" },
    { pattern: /(?:--allow-read|--allow-write|--allow-net|--allow-run|--allow-all)/, severity: "medium" as const, title: "MCP server uses Deno broad permission", category: "privilege_escalation" },
    { pattern: /(?:pastebin|discord\.com\/api|hooks\.slack)/, severity: "high" as const, title: "MCP server sends to webhook/paste service", category: "data_exfiltration" },
  ];

  for (const dc of dangerousCmds) {
    if (dc.pattern.test(commandStr)) {
      findings.push({
        category: dc.category,
        severity: dc.severity,
        title: dc.title,
        description: `Detected in ${server.name} MCP server configuration.`,
        evidence: dc.pattern.exec(commandStr)?.[0] || "",
        analysisPass: pass,
        fix: `Review ${server.name}'s configuration — this pattern is associated with security risks.`,
      });
    }
  }

  if (server.packageJson) {
    const pjStr = JSON.stringify(server.packageJson).toLowerCase();
    const npmPatterns = [
      { pattern: /postinstall|preinstall|prepare/, severity: "high" as const, title: "MCP npm package has install scripts", category: "supply_chain" },
      { pattern: /"files":\s*\[/, severity: "low" as const, title: "MCP npm package published with files", category: "supply_chain" },
    ];

    for (const np of npmPatterns) {
      if (np.pattern.test(pjStr)) {
        findings.push({
          category: np.category,
          severity: np.severity,
          title: np.title,
          description: `${server.name} npm package has potentially risky characteristics.`,
          analysisPass: pass,
          fix: "Audit the npm package contents before installing as an MCP server.",
        });
      }
    }

    const depCount = Object.keys((server.packageJson.dependencies as Record<string, string>) || {}).length;
    const devDepCount = Object.keys((server.packageJson.devDependencies as Record<string, string>) || {}).length;
    if (depCount + devDepCount > 50) {
      findings.push({
        category: "supply_chain",
        severity: "low",
        title: "MCP server has large dependency tree",
        description: `${depCount + devDepCount} dependencies — larger attack surface.`,
        analysisPass: pass,
        fix: "Review the dependency tree for known vulnerabilities.",
      });
    }
  }

  const hasToolDesc = server.toolDescriptions && server.toolDescriptions.length > 0;
  if (hasToolDesc) {
    const toolText = server.toolDescriptions!.join(" ").toLowerCase();
    const injectionPatterns = [
      { pattern: /ignore\s+(all\s+)?previous/, severity: "medium" as const, title: "MCP tool prompt injection risk", category: "prompt_injection" },
      { pattern: /you\s+are\s+now/, severity: "medium" as const, title: "MCP tool system override risk", category: "prompt_injection" },
      { pattern: /do\s+anything\s+now|developer\s+mode/, severity: "medium" as const, title: "MCP tool jailbreak risk", category: "prompt_injection" },
    ];

    for (const ip of injectionPatterns) {
      if (ip.pattern.test(toolText)) {
        findings.push({
          category: ip.category,
          severity: ip.severity,
          title: ip.title,
          description: `${server.name} MCP server tool description contains prompt injection patterns.`,
          evidence: ip.pattern.exec(toolText)?.[0] || "",
          analysisPass: pass,
          fix: "Remove prompt injection patterns from tool descriptions.",
        });
      }
    }
  }

  // Check if MCP server runs as a known dangerous command
  const cmd = (server.config.command as string) || "";
  const args = (server.config.args as string[]) || [];
  const fullCmd = [cmd, ...args].join(" ").toLowerCase();

  for (const dc of dangerousCmds) {
    if (dc.pattern.test(fullCmd)) {
      findings.push({
        category: dc.category,
        severity: dc.severity,
        title: `${dc.title} (command)`,
        description: `MCP server ${server.name} launches: ${fullCmd.slice(0, 100)}`,
        analysisPass: pass,
        fix: "Replace dangerous command patterns with safer alternatives.",
      });
    }
  }

  return findings;
}
