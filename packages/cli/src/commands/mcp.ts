import { detectMCPServers, scanMCPServer } from "@clawvet/shared";
import chalk from "chalk";

export interface MCPOptions {
  format?: "terminal" | "json";
  quiet?: boolean;
}

export async function mcpCommand(options: MCPOptions = {}): Promise<void> {
  const servers = detectMCPServers();

  if (options.format === "json") {
    const results = [];
    for (const server of servers) {
      const findings = scanMCPServer(server);
      results.push({
        name: server.name,
        agentId: server.agentId,
        source: server.source,
        sourceType: server.sourceType,
        findings: findings.map((f) => ({
          severity: f.severity,
          title: f.title,
          category: f.category,
          description: f.description,
        })),
      });
    }
    console.log(JSON.stringify({ total: servers.length, servers: results }, null, 2));
    return;
  }

  console.log(chalk.bold("\n🔌 ClawVet MCP — MCP Server Security Scan\n"));

  if (servers.length === 0) {
    console.log(chalk.yellow("  No MCP servers detected on this system.\n"));
    return;
  }

  console.log(chalk.dim(`  Found ${servers.length} MCP server(s)\n`));

  let totalFindings = 0;

  for (const server of servers) {
    console.log(chalk.cyan(`  ${server.name}`));
    console.log(chalk.dim(`    Source: ${server.source}`));
    console.log(chalk.dim(`    Agent: ${server.agentId}`));
    console.log(chalk.dim(`    Type: ${server.sourceType}`));

    const findings = scanMCPServer(server);
    totalFindings += findings.length;

    if (findings.length === 0) {
      console.log(chalk.green(`    ✅ No issues found\n`));
      continue;
    }

    for (const f of findings) {
      const sevColor = f.severity === "critical" ? chalk.bgRed.white : f.severity === "high" ? chalk.red : f.severity === "medium" ? chalk.yellow : chalk.dim;
      console.log(`    ${sevColor(`[${f.severity.toUpperCase()}]`)} ${f.title}`);
      if (!options.quiet) {
        console.log(chalk.dim(`      ${f.description}`));
      }
    }
    console.log();
  }

  console.log(chalk.bold("\n📊 Summary"));
  console.log(`  MCP Servers: ${servers.length}`);
  console.log(`  Findings: ${totalFindings}`);

  if (totalFindings > 0) {
    console.log(chalk.red(`\n  ⚠ ${totalFindings} potential issues found\n`));
  } else {
    console.log(chalk.green(`\n  ✅ No issues detected\n`));
  }
}
