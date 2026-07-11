import { detectInstalledAgents, discoverAgentSkills, getKnownAgents, scanSkill } from "@clawvet/shared";
import { printScanResult } from "../output/terminal.js";
import chalk from "chalk";

export interface DoctorOptions {
  format?: "terminal" | "json";
  failOn?: "critical" | "high" | "medium" | "low";
  quiet?: boolean;
}

export async function doctorCommand(options: DoctorOptions = {}): Promise<void> {
  const installed = detectInstalledAgents();
  const known = getKnownAgents();

  if (options.format === "json") {
    const jsonOutput: Record<string, unknown> = {
      detectedAgents: installed.map((a) => a.id),
      totalAgents: known.length,
      totalInstalled: installed.length,
      totalSkillsScanned: 0,
    };

    let grandTotal = 0;
    const agentResults: Record<string, unknown> = {};

    for (const agent of installed) {
      const skills = discoverAgentSkills(agent);
      grandTotal += skills.length;
    }

    jsonOutput.totalSkillsScanned = grandTotal;

    for (const agent of installed) {
      const skills = discoverAgentSkills(agent);
      for (const skill of skills) {
        const result = await scanSkill(skill.content, { skillName: skill.skillName });
        if (!agentResults[agent.id]) {
          agentResults[agent.id] = {
            name: agent.name,
            skills: [],
            totalFindings: 0,
          };
        }
        (agentResults[agent.id] as { skills: unknown[] }).skills.push({
          name: skill.skillName,
          path: skill.skillPath,
          riskScore: result.riskScore,
          riskGrade: result.riskGrade,
          findings: result.findings.length,
        });
        (agentResults[agent.id] as { totalFindings: number }).totalFindings += result.findings.length;
      }
    }

    jsonOutput.agents = agentResults;
    console.log(JSON.stringify(jsonOutput, null, 2));
    return;
  }

  console.log(chalk.bold("\n🧪 ClawVet Doctor — System Diagnostics\n"));
  console.log(chalk.dim(`  Agent registry: ${known.length} known, ${installed.length} detected\n`));

  if (installed.length === 0) {
    console.log(chalk.yellow("  No supported AI agents detected on this system."));
    console.log(chalk.dim(`  Known agents:\n`));
    for (const agent of known) {
      console.log(chalk.dim(`    ${chalk.bold(agent.name.padEnd(20))} ${agent.configDir}`));
    }
    console.log();
    return;
  }

  let totalSkills = 0;
  let totalFindings = 0;

  for (const agent of installed) {
    const skills = discoverAgentSkills(agent);
    totalSkills += skills.length;

    console.log(chalk.cyan(`  ${agent.name}`));
    console.log(chalk.dim(`    Config: ${agent.configDir}`));

    if (skills.length === 0) {
      console.log(chalk.dim(`    Skills: none found\n`));
      continue;
    }

    console.log(chalk.dim(`    Skills: ${skills.length}`));

    for (const skill of skills) {
      const result = await scanSkill(skill.content, { skillName: skill.skillName });
      totalFindings += result.findings.length;

      if (!options.quiet) {
        printScanResult(result);
      }
    }
    console.log();
  }

  console.log(chalk.bold("\n📊 Summary"));
  console.log(`  Agents: ${installed.length}`);
  console.log(`  Skills: ${totalSkills}`);
  console.log(`  Findings: ${totalFindings}`);

  if (totalFindings > 0) {
    console.log(chalk.red(`\n  ⚠ ${totalFindings} potential threats found across ${totalSkills} skills\n`));
  } else {
    console.log(chalk.green(`\n  ✅ No threats detected\n`));
  }
}
