import { readdirSync, existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import { scanSkill } from "@clawvet/shared";
import { printScanResult } from "../output/terminal.js";
import chalk from "chalk";

const SKILL_DIRS = [
  join(homedir(), ".openclaw", "skills"),
  join(homedir(), ".openclaw", "workspace", "skills"),
];

export async function auditCommand(): Promise<void> {
  console.log(chalk.bold("\nClawVet Audit — Scanning all installed skills\n"));

  let totalScanned = 0;
  let totalThreats = 0;

  for (const dir of SKILL_DIRS) {
    if (!existsSync(dir)) continue;

    const entries = readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      const skillFile = join(dir, entry.name, "SKILL.md");
      if (!existsSync(skillFile)) continue;

      const content = readFileSync(skillFile, "utf-8");
      const result = await scanSkill(content);
      totalScanned++;
      totalThreats += result.findings.length;

      printScanResult(result);
    }
  }

  console.log(chalk.bold(`\nAudit complete: ${totalScanned} skills scanned, ${totalThreats} findings\n`));
}
