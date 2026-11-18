import { readdirSync, existsSync, statSync } from "node:fs";
import { join, basename } from "node:path";
import { skillDirs } from "../skill-dirs.js";
import { failsAt, scanLocalSkill, type FailOn, type LocalScanResult } from "../local-scan.js";
import { printScanResult } from "../output/terminal.js";
import { sendAuditTelemetry } from "../telemetry.js";
import chalk from "chalk";


const isDirectory = (path: string) => { try { return statSync(path).isDirectory(); } catch { return false; } };

export interface AuditOptions {
  dir?: string;
  format?: "terminal" | "json";
  failOn?: FailOn;
}

export async function auditCommand(options: AuditOptions = {}): Promise<void> {
  const SKILL_DIRS = options.dir ? [options.dir] : skillDirs();
  // JSON keeps stdout to one document, so CI can parse it.
  const json = options.format === "json";
  const log = json ? () => {} : (...args: unknown[]) => console.log(...args);
  const skills: Array<{ path: string } & LocalScanResult> = [];
  log(chalk.bold("\nClawVet Audit — Scanning all installed skills\n"));

  const startedAt = Date.now();
  let totalScanned = 0;
  let totalThreats = 0;
  let incomplete = 0;
  const grades: Record<string, number> = { A: 0, B: 0, C: 0, D: 0, F: 0 };

  for (const dir of SKILL_DIRS) {
    if (!existsSync(dir)) {
      if (options.dir) {
        console.error(chalk.yellow(`Warning: Directory not found: ${dir}\n`));
        process.exit(1);
      }
      continue;
    }

    // If the dir itself contains a SKILL.md, scan it directly
    const directSkillFile = join(dir, "SKILL.md");
    if (existsSync(directSkillFile)) {
      const result = await scanLocalSkill(directSkillFile, { skillName: basename(dir) });
      skills.push({ path: dir, ...result });
      if (result.status === "failed") incomplete++;
      totalScanned++;
      totalThreats += result.findings.length;
      if (result.status !== "failed") {
        grades[result.riskGrade] = (grades[result.riskGrade] ?? 0) + 1;
      }
      if (!json) printScanResult(result);
      continue;
    }

    const entries = readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      // A symlinked skill folder is still a skill; skipping it would pass CI unscanned.
      if (!entry.isDirectory() && !(entry.isSymbolicLink() && isDirectory(join(dir, entry.name)))) continue;
      const skillFile = join(dir, entry.name, "SKILL.md");
      if (!existsSync(skillFile)) continue;

      const result = await scanLocalSkill(skillFile, { skillName: entry.name });
      skills.push({ path: join(dir, entry.name), ...result });
      if (result.status === "failed") incomplete++;
      totalScanned++;
      totalThreats += result.findings.length;
      if (result.status !== "failed") {
        grades[result.riskGrade] = (grades[result.riskGrade] ?? 0) + 1;
      }

      if (!json) printScanResult(result);
    }
  }

  const gradeColors: Record<string, (s: string) => string> = {
    A: chalk.green.bold,
    B: chalk.greenBright,
    C: chalk.yellow.bold,
    D: chalk.redBright.bold,
    F: chalk.bgRed.white.bold,
  };
  const gradeSummary = (["A", "B", "C", "D", "F"] as const)
    .filter((g) => grades[g] > 0)
    .map((g) => `${gradeColors[g](g)} ${grades[g]}`)
    .join("  ");

  log(
    chalk.bold(
      `\nAudit complete: ${totalScanned} skills scanned, ${totalThreats} findings`
    )
  );
  if (totalScanned > 0) {
    log(`  Grades: ${gradeSummary}`);
  }
  const blocked = grades.D + grades.F;
  if (blocked > 0) {
    log(
      chalk.red(`  ${blocked} skill${blocked > 1 ? "s" : ""} graded D or F — review before use`)
    );
  }
  if (incomplete) console.error(`${incomplete} skill(s) could not be fully inspected; review required.`);
  log();
  if (json) {
    console.log(JSON.stringify({ summary: { scanned: totalScanned, findings: totalThreats, incomplete, grades }, skills }, null, 2));
  }

  // One session-level telemetry event for the whole audit (best-effort).
  await sendAuditTelemetry({
    skillsScanned: totalScanned,
    findingsTotal: totalThreats,
    grades,
    durationMs: Date.now() - startedAt,
  });
  const failOn = options.failOn;
  if (incomplete || (failOn && skills.some((result) => failsAt(result, failOn)))) process.exitCode = 1;
}
