import { readdirSync, existsSync, statSync } from "node:fs";
import { join, basename } from "node:path";
import chalk from "chalk";
import { discoverAuditTargets, type AuditEcosystem, type AuditTarget } from "../skill-dirs.js";
import { failsAt, type FailOn } from "../local-scan.js";
import {
  printCompactAuditRow,
  printMachinePermissionsSummary,
  scanAuditTarget,
  summarizeAuditPermissions,
  type AuditScanEntry,
} from "../audit-scanners.js";
import { printScanResult } from "../output/terminal.js";
import { sendAuditTelemetry } from "../telemetry.js";

const isDirectory = (path: string) => { try { return statSync(path).isDirectory(); } catch { return false; } };

export interface AuditOptions {
  dir?: string;
  format?: "terminal" | "json";
  failOn?: FailOn;
  summary?: boolean;
  ecosystem?: AuditEcosystem;
  env?: NodeJS.ProcessEnv;
  cwd?: string;
}

function discoverCustomDirTargets(dir: string): AuditTarget[] {
  const targets: AuditTarget[] = [];
  const directSkillFile = join(dir, "SKILL.md");
  if (existsSync(directSkillFile)) {
    targets.push({ ecosystem: "custom", kind: "skill-dir", name: basename(dir), path: dir });
    return targets;
  }
  const entries = readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    // A symlinked skill folder is still a skill; skipping it would pass CI unscanned.
    const child = join(dir, entry.name);
    if (!entry.isDirectory() && !(entry.isSymbolicLink() && isDirectory(child))) continue;
    const skillFile = join(child, "SKILL.md");
    if (!existsSync(skillFile)) continue;
    targets.push({ ecosystem: "custom", kind: "skill-dir", name: entry.name, path: child });
  }
  return targets;
}

export async function auditCommand(options: AuditOptions = {}): Promise<void> {
  // JSON keeps stdout to one document, so CI can parse it.
  const json = options.format === "json";
  const log = json ? () => {} : (...args: unknown[]) => console.log(...args);

  let targets: AuditTarget[];
  if (options.dir) {
    if (!existsSync(options.dir)) {
      console.error(chalk.yellow(`Warning: Directory not found: ${options.dir}\n`));
      process.exit(1);
    }
    targets = discoverCustomDirTargets(options.dir);
  } else {
    targets = discoverAuditTargets(options.env ?? process.env, options.cwd ?? process.cwd(), {
      ecosystem: options.ecosystem,
    });
  }

  const skills: AuditScanEntry[] = [];
  log(
    chalk.bold(
      options.dir
        ? `\nClawVet Audit — Scanning skills in ${options.dir}\n`
        : "\nClawVet Audit — Scanning installed agent skills, rules, hooks & MCP configs\n",
    ),
  );

  const startedAt = Date.now();
  let totalScanned = 0;
  let totalThreats = 0;
  let incomplete = 0;
  const grades: Record<string, number> = { A: 0, B: 0, C: 0, D: 0, F: 0 };

  for (const target of targets) {
    const entry = await scanAuditTarget(target);
    skills.push(entry);
    if (entry.status === "failed") incomplete++;
    totalScanned++;
    totalThreats += entry.findings.length;
    if (entry.status !== "failed") {
      grades[entry.riskGrade] = (grades[entry.riskGrade] ?? 0) + 1;
    }

    if (!json) {
      if (options.summary) {
        printCompactAuditRow(entry);
      } else {
        printScanResult(entry);
      }
    }
  }

  const permissions = summarizeAuditPermissions(skills);

  if (!json) {
    if (totalScanned === 0) {
      log(chalk.dim("  No installed skills, agent rules, hooks, or MCP configs found."));
      log(chalk.dim("  Tip: pass --dir <path> to scan a specific folder, or run 'clawvet init' to protect OpenClaw & Claude Code.\n"));
    } else {
      printMachinePermissionsSummary(skills, permissions, grades, totalThreats);
    }
  }

  if (incomplete) console.error(`${incomplete} item(s) could not be fully inspected; review required.`);

  if (json) {
    console.log(
      JSON.stringify(
        {
          summary: {
            scanned: totalScanned,
            findings: totalThreats,
            incomplete,
            grades,
            ecosystems: permissions.byEcosystem,
            permissions,
          },
          skills,
        },
        null,
        2,
      ),
    );
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
