import chalk from "chalk";
import type { BundledFile, ScanResult, Severity } from "@clawvet/shared";
import type { AssemblyResult } from "../assemble.js";

// Strip ANSI/OSC/DCS/C1 escape sequences and control characters so untrusted
// skill text cannot forge terminal lines or reach terminal features (e.g. OSC 52).
export function sanitizeTerminal(value: string): string {
  return value
    .replace(/\x1b\][^\x07\x1b]*(?:\x07|\x1b\\|$)/g, "")
    .replace(/\x1b[PX^_][^\x1b]*(?:\x1b\\|$)/g, "")
    .replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, "")
    .replace(/\x1b[@-Z\\-_]/g, "")
    .replace(/\x9b[0-?]*[ -/]*[@-~]/g, "")
    .replace(/\r\n?|\n/g, " ")
    .replace(/[\x00-\x08\x0b-\x1f\x7f-\x9f]/g, "");
}

function formatLocation(lineNumber: number, files?: BundledFile[]): string {
  const file = files?.find((f) => lineNumber >= f.startLine && lineNumber <= f.endLine);
  if (!file) return `Line: ${lineNumber}`;
  return `Location: ${sanitizeTerminal(file.path)}:${lineNumber - file.startLine + 1}`;
}

const SEVERITY_COLORS: Record<Severity, (s: string) => string> = {
  critical: chalk.bgRed.white.bold,
  high: chalk.red.bold,
  medium: chalk.yellow,
  low: chalk.blue,
};

const GRADE_COLORS: Record<string, (s: string) => string> = {
  A: chalk.green.bold,
  B: chalk.greenBright,
  C: chalk.yellow.bold,
  D: chalk.redBright.bold,
  F: chalk.bgRed.white.bold,
};

export function printScanResult(result: ScanResult & { coverage?: AssemblyResult["coverage"] }): void {
  const files = result.coverage?.files;
  console.log();
  console.log(chalk.bold("━".repeat(60)));
  console.log(chalk.bold("  ClawVet Scan Report"));
  console.log(chalk.bold("━".repeat(60)));
  console.log();

  console.log(`  Skill:   ${chalk.bold(sanitizeTerminal(String(result.skillName ?? "unknown")))}`);
  if (result.skillVersion) {
    console.log(`  Version: ${sanitizeTerminal(String(result.skillVersion))}`);
  }
  console.log();

  if (result.status === "failed") {
    console.log(chalk.red(`  Inspection incomplete: ${sanitizeTerminal(String(result.summary || "Could not inspect all referenced files."))}`));
    console.log(chalk.red("  Partial results below cannot clear this skill for installation."));
    console.log();
  }

  // Risk score
  const gradeColor = GRADE_COLORS[result.riskGrade] || chalk.white;
  console.log(
    `  Risk Score: ${gradeColor(`${Math.round(result.riskScore)}/100`)}  Grade: ${gradeColor(result.riskGrade)}`
  );
  console.log();

  // Findings summary
  const fc = result.findingsCount;
  console.log("  Findings:");
  if (fc.critical)
    console.log(
      `    ${SEVERITY_COLORS.critical(` CRITICAL `)} ${fc.critical}`
    );
  if (fc.high)
    console.log(`    ${SEVERITY_COLORS.high("HIGH")}     ${fc.high}`);
  if (fc.medium)
    console.log(`    ${SEVERITY_COLORS.medium("MEDIUM")}   ${fc.medium}`);
  if (fc.low) console.log(`    ${SEVERITY_COLORS.low("LOW")}      ${fc.low}`);
  if (!fc.critical && !fc.high && !fc.medium && !fc.low) {
    console.log(`    ${chalk.green("No findings in inspected content.")}`);
  }
  console.log();

  // Detailed findings
  if (result.findings.length > 0) {
    console.log(chalk.bold("  Details:"));
    console.log();
    for (const f of result.findings) {
      const color = SEVERITY_COLORS[f.severity];
      const confStr = f.confidence != null ? ` ${Math.round(f.confidence * 100)}%` : "";
      console.log(`  ${color(`[${f.severity.toUpperCase()}${confStr}]`)} ${sanitizeTerminal(String(f.title))}`);
      console.log(`    ${chalk.dim(sanitizeTerminal(String(f.description)))}`);
      if (f.evidence) {
        console.log(`    Evidence: ${chalk.italic(sanitizeTerminal(String(f.evidence)))}`);
      }
      if (f.lineNumber) {
        console.log(`    ${formatLocation(f.lineNumber, files)}`);
      }
      if (f.fix) {
        console.log(`    Fix: ${chalk.green(sanitizeTerminal(String(f.fix)))}`);
      }
      console.log();
    }
  }

  // Recommendation
  const recColors: Record<string, (s: string) => string> = {
    block: chalk.bgRed.white.bold,
    warn: chalk.bgYellow.black.bold,
    approve: chalk.bgGreen.black.bold,
  };
  const rec = result.recommendation || "approve";
  console.log(
    `  Recommendation: ${(recColors[rec] || chalk.white)(` ${rec.toUpperCase()} `)}`
  );
  console.log();
  console.log(chalk.bold("━".repeat(60)));
  console.log();
}
