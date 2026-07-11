import { writeFileSync, existsSync, mkdirSync, chmodSync, readFileSync, unlinkSync } from "node:fs";
import { join } from "node:path";
import { execSync } from "node:child_process";
import chalk from "chalk";

const HOOK_CONTENT = `#!/bin/sh
# ClawVet pre-commit hook — scans staged SKILL.md files for security threats
# Installed by: clawvet hook --install

echo "🔍 ClawVet: Scanning staged skills..."
exec npx clawvet@latest scan --quiet --fail-on high
`;

export async function hookInstallCommand(): Promise<void> {
  try {
    const gitRoot = execSync("git rev-parse --show-toplevel", { encoding: "utf-8" }).trim();
    const hooksDir = join(gitRoot, ".git", "hooks");
    const hookPath = join(hooksDir, "pre-commit");

    if (!existsSync(hooksDir)) {
      mkdirSync(hooksDir, { recursive: true });
    }

    writeFileSync(hookPath, HOOK_CONTENT, "utf-8");
    try { chmodSync(hookPath, 0o755); } catch {}

    console.log(chalk.green("\n✅ ClawVet pre-commit hook installed"));
    console.log(chalk.dim(`  ${hookPath}\n`));
  } catch (err) {
    console.error(chalk.red("Not a git repository.\n"));
    process.exit(1);
  }
}

export async function hookRemoveCommand(): Promise<void> {
  try {
    const gitRoot = execSync("git rev-parse --show-toplevel", { encoding: "utf-8" }).trim();
    const hookPath = join(gitRoot, ".git", "hooks", "pre-commit");

    if (!existsSync(hookPath)) {
      console.log(chalk.yellow("No ClawVet pre-commit hook found.\n"));
      return;
    }

    const content = readFileSync(hookPath, "utf-8");
    if (!content.includes("ClawVet")) {
      console.log(chalk.yellow("Existing pre-commit hook is not from ClawVet — skipping.\n"));
      return;
    }

    unlinkSync(hookPath);
    console.log(chalk.green("✅ ClawVet pre-commit hook removed.\n"));
  } catch {
    console.error(chalk.red("Not a git repository.\n"));
    process.exit(1);
  }
}
