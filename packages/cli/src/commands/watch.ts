import { existsSync, watch } from "node:fs";
import { join, dirname, basename, resolve } from "node:path";
import { homedir } from "node:os";
import chalk from "chalk";
import { scanLocalSkill } from "../local-scan.js";
import { printScanResult } from "../output/terminal.js";

const DEFAULT_SKILL_DIRS = [
  join(homedir(), ".openclaw", "skills"),
  join(homedir(), ".openclaw", "workspace", "skills"),
];

export async function watchCommand(options: {
  threshold?: number;
  dir?: string;
}): Promise<void> {
  const threshold = options.threshold || 50;
  const SKILL_DIRS = options.dir ? [options.dir] : DEFAULT_SKILL_DIRS;
  console.log(
    chalk.bold(
      `\nClawVet Watch — monitoring skill directories (threshold: ${threshold})\n`
    )
  );

  const watchDirs: string[] = [];
  for (const dir of SKILL_DIRS) {
    if (existsSync(dir)) {
      watchDirs.push(dir);
    }
  }

  if (watchDirs.length === 0) {
    console.log(
      chalk.yellow(
        "No OpenClaw skill directories found. Watching will start when directories are created.\n"
      )
    );
    console.log(chalk.dim("Expected directories:"));
    for (const dir of SKILL_DIRS) {
      console.log(chalk.dim(`  ${dir}`));
    }
    console.log();
    process.exit(1);
  }

  console.log(chalk.dim("Watching:"));
  for (const dir of watchDirs) {
    console.log(chalk.dim(`  ${dir}`));
  }
  console.log();

  for (const dir of watchDirs) {
    const watcher = watch(dir, { recursive: true }, async (event, filename) => {
      if (!filename) return;
      // A referenced helper changing matters even when SKILL.md is unchanged.
      let skillDir = dirname(resolve(dir, filename));
      const root = resolve(dir);
      while (!existsSync(join(skillDir, "SKILL.md")) && skillDir !== root) {
        const parent = dirname(skillDir);
        if (parent === skillDir) return;
        skillDir = parent;
      }
      const skillFile = join(skillDir, "SKILL.md");
      if (!existsSync(skillFile)) return;

      console.log(chalk.dim(`\nDetected change: ${filename}`));

      try {
        const result = await scanLocalSkill(skillFile, {
          skillName: basename(dirname(skillFile)),
        });

        if (result.cached) {
          console.log(chalk.dim("(cached)"));
        }
        printScanResult(result);

        if (result.status === "failed" || result.riskScore > threshold) {
          console.log(
            chalk.bgRed.white.bold(
              ` REVIEW REQUIRED — incomplete inspection or risk above ${threshold} `
            )
          );
          console.log(
            chalk.red(
              `This skill should not be installed. Run 'clawvet scan ${skillFile}' for details.\n`
            )
          );
        }
      } catch (err) {
        console.error(chalk.red(`Error scanning ${filename}:`), err);
      }
    });

    process.on("SIGINT", () => {
      watcher.close();
      console.log(chalk.dim("\nWatch stopped."));
      process.exit(0);
    });
  }

  console.log(chalk.dim("Press Ctrl+C to stop watching.\n"));
  await new Promise(() => {});
}
