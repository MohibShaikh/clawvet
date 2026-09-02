import { Command } from "commander";
import { readFileSync } from "node:fs";
import { execFile } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { scanCommand } from "./commands/scan.js";
import { auditCommand } from "./commands/audit.js";
import { watchCommand } from "./commands/watch.js";
import { badgeCommand } from "./commands/badge.js";
import { policyCommand } from "./commands/policy.js";
import { FEEDBACK_URL, FEEDBACK_DISPLAY_URL } from "./feedback.js";

// Open a URL in the user's browser without going through a shell. Using
// execFile (not exec) means the URL is passed as an argument, never
// interpolated into a command string a shell would parse — no shell-exec
// surface even though the URL here is a constant.
function openUrl(url: string): void {
  const child =
    process.platform === "win32"
      ? execFile("cmd", ["/c", "start", "", url])
      : process.platform === "darwin"
        ? execFile("open", [url])
        : execFile("xdg-open", [url]);
  // Opening a browser is best-effort — never crash the CLI if the opener is
  // missing (e.g. a headless Linux box without xdg-open).
  child.on("error", () => {});
}

function readPackageVersion(): string {
  try {
    const here = dirname(fileURLToPath(import.meta.url));
    const pkg = JSON.parse(readFileSync(join(here, "..", "package.json"), "utf-8"));
    return pkg.version;
  } catch {
    return "0.0.0";
  }
}

const program = new Command();

program
  .name("clawvet")
  .description("Skill vetting & supply chain security for OpenClaw")
  .version(readPackageVersion());

program
  .command("scan")
  .description("Scan a skill for security threats")
  .argument("<target>", "Path to skill folder or SKILL.md file")
  .option("--format <format>", "Output format: terminal, json, or sarif", "terminal")
  .option("--fail-on <severity>", "Exit 1 if findings at this severity or above")
  .option("--semantic", "Enable AI semantic analysis (requires ANTHROPIC_API_KEY)")
  .option("--remote", "Fetch skill from ClawHub by name instead of local path")
  .option("-q, --quiet", "Suppress all output, exit code only (0=pass, 1=fail)")
  .option("--subscribe", "Open a prefilled GitHub issue to send feedback")
  .action(async (target, opts) => {
    if (opts.subscribe) {
      console.log(`Opening ${FEEDBACK_DISPLAY_URL} ...`);
      openUrl(FEEDBACK_URL);
    }
    await scanCommand(target, {
      format: opts.format,
      failOn: opts.failOn,
      semantic: opts.semantic,
      remote: opts.remote,
      quiet: opts.quiet,
    });
  });

program
  .command("policy")
  .description("OpenClaw install-policy hook: staged install metadata on stdin, JSON verdict on stdout")
  .option("--block-at <score>", "Risk score at or above which to block the install", "76")
  .action(async (opts) => {
    await policyCommand({ blockAt: Number(opts.blockAt) });
  });

program
  .command("audit")
  .description("Scan all installed OpenClaw skills")
  .option("--dir <path>", "Custom skills directory to scan")
  .action(async (opts) => {
    await auditCommand({ dir: opts.dir });
  });

program
  .command("watch")
  .description("Pre-install hook — blocks risky skill installs")
  .option("--threshold <score>", "Risk score threshold (default 50)", "50")
  .option("--dir <path>", "Custom skills directory to watch")
  .action(async (opts) => {
    await watchCommand({ threshold: parseInt(opts.threshold), dir: opts.dir });
  });

program
  .command("badge")
  .description("Generate a trust badge for a skill's README")
  .argument("<target>", "Path to skill folder or SKILL.md file")
  .option("--md", "Output only the markdown snippet")
  .action(async (target, opts) => {
    await badgeCommand(target, { markdown: opts.md });
  });

program
  .command("feedback")
  .description("Open a prefilled GitHub issue to send feedback")
  .action(async () => {
    console.log(`Opening ${FEEDBACK_DISPLAY_URL} ...`);
    openUrl(FEEDBACK_URL);
  });

program.parse();
