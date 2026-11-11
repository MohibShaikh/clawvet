import { Command, InvalidArgumentError } from "commander";
import { readFileSync } from "node:fs";
import { execFile } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { scanCommand } from "./commands/scan.js";
import { auditCommand } from "./commands/audit.js";
import { watchCommand } from "./commands/watch.js";
import { badgeCommand } from "./commands/badge.js";
import { reviewCommand, approveCommand } from "./commands/review.js";
import { gateCommand } from "./commands/gate.js";
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

// The blocking line only means something inside 0-100. Rejecting the range at
// parse time beats silently installing a config that can never block.
function parseBlockAt(value: string): number {
  const score = Number(value);
  if (!Number.isInteger(score) || score < 0 || score > 100) {
    throw new InvalidArgumentError("--block-at must be an integer from 0 to 100");
  }
  return score;
}

function parseRuns(value: string): number {
  const runs = Number(value);
  if (!Number.isInteger(runs) || runs < 1 || runs > 5) throw new InvalidArgumentError("--semantic-runs must be an integer from 1 to 5");
  return runs;
}

function parseMs(value: string): number {
  const ms = Number(value);
  if (!Number.isInteger(ms) || ms < 100 || ms > 600_000) throw new InvalidArgumentError("--semantic-timeout must be milliseconds from 100 to 600000");
  return ms;
}

function parseOnError(value: string): "warn" | "ignore" {
  if (value !== "warn" && value !== "ignore") throw new InvalidArgumentError("--semantic-on-error must be warn or ignore");
  return value;
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
  .option("--semantic", "Add an LLM judge with your own key (ANTHROPIC_API_KEY, or CLAWVET_LLM_* for OpenAI-compatible and local models)")
  .option("--semantic-runs <n>", "Judge runs to majority-vote (1-5)", parseRuns)
  .option("--semantic-timeout <ms>", "Total judge deadline in milliseconds", parseMs)
  .option("--semantic-cache", "Cache judge verdicts by content under ~/.cache/clawvet")
  .option("--baseline <path>", "Accept findings recorded in a baseline file or directory (kept outside the skill)")
  .option("--write-baseline <file>", "Write a baseline accepting every current finding and coverage gap")
  .option("--reason <text>", "Why the findings in --write-baseline are accepted (required with it)")
  .option("--expires <iso>", "Expiry for --write-baseline entries, e.g. 2027-01-01T00:00:00Z")
  .option("--osv", "Look up pinned dependencies on OSV.dev (network)")
  .option("--osv-cache", "Cache OSV results under ~/.cache/clawvet")
  .option("--remote", "Fetch skill from ClawHub by name instead of local path")
  .option("-q, --quiet", "Suppress all output, exit code only (0=pass, 1=fail)")
  .option("--strict", "Fail on every gap in inspection coverage, not only clear evidence")
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
      semanticRuns: opts.semanticRuns,
      semanticTimeoutMs: opts.semanticTimeout,
      semanticCache: opts.semanticCache,
      baseline: opts.baseline,
      writeBaseline: opts.writeBaseline,
      reason: opts.reason,
      expires: opts.expires,
      osv: opts.osv,
      osvCache: opts.osvCache,
      remote: opts.remote,
      quiet: opts.quiet,
      strict: opts.strict,
    });
  });

program
  .command("review")
  .description("Review a staged skill and compare it with an earlier approval")
  .argument("<target>", "Skill directory or SKILL.md")
  .requiredOption("--output <file>", "Write a new JSON review outside the skill directory")
  .option("--baseline <file>", "Previous approval receipt to compare against")
  .option("--block-at <score>", "Approval blocking threshold", parseBlockAt, 76)
  .action(reviewCommand);

program
  .command("approve")
  .description("Approve a reviewed skill after verifying that its files and analysis still match")
  .argument("<target>", "Skill directory or SKILL.md")
  .requiredOption("--review <file>", "JSON report you have reviewed")
  .requiredOption("--output <file>", "Write a new approval receipt outside the skill directory")
  .action(approveCommand);

program
  .command("gate")
  .alias("policy")
  .description("OpenClaw install-policy hook: staged install metadata on stdin, JSON verdict on stdout")
  .option("--block-at <score>", "Risk score at or above which to block the install", parseBlockAt, 76)
  .option("--approval <file>", "Require a matching operator-owned approval receipt")
  .option("--print-config", "Print a ready-to-paste OpenClaw installPolicy config with resolved paths")
  .option("--strict", "Block every gap in inspection coverage and ask about reviewable ones")
  .option("--semantic", "Add an LLM judge with your own key, read from the gateway's environment")
  .option("--semantic-runs <n>", "Judge runs to majority-vote (1-5)", parseRuns)
  .option("--semantic-timeout <ms>", "Judge deadline in milliseconds (default 8000)", parseMs)
  .option("--semantic-cache", "Cache judge verdicts by content under ~/.cache/clawvet")
  .option("--semantic-on-error <policy>", "When the judge is unavailable: warn (default) or ignore", parseOnError)
  .option("--baseline <path>", "Operator baseline file, or a directory of them, accepting known findings")
  .option("--osv", "Look up pinned dependencies on OSV.dev (network; off by default)")
  .option("--osv-cache", "Cache OSV results under ~/.cache/clawvet")
  .action(async (opts) => {
    // `policy` was the name in 0.12.0. It collides with `openclaw policy`,
    // which lints workspace config rather than gating installs. Kept as an
    // alias so a config written against 0.12.0 keeps working; the notice goes
    // to stderr because stdout carries the JSON verdict the host parses.
    if (process.argv[2] === "policy") {
      process.stderr.write(
        "clawvet: 'policy' is deprecated, use 'gate'. Update args to [\"gate\"] in your installPolicy config.\n"
      );
    }
    await gateCommand({
      blockAt: opts.blockAt, printConfig: opts.printConfig, approval: opts.approval, strict: opts.strict,
      semantic: opts.semantic, semanticRuns: opts.semanticRuns, semanticTimeoutMs: opts.semanticTimeout,
      semanticCache: opts.semanticCache, semanticOnError: opts.semanticOnError,
      baseline: opts.baseline, osv: opts.osv, osvCache: opts.osvCache,
    });
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
  .description("Monitor skill file changes and report risks (does not block installs)")
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
