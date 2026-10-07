import { readFileSync, existsSync, statSync } from "node:fs";
import { resolve, join, basename, dirname } from "node:path";
import chalk from "chalk";
import { scanSkill } from "@clawvet/shared";
import { printScanResult } from "../output/terminal.js";
import { printJsonResult } from "../output/json.js";
import { printSarifResult } from "../output/sarif.js";
import { sendTelemetry, hasBeenAsked, setTelemetry, isTelemetryEnabled, getScanCount } from "../telemetry.js";
import { assembleSkill, ASSEMBLY_LIMITS, type AssemblyResult } from "../assemble.js";
import { applyCoverage } from "../local-scan.js";
import { RULES } from "../policy.js";
import { FEEDBACK_DISPLAY_URL } from "../feedback.js";

export interface ScanOptions {
  format?: "terminal" | "json" | "sarif";
  failOn?: "critical" | "high" | "medium" | "low";
  semantic?: boolean;
  remote?: boolean;
  quiet?: boolean;
  strict?: boolean;
}

const SLUG_PATTERN = /^[a-z0-9][a-z0-9_-]{0,63}$/i;

async function readRemoteResponse(res: Response): Promise<string> {
  const reader = res.body?.getReader();
  if (!reader) return "";
  const chunks: Uint8Array[] = [];
  let bytes = 0;
  try {
    for (;;) {
      const chunk = await reader.read();
      if (chunk.done) break;
      bytes += chunk.value.byteLength;
      if (bytes > ASSEMBLY_LIMITS.fileBytes) {
        await reader.cancel();
        throw new Error("Remote manifest exceeds the 256 KiB inspection limit");
      }
      chunks.push(chunk.value);
    }
    return new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks));
  } finally {
    reader.releaseLock();
  }
}

async function fetchRemoteSkill(slug: string): Promise<string> {
  if (!SLUG_PATTERN.test(slug)) {
    throw new Error(
      `Invalid skill name "${slug}". Must be 1-64 chars, alphanumeric + dash/underscore.`
    );
  }

  const encoded = encodeURIComponent(slug);
  // The ClawHub catalog API returns the skill record as JSON, with the full
  // SKILL.md content in `skill.description`. The other sources serve raw
  // markdown. Try the catalog first, then fall back to raw endpoints.
  const sources: Array<{ url: string; json: boolean }> = [
    { url: `https://clawhub.ai/api/v1/skills/${encoded}`, json: true },
    { url: `https://clawhub.ai/api/v1/skills/${encoded}/raw`, json: false },
    {
      url: `https://raw.githubusercontent.com/openclaw/skills/main/${encoded}/SKILL.md`,
      json: false,
    },
  ];

  for (const { url, json } of sources) {
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(10000) });
      if (!res.ok) continue;

      const text = await readRemoteResponse(res);
      if (!json) return text;

      const body = JSON.parse(text) as {
        skill?: { description?: string };
      };
      const content = body?.skill?.description;
      if (typeof content === "string" && content.includes("---")) {
        return content;
      }
    } catch {
      // try next
    }
  }

  throw new Error(
    `Could not fetch skill "${slug}" from ClawHub. Check the skill name and try again.`
  );
}

export async function scanCommand(
  target: string,
  options: ScanOptions
): Promise<void> {
  if (options.semantic) {
    console.error("CLI semantic analysis is not implemented. Use the authenticated API for semantic analysis; no scan was performed.");
    process.exitCode = 1;
    return;
  }
  let content: string;
  let assembly: AssemblyResult | undefined;
  let fallbackName: string | undefined;

  if (options.remote) {
    try {
      process.stderr.write(`Fetching "${target}" from ClawHub...\n`);
      content = await fetchRemoteSkill(target);
      fallbackName = target;
      assembly = {
        content,
        coverage: {
          complete: false,
          files: [{ path: "SKILL.md", startLine: 1, endLine: content.split("\n").length }],
          issues: [{ path: target, rule: "remote-manifest", reason: RULES["remote-manifest"].message }],
          warnings: [],
        },
      };
    } catch (err) {
      console.error(
        err instanceof Error ? err.message : "Failed to fetch remote skill"
      );
      process.exit(1);
    }
  } else {
    const skillPath = resolve(target);
    let skillFile = skillPath;
    let skillDir: string | undefined;

    if (
      existsSync(skillPath) &&
      statSync(skillPath).isDirectory() &&
      existsSync(join(skillPath, "SKILL.md"))
    ) {
      skillDir = skillPath;
      skillFile = join(skillPath, "SKILL.md");
    }

    if (!existsSync(skillFile) || statSync(skillFile).isDirectory()) {
      console.error(`Error: Cannot find SKILL.md at ${skillFile}`);
      console.error(`Hint: If this is a directory of skills, use 'clawvet audit --dir ${target}' instead.`);
      process.exit(1);
    }

    assembly = assembleSkill(skillDir || dirname(skillFile), undefined, basename(skillFile));
    content = assembly.content;
    fallbackName = basename(dirname(skillFile));
  }

  // Load .clawvetban — block skills by name, author, or slug
  const banFile = join(process.cwd(), ".clawvetban");
  if (existsSync(banFile)) {
    const banEntries = readFileSync(banFile, "utf-8")
      .split("\n")
      .map((l) => l.trim().toLowerCase())
      .filter((l) => l && !l.startsWith("#"));

    // Quick parse frontmatter to check name/author before full scan
    const fmMatch = content.match(/^---\r?\n([\s\S]*?)\r?\n---/);
    if (fmMatch) {
      const fmText = fmMatch[1].toLowerCase();
      for (const ban of banEntries) {
        const targetLower = target.toLowerCase();
        if (
          targetLower.includes(ban) ||
          fmText.includes(`name: ${ban}`) ||
          fmText.includes(`author: ${ban}`) ||
          fmText.includes(`slug: ${ban}`)
        ) {
          console.error(
            chalk.bgRed.white.bold(` BANNED `) +
            chalk.red(` Skill matches ban list entry: ${ban}`)
          );
          console.error(chalk.dim(`  Source: ${banFile}`));
          process.exit(1);
        }
      }
    }
  }

  // Load .clawvetignore
  const ignoreFile = join(process.cwd(), ".clawvetignore");
  const ignorePatterns: string[] = [];
  if (existsSync(ignoreFile)) {
    const lines = readFileSync(ignoreFile, "utf-8").split("\n");
    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed && !trimmed.startsWith("#")) {
        ignorePatterns.push(trimmed);
      }
    }
  }

  const scanned = await scanSkill(content, {
    semantic: options.semantic ?? false,
    ignorePatterns: ignorePatterns.length ? ignorePatterns : undefined,
    skillName: fallbackName,
  });
  const result = assembly ? applyCoverage(scanned, assembly, options.strict ? "strict" : "default") : scanned;

  if (!options.quiet) {
    if (options.format === "sarif") {
      printSarifResult(result);
    } else if (options.format === "json") {
      printJsonResult(result);
    } else {
      printScanResult(result);
    }
  }

  // Telemetry: first-run opt-in prompt (only in interactive TTY)
  const isInteractive = !options.quiet && options.format !== "json" && options.format !== "sarif";
  if (isInteractive) {
    if (!hasBeenAsked() && !isTelemetryEnabled() && process.stdin.isTTY) {
      const readline = await import("node:readline");
      const rl = readline.createInterface({ input: process.stdin, output: process.stderr });
      const answer = await new Promise<string>((resolve) => {
        rl.question(
          chalk.dim("Help improve ClawVet — send anonymous usage stats? (y/n) "),
          (a) => { rl.close(); resolve(a.trim().toLowerCase()); }
        );
      });
      setTelemetry(answer === "y" || answer === "yes");
    }

  }

  // Await telemetry so it completes before any process.exit()
  if (result.status === "complete") await sendTelemetry(result);

  // Show feedback CTA every 5th scan (after increment)
  if (isInteractive && getScanCount() % 5 === 0) {
    console.log(
      chalk.dim("  ") +
      chalk.cyan("Got feedback? → ") +
      chalk.underline.cyan(FEEDBACK_DISPLAY_URL)
    );
    console.log();
  }

  if (result.status === "failed") process.exit(1);

  const failOn = options.failOn || (options.quiet ? "high" : undefined);
  if (failOn) {
    const severityOrder = ["low", "medium", "high", "critical"];
    const threshold = severityOrder.indexOf(failOn);
    const hasFailure = result.findings.some(
      (f) => severityOrder.indexOf(f.severity) >= threshold
    );
    if (hasFailure) {
      process.exit(1);
    }
  }
}
