import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import chalk from "chalk";
import { buildGateConfig, type BuiltGateConfig } from "./gate.js";
import { auditCommand } from "./audit.js";
import { scanAuditTarget } from "../audit-scanners.js";
import { sanitizeTerminal } from "../output/terminal.js";
import type { AuditTarget } from "../skill-dirs.js";

export interface InitOptions {
  dryRun?: boolean;
  yes?: boolean;
  strict?: boolean;
  semantic?: boolean;
  blockAt?: number;
  audit?: boolean;
  fixPermissions?: boolean;
  openclawConfig?: string;
  claudeSettings?: string;
  skipOpenclaw?: boolean;
  skipClaude?: boolean;
  env?: NodeJS.ProcessEnv;
  cwd?: string;
}

export interface DetectedTargets {
  openclawConfig?: { path: string; exists: boolean };
  claudeSettings?: { path: string; exists: boolean };
}

export interface InitSummary {
  dryRun: boolean;
  openclaw: "configured" | "unchanged" | "skipped" | "not-detected" | "dry-run";
  claude: "configured" | "unchanged" | "skipped" | "not-detected" | "dry-run";
  backups: string[];
  writablePaths: string[];
  fixedPermissions: string[];
  failedPermissions: string[];
}

export function detectInitTargets(
  env: NodeJS.ProcessEnv = process.env,
  options: Pick<InitOptions, "openclawConfig" | "claudeSettings" | "skipOpenclaw" | "skipClaude"> = {},
): DetectedTargets {
  const home = env.HOME || env.USERPROFILE || homedir();
  const out: DetectedTargets = {};

  if (!options.skipOpenclaw) {
    if (options.openclawConfig) {
      const p = resolve(options.openclawConfig);
      out.openclawConfig = { path: p, exists: existsSync(p) };
    } else {
      const stateDir = env.OPENCLAW_STATE_DIR ? resolve(env.OPENCLAW_STATE_DIR) : join(home, ".openclaw");
      const openclawJson = join(stateDir, "openclaw.json");
      const legacyConfigJson = join(stateDir, "config.json");
      if (existsSync(openclawJson)) {
        out.openclawConfig = { path: openclawJson, exists: true };
      } else if (existsSync(legacyConfigJson)) {
        out.openclawConfig = { path: legacyConfigJson, exists: true };
      } else if (existsSync(stateDir)) {
        out.openclawConfig = { path: openclawJson, exists: false };
      }
    }
  }

  if (!options.skipClaude) {
    if (options.claudeSettings) {
      const p = resolve(options.claudeSettings);
      out.claudeSettings = { path: p, exists: existsSync(p) };
    } else {
      const claudeDir = env.CLAUDE_CONFIG_DIR ? resolve(env.CLAUDE_CONFIG_DIR) : join(home, ".claude");
      const settingsJson = join(claudeDir, "settings.json");
      if (existsSync(settingsJson)) {
        out.claudeSettings = { path: settingsJson, exists: true };
      } else if (existsSync(claudeDir)) {
        out.claudeSettings = { path: settingsJson, exists: false };
      }
    }
  }

  return out;
}

export function patchOpenClawConfig(
  existing: Record<string, unknown>,
  gateConfig: BuiltGateConfig["config"],
): { updated: Record<string, unknown>; changed: boolean } {
  const existingSecurity =
    existing.security && typeof existing.security === "object" && !Array.isArray(existing.security)
      ? (existing.security as Record<string, unknown>)
      : {};
  const nextInstallPolicy = gateConfig.security.installPolicy;
  const prevInstallPolicy = existingSecurity.installPolicy;

  const changed = JSON.stringify(prevInstallPolicy) !== JSON.stringify(nextInstallPolicy);
  const updated: Record<string, unknown> = {
    ...existing,
    security: {
      ...existingSecurity,
      installPolicy: nextInstallPolicy,
    },
  };
  return { updated, changed };
}

function shellQuote(arg: string): string {
  if (/^[A-Za-z0-9_./:@=-]+$/.test(arg)) return arg;
  if (process.platform === "win32") return `"${arg.replace(/"/g, '\\"')}"`;
  return `'${arg.replace(/'/g, "'\\''")}'`;
}

export function buildClaudeHookCommand(command: string, self: string): string {
  return `${shellQuote(command)} ${shellQuote(self)} claude-hook`;
}

const CLAWVET_HOOK_MARKER = /\bclaude-hook\b/;

export function patchClaudeSettings(
  existing: Record<string, unknown>,
  hookCommand: string,
): { updated: Record<string, unknown>; changed: boolean } {
  const existingHooks =
    existing.hooks && typeof existing.hooks === "object" && !Array.isArray(existing.hooks)
      ? (existing.hooks as Record<string, unknown>)
      : {};
  const existingPost = Array.isArray(existingHooks.PostToolUse)
    ? [...existingHooks.PostToolUse]
    : [];

  const desiredEntry = {
    matcher: "Write|Edit",
    hooks: [
      {
        type: "command",
        command: hookCommand,
      },
    ],
  };

  // Replace any prior ClawVet claude-hook entry in-place for idempotency.
  let replaced = false;
  let unchanged = false;
  const nextPost = existingPost.map((entry) => {
    if (!entry || typeof entry !== "object") return entry;
    const rec = entry as { matcher?: unknown; hooks?: unknown };
    if (Array.isArray(rec.hooks)) {
      const hasClawvet = rec.hooks.some(
        (h) => h && typeof h === "object" && typeof (h as { command?: unknown }).command === "string" && CLAWVET_HOOK_MARKER.test((h as { command: string }).command),
      );
      if (hasClawvet) {
        replaced = true;
        if (JSON.stringify(entry) === JSON.stringify(desiredEntry)) {
          unchanged = true;
          return entry;
        }
        return desiredEntry;
      }
    }
    return entry;
  });

  if (!replaced) {
    nextPost.push(desiredEntry);
  }

  const changed = !unchanged;
  const updated: Record<string, unknown> = {
    ...existing,
    hooks: {
      ...existingHooks,
      PostToolUse: nextPost,
    },
  };
  return { updated, changed };
}

function readJsonObject(filePath: string): Record<string, unknown> {
  if (!existsSync(filePath)) return {};
  const raw = readFileSync(filePath, "utf-8").trim();
  if (!raw) return {};
  const parsed: unknown = JSON.parse(raw);
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(`${filePath} does not contain a JSON object.`);
  }
  return parsed as Record<string, unknown>;
}

function writeJsonAtomicWithBackup(filePath: string, data: Record<string, unknown>): string | undefined {
  mkdirSync(dirname(filePath), { recursive: true });
  let backupPath: string | undefined;
  let mode = 0o600;
  if (existsSync(filePath)) {
    try { mode = statSync(filePath).mode & 0o777; } catch { /* default 0o600 */ }
    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    backupPath = `${filePath}.bak.${stamp}`;
    copyFileSync(filePath, backupPath);
  }
  const tmpPath = `${filePath}.tmp.${process.pid}`;
  writeFileSync(tmpPath, JSON.stringify(data, null, 2) + "\n", { mode });
  renameSync(tmpPath, filePath);
  return backupPath;
}

async function askYesNo(promptText: string, defaultYes = true): Promise<boolean> {
  if (!process.stdin.isTTY) return defaultYes;
  const readline = await import("node:readline");
  const rl = readline.createInterface({ input: process.stdin, output: process.stderr });
  const suffix = defaultYes ? " (Y/n) " : " (y/N) ";
  const answer = await new Promise<string>((resolveAnswer) => {
    rl.question(promptText + suffix, (a) => {
      rl.close();
      resolveAnswer(a.trim().toLowerCase());
    });
  });
  if (!answer) return defaultYes;
  return answer === "y" || answer === "yes";
}

export async function initCommand(options: InitOptions = {}): Promise<InitSummary> {
  const env = options.env ?? process.env;
  const cwd = options.cwd ?? process.cwd();
  const dryRun = Boolean(options.dryRun);
  const autoYes = Boolean(options.yes);

  console.log(chalk.bold(`\nClawVet Init${dryRun ? " (dry run)" : ""} — One-command agent security setup\n`));

  const built = buildGateConfig(options.blockAt, {
    strict: options.strict,
    semantic: options.semantic,
  });
  const targets = detectInitTargets(env, options);

  const summary: InitSummary = {
    dryRun,
    openclaw: targets.openclawConfig ? "skipped" : "not-detected",
    claude: targets.claudeSettings ? "skipped" : "not-detected",
    backups: [],
    writablePaths: built.writable,
    fixedPermissions: [],
    failedPermissions: [],
  };

  // 1. OpenClaw installPolicy setup
  if (targets.openclawConfig) {
    const ocPath = targets.openclawConfig.path;
    console.log(chalk.cyan(`Detected OpenClaw config: ${ocPath}${targets.openclawConfig.exists ? "" : " (will create)"}`));
    try {
      const existing = readJsonObject(ocPath);
      const { updated, changed } = patchOpenClawConfig(existing, built.config);
      if (!changed) {
        console.log(chalk.green("  OpenClaw security.installPolicy is already up to date.\n"));
        summary.openclaw = "unchanged";
      } else if (dryRun) {
        console.log(chalk.dim("  [dry-run] Would patch security.installPolicy with:"));
        console.log(chalk.dim(JSON.stringify(built.config.security.installPolicy, null, 2).replace(/^/gm, "    ")));
        console.log();
        summary.openclaw = "dry-run";
      } else {
        const proceed = autoYes || await askYesNo(`  Patch ${ocPath} with ClawVet install gate (backup created automatically)?`, true);
        if (proceed) {
          const backup = writeJsonAtomicWithBackup(ocPath, updated);
          if (backup) {
            summary.backups.push(backup);
            console.log(chalk.dim(`  Backup saved: ${backup}`));
          }
          console.log(chalk.green(`  Configured OpenClaw install gate in ${ocPath}\n`));
          summary.openclaw = "configured";
        } else {
          console.log(chalk.dim("  Skipped OpenClaw config.\n"));
          summary.openclaw = "skipped";
        }
      }
    } catch (err) {
      console.error(chalk.red(`  Could not update ${ocPath}: ${err instanceof Error ? err.message : String(err)}\n`));
      process.exitCode = 1;
    }
  } else {
    console.log(chalk.dim("OpenClaw: not detected (~/.openclaw not found). Pass --openclaw-config <path> if stored elsewhere.\n"));
  }

  // 2. Writable path preflight for OpenClaw (chmod go-w)
  if (built.writable.length > 0 && (targets.openclawConfig || options.fixPermissions)) {
    const quoted = built.writable.map((p) => `'${p.replace(/'/g, "'\\''")}'`).join(" ");
    console.log(chalk.yellow("Permission check: OpenClaw rejects installPolicy hooks when the binary, script, or any parent dir is group/world-writable."));
    for (const p of built.writable) console.log(chalk.yellow(`  writable: ${p}`));

    if (dryRun) {
      console.log(chalk.dim(`  [dry-run] Would tighten permissions: chmod go-w ${quoted}\n`));
    } else {
      const fix = options.fixPermissions || (!autoYes && await askYesNo("  Remove group/other write bits (chmod go-w) on those paths now?", false));
      if (fix) {
        for (const p of built.writable) {
          try {
            const mode = statSync(p).mode & 0o7777;
            chmodSync(p, mode & ~0o022);
            summary.fixedPermissions.push(p);
          } catch {
            summary.failedPermissions.push(p);
          }
        }
        if (summary.fixedPermissions.length > 0) {
          console.log(chalk.green(`  Fixed permissions on ${summary.fixedPermissions.length} path(s).`));
        }
        if (summary.failedPermissions.length > 0) {
          const remQuoted = summary.failedPermissions.map((p) => `'${p.replace(/'/g, "'\\''")}'`).join(" ");
          console.log(chalk.yellow(`  Could not chmod (may need sudo): chmod go-w ${remQuoted}`));
        }
        console.log();
      } else {
        console.log(chalk.dim(`  Run manually if OpenClaw rejects the hook: chmod go-w ${quoted}\n`));
      }
    }
  }

  // 3. Claude Code PostToolUse skill/rule/MCP guard hook
  if (targets.claudeSettings) {
    const ccPath = targets.claudeSettings.path;
    const hookCmd = buildClaudeHookCommand(built.command, built.self);
    console.log(chalk.cyan(`Detected Claude Code settings: ${ccPath}${targets.claudeSettings.exists ? "" : " (will create)"}`));
    try {
      const existing = readJsonObject(ccPath);
      const { updated, changed } = patchClaudeSettings(existing, hookCmd);
      if (!changed) {
        console.log(chalk.green("  Claude Code ClawVet PostToolUse skill/rule guard hook is already configured.\n"));
        summary.claude = "unchanged";
      } else if (dryRun) {
        console.log(chalk.dim("  [dry-run] Would add PostToolUse (Write|Edit) hook to scan edited skills, rules, and MCP configs:"));
        console.log(chalk.dim(`    ${hookCmd}\n`));
        summary.claude = "dry-run";
      } else {
        const proceed = autoYes || await askYesNo(`  Add ClawVet PostToolUse guard hook to ${ccPath} (scans only skills, rules & MCP configs; backup created)?`, true);
        if (proceed) {
          const backup = writeJsonAtomicWithBackup(ccPath, updated);
          if (backup) {
            summary.backups.push(backup);
            console.log(chalk.dim(`  Backup saved: ${backup}`));
          }
          console.log(chalk.green(`  Configured Claude Code guard hook in ${ccPath}\n`));
          summary.claude = "configured";
        } else {
          console.log(chalk.dim("  Skipped Claude Code settings.\n"));
          summary.claude = "skipped";
        }
      }
    } catch (err) {
      console.error(chalk.red(`  Could not update ${ccPath}: ${err instanceof Error ? err.message : String(err)}\n`));
      process.exitCode = 1;
    }
  } else {
    console.log(chalk.dim("Claude Code: not detected (~/.claude not found). Pass --claude-settings <path> if stored elsewhere.\n"));
  }

  // 4. Instant payoff: run a compact multi-agent audit right away
  if (options.audit !== false && !dryRun) {
    console.log(chalk.bold("Running immediate audit of your installed skills, rules, hooks & MCP configs..."));
    await auditCommand({ summary: true, env, cwd });
  } else if (dryRun) {
    console.log(chalk.dim("[dry-run] Skipped audit execution. Run 'clawvet audit --summary' any time to inspect your machine.\n"));
  }

  return summary;
}

const AGENT_FILE_PATTERNS = [
  /(?:^|\/)SKILL\.md$/i,
  /(?:^|\/)\.claude\/(?:skills|commands)\//i,
  /(?:^|\/)\.cursor\/rules\//i,
  /(?:^|\/)\.cursorrules$/i,
  /(?:^|\/)\.codex\/skills\//i,
  /(?:^|\/)(?:AGENTS|CLAUDE)\.md$/,
  /(?:^|\/)\.windsurfrules$/i,
  /(?:^|\/)\.windsurf\/rules\//i,
  /(?:^|\/)(?:\.?mcp|mcp_config|claude_desktop_config)\.json$/i,
  /(?:^|\/)\.claude\/settings(?:\.local)?\.json$/i,
];

export function isWatchedAgentFile(filePath: string): boolean {
  const normalized = filePath.replaceAll("\\", "/");
  return AGENT_FILE_PATTERNS.some((re) => re.test(normalized));
}

function classifyWatchedFile(filePath: string): AuditTarget {
  const normalized = filePath.replaceAll("\\", "/");
  const base = basename(filePath);
  if (/^SKILL\.md$/i.test(base)) {
    return { ecosystem: normalized.includes("/.claude/") ? "claude-code" : "openclaw", kind: "skill-dir", name: basename(dirname(filePath)), path: dirname(filePath) };
  }
  if (/(?:\.?mcp|mcp_config|claude_desktop_config)\.json$/i.test(base)) {
    return { ecosystem: "mcp", kind: "mcp-config", name: `mcp:${base}`, path: filePath };
  }
  if (/^settings(?:\.local)?\.json$/i.test(base) && normalized.includes("/.claude/")) {
    return { ecosystem: "claude-code", kind: "claude-settings", name: base, path: filePath };
  }
  return { ecosystem: "claude-code", kind: "rule-file", name: base, path: filePath };
}

/**
 * Lightweight PostToolUse hook for Claude Code. Reads hook JSON from stdin,
 * returns immediately for normal source files, and emits a structured
 * `systemMessage` warning if a written/edited skill, rule, or MCP config has
 * security risks.
 */
export async function claudeHookCommand(): Promise<void> {
  let raw = "";
  try {
    const chunks: Buffer[] = [];
    let size = 0;
    const deadline = setTimeout(() => process.exit(0), 2000);
    try {
      for await (const chunk of process.stdin) {
        size += (chunk as Buffer).length;
        if (size > 512 * 1024) return;
        chunks.push(chunk as Buffer);
      }
    } finally { clearTimeout(deadline); }
    raw = Buffer.concat(chunks).toString("utf-8").trim();
  } catch {
    return;
  }
  if (!raw) return;

  let payload: { tool_input?: { file_path?: unknown; path?: unknown } };
  try {
    payload = JSON.parse(raw) as { tool_input?: { file_path?: unknown; path?: unknown } };
  } catch {
    return;
  }
  const filePath = typeof payload?.tool_input?.file_path === "string"
    ? payload.tool_input.file_path
    : typeof payload?.tool_input?.path === "string"
      ? payload.tool_input.path
      : undefined;

  if (!filePath || !isWatchedAgentFile(filePath) || !existsSync(filePath)) return;

  try {
    const target = classifyWatchedFile(resolve(filePath));
    const result = await scanAuditTarget(target);
    const risky =
      result.status === "failed" ||
      result.riskGrade === "C" ||
      result.riskGrade === "D" ||
      result.riskGrade === "F" ||
      result.findingsCount.critical > 0 ||
      result.findingsCount.high > 0;
    if (!risky) return;

    const top = result.findings
      .filter((f) => f.severity === "critical" || f.severity === "high" || f.severity === "medium")
      .slice(0, 3)
      .map((f) => `[${f.severity}] ${sanitizeTerminal(f.title)}`)
      .join("; ");
    const msg = `ClawVet security warning for ${sanitizeTerminal(filePath)}: Grade ${result.riskGrade} (risk ${Math.round(result.riskScore)}/100)${top ? ` — ${top}` : ""}. Run 'clawvet scan ${filePath}' to inspect.`;
    process.stdout.write(JSON.stringify({ systemMessage: msg }) + "\n");
  } catch {
    // Advisory hook must never crash Claude Code edits.
  }
}
