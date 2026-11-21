import { closeSync, constants, fstatSync, openSync, readSync } from "node:fs";
import { basename, join } from "node:path";
import chalk from "chalk";
import { rescore, scanSkill } from "@clawvet/shared";
import type { Capability, Finding, ScanResult } from "@clawvet/shared";
import { ASSEMBLY_LIMITS } from "./assemble.js";
import { locateCapabilities } from "./capabilities.js";
import { scanLocalSkill, type LocalScanResult } from "./local-scan.js";
import { sanitizeTerminal } from "./output/terminal.js";
import type { AuditEcosystem, AuditTarget, AuditTargetKind } from "./skill-dirs.js";

export interface AuditScanEntry extends LocalScanResult {
  path: string;
  ecosystem: AuditEcosystem;
  kind: AuditTargetKind;
}

export interface MachinePermissionsSummary {
  byEcosystem: Record<string, { scanned: number; findings: number; highRisk: number }>;
  secrets: Array<{ value: string; count: number; items: string[] }>;
  persistence: Array<{ value: string; count: number; items: string[] }>;
  network: {
    totalItems: number;
    riskyItems: number;
    topSites: Array<{ value: string; count: number; risky?: boolean }>;
  };
  env: Array<{ value: string; count: number }>;
  behaviors: Array<{ value: string; count: number; severity?: string }>;
  highRiskCount: number;
}

const ECOSYSTEM_LABELS: Record<AuditEcosystem, string> = {
  openclaw: "OpenClaw",
  "claude-code": "Claude Code",
  cursor: "Cursor",
  codex: "Codex",
  windsurf: "Windsurf",
  mcp: "MCP",
  custom: "Custom",
};

function readBoundedText(filePath: string): { text?: string; error?: string } {
  let fd: number | undefined;
  try {
    fd = openSync(filePath, constants.O_RDONLY | constants.O_NONBLOCK);
    const stat = fstatSync(fd);
    if (!stat.isFile()) return { error: "Target is not a regular file." };
    if (stat.size > ASSEMBLY_LIMITS.fileBytes) {
      return { error: `File exceeds the ${ASSEMBLY_LIMITS.fileBytes / 1024} KiB inspection limit.` };
    }
    const buffer = Buffer.alloc(ASSEMBLY_LIMITS.fileBytes + 1);
    let length = 0;
    while (length < buffer.length) {
      const count = readSync(fd, buffer, length, buffer.length - length, null);
      if (!count) break;
      length += count;
    }
    if (length > ASSEMBLY_LIMITS.fileBytes) {
      return { error: `File exceeds the ${ASSEMBLY_LIMITS.fileBytes / 1024} KiB inspection limit.` };
    }
    const bytes = buffer.subarray(0, length);
    if (bytes.includes(0)) return { error: "File contains binary data." };
    return { text: new TextDecoder("utf-8", { fatal: true }).decode(bytes) };
  } catch (err) {
    return { error: err instanceof Error ? err.message : "Could not read file." };
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

function failedEntry(target: AuditTarget, reason: string): AuditScanEntry {
  return {
    path: target.path,
    ecosystem: target.ecosystem,
    kind: target.kind,
    skillName: target.name,
    skillSource: "local",
    status: "failed",
    riskScore: 0,
    riskGrade: "F",
    findingsCount: { critical: 0, high: 0, medium: 0, low: 0 },
    findings: [],
    recommendation: "block",
    summary: reason,
    capabilities: [],
    coverage: {
      complete: false,
      files: [],
      issues: [{ path: basename(target.path), rule: "unreadable", reason }],
      warnings: [],
    },
  };
}

function stripMetadataAndRescore(result: ScanResult, extraFindings: Finding[] = []): ScanResult {
  const kept = result.findings.filter((f) => f.category !== "metadata");
  return rescore(result, [...kept, ...extraFindings]);
}

function isClawvetOwnHook(command: string): boolean {
  return /\bclawvet\b/i.test(command) && /\b(?:claude-hook|gate)\b/.test(command);
}

function extractClaudeHookCommands(hooksObj: Record<string, unknown>): Array<{ event: string; matcher?: string; command: string }> {
  const out: Array<{ event: string; matcher?: string; command: string }> = [];
  for (const [event, value] of Object.entries(hooksObj)) {
    const list = Array.isArray(value) ? value : [value];
    for (const item of list) {
      if (!item || typeof item !== "object") continue;
      const rec = item as Record<string, unknown>;
      const matcher = typeof rec.matcher === "string" ? rec.matcher : undefined;
      if (typeof rec.command === "string" && rec.command.trim()) {
        out.push({ event, matcher, command: rec.command });
      }
      if (Array.isArray(rec.hooks)) {
        for (const inner of rec.hooks) {
          if (!inner || typeof inner !== "object") continue;
          const innerRec = inner as Record<string, unknown>;
          if (typeof innerRec.command === "string" && innerRec.command.trim()) {
            out.push({ event, matcher, command: innerRec.command });
          }
        }
      }
    }
  }
  return out;
}

const LOCAL_HOST_URL = /^http:\/\/(?:localhost|127\.0\.0\.1|\[::1\]|0\.0\.0\.0)(?::\d+)?(?:\/|$)/i;

function formatArg(arg: string): string {
  if (/^[A-Za-z0-9_./:@~=-]+$/.test(arg)) return arg;
  return JSON.stringify(arg);
}

function extractMcpCommands(
  serversObj: Record<string, unknown>,
): { scriptLines: string[]; extraFindings: Finding[] } {
  const scriptLines: string[] = [];
  const extraFindings: Finding[] = [];

  for (const [serverName, rawCfg] of Object.entries(serversObj)) {
    if (!rawCfg || typeof rawCfg !== "object" || Array.isArray(rawCfg)) continue;
    const cfg = rawCfg as Record<string, unknown>;
    scriptLines.push(`# mcp server: ${serverName}`);

    if (typeof cfg.command === "string" && cfg.command.trim()) {
      const args = Array.isArray(cfg.args)
        ? cfg.args.filter((a): a is string => typeof a === "string")
        : [];
      const joined = [cfg.command.trim(), ...args.map(formatArg)].join(" ");
      scriptLines.push(joined);

      // Detect shell -c / -lc wrappers with inline payloads directly inside MCP server commands.
      const baseCmd = basename(cfg.command.trim()).toLowerCase();
      if ((baseCmd === "sh" || baseCmd === "bash" || baseCmd === "zsh") && args.some((a) => /^-[a-z]*c$/i.test(a))) {
        const idx = args.findIndex((a) => /^-[a-z]*c$/i.test(a));
        const inline = args[idx + 1];
        if (inline) {
          scriptLines.push(inline);
        }
      }
    }

    const remoteUrl = [cfg.url, cfg.serverUrl, cfg.endpoint].find((u): u is string => typeof u === "string" && u.trim().length > 0);
    if (remoteUrl) {
      scriptLines.push(`curl -fsSL ${formatArg(remoteUrl.trim())}`);
      if (/^http:\/\//i.test(remoteUrl.trim()) && !LOCAL_HOST_URL.test(remoteUrl.trim())) {
        extraFindings.push({
          id: "mcp-insecure-http",
          category: "network_security",
          severity: "medium",
          title: `Remote MCP server "${serverName}" uses unencrypted HTTP`,
          description: "Tool calls and credentials sent to a remote MCP endpoint over plain HTTP can be intercepted or modified in transit.",
          evidence: remoteUrl.trim().slice(0, 120),
          analysisPass: "mcp-audit",
          confidence: 0.9,
          fix: "Switch the MCP server endpoint to HTTPS.",
        });
      }
    }

    if (cfg.env && typeof cfg.env === "object" && !Array.isArray(cfg.env)) {
      for (const [k, v] of Object.entries(cfg.env as Record<string, unknown>)) {
        if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(k)) continue;
        if (typeof v === "string") {
          // Template reference like ${OPENAI_API_KEY} -> expose as env read; literal -> expose assignment so hardcoded secrets are scanned.
          if (/^\$\{?[A-Z][A-Z0-9_]{2,}\}?$/.test(v.trim())) {
            scriptLines.push(`export ${k}=${v.trim()}`);
          } else if (v.trim().length > 0) {
            scriptLines.push(`export ${k}=${JSON.stringify(v)}`);
          } else {
            scriptLines.push(`echo "$${k}"`);
          }
        }
      }
    }
  }
  return { scriptLines, extraFindings };
}

export async function scanAuditTarget(target: AuditTarget): Promise<AuditScanEntry> {
  if (target.kind === "skill-dir") {
    const result = await scanLocalSkill(join(target.path, "SKILL.md"), { skillName: target.name });
    return {
      ...result,
      capabilities: locateCapabilities(result.capabilities, result.coverage?.files),
      path: target.path,
      ecosystem: target.ecosystem,
      kind: target.kind,
    };
  }

  const read = readBoundedText(target.path);
  if (read.error || read.text === undefined) {
    return failedEntry(target, read.error ?? "Could not read file.");
  }

  const fileLabel = basename(target.path);
  const makeCoverage = (text: string) => ({
    complete: true,
    files: [{ path: fileLabel, startLine: 1, endLine: text.split("\n").length }],
    issues: [],
    warnings: [],
  });

  if (target.kind === "rule-file") {
    const raw = await scanSkill(read.text, {
      skillName: target.name,
      files: [{ path: fileLabel, startLine: 1, endLine: read.text.split("\n").length }],
    });
    const cleaned = stripMetadataAndRescore(raw);
    const coverage = makeCoverage(read.text);
    return {
      ...cleaned,
      capabilities: locateCapabilities(cleaned.capabilities, coverage.files),
      coverage,
      path: target.path,
      ecosystem: target.ecosystem,
      kind: target.kind,
    };
  }

  if (target.kind === "claude-settings") {
    let parsed: Record<string, unknown>;
    try {
      parsed = JSON.parse(read.text) as Record<string, unknown>;
    } catch {
      return failedEntry(target, "Could not parse Claude settings JSON.");
    }
    const hooksObj = (parsed.hooks && typeof parsed.hooks === "object" && !Array.isArray(parsed.hooks))
      ? (parsed.hooks as Record<string, unknown>)
      : {};
    const hookCommands = extractClaudeHookCommands(hooksObj).filter((h) => !isClawvetOwnHook(h.command));
    const lines = [
      `---`,
      `name: ${target.name}`,
      `description: Claude Code hooks configuration`,
      `---`,
      "```bash",
      ...hookCommands.flatMap((h) => [
        `# hook: ${h.event}${h.matcher ? ` (${h.matcher})` : ""}`,
        h.command,
      ]),
      "```",
    ];
    const synthetic = lines.join("\n") + "\n";
    const raw = await scanSkill(synthetic, { skillName: target.name });
    const cleaned = stripMetadataAndRescore(raw);
    const coverage = makeCoverage(synthetic);
    return {
      ...cleaned,
      capabilities: (cleaned.capabilities ?? []).map((c) => ({ ...c, file: fileLabel })),
      coverage,
      path: target.path,
      ecosystem: target.ecosystem,
      kind: target.kind,
    };
  }

  // mcp-config
  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(read.text) as Record<string, unknown>;
  } catch {
    return failedEntry(target, "Could not parse MCP configuration JSON.");
  }
  const serversObj: Record<string, unknown> = {
    ...(parsed.mcpServers && typeof parsed.mcpServers === "object" && !Array.isArray(parsed.mcpServers)
      ? (parsed.mcpServers as Record<string, unknown>)
      : {}),
    ...(parsed.servers && typeof parsed.servers === "object" && !Array.isArray(parsed.servers)
      ? (parsed.servers as Record<string, unknown>)
      : {}),
  };
  const { scriptLines, extraFindings } = extractMcpCommands(serversObj);
  const synthetic = [
    "---",
    `name: ${target.name}`,
    "description: MCP server configuration",
    "---",
    "```bash",
    ...scriptLines,
    "```",
  ].join("\n") + "\n";
  const raw = await scanSkill(synthetic, { skillName: target.name });
  const cleaned = stripMetadataAndRescore(raw, extraFindings);
  const coverage = makeCoverage(synthetic);
  return {
    ...cleaned,
    capabilities: (cleaned.capabilities ?? []).map((c) => ({ ...c, file: fileLabel })),
    coverage,
    path: target.path,
    ecosystem: target.ecosystem,
    kind: target.kind,
  };
}

export function summarizeAuditPermissions(entries: AuditScanEntry[]): MachinePermissionsSummary {
  const byEcosystem: Record<string, { scanned: number; findings: number; highRisk: number }> = {};
  const secretMap = new Map<string, Set<string>>();
  const persistMap = new Map<string, Set<string>>();
  const siteMap = new Map<string, { items: Set<string>; risky: boolean }>();
  const envMap = new Map<string, Set<string>>();
  const behaviorMap = new Map<string, { items: Set<string>; severity?: string }>();
  const networkItems = new Set<string>();
  const riskyNetworkItems = new Set<string>();
  let highRiskCount = 0;

  for (const entry of entries) {
    const eco = entry.ecosystem;
    if (!byEcosystem[eco]) byEcosystem[eco] = { scanned: 0, findings: 0, highRisk: 0 };
    byEcosystem[eco].scanned++;
    byEcosystem[eco].findings += entry.findings.length;

    const isHighRisk =
      entry.status === "failed" ||
      entry.riskGrade === "D" ||
      entry.riskGrade === "F" ||
      entry.findingsCount.critical > 0 ||
      entry.findingsCount.high > 0;
    if (isHighRisk) {
      highRiskCount++;
      byEcosystem[eco].highRisk++;
    }

    const itemLabel = entry.skillName || basename(entry.path);
    const caps: Capability[] = entry.capabilities ?? [];
    for (const c of caps) {
      if (c.kind === "secret") {
        let s = secretMap.get(c.value);
        if (!s) { s = new Set(); secretMap.set(c.value, s); }
        s.add(itemLabel);
      } else if (c.kind === "persistence") {
        let s = persistMap.get(c.value);
        if (!s) { s = new Set(); persistMap.set(c.value, s); }
        s.add(itemLabel);
      } else if (c.kind === "network") {
        networkItems.add(entry.path);
        if (c.risky) riskyNetworkItems.add(entry.path);
        let rec = siteMap.get(c.value);
        if (!rec) { rec = { items: new Set(), risky: false }; siteMap.set(c.value, rec); }
        rec.items.add(itemLabel);
        if (c.risky) rec.risky = true;
      } else if (c.kind === "env") {
        let s = envMap.get(c.value);
        if (!s) { s = new Set(); envMap.set(c.value, s); }
        s.add(itemLabel);
      } else if (c.kind === "behavior") {
        let rec = behaviorMap.get(c.value);
        if (!rec) { rec = { items: new Set(), severity: c.severity }; behaviorMap.set(c.value, rec); }
        rec.items.add(itemLabel);
        if (c.severity === "critical") rec.severity = "critical";
      }
    }
  }

  return {
    byEcosystem,
    secrets: [...secretMap.entries()]
      .map(([value, items]) => ({ value, count: items.size, items: [...items].sort() }))
      .sort((a, b) => b.count - a.count || a.value.localeCompare(b.value)),
    persistence: [...persistMap.entries()]
      .map(([value, items]) => ({ value, count: items.size, items: [...items].sort() }))
      .sort((a, b) => b.count - a.count || a.value.localeCompare(b.value)),
    network: {
      totalItems: networkItems.size,
      riskyItems: riskyNetworkItems.size,
      topSites: [...siteMap.entries()]
        .map(([value, rec]) => ({ value, count: rec.items.size, ...(rec.risky ? { risky: true } : {}) }))
        .sort((a, b) => Number(Boolean(b.risky)) - Number(Boolean(a.risky)) || b.count - a.count || a.value.localeCompare(b.value))
        .slice(0, 12),
    },
    env: [...envMap.entries()]
      .map(([value, items]) => ({ value, count: items.size }))
      .sort((a, b) => b.count - a.count || a.value.localeCompare(b.value)),
    behaviors: [...behaviorMap.entries()]
      .map(([value, rec]) => ({ value, count: rec.items.size, ...(rec.severity ? { severity: rec.severity } : {}) }))
      .sort((a, b) => b.count - a.count || a.value.localeCompare(b.value)),
    highRiskCount,
  };
}

const GRADE_COLORS: Record<string, (s: string) => string> = {
  A: chalk.green.bold,
  B: chalk.greenBright,
  C: chalk.yellow.bold,
  D: chalk.redBright.bold,
  F: chalk.bgRed.white.bold,
};

export function printCompactAuditRow(entry: AuditScanEntry): void {
  const eco = ECOSYSTEM_LABELS[entry.ecosystem] ?? entry.ecosystem;
  const grade = entry.status === "failed" ? chalk.bgRed.white.bold(" ERR ") : (GRADE_COLORS[entry.riskGrade] ?? chalk.white)(` ${entry.riskGrade} `);
  const score = entry.status === "failed" ? "inc " : `${String(Math.round(entry.riskScore)).padStart(3)} `;
  const caps = entry.capabilities ?? [];
  const highlights: string[] = [];
  const secrets = caps.filter((c) => c.kind === "secret").map((c) => c.value);
  const persist = caps.filter((c) => c.kind === "persistence").map((c) => c.value);
  const riskySites = caps.filter((c) => c.kind === "network" && c.risky).map((c) => c.value);
  if (secrets.length) highlights.push(chalk.red(`secrets:${secrets.slice(0, 2).join(",")}`));
  if (persist.length) highlights.push(chalk.yellow(`persist:${persist.slice(0, 2).join(",")}`));
  if (riskySites.length) highlights.push(chalk.magenta(`risky:${riskySites.slice(0, 2).join(",")}`));
  if (!highlights.length && entry.findings.length > 0) {
    highlights.push(chalk.dim(`${entry.findings.length} finding${entry.findings.length === 1 ? "" : "s"}`));
  }
  const extra = highlights.length ? `  ${highlights.join(" ")}` : "";
  console.log(`  ${grade} ${chalk.dim(score)} ${chalk.cyan(eco.padEnd(11))} ${sanitizeTerminal(entry.skillName)}${extra}`);
}

export function printMachinePermissionsSummary(
  entries: AuditScanEntry[],
  permissions: MachinePermissionsSummary,
  grades: Record<string, number>,
  totalThreats: number,
): void {
  const totalScanned = entries.length;
  console.log();
  console.log(chalk.bold("━".repeat(60)));
  console.log(chalk.bold("  Machine Permissions Summary"));
  console.log(chalk.bold("━".repeat(60)));

  const ecoParts = Object.entries(permissions.byEcosystem)
    .map(([eco, stats]) => `${ECOSYSTEM_LABELS[eco as AuditEcosystem] ?? eco}: ${stats.scanned}`)
    .join(", ");

  console.log(`  Scanned:     ${chalk.bold(String(totalScanned))} item${totalScanned === 1 ? "" : "s"}${ecoParts ? chalk.dim(` (${ecoParts})`) : ""}, ${totalThreats} finding${totalThreats === 1 ? "" : "s"}`);

  if (totalScanned > 0) {
    const gradeSummary = (["A", "B", "C", "D", "F"] as const)
      .filter((g) => grades[g] > 0)
      .map((g) => `${GRADE_COLORS[g](g)} ${grades[g]}`)
      .join("  ");
    if (gradeSummary) console.log(`  Grades:      ${gradeSummary}`);
  }

  if (permissions.secrets.length > 0) {
    const list = permissions.secrets
      .slice(0, 5)
      .map((s) => `${chalk.red.bold(String(s.count))} access ${sanitizeTerminal(s.value)}`)
      .join(", ");
    console.log(`  Secrets:     ${list}`);
  } else {
    console.log(`  Secrets:     ${chalk.green("0 items access host credential stores")}`);
  }

  if (permissions.persistence.length > 0) {
    const list = permissions.persistence
      .slice(0, 4)
      .map((p) => `${chalk.yellow.bold(String(p.count))} write ${sanitizeTerminal(p.value)}`)
      .join(", ");
    console.log(`  Persistence: ${list}`);
  } else {
    console.log(`  Persistence: ${chalk.green("0 items write OS startup/cron persistence")}`);
  }

  if (permissions.network.totalItems > 0) {
    const riskyPart = permissions.network.riskyItems > 0
      ? chalk.red(` (${permissions.network.riskyItems} risky: ${permissions.network.topSites.filter((s) => s.risky).slice(0, 3).map((s) => sanitizeTerminal(s.value)).join(", ")})`)
      : chalk.dim(` (top: ${permissions.network.topSites.slice(0, 3).map((s) => sanitizeTerminal(s.value)).join(", ")})`);
    console.log(`  Network:     ${permissions.network.totalItems} item${permissions.network.totalItems === 1 ? "" : "s"} contact external hosts${riskyPart}`);
  } else {
    console.log(`  Network:     ${chalk.green("0 items contact external hosts")}`);
  }

  if (permissions.env.length > 0) {
    const topEnv = permissions.env.slice(0, 4).map((e) => `${sanitizeTerminal(e.value)} (${e.count})`).join(", ");
    const more = permissions.env.length > 4 ? chalk.dim(` +${permissions.env.length - 4} more`) : "";
    console.log(`  Env vars:    ${topEnv}${more}`);
  }

  if (permissions.highRiskCount > 0) {
    console.log(`  High-risk:   ${chalk.red.bold(`${permissions.highRiskCount} item${permissions.highRiskCount === 1 ? "" : "s"} graded D/F or with high/critical findings — review before use`)}`);
  } else if (totalScanned > 0) {
    console.log(`  High-risk:   ${chalk.green("0 high-risk items detected")}`);
  }
  console.log(chalk.bold("━".repeat(60)));
  console.log();
}
