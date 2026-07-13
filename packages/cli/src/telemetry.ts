import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { join } from "node:path";
import { homedir, platform, release } from "node:os";
import { randomUUID, createHash } from "node:crypto";
import type { ScanResult } from "@clawvet/shared";

const CONFIG_DIR = join(homedir(), ".clawvet");
const CONFIG_FILE = join(CONFIG_DIR, "config.json");
const TELEMETRY_ENDPOINT = "https://bazzzz--0ab7a9301f3911f1ab9942dde27851f2.web.val.run";

// Never send raw skill names — that would leak what skills a user has
// installed (including private/internal ones) to the telemetry endpoint.
// A SHA-256 hash still lets us correlate a *known public* skill across devices
// (hash the public name and match), but arbitrary/private names stay
// unrecoverable, so nothing sensitive leaves the machine in cleartext.
function hashSkillName(name: string): string {
  return createHash("sha256").update(name).digest("hex").slice(0, 16);
}

// Tag traffic so dev/CI runs can be excluded from product metrics server-side
// instead of polluting them (the "dev-local" rows problem).
function detectEnvironment(): "ci" | "development" | "production" {
  if (process.env.CI || process.env.GITHUB_ACTIONS) return "ci";
  if (process.env.CLAWVET_ENV === "development" || process.env.NODE_ENV === "development") {
    return "development";
  }
  return "production";
}

function readCliVersion(): string {
  try {
    const pkg = JSON.parse(
      readFileSync(new URL("../package.json", import.meta.url), "utf-8")
    );
    return pkg.version ?? "0.0.0";
  } catch {
    return "0.0.0";
  }
}

interface Config {
  telemetry?: "on" | "off" | undefined; // undefined = not yet asked
  deviceId?: string;
  scanCount?: number;
}

function loadConfig(): Config {
  try {
    if (existsSync(CONFIG_FILE)) {
      return JSON.parse(readFileSync(CONFIG_FILE, "utf-8"));
    }
  } catch {
    // corrupted config, start fresh
  }
  return {};
}

function saveConfig(config: Config): void {
  try {
    mkdirSync(CONFIG_DIR, { recursive: true });
    writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2));
  } catch {
    // non-critical, ignore
  }
}

export function isTelemetryEnabled(): boolean {
  const env = process.env.CLAWVET_TELEMETRY;
  if (env === "0" || env === "off") return false;
  if (env === "1" || env === "on") return true;
  const config = loadConfig();
  return config.telemetry === "on";
}

export function setTelemetry(enabled: boolean): void {
  const config = loadConfig();
  config.telemetry = enabled ? "on" : "off";
  saveConfig(config);
}

export function hasBeenAsked(): boolean {
  const config = loadConfig();
  return config.telemetry !== undefined;
}

function getDeviceId(): string {
  const config = loadConfig();
  if (!config.deviceId) {
    config.deviceId = randomUUID();
    saveConfig(config);
  }
  return config.deviceId;
}

function incrementScanCount(): number {
  const config = loadConfig();
  config.scanCount = (config.scanCount || 0) + 1;
  saveConfig(config);
  return config.scanCount;
}

export function getScanCount(): number {
  return loadConfig().scanCount || 0;
}

export function sendTelemetry(result: ScanResult): Promise<void> {
  if (!isTelemetryEnabled()) return Promise.resolve();

  const scanCount = incrementScanCount();

  const payload = {
    event: "scan_completed",
    deviceId: getDeviceId(),
    scanCount,
    ts: new Date().toISOString(),
    os: platform(),
    osVersion: release(),
    cliVersion: readCliVersion(),
    environment: detectEnvironment(),
    skillHash: hashSkillName(result.skillName),
    riskScore: result.riskScore,
    riskGrade: result.riskGrade,
    findingsCount: result.findingsCount,
    cached: result.cached ?? false,
  };

  return post(payload);
}

export interface AuditSummary {
  skillsScanned: number;
  findingsTotal: number;
  grades: Record<string, number>;
  durationMs: number;
}

/**
 * One session-level event summarising a whole `clawvet audit` run, instead of
 * one event per scanned skill. Lets an audit of N skills register as a single
 * data point (the strongest usage signal) without inflating scan counts.
 */
export function sendAuditTelemetry(summary: AuditSummary): Promise<void> {
  if (!isTelemetryEnabled()) return Promise.resolve();

  const payload = {
    event: "audit_completed",
    deviceId: getDeviceId(),
    ts: new Date().toISOString(),
    os: platform(),
    osVersion: release(),
    cliVersion: readCliVersion(),
    environment: detectEnvironment(),
    skillsScanned: summary.skillsScanned,
    findingsTotal: summary.findingsTotal,
    grades: summary.grades,
    durationMs: summary.durationMs,
  };

  return post(payload);
}

function post(payload: unknown): Promise<void> {
  return fetch(TELEMETRY_ENDPOINT, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(3000),
  })
    .then(() => {})
    .catch(() => {
      // silently ignore — telemetry is best-effort
    });
}
