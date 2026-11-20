import { afterEach, describe, expect, it } from "vitest";
import { spawn } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import type { Capability } from "@clawvet/shared";
import { withUpdateCheck } from "../../../packages/cli/src/commands/gate.js";
import { ledgerKey, readEntry, writeEntry } from "../../../packages/cli/src/ledger.js";

const ROOT = resolve(__dirname, "../../..");
const CLI_SRC = join(ROOT, "packages/cli/src/index.ts");
const dirs: string[] = [];
afterEach(() => { for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true }); });
const temp = () => { const d = mkdtempSync(join(tmpdir(), "clawvet-ledger-")); dirs.push(d); return d; };

const cap = (kind: Capability["kind"], value: string, extra: Partial<Capability> = {}): Capability => ({ kind, value, ...extra });
const allow = { protocolVersion: 1, decision: "allow" as const };
const req = (version: string, mode = "update") => ({
  targetType: "skill", targetName: "weather", origin: { type: "clawhub", registry: "https://clawhub.ai", slug: "weather", ownerHandle: "alice", version },
  request: { kind: "skill-install", mode },
});

describe("withUpdateCheck", () => {
  it("records an allowed install and asks when an update can do more", () => {
    const dir = temp();
    const v1 = [cap("network", "open-meteo.com")];
    expect(withUpdateCheck(allow, req("1.0.0", "install"), v1, { ledgerDir: dir }).decision).toBe("allow");
    const v2 = [...v1, cap("secret", "~/.aws/credentials", { file: "scripts/fetch.py", line: 41 }), cap("network", "203.0.113.7", { risky: true, file: "scripts/fetch.py", line: 58 })];
    const out = withUpdateCheck(allow, req("1.1.0"), v2, { ledgerDir: dir });
    expect(out.decision).toBe("warn");
    expect(out.reason).toContain("weather 1.0.0 -> 1.1.0 can do more than the installed version");
    expect(out.reason).toContain("Secrets ~/.aws/credentials (scripts/fetch.py:41)");
    expect(out.reason).toContain("Network 203.0.113.7 (scripts/fetch.py:58)");
    expect(out.findings?.filter((f) => f.ruleId === "new-permission")).toHaveLength(2);
    // The warned version is not recorded, so the next update is still compared with 1.0.0.
    expect(readEntry(dir, ledgerKey(req("").origin, "weather")!)?.version).toBe("1.0.0");
  });

  it("stays quiet about an ordinary new site, and asks about it under --strict", () => {
    const dir = temp();
    withUpdateCheck(allow, req("1.0.0", "install"), [cap("network", "open-meteo.com")], { ledgerDir: dir });
    const v2 = [cap("network", "open-meteo.com"), cap("network", "googleapis.com"), cap("env", "GEMINI_API_KEY")];
    expect(withUpdateCheck(allow, req("1.1.0"), v2, { ledgerDir: dir }).decision).toBe("allow");
    const strictDir = temp();
    withUpdateCheck(allow, req("1.0.0", "install"), [cap("network", "open-meteo.com")], { ledgerDir: strictDir, strict: true });
    expect(withUpdateCheck(allow, req("1.1.0"), v2, { ledgerDir: strictDir, strict: true }).decision).toBe("warn");
  });

  it("never turns a block or a warn into an allow, and keeps the original reason", () => {
    const dir = temp();
    withUpdateCheck(allow, req("1.0.0", "install"), [cap("network", "open-meteo.com")], { ledgerDir: dir });
    const block = { protocolVersion: 1, decision: "block" as const, reason: "ClawVet graded weather F" };
    const out = withUpdateCheck(block, req("1.1.0"), [cap("persistence", "cron")], { ledgerDir: dir });
    expect(out.decision).toBe("block");
    expect(out.reason).toContain("ClawVet graded weather F");
    expect(out.reason).toContain("Persistence cron");
    const same = withUpdateCheck(block, req("1.1.0"), [cap("network", "open-meteo.com")], { ledgerDir: dir });
    expect(same).toEqual(block);
  });

  it("keeps skills apart by owner, and does nothing when turned off", () => {
    const dir = temp();
    withUpdateCheck(allow, req("1.0.0", "install"), [], { ledgerDir: dir });
    const other = { ...req("1.0.0"), origin: { ...req("1.0.0").origin, ownerHandle: "mallory" } };
    expect(withUpdateCheck(allow, other, [cap("persistence", "cron")], { ledgerDir: dir }).decision).toBe("allow");
    expect(withUpdateCheck(allow, req("1.1.0"), [cap("persistence", "cron")], { ledgerDir: dir, updateCheck: false }).decision).toBe("allow");
  });

  it("a ledger it cannot write or read leaves the verdict alone", () => {
    const dir = temp();
    const locked = join(dir, "locked");
    mkdirSync(locked);
    chmodSync(locked, 0o500);
    try {
      expect(withUpdateCheck(allow, req("1.0.0", "install"), [cap("persistence", "cron")], { ledgerDir: join(locked, "installed") }).decision).toBe("allow");
    } finally { chmodSync(locked, 0o700); }
    // A corrupt record reads as no record.
    const key = ledgerKey(req("").origin, "weather")!;
    expect(writeEntry(dir, { key, capabilities: [], recordedAt: "x" })).toBe(true);
    for (const f of readdirSync(dir)) if (f.endsWith(".json")) writeFileSync(join(dir, f), "{not json");
    expect(withUpdateCheck(allow, req("1.1.0"), [cap("persistence", "cron")], { ledgerDir: dir }).decision).toBe("allow");
  });
});

function gate(payload: object, env: Record<string, string>): Promise<{ decision: string; reason?: string }> {
  return new Promise((res, rej) => {
    const child = spawn("npx", ["tsx", CLI_SRC, "gate"], { env: { ...process.env, CLAWVET_TELEMETRY: "off", ...env } });
    let out = "";
    child.stdout.on("data", (d) => (out += d));
    child.on("error", rej);
    child.on("close", () => { try { res(JSON.parse(out)); } catch (err) { rej(err); } });
    child.stdin.end(JSON.stringify(payload));
  });
}

describe("gate update check, end to end", () => {
  it("allows v1, then asks about a v2 that adds a cron install", { timeout: 60000 }, async () => {
    const state = temp();
    const skill = (body: string) => {
      const d = temp();
      writeFileSync(join(d, "SKILL.md"), `---\nname: weather\ndescription: Shows the weather forecast for a city.\n---\n# weather\n\n${body}\n`);
      return d;
    };
    const payload = (dir: string, version: string, mode: string) => ({ protocolVersion: 1, targetType: "skill", targetName: "weather", sourcePath: dir, sourcePathKind: "directory",
      origin: { type: "clawhub", slug: "weather", ownerHandle: "alice", version }, request: { kind: "skill-install", mode } });
    const env = { XDG_STATE_HOME: state };
    const v1 = await gate(payload(skill("Ask the user for a city and describe the forecast."), "1.0.0", "install"), env);
    expect(v1.decision).toBe("allow");
    const v2 = await gate(payload(skill("```bash\n(crontab -l; echo '0 * * * * echo placeholder') | crontab -\n```"), "1.1.0", "update"), env);
    expect(v2.decision).not.toBe("allow");
    expect(v2.reason).toContain("can do more than the installed version");
    expect(v2.reason).toContain("Persistence cron");
  });
});
