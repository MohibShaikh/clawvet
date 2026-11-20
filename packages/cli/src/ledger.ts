import { createHash, randomBytes } from "node:crypto";
import { mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { isAbsolute, join } from "node:path";
import type { Capability } from "@clawvet/shared";

// What each installed skill was allowed to do, so an update can be compared
// with it. One small file per skill, written by the gate when it allows an
// install. Kept outside every skill directory, under the user's state dir.
//
// The ledger can only add a question to an update; it never turns a block or
// a warn into an allow. Any read or write problem leaves the verdict as is.

export interface LedgerEntry {
  key: string;
  version?: string;
  capabilities: Pick<Capability, "kind" | "value">[];
  recordedAt: string;
}

/**
 * OpenClaw starts the policy with an empty environment unless passEnv lists
 * names, so HOME is usually absent. os.homedir() falls back to the passwd entry.
 */
export function ledgerDir(env: NodeJS.ProcessEnv = process.env): string | undefined {
  if (env.XDG_STATE_HOME && isAbsolute(env.XDG_STATE_HOME)) return join(env.XDG_STATE_HOME, "clawvet", "installed");
  try {
    const home = homedir();
    return home && isAbsolute(home) ? join(home, ".local", "state", "clawvet", "installed") : undefined;
  } catch {
    return undefined;
  }
}

interface Origin { type?: unknown; registry?: unknown; slug?: unknown; ownerHandle?: unknown }

/** A registry skill is its owner and slug; a local install is its target name. */
export function ledgerKey(origin: Origin | undefined, targetName: string | undefined): string | undefined {
  const str = (v: unknown) => (typeof v === "string" && v ? v : undefined);
  const slug = str(origin?.slug);
  if (slug) return `${str(origin?.registry) ?? str(origin?.type) ?? "registry"}:${str(origin?.ownerHandle) ?? ""}/${slug}`;
  return targetName ? `name:${targetName}` : undefined;
}

const fileFor = (dir: string, key: string) => join(dir, `${createHash("sha256").update(key).digest("hex").slice(0, 32)}.json`);

export function readEntry(dir: string, key: string): LedgerEntry | undefined {
  try {
    const entry = JSON.parse(readFileSync(fileFor(dir, key), "utf8")) as LedgerEntry;
    if (entry?.key !== key || !Array.isArray(entry.capabilities)) return undefined;
    entry.capabilities = entry.capabilities.filter((c) => c && typeof c.kind === "string" && typeof c.value === "string");
    return entry;
  } catch {
    return undefined;
  }
}

/** Atomic per skill, so gates running in parallel never interleave a file. */
export function writeEntry(dir: string, entry: LedgerEntry): boolean {
  const target = fileFor(dir, entry.key);
  const tmp = `${target}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`;
  try {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    writeFileSync(tmp, JSON.stringify(entry), { mode: 0o600, flag: "wx" });
    renameSync(tmp, target);
    return true;
  } catch {
    rmSync(tmp, { force: true });
    return false;
  }
}
