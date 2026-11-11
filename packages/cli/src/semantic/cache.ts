import { createHash, randomBytes } from "node:crypto";
import { mkdir, readFile, rename, unlink, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import type { SemanticConfig } from "./config.js";
import { PROMPT_VERSION } from "./prompt.js";

const TTL = 7 * 24 * 60 * 60 * 1000;
export function cachePath(content: string, config: SemanticConfig): string {
  // Include the budget too: changing it changes which evidence the judge sees.
  const key = createHash("sha256").update(JSON.stringify([content, config.provider, config.model,
    // The whole endpoint, not the host: one host can route paths to different
    // models or tenants, and a verdict from one must not answer for another.
    new URL(config.baseUrl).href.replace(/\/$/, ""), PROMPT_VERSION, config.runs ?? 1, config.maxChars ?? 60_000])).digest("hex");
  return join(process.env.XDG_CACHE_HOME || join(homedir(), ".cache"), "clawvet", "semantic", `${key}.json`);
}
export async function readCache(path: string): Promise<string[] | undefined> {
  try {
    const entry = JSON.parse(await readFile(path, "utf8"));
    if (typeof entry.createdAt !== "number" || Date.now() - entry.createdAt >= TTL || entry.createdAt > Date.now() ||
        !Array.isArray(entry.verdicts) || !entry.verdicts.every((text: unknown) => typeof text === "string")) return;
    return entry.verdicts;
  } catch { return; }
}
export async function writeCache(path: string, verdicts: string[]): Promise<void> {
  const temp = `${path}.${randomBytes(12).toString("hex")}.tmp`;
  try {
    await mkdir(join(path, ".."), { recursive: true, mode: 0o700 });
    await writeFile(temp, JSON.stringify({ createdAt: Date.now(), verdicts }), { mode: 0o600, flag: "wx" });
    await rename(temp, path);
  } catch {
    // An optional cache must not make an otherwise available judge fail.
  } finally { await unlink(temp).catch(() => {}); }
}
