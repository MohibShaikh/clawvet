import { createHash, randomUUID } from "node:crypto";
import { mkdir, readFile, rename, unlink, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import type { Finding, Severity } from "@clawvet/shared";

// Structural input keeps the CLI independent of shared source paths at build time.
interface PinnedDependency { ecosystem: "PyPI" | "npm"; name: string; version: string; path: string; line: number }

interface Vulnerability {
  id: string;
  aliases?: string[];
  summary?: string;
  severity?: Array<{ type?: string; score: string }>;
  database_specific?: { severity?: string };
  affected?: Array<{ severity?: Array<{ type?: string; score: string }>; ranges?: Array<{ events?: Array<{ fixed?: string }> }> }>;
}
const BATCH_MAX_BYTES = 8 * 1024 * 1024;
const DETAIL_MAX_BYTES = 1024 * 1024;
const SUMMARY_MAX = 300;
const FIXED_MAX = 10;
export interface OsvOptions { timeoutMs?: number; cache?: boolean; fetchImpl?: typeof fetch }

function cvss(value: string): number | undefined {
  if (/^\d+(?:\.\d+)?$/.test(value)) { const n = Number(value); return n >= 0 && n <= 10 ? n : undefined; }
  const metrics = Object.fromEntries(value.split("/").map((s) => s.split(":")));
  const pick = (key: string, values: Record<string, number>) => values[metrics[key]];
  if (/^CVSS:3\.[01]\//.test(value)) {
    const changed = metrics.S === "C";
    if (!["C", "U"].includes(metrics.S)) return undefined;
    const av = pick("AV", { N: .85, A: .62, L: .55, P: .2 });
    const ac = pick("AC", { L: .77, H: .44 });
    const pr = pick("PR", { N: .85, L: changed ? .68 : .62, H: changed ? .5 : .27 });
    const ui = pick("UI", { N: .85, R: .62 });
    const impacts = ["C", "I", "A"].map((k) => pick(k, { H: .56, L: .22, N: 0 }));
    if ([av, ac, pr, ui, ...impacts].some((n) => n === undefined)) return undefined;
    const iss = 1 - impacts.reduce((p, n) => p * (1 - n), 1);
    const impact = changed ? 7.52 * (iss - .029) - 3.25 * (iss - .02) ** 15 : 6.42 * iss;
    if (impact <= 0) return 0;
    const total = (impact + 8.22 * av * ac * pr * ui) * (changed ? 1.08 : 1);
    return Math.ceil((Math.min(total, 10) - 1e-10) * 10) / 10;
  }
  if (metrics.Au) {
    const values = [pick("AV", { L: .395, A: .646, N: 1 }), pick("AC", { H: .35, M: .61, L: .71 }), pick("Au", { M: .45, S: .56, N: .704 })];
    const impacts = ["C", "I", "A"].map((k) => pick(k, { N: 0, P: .275, C: .66 }));
    if ([...values, ...impacts].some((n) => n === undefined)) return undefined;
    const impact = 10.41 * (1 - impacts.reduce((p, n) => p * (1 - n), 1));
    return Math.round(((.6 * impact + .4 * 20 * values.reduce((p, n) => p * n, 1) - 1.5) * (impact ? 1.176 : 0)) * 10) / 10;
  }
  return undefined;
}
function validDetail(value: unknown, id: string): value is Vulnerability {
  if (!value || typeof value !== "object") return false;
  const v = value as Vulnerability;
  if (v.id !== id || (v.summary !== undefined && typeof v.summary !== "string")) return false;
  if (v.aliases !== undefined && (!Array.isArray(v.aliases) || !v.aliases.every((a) => typeof a === "string"))) return false;
  if (v.severity !== undefined && (!Array.isArray(v.severity) || !v.severity.every((s) => s && typeof s.score === "string"))) return false;
  if (v.database_specific?.severity !== undefined && typeof v.database_specific.severity !== "string") return false;
  if (v.affected !== undefined) {
    if (!Array.isArray(v.affected)) return false;
    for (const a of v.affected) {
      if (!a || (a.ranges !== undefined && !Array.isArray(a.ranges))) return false;
      if (a.severity !== undefined && (!Array.isArray(a.severity) || !a.severity.every((s) => s && typeof s.score === "string"))) return false;
      for (const r of a.ranges ?? []) {
        if (!r || (r.events !== undefined && !Array.isArray(r.events))) return false;
        if (r.events?.some((e) => !e || typeof e !== "object")) return false;
      }
    }
  }
  return true;
}

function severity(vuln: Vulnerability): Severity {
  const scores = [...(vuln.severity ?? []), ...(vuln.affected ?? []).flatMap((a) => a.severity ?? [])].map((s) => cvss(s.score)).filter((s): s is number => s !== undefined);
  if (scores.length) { const score = Math.max(...scores); return score >= 9 ? "critical" : score >= 7 ? "high" : score >= 4 ? "medium" : "low"; }
  const fallback = vuln.database_specific?.severity?.toLowerCase();
  return fallback === "critical" || fallback === "high" || fallback === "medium" || fallback === "low" ? fallback : "medium";
}

export async function queryOsv(deps: PinnedDependency[], options: OsvOptions = {}): Promise<{ findings: Finding[]; errors: string[] }> {
  const findings: Finding[] = [];
  const errors: string[] = [];
  if (!deps.length) return { findings, errors };
  const controller = new AbortController();
  const timeoutMs = options.timeoutMs ?? 3000;
  let expire!: () => void;
  const expired = new Promise<never>((_, reject) => { expire = () => { controller.abort(); reject(new Error("OSV deadline exceeded")); }; });
  const timer = setTimeout(expire, timeoutMs);
  // Race every operation too: an injected fetch may ignore AbortSignal.
  const bounded = <T>(p: Promise<T>): Promise<T> => Promise.race([p, expired]);
  const directory = join(process.env.XDG_CACHE_HOME || join(homedir(), ".cache"), "clawvet", "osv");
  const filename = (kind: string, key: string) => join(directory, `${kind}-${createHash("sha256").update(key).digest("hex")}.json`);
  const read = async <T>(kind: string, key: string, ttl: number): Promise<T | undefined> => {
    if (!options.cache) return undefined;
    try {
      const data = JSON.parse(await bounded(readFile(filename(kind, key), "utf8")));
      if (typeof data.time === "number" && data.time <= Date.now() && Date.now() - data.time < ttl) return data.value as T;
    } catch { /* Cache misses and corrupt entries use the network. */ }
    return undefined;
  };
  const write = async (kind: string, key: string, value: unknown) => {
    if (!options.cache || controller.signal.aborted) return;
    const target = filename(kind, key);
    const temp = `${target}.${randomUUID()}.tmp`;
    try {
      await bounded(mkdir(directory, { recursive: true, mode: 0o700 }));
      await bounded(writeFile(temp, JSON.stringify({ time: Date.now(), value }), { mode: 0o600, flag: "wx" }));
      await bounded(rename(temp, target));
    } catch { /* A cache failure must not hide a successful lookup. */ }
    finally { await unlink(temp).catch(() => {}); }
  };
  const fetchImpl = options.fetchImpl ?? globalThis.fetch;
  // Bodies are read with a byte cap before parsing: JSON.parse is synchronous,
  // so an oversized body would hold the deadline off and fill memory.
  const request = async (url: string, init?: RequestInit, maxBytes = DETAIL_MAX_BYTES): Promise<unknown> => {
    if (controller.signal.aborted) throw new Error("OSV deadline exceeded");
    const response = await bounded(fetchImpl(url, { ...init, signal: controller.signal }));
    if (!response.ok) throw new Error(`OSV HTTP ${response.status}`);
    const reader = response.body?.getReader();
    if (!reader) throw new Error("OSV empty response");
    const chunks: Uint8Array[] = [];
    let size = 0;
    for (;;) {
      const { done, value } = await bounded(reader.read());
      if (done) break;
      size += value.byteLength;
      if (size > maxBytes) { await reader.cancel().catch(() => {}); throw new Error("OSV response too large"); }
      chunks.push(value);
    }
    return JSON.parse(new TextDecoder().decode(Buffer.concat(chunks)));
  };
  const keyOf = (dep: PinnedDependency) => JSON.stringify([dep.ecosystem, dep.name, dep.version]);
  const unique = [...new Map(deps.map((d) => [keyOf(d), d])).values()];
  const hits = new Map<string, string[]>();
  const details = new Map<string, Vulnerability>();
  try {
    const missing: PinnedDependency[] = [];
    for (const dep of unique) {
      const cached = await read<unknown>("query", keyOf(dep), 24 * 60 * 60 * 1000);
      if (Array.isArray(cached) && cached.every((id) => typeof id === "string")) hits.set(keyOf(dep), cached);
      else missing.push(dep);
    }
    for (let i = 0; i < missing.length; i += 1000) {
      const batch = missing.slice(i, i + 1000);
      const data = await request("https://api.osv.dev/v1/querybatch", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ queries: batch.map((d) => ({ package: { ecosystem: d.ecosystem, name: d.name }, version: d.version })) }) }, BATCH_MAX_BYTES) as { results?: Array<{ vulns?: unknown }> };
      if (!Array.isArray(data?.results) || data.results.length !== batch.length) throw new Error("OSV malformed batch response");
      for (let j = 0; j < batch.length; j++) {
        const result = data.results[j];
        const listed = result && typeof result === "object" && Array.isArray(result.vulns) ? result.vulns : [];
        // Keep every well-formed id. A malformed neighbour is reported, never a
        // reason to drop the MAL- id next to it.
        const wellFormed = listed.flatMap((v: unknown) => {
          const id = (v as { id?: unknown } | null)?.id;
          return typeof id === "string" && id.length <= 128 ? [id] : [];
        });
        const ids = [...new Set(wellFormed)];
        if (wellFormed.length !== listed.length || (result && typeof result === "object" && result.vulns !== undefined && !Array.isArray(result.vulns))) {
          errors.push(`OSV malformed vulnerability ids for ${batch[j].name}`);
        } else await write("query", keyOf(batch[j]), ids);
        hits.set(keyOf(batch[j]), ids);
      }
    }
    const ids = [...new Set([...hits.values()].flat())];
    let next = 0;
    await Promise.all(Array.from({ length: Math.min(8, ids.length) }, async () => {
      while (next < ids.length && !controller.signal.aborted) {
        const id = ids[next++];
        try {
          let detail = await read<Vulnerability>("vuln", id, 7 * 24 * 60 * 60 * 1000);
          if (!validDetail(detail, id)) {
            detail = await request(`https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`) as Vulnerability;
            if (!validDetail(detail, id)) throw new Error(`OSV malformed details for ${id}`);
            await write("vuln", id, detail);
          }
          details.set(id, detail);
        } catch (e) { errors.push(e instanceof Error ? e.message : String(e)); }
      }
    }));
  } catch (e) { errors.push(e instanceof Error ? e.message : String(e)); }
  finally { clearTimeout(timer); }
  for (const dep of unique) for (const id of hits.get(keyOf(dep)) ?? []) {
    const detail = details.get(id);
    // A MAL identifier remains direct evidence even when its detail lookup fails.
    const malicious = [id, ...(Array.isArray(detail?.aliases) ? detail.aliases : [])].some((alias) => typeof alias === "string" && alias.startsWith("MAL-"));
    if (!detail && !malicious) continue;
    const fixed = [...new Set((Array.isArray(detail?.affected) ? detail.affected : []).flatMap((a) => (a.ranges ?? []).flatMap((r) => (r.events ?? []).flatMap((e) => typeof e.fixed === "string" ? [e.fixed] : []))))];
    findings.push({ category: "dependency_risk", severity: malicious ? "critical" : severity(detail!), disqualifying: malicious,
      title: `${malicious ? "Known malicious dependency" : "Known vulnerable dependency"}: ${id}`, description: `${(detail?.summary ?? id).slice(0, SUMMARY_MAX)}${fixed.length ? ` Fixed versions: ${fixed.slice(0, FIXED_MAX).join(", ")}.` : ""}`,
      evidence: `${dep.name}${dep.ecosystem === "PyPI" ? "==" : "@"}${dep.version}`, lineNumber: dep.line, analysisPass: "osv" });
  }
  return { findings, errors: [...new Set(errors)] };
}
