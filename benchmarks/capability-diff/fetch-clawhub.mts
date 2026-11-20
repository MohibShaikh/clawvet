// Download recent version pairs of the most-downloaded ClawHub skills, for
// measuring how often a benign update changes its capabilities. Archives go to
// a cache outside the repo and are never executed.
//
//   npx tsx benchmarks/capability-diff/fetch-clawhub.mts [skills=400] [versions=6]
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

const API = "https://clawhub.ai/api/v1";
const CACHE = process.env.CLAWHUB_CACHE ?? join(homedir(), ".cache/clawvet-bench/clawhub");
const wantSkills = Number(process.argv[2] ?? 400);
const perSkill = Number(process.argv[3] ?? 6);

async function json(url: string): Promise<any> {
  for (let attempt = 0; ; attempt++) {
    const res = await fetch(url);
    if (res.ok) return res.json();
    if (attempt >= 4 || res.status < 429) throw new Error(`${res.status} ${url}`);
    await new Promise((r) => setTimeout(r, 2000 * 2 ** attempt));
  }
}

// A slug can belong to several publishers; the owner handle picks one.
const query = (s: Skill) => `slug=${encodeURIComponent(s.slug)}&ownerHandle=${encodeURIComponent(s.owner)}`;

async function download(skill: Skill, version: string): Promise<boolean> {
  const dir = join(CACHE, skill.owner, skill.slug), dest = join(dir, version);
  if (existsSync(dest)) return true;
  let res = await fetch(`${API}/download?${query(skill)}&version=${encodeURIComponent(version)}`);
  for (let attempt = 0; res.status === 429 && attempt < 4; attempt++) {
    await new Promise((r) => setTimeout(r, 2000 * 2 ** attempt));
    res = await fetch(`${API}/download?${query(skill)}&version=${encodeURIComponent(version)}`);
  }
  if (!res.ok) { console.error(`download ${skill.owner}/${skill.slug}@${version}: ${res.status}`); return false; }
  mkdirSync(dir, { recursive: true });
  const tmp = mkdtempSync(join(dir, ".tmp-"));
  writeFileSync(join(tmp, "a.zip"), Buffer.from(await res.arrayBuffer()));
  try {
    // unzip refuses absolute paths and ../ entries.
    execFileSync("unzip", ["-qq", "-o", "a.zip", "-d", "x"], { cwd: tmp, stdio: "ignore" });
    rmSync(join(tmp, "x", "_meta.json"), { force: true });
    renameSync(join(tmp, "x"), dest);
    return true;
  } catch { return false; } finally { rmSync(tmp, { recursive: true, force: true }); }
}

type Skill = { owner: string; slug: string; versions: number };
const skills: Skill[] = [];
for (let cursor: string | undefined; skills.length < wantSkills;) {
  const page = await json(`${API}/skills?limit=200&sort=downloads${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`);
  for (const item of page.items) if (item.ownerHandle) skills.push({ owner: item.ownerHandle, slug: item.slug, versions: item.stats?.versions ?? 0 });
  cursor = page.nextCursor ?? undefined;
  if (!cursor) break;
}
const multi = skills.slice(0, wantSkills).filter((s) => s.versions >= 2);
console.error(`${multi.length} of ${Math.min(wantSkills, skills.length)} skills have two or more versions`);

const manifest: { slug: string; versions: string[] }[] = [];
let next = 0;
async function worker() {
  while (next < multi.length) {
    const skill = multi[next++];
    const slug = `${skill.owner}/${skill.slug}`;
    try {
      const list = await json(`${API}/skills/${encodeURIComponent(skill.slug)}/versions?limit=${perSkill}&ownerHandle=${encodeURIComponent(skill.owner)}`);
      const versions: string[] = [];
      for (const item of list.items.slice(0, perSkill)) if (await download(skill, item.version)) versions.push(item.version);
      // Oldest first, so consecutive entries are (before, after) pairs.
      manifest.push({ slug, versions: versions.reverse() });
    } catch (err) { console.error(`skip ${slug}: ${(err as Error).message}`); }
  }
}
await Promise.all(Array.from({ length: 6 }, worker));
manifest.sort((a, b) => a.slug.localeCompare(b.slug));
writeFileSync(join(CACHE, "manifest.json"), JSON.stringify(manifest, null, 1));
console.error(`${manifest.reduce((n, m) => n + Math.max(0, m.versions.length - 1), 0)} version pairs in ${join(CACHE, "manifest.json")}`);
