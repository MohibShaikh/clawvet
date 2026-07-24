#!/usr/bin/env node
// Verify a clawvet release is consistent everywhere it is published.
//
// Every check here exists because that exact drift actually happened:
// npm shipped 0.8.0 while git had no tag and no commit for it; ClawHub served
// 0.6.3 while its own listing advertised 0.7-0.8 features; the Releases page
// sat on v0.7.5 while npm was two versions ahead. Assume nothing is in sync
// until it has been read back from the source of truth.
//
//   node scripts/release-check.mjs

import { execFileSync } from "node:child_process";
import { readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const results = [];
let hardFail = false;

function record(level, name, detail) {
  results.push({ level, name, detail });
  if (level === "FAIL") hardFail = true;
}
const pass = (n, d) => record("PASS", n, d);
const warn = (n, d) => record("WARN", n, d);
const fail = (n, d) => record("FAIL", n, d);

function sh(cmd, args, opts = {}) {
  return execFileSync(cmd, args, {
    cwd: ROOT,
    encoding: "utf-8",
    stdio: ["ignore", "pipe", "pipe"],
    ...opts,
  }).trim();
}

// Network / CLI calls that are allowed to be unavailable (offline, no gh auth).
function trySh(cmd, args, opts) {
  try {
    return { ok: true, out: sh(cmd, args, opts) };
  } catch (err) {
    return { ok: false, err: (err.stderr || err.message || "").toString().trim() };
  }
}

async function tryFetchJson(url) {
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(10000) });
    if (!res.ok) return { ok: false, err: `HTTP ${res.status}` };
    return { ok: true, json: await res.json() };
  } catch (err) {
    return { ok: false, err: String(err.message || err) };
  }
}

function frontmatterVersion(file) {
  if (!existsSync(file)) return null;
  const m = readFileSync(file, "utf-8").match(/^---\r?\n([\s\S]*?)\r?\n---/);
  if (!m) return null;
  const v = m[1].match(/^version:\s*(.+)$/m);
  return v ? v[1].trim() : null;
}

// ---------------------------------------------------------------- local state

const pkgPath = join(ROOT, "packages/cli/package.json");
const version = JSON.parse(readFileSync(pkgPath, "utf-8")).version;
const tag = `v${version}`;
console.log(`\nclawvet release check — packages/cli is at ${version}\n`);

// A dirty tree is how 0.8.0 got published to npm without ever being committed.
const status = sh("git", ["status", "--porcelain"]);
const dirty = status
  .split("\n")
  .filter((l) => l.trim() && !l.includes(".vscode/"));
dirty.length
  ? warn("working tree", `${dirty.length} uncommitted change(s) — release from a clean tree`)
  : pass("working tree", "clean");

const branch = sh("git", ["rev-parse", "--abbrev-ref", "HEAD"]);
const ahead = trySh("git", ["rev-list", "--count", `origin/${branch}..HEAD`]);
if (ahead.ok) {
  ahead.out === "0"
    ? pass("branch synced", `${branch} matches origin`)
    : fail("branch synced", `${branch} is ${ahead.out} commit(s) ahead of origin — push first`);
} else {
  warn("branch synced", "could not compare against origin");
}

// ------------------------------------------------------------------- changelog

const changelog = existsSync(join(ROOT, "CHANGELOG.md"))
  ? readFileSync(join(ROOT, "CHANGELOG.md"), "utf-8")
  : "";
changelog.includes(`## ${version}`)
  ? pass("changelog", `has a ## ${version} entry`)
  : fail("changelog", `no "## ${version}" entry in CHANGELOG.md`);

// ------------------------------------------------------------------- git tags

const localTag = trySh("git", ["rev-parse", "--verify", `refs/tags/${tag}`]);
localTag.ok ? pass("git tag", `${tag} exists locally`) : fail("git tag", `${tag} not created`);

const remoteTag = trySh("git", ["ls-remote", "--tags", "origin", tag]);
if (remoteTag.ok) {
  if (remoteTag.out.includes(tag)) {
    pass("tag pushed", `${tag} is on origin`);
  } else {
    fail(
      "tag pushed",
      localTag.ok
        ? `${tag} exists locally but was never pushed — run: git push origin ${tag}`
        : `${tag} is not on origin (it does not exist locally either)`
    );
  }
} else {
  warn("tag pushed", "could not reach origin");
}

// -------------------------------------------------------------- github release

// `isLatest` is not a field in every gh version, so ask the API which release
// GitHub considers latest and compare tag names.
const rel = trySh("gh", ["release", "view", tag, "--json", "tagName,isDraft"]);
if (rel.ok) {
  const r = JSON.parse(rel.out);
  if (r.isDraft) {
    warn("github release", `${tag} exists but is still a draft`);
  } else {
    const latest = trySh("gh", [
      "api",
      "repos/{owner}/{repo}/releases/latest",
      "--jq",
      ".tag_name",
    ]);
    if (!latest.ok) {
      pass("github release", `${tag} is published`);
    } else if (latest.out.trim() === tag) {
      pass("github release", `${tag} is published and is Latest`);
    } else {
      warn(
        "github release",
        `${tag} is published but Releases shows ${latest.out.trim()} as Latest`
      );
    }
  }
} else if (/release not found|not found/i.test(rel.err)) {
  fail("github release", `no Release for ${tag} — tags alone do not update the Releases page`);
} else {
  warn("github release", `gh unavailable — ${rel.err.split("\n")[0]}`);
}

// ----------------------------------------------------------------------- npm

const npmView = trySh("npm", ["view", "clawvet", "version"], { shell: process.platform === "win32" });
if (npmView.ok) {
  const npmVersion = npmView.out.split("\n").pop().trim();
  npmVersion === version
    ? pass("npm", `latest is ${npmVersion}`)
    : warn("npm", `latest is ${npmVersion}, repo is ${version} — not published yet?`);
} else {
  warn("npm", "could not reach the npm registry");
}

// ------------------------------------------------------- plugin + skill layout

const marketplace = join(ROOT, ".claude-plugin/marketplace.json");
const pluginJson = join(ROOT, "plugins/clawvet-guard/.claude-plugin/plugin.json");
for (const [label, file] of [["marketplace.json", marketplace], ["plugin.json", pluginJson]]) {
  if (!existsSync(file)) {
    fail(label, "missing");
    continue;
  }
  try {
    JSON.parse(readFileSync(file, "utf-8"));
    pass(label, "valid JSON");
  } catch (err) {
    fail(label, `invalid JSON — ${err.message}`);
  }
}

// A second copy of a SKILL.md is how a listing starts serving stale content.
const guardCopies = sh("git", ["ls-files", "*clawvet-guard/SKILL.md"])
  .split("\n")
  .filter(Boolean);
if (guardCopies.length === 1) {
  pass("clawvet-guard skill", "exactly one copy tracked");
} else if (guardCopies.length === 0) {
  fail("clawvet-guard skill", "no SKILL.md tracked");
} else {
  const same = guardCopies
    .map((f) => readFileSync(join(ROOT, f), "utf-8"))
    .every((c, _, arr) => c === arr[0]);
  same
    ? warn("clawvet-guard skill", `${guardCopies.length} copies, identical for now — they will drift`)
    : fail("clawvet-guard skill", `${guardCopies.length} copies and they ALREADY differ`);
}

// --------------------------------------------------------------- clawhub state

// ClawHub auto-assigns its own version and ignores SKILL.md frontmatter, so its
// number is reported, never asserted equal to npm.
for (const slug of ["clawvet", "clawvet-guard"]) {
  const r = await tryFetchJson(`https://clawhub.ai/api/v1/skills/${slug}`);
  if (!r.ok) {
    warn(`clawhub/${slug}`, `not publicly reachable (${r.err}) — hidden or unpublished?`);
    continue;
  }
  const desc = r.json?.skill?.description ?? "";
  if (!desc) {
    fail(`clawhub/${slug}`, "listing exists but has no SKILL.md content attached");
    continue;
  }
  const fmv = desc.match(/^version:\s*(.+)$/m);
  pass(`clawhub/${slug}`, `public, serving version ${fmv ? fmv[1].trim() : "unknown"}`);
}

// The root SKILL.md is what a ClawHub re-import reads for the clawvet listing.
const rootSkill = frontmatterVersion(join(ROOT, "SKILL.md"));
if (!rootSkill) {
  warn("SKILL.md", "no version in frontmatter");
} else if (rootSkill === version) {
  pass("SKILL.md", `frontmatter matches package.json (${rootSkill})`);
} else {
  warn("SKILL.md", `frontmatter is ${rootSkill} but package.json is ${version}`);
}

// -------------------------------------------------------------------- summary

const icon = { PASS: "  ok  ", WARN: " warn ", FAIL: " FAIL " };
for (const r of results) console.log(`[${icon[r.level]}] ${r.name.padEnd(22)} ${r.detail}`);

const counts = results.reduce((a, r) => ((a[r.level] = (a[r.level] || 0) + 1), a), {});
console.log(
  `\n${counts.PASS || 0} passed, ${counts.WARN || 0} warnings, ${counts.FAIL || 0} failures\n`
);

process.exit(hardFail ? 1 : 0);
