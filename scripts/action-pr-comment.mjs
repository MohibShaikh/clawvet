#!/usr/bin/env node
/**
 * Formats and upserts a sticky ClawVet Permissions Diff PR comment for the
 * GitHub Action (`comment-pr: true`). Zero external dependencies; uses Node 22
 * built-in `fetch`.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const GRADE_COLORS = {
  A: "brightgreen",
  B: "green",
  C: "yellow",
  D: "orange",
  F: "red",
};

const GRADE_LABELS = {
  A: "safe",
  B: "safe",
  C: "review",
  D: "risky",
  F: "dangerous",
};

const KIND_LABELS = {
  network: "Network",
  secret: "Secrets",
  env: "Env vars",
  persistence: "Persistence",
  behavior: "Behaviour",
};

const KIND_ORDER = ["secret", "persistence", "behavior", "network", "env"];
const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3 };

/** Escape untrusted text so it cannot break Markdown tables or inject HTML/links. */
export function escapeMdCell(value) {
  return String(value ?? "")
    .replace(/[\x00-\x08\x0b-\x1f\x7f-\x9f]/g, "")
    .replace(/\r?\n/g, " ")
    .replace(/\\/g, "\\\\")
    .replace(/\|/g, "\\|")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/`/g, "\\`")
    .replace(/\[/g, "\\[")
    .replace(/\]/g, "\\]")
    .trim();
}

export function commentMarker(skillPath) {
  const safe = String(skillPath || ".").replace(/-->/g, "").replace(/[\r\n]/g, "");
  return `<!-- clawvet-pr-comment:${safe} -->`;
}

export function computePermissionsDiff(baseCapabilities = [], headCapabilities = []) {
  const key = (c) => `${c.kind}\u0000${c.value}`;
  const baseKeys = new Set(baseCapabilities.map(key));
  const headKeys = new Set(headCapabilities.map(key));
  return {
    added: headCapabilities.filter((c) => !baseKeys.has(key(c))),
    removed: baseCapabilities.filter((c) => !headKeys.has(key(c))),
    unchanged: headCapabilities.filter((c) => baseKeys.has(key(c))),
  };
}

function formatCapChip(cap) {
  const label = KIND_LABELS[cap.kind] ?? cap.kind;
  const tag = cap.risky ? " (risky)" : cap.declared ? " (declared)" : "";
  const where = cap.file ? ` (${escapeMdCell(cap.file)}${cap.line ? `:${cap.line}` : ""})` : "";
  return `**${label}:** \`${escapeMdCell(cap.value)}\`${tag}${where}`;
}

function formatPermissionsTable(capabilities = []) {
  if (!capabilities.length) {
    return "_No network hosts, credential stores, secret env vars, persistence, or high-risk behaviours detected in code._";
  }
  const rows = [];
  for (const kind of KIND_ORDER) {
    const items = capabilities.filter((c) => c.kind === kind);
    if (!items.length) continue;
    const values = items
      .slice(0, 8)
      .map((c) => `\`${escapeMdCell(c.value)}\`${c.risky ? " (risky)" : c.declared ? " (declared)" : ""}`)
      .join(", ");
    const more = items.length > 8 ? ` (+${items.length - 8} more)` : "";
    rows.push(`| ${KIND_LABELS[kind] ?? kind} | ${values}${more} |`);
  }
  return ["| Category | Detected in code |", "|---|---|", ...rows].join("\n");
}

function locateFinding(finding, files = []) {
  if (!finding.lineNumber) return "";
  const file = files.find((f) => finding.lineNumber >= f.startLine && finding.lineNumber <= f.endLine);
  if (!file) return `L${finding.lineNumber}`;
  return `${escapeMdCell(file.path)}:${finding.lineNumber - file.startLine + 1}`;
}

export function renderPrComment({ skillPath, headResult, baseResult = null, baseRef = "" }) {
  const marker = commentMarker(skillPath);
  const grade = headResult.riskGrade || "F";
  const score = Math.round(Number(headResult.riskScore ?? 0));
  const rec = String(headResult.recommendation || (headResult.status === "failed" ? "block" : "approve")).toUpperCase();
  const label = GRADE_LABELS[grade] || "review";
  const color = GRADE_COLORS[grade] || "lightgrey";
  const badgeUrl = `https://img.shields.io/badge/clawvet-${grade}%20${label}-${color}`;
  const repoLink = "https://github.com/MohibShaikh/clawvet";
  const name = escapeMdCell(headResult.skillName || skillPath || "skill");

  const lines = [
    marker,
    `### ClawVet Security Report: \`${name}\``,
    "",
    `[![ClawVet ${grade}](${badgeUrl})](${repoLink}) &nbsp; **Grade ${grade}** (risk **${score}/100**) &nbsp;|&nbsp; Verdict: **${rec}**`,
    "",
  ];

  if (headResult.status === "failed") {
    lines.push(
      `> **Inspection incomplete:** ${escapeMdCell(headResult.summary || "Some referenced files could not be inspected.")}`,
      "",
    );
  }

  const headCaps = Array.isArray(headResult.capabilities) ? headResult.capabilities : [];
  if (baseResult && typeof baseResult === "object") {
    const baseCaps = Array.isArray(baseResult.capabilities) ? baseResult.capabilities : [];
    const baseScore = Math.round(Number(baseResult.riskScore ?? 0));
    const baseGrade = baseResult.riskGrade || "?";
    const delta = score - baseScore;
    const deltaStr = delta === 0 ? "0" : delta > 0 ? `+${delta}` : `${delta}`;
    const diff = computePermissionsDiff(baseCaps, headCaps);
    const refNote = baseRef ? ` vs \`${escapeMdCell(baseRef)}\`` : "";

    lines.push(`#### Permissions Diff${refNote}`);
    lines.push(`- Risk change: **Grade ${baseGrade} (${baseScore}) -> Grade ${grade} (${score})** (${deltaStr})`);

    if (diff.added.length === 0 && diff.removed.length === 0) {
      lines.push("- **No permission changes in this PR.**");
    } else {
      if (diff.added.length > 0) {
        lines.push(`- **Added permissions (${diff.added.length}):**`);
        for (const c of diff.added.slice(0, 12)) {
          lines.push(`  - \`+\` ${formatCapChip(c)}`);
        }
        if (diff.added.length > 12) lines.push(`  - _...+${diff.added.length - 12} more_`);
      } else {
        lines.push("- **Added permissions:** none");
      }
      if (diff.removed.length > 0) {
        lines.push(`- **Removed permissions (${diff.removed.length}):**`);
        for (const c of diff.removed.slice(0, 8)) {
          lines.push(`  - \`-\` ${formatCapChip(c)}`);
        }
        if (diff.removed.length > 8) lines.push(`  - _...+${diff.removed.length - 8} more_`);
      }
    }
    lines.push("");
    lines.push("<details><summary>All current permissions</summary>", "", formatPermissionsTable(headCaps), "", "</details>", "");
  } else {
    lines.push("#### Permissions (what this skill's code can do)", "", formatPermissionsTable(headCaps), "");
  }

  const findings = Array.isArray(headResult.findings) ? [...headResult.findings] : [];
  findings.sort((a, b) => (SEVERITY_RANK[a.severity] ?? 9) - (SEVERITY_RANK[b.severity] ?? 9));

  if (findings.length > 0) {
    const files = headResult.coverage?.files ?? [];
    lines.push(`#### Findings (${findings.length})`, "", "| Severity | Finding | Location | Evidence |", "|---|---|---|---|");
    for (const f of findings.slice(0, 10)) {
      const sev = escapeMdCell(String(f.severity || "info").toUpperCase());
      const title = escapeMdCell(f.title || f.category || "Finding");
      const loc = locateFinding(f, files) || "-";
      const ev = f.evidence ? `\`${escapeMdCell(String(f.evidence).slice(0, 72))}\`` : "-";
      lines.push(`| **${sev}** | ${title} | ${loc} | ${ev} |`);
    }
    if (findings.length > 10) {
      lines.push("", `_...and ${findings.length - 10} more finding(s). Run \`clawvet scan ${escapeMdCell(skillPath)}\` locally for the full report._`);
    }
    lines.push("");
  } else {
    lines.push("#### Findings", "", "No security findings detected.", "");
  }

  if (headResult.status !== "failed") {
    const mdBadge = `[![ClawVet ${grade}](${badgeUrl})](${repoLink})`;
    lines.push(
      "<details><summary>README Trust Badge</summary>",
      "",
      "```markdown",
      mdBadge,
      "```",
      "",
      "</details>",
      "",
    );
  }

  lines.push(
    "---",
    `Scanned by [ClawVet](${repoLink}) · Audit your local agent skills, rules & MCP configs: \`npm i -g clawvet && clawvet audit\``,
  );
  return lines.join("\n");
}

export async function upsertPrComment({
  token,
  repo,
  prNumber,
  marker,
  body,
  apiBase = "https://api.github.com",
  fetchImpl = fetch,
}) {
  const headers = {
    Authorization: `Bearer ${token}`,
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "Content-Type": "application/json",
    "User-Agent": "clawvet-action",
  };

  let existingId = null;
  for (let page = 1; page <= 5; page++) {
    const listUrl = `${apiBase}/repos/${repo}/issues/${prNumber}/comments?per_page=100&page=${page}`;
    const res = await fetchImpl(listUrl, { headers });
    if (!res.ok) {
      throw new Error(`Failed to list PR comments (${res.status}): ${await res.text()}`);
    }
    const comments = await res.json();
    if (!Array.isArray(comments) || comments.length === 0) break;
    const match = comments.find((c) => typeof c?.body === "string" && c.body.includes(marker));
    if (match) {
      existingId = match.id;
      break;
    }
    if (comments.length < 100) break;
  }

  if (existingId != null) {
    const patchUrl = `${apiBase}/repos/${repo}/issues/comments/${existingId}`;
    const res = await fetchImpl(patchUrl, {
      method: "PATCH",
      headers,
      body: JSON.stringify({ body }),
    });
    if (!res.ok) {
      throw new Error(`Failed to update PR comment (${res.status}): ${await res.text()}`);
    }
    return { action: "updated", commentId: existingId };
  }

  const postUrl = `${apiBase}/repos/${repo}/issues/${prNumber}/comments`;
  const res = await fetchImpl(postUrl, {
    method: "POST",
    headers,
    body: JSON.stringify({ body }),
  });
  if (!res.ok) {
    throw new Error(`Failed to create PR comment (${res.status}): ${await res.text()}`);
  }
  const created = await res.json();
  return { action: "created", commentId: created?.id ?? null };
}

async function main() {
  const token = process.env.GITHUB_TOKEN;
  const repo = process.env.GITHUB_REPOSITORY;
  const eventPath = process.env.GITHUB_EVENT_PATH;
  const headJsonPath = process.env.CLAWVET_HEAD_JSON;
  const baseJsonPath = process.env.CLAWVET_BASE_JSON;
  const skillPath = process.env.CLAWVET_INPUT_PATH || ".";
  const baseRef = process.env.CLAWVET_BASE_REF || "";

  if (!token || !repo || !eventPath || !headJsonPath) {
    console.error("ClawVet PR comment skipped: missing GitHub PR context or scan output.");
    return;
  }

  const event = JSON.parse(readFileSync(eventPath, "utf-8"));
  const prNumber = event?.pull_request?.number ?? event?.number;
  if (!prNumber) {
    console.error("ClawVet PR comment skipped: not a pull_request event.");
    return;
  }

  const headResult = JSON.parse(readFileSync(headJsonPath, "utf-8"));
  let baseResult = null;
  if (baseJsonPath) {
    try {
      const raw = readFileSync(baseJsonPath, "utf-8").trim();
      if (raw) baseResult = JSON.parse(raw);
    } catch {
      baseResult = null;
    }
  }

  const marker = commentMarker(skillPath);
  const body = renderPrComment({ skillPath, headResult, baseResult, baseRef });
  const result = await upsertPrComment({ token, repo, prNumber, marker, body });
  console.log(`ClawVet PR comment ${result.action} on ${repo}#${prNumber}`);
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  main().catch((err) => {
    console.error(`ClawVet PR comment warning: ${err instanceof Error ? err.message : String(err)}`);
    process.exitCode = 1;
  });
}
