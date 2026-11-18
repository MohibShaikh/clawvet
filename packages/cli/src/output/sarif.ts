import type { BundledFile, ScanResult, Finding, Severity } from "@clawvet/shared";
import type { AssemblyResult } from "../assemble.js";
import { applyProfile, type Profile } from "../policy.js";

const SEVERITY_TO_SARIF: Record<Severity, string> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
};

const SEVERITY_TO_LEVEL: Record<Severity, string> = {
  critical: "9.0",
  high: "7.0",
  medium: "4.0",
  low: "1.0",
};

export interface SarifOptions {
  /** Prefix for artifact paths, relative to the repository root (the skill folder). */
  root?: string;
  /** The profile the scan ran under, which decides which coverage gaps block. */
  profile?: Profile;
}

// Finding lines are positions in the assembled bundle: SKILL.md, then each
// bundled file appended after it. Code scanning needs the file and the line in it.
function locate(line: number | undefined, files: BundledFile[]): { path: string; line: number } {
  const file = line ? files.find((f) => line >= f.startLine && line <= f.endLine) : undefined;
  // A line in no file is one ClawVet inserted between files; report the entry file.
  if (!file) return { path: files[0]?.path ?? "SKILL.md", line: files.length ? 1 : line ?? 1 };
  return { path: file.path, line: line! - file.startLine + 1 };
}

// Each segment is encoded on its own, so "#", "?" and ":" in a name stay part of it.
const location = (path: string, line: number) => [{
  physicalLocation: { artifactLocation: { uri: path.split("/").map(encodeURIComponent).join("/") }, region: { startLine: line } },
}];

export function printSarifResult(result: ScanResult & { coverage?: AssemblyResult["coverage"] }, options: SarifOptions = {}): void {
  const files = result.coverage?.files ?? [];
  const uri = (path: string) => (options.root && options.root !== "." ? `${options.root}/${path}` : path);
  const rules = new Map<string, { id: string; title: string; description: string; severity: Severity }>();
  const ruleOf = (f: Finding) => f.category + "/" + f.title.toLowerCase().replace(/[^a-z0-9]+/g, "-");

  for (const f of result.findings) {
    const id = ruleOf(f);
    if (!rules.has(id)) rules.set(id, { id, title: f.title, description: f.description, severity: f.severity });
  }

  // A coverage gap that blocks is a result too, so a blocked skill shows up in
  // code scanning rather than only on the tool-status page. It sits on the file
  // that made the reference, or on the entry file.
  const gaps = result.coverage ? applyProfile(result.coverage, options.profile) : { block: [], ask: [] };
  const known = new Set(files.map((f) => f.path));
  const gapResults = [...gaps.block.map((i) => ({ i, severity: "high" as const })), ...gaps.ask.map((i) => ({ i, severity: "medium" as const }))]
    .map(({ i, severity }) => {
      const id = `coverage/${i.rule}`;
      if (!rules.has(id)) rules.set(id, { id, title: `Inspection gap: ${i.rule}`, description: i.reason, severity });
      const file = [i.source, i.path].find((p) => p && known.has(p)) ?? files[0]?.path ?? "SKILL.md";
      return {
        ruleId: id,
        level: SEVERITY_TO_SARIF[severity],
        message: { text: `${i.path}: ${i.reason}` },
        // A gap's line belongs to its own path; anywhere else, point at line 1.
        locations: location(uri(file), file === i.path ? i.line ?? 1 : 1),
      };
    });

  const sarif = {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "clawvet",
            informationUri: "https://github.com/MohibShaikh/clawvet",
            rules: [...rules.values()].map((r) => ({
              id: r.id,
              shortDescription: { text: r.title },
              fullDescription: { text: r.description },
              defaultConfiguration: {
                level: SEVERITY_TO_SARIF[r.severity],
              },
              properties: {
                "security-severity": SEVERITY_TO_LEVEL[r.severity],
              },
            })),
          },
        },
        invocations: [{
          executionSuccessful: result.status !== "failed",
          ...(result.status === "failed" ? {
            toolExecutionNotifications: [{
              level: "error",
              message: { text: result.summary || "Inspection incomplete" },
            }],
          } : {}),
        }],
        results: [
          ...result.findings.map((f) => {
            const at = locate(f.lineNumber ?? undefined, files);
            return {
              ruleId: ruleOf(f),
              level: SEVERITY_TO_SARIF[f.severity],
              message: {
                text: f.description + (f.evidence ? ` Evidence: ${f.evidence}` : ""),
                ...(f.fix ? { markdown: `${f.description}\n\n**Fix:** ${f.fix}` } : {}),
              },
              locations: location(uri(at.path), at.line),
            };
          }),
          ...gapResults,
        ],
      },
    ],
  };

  console.log(JSON.stringify(sarif, null, 2));
}
