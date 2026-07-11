import type { ScanResult, Finding } from "@clawvet/shared";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#dc2626",
  high: "#ea580c",
  medium: "#ca8a04",
  low: "#6b7280",
};

function findingRow(f: Finding): string {
  const color = SEVERITY_COLORS[f.severity] || "#6b7280";
  return `
    <tr>
      <td><span style="background:${color};color:#fff;padding:2px 8px;border-radius:4px;font-size:12px">${f.severity.toUpperCase()}</span></td>
      <td style="font-weight:600">${f.title}</td>
      <td>${f.description}</td>
      <td>${f.lineNumber || "-"}</td>
      <td>${f.analysisPass}</td>
    </tr>`;
}

export function printHtmlReport(results: ScanResult | ScanResult[]): void {
  const arr = Array.isArray(results) ? results : [results];

  const allFindings = arr.flatMap((r) => r.findings);
  const totalCritical = allFindings.filter((f) => f.severity === "critical").length;
  const totalHigh = allFindings.filter((f) => f.severity === "high").length;
  const totalMedium = allFindings.filter((f) => f.severity === "medium").length;
  const totalLow = allFindings.filter((f) => f.severity === "low").length;

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ClawVet Security Report</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #e2e8f0; padding: 2rem; }
  .container { max-width: 1200px; margin: 0 auto; }
  h1 { font-size: 1.5rem; margin-bottom: 0.5rem; }
  .subtitle { color: #94a3b8; margin-bottom: 2rem; }
  .summary { display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin-bottom: 2rem; }
  .stat { background: #1e293b; padding: 1rem; border-radius: 8px; text-align: center; }
  .stat .count { font-size: 2rem; font-weight: 700; }
  .stat .label { font-size: 0.875rem; color: #94a3b8; margin-top: 0.25rem; }
  .stat.critical .count { color: #dc2626; }
  .stat.high .count { color: #ea580c; }
  .stat.medium .count { color: #ca8a04; }
  .stat.low .count { color: #6b7280; }
  table { width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 8px; overflow: hidden; }
  th { text-align: left; padding: 0.75rem 1rem; background: #334155; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; color: #94a3b8; }
  td { padding: 0.75rem 1rem; border-top: 1px solid #334155; font-size: 0.875rem; vertical-align: top; }
  .skill-header { background: #1e293b; padding: 1rem; border-radius: 8px; margin-bottom: 1rem; border-left: 4px solid #3b82f6; }
  .skill-header h2 { font-size: 1.125rem; }
  .skill-header .meta { color: #94a3b8; font-size: 0.875rem; margin-top: 0.25rem; }
  .skill-section { margin-bottom: 2rem; }
  .grade { display: inline-block; padding: 2px 10px; border-radius: 4px; font-weight: 700; font-size: 0.875rem; }
  .grade-A { background: #166534; color: #bbf7d0; }
  .grade-B { background: #166534; color: #bbf7d0; }
  .grade-C { background: #854d0e; color: #fef08a; }
  .grade-D { background: #9a3412; color: #fed7aa; }
  .grade-F { background: #991b1b; color: #fecaca; }
  footer { margin-top: 2rem; text-align: center; color: #475569; font-size: 0.75rem; }
</style>
</head>
<body>
<div class="container">
  <h1>🔍 ClawVet Security Report</h1>
  <p class="subtitle">Generated on ${new Date().toISOString().split("T")[0]} — ${arr.length} skill(s) scanned</p>

  <div class="summary">
    <div class="stat critical"><div class="count">${totalCritical}</div><div class="label">Critical</div></div>
    <div class="stat high"><div class="count">${totalHigh}</div><div class="label">High</div></div>
    <div class="stat medium"><div class="count">${totalMedium}</div><div class="label">Medium</div></div>
    <div class="stat low"><div class="count">${totalLow}</div><div class="label">Low</div></div>
  </div>

  ${arr.map((r) => `
  <div class="skill-section">
    <div class="skill-header">
      <h2>${r.skillName} <span class="grade grade-${r.riskGrade}">${r.riskGrade}</span></h2>
      <div class="meta">Score: ${r.riskScore}/100 &middot; ${r.findings.length} finding(s) &middot; ${r.skillVersion || "no version"}</div>
    </div>

    ${r.findings.length > 0 ? `
    <table>
      <thead><tr><th>Severity</th><th>Title</th><th>Description</th><th>Line</th><th>Pass</th></tr></thead>
      <tbody>${r.findings.map(findingRow).join("")}</tbody>
    </table>` : '<p style="color:#22c55e">✅ No threats found</p>'}
  </div>`).join("")}

  <footer>ClawVet — AI Agent Skill Security Scanner</footer>
</div>
</body>
</html>`;

  console.log(html);
}
