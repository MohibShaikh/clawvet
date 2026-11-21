import { configureDataflowParser, scanSkill } from "@clawvet/shared";
import type { Capability, Finding, RiskGrade, ScanResult } from "@clawvet/shared";
import { DEMO_SAMPLES } from "./samples.js";
import { resolveSkillFetchUrls } from "./github-url.js";

const GRADE_COLORS: Record<RiskGrade, string> = {
  A: "brightgreen",
  B: "green",
  C: "yellow",
  D: "orange",
  F: "red",
};

const GRADE_LABELS: Record<RiskGrade, string> = {
  A: "safe",
  B: "safe",
  C: "review",
  D: "risky",
  F: "dangerous",
};

const CAP_LABELS: Record<Capability["kind"], string> = {
  secret: "Secrets",
  persistence: "Persistence",
  behavior: "High-risk behaviours",
  network: "Network sites",
  env: "Secret env vars",
};

const CAP_ORDER: Capability["kind"][] = ["secret", "persistence", "behavior", "network", "env"];
const SEV_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
const MAX_REMOTE_BYTES = 256 * 1024;

// Configure WebAssembly Tree-sitter to load from the static assets bundled
// alongside index.html (works on Cloudflare Pages, Vercel, and GitHub Pages).
configureDataflowParser({
  locateWasm: () => new URL("./wasm/web-tree-sitter.wasm", window.location.href).href,
  resolveGrammar: (grammar) => new URL(`./grammars/tree-sitter-${grammar}.wasm`, window.location.href).href,
});

function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  className?: string,
  text?: string,
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function getEl<T extends HTMLElement>(id: string): T {
  const found = document.getElementById(id);
  if (!found) throw new Error(`Missing element #${id}`);
  return found as T;
}

function setStatus(message: string, tone: "idle" | "busy" | "error" | "ok" = "idle"): void {
  const box = getEl<HTMLDivElement>("status-bar");
  box.textContent = message;
  box.dataset.tone = tone;
}

function renderPermissions(caps: Capability[] | undefined): void {
  const container = getEl<HTMLDivElement>("permissions-grid");
  container.replaceChildren();
  const list = caps ?? [];

  if (list.length === 0) {
    container.appendChild(
      el("div", "empty-ok", "No network hosts, credential stores, secret env vars, persistence writes, or high-risk behaviours detected in code."),
    );
    return;
  }

  for (const kind of CAP_ORDER) {
    const items = list.filter((c) => c.kind === kind);
    if (items.length === 0) continue;
    const group = el("div", "perm-group");
    group.appendChild(el("div", "perm-label", CAP_LABELS[kind]));
    const chips = el("div", "perm-chips");
    for (const c of items) {
      const chipTone =
        kind === "secret" || kind === "persistence" || c.risky || c.severity === "critical"
          ? "danger"
          : kind === "behavior"
            ? "warn"
            : c.declared
              ? "safe"
              : "neutral";
      const chip = el("span", `chip chip-${chipTone}`);
      const suffix = c.risky ? " (risky)" : c.declared ? " (declared)" : "";
      const loc = c.line ? ` :${c.line}` : "";
      chip.textContent = `${c.value}${suffix}${loc}`;
      chips.appendChild(chip);
    }
    group.appendChild(chips);
    container.appendChild(group);
  }
}

function renderFindings(findings: Finding[]): void {
  const container = getEl<HTMLDivElement>("findings-list");
  container.replaceChildren();

  const sorted = [...findings].sort((a, b) => (SEV_RANK[a.severity] ?? 9) - (SEV_RANK[b.severity] ?? 9));
  getEl<HTMLSpanElement>("findings-heading-count").textContent = String(sorted.length);

  if (sorted.length === 0) {
    container.appendChild(el("div", "empty-ok", "No security findings detected in inspected content."));
    return;
  }

  for (const f of sorted) {
    const card = el("article", `finding-card sev-${f.severity}`);
    const head = el("div", "finding-head");
    const badge = el("span", `sev-badge sev-${f.severity}`, f.severity.toUpperCase());
    const title = el("span", "finding-title", f.title);
    head.append(badge, title);

    const meta = el("span", "finding-meta");
    const parts: string[] = [];
    if (f.analysisPass) parts.push(f.analysisPass);
    if (f.lineNumber) parts.push(`L${f.lineNumber}`);
    if (f.confidence != null) parts.push(`${Math.round(f.confidence * 100)}%`);
    meta.textContent = parts.join(" · ");
    head.appendChild(meta);
    card.appendChild(head);

    card.appendChild(el("p", "finding-desc", f.description));

    if (f.evidence) {
      const ev = el("pre", "finding-evidence", f.evidence);
      card.appendChild(ev);
    }
    if (f.fix) {
      const fix = el("div", "finding-fix");
      fix.append(el("strong", undefined, "Fix: "), document.createTextNode(f.fix));
      card.appendChild(fix);
    }
    container.appendChild(card);
  }
}

function renderResult(result: ScanResult, elapsedMs: number): void {
  const panel = getEl<HTMLElement>("results-panel");
  panel.hidden = false;

  const gradeEl = getEl<HTMLDivElement>("grade-badge");
  gradeEl.textContent = result.riskGrade;
  gradeEl.dataset.grade = result.riskGrade;

  getEl<HTMLHeadingElement>("result-name").textContent = result.skillName || "unknown";
  getEl<HTMLSpanElement>("result-score").textContent = `${Math.round(result.riskScore)}/100`;

  const rec = (result.recommendation ?? "approve").toUpperCase();
  const verdictEl = getEl<HTMLSpanElement>("result-verdict");
  verdictEl.textContent = rec;
  verdictEl.dataset.verdict = (result.recommendation ?? "approve").toLowerCase();

  const dataflowRan = result.findings.some((f) => f.analysisPass === "dataflow");
  getEl<HTMLSpanElement>("result-timing").textContent =
    `${Math.max(1, Math.round(elapsedMs))} ms · client-side WASM${dataflowRan ? " (AST dataflow hit)" : ""}`;

  const fc = result.findingsCount;
  getEl<HTMLSpanElement>("count-critical").textContent = String(fc.critical);
  getEl<HTMLSpanElement>("count-high").textContent = String(fc.high);
  getEl<HTMLSpanElement>("count-medium").textContent = String(fc.medium);
  getEl<HTMLSpanElement>("count-low").textContent = String(fc.low);

  renderPermissions(result.capabilities);
  renderFindings(result.findings);

  const label = GRADE_LABELS[result.riskGrade];
  const color = GRADE_COLORS[result.riskGrade];
  const badgeUrl = `https://img.shields.io/badge/clawvet-${result.riskGrade}%20${label}-${color}`;
  const repoUrl = "https://github.com/MohibShaikh/clawvet";
  const md = `[![ClawVet ${result.riskGrade}](${badgeUrl})](${repoUrl})`;

  getEl<HTMLImageElement>("badge-preview-img").src = badgeUrl;
  getEl<HTMLImageElement>("badge-preview-img").alt = `ClawVet ${result.riskGrade}`;
  getEl<HTMLInputElement>("badge-markdown").value = md;
}

async function runScan(content: string, skillName?: string): Promise<void> {
  const trimmed = content.trim();
  if (!trimmed) {
    setStatus("Paste a SKILL.md, rule file, or fetch a GitHub URL first.", "error");
    return;
  }
  setStatus("Scanning locally in browser (static rules + WebAssembly AST dataflow)...", "busy");
  const start = performance.now();
  try {
    const result = await scanSkill(content, { skillName, skipCache: true });
    const elapsed = performance.now() - start;
    renderResult(result, elapsed);
    setStatus(`Scan complete in ${Math.max(1, Math.round(elapsed))} ms. Nothing left your browser.`, "ok");
  } catch (err) {
    setStatus(`Scan failed: ${err instanceof Error ? err.message : String(err)}`, "error");
  }
}

async function fetchFromUrl(rawUrl: string): Promise<void> {
  const resolved = resolveSkillFetchUrls(rawUrl);
  if (resolved.error || resolved.urls.length === 0) {
    setStatus(resolved.error ?? "Invalid URL.", "error");
    return;
  }
  setStatus(`Fetching ${resolved.urls[0]} ...`, "busy");
  for (const url of resolved.urls) {
    try {
      const res = await fetch(url);
      if (!res.ok) continue;
      const text = await res.text();
      if (text.length > MAX_REMOTE_BYTES) {
        setStatus("Remote file exceeds the 256 KiB browser scan limit.", "error");
        return;
      }
      const textarea = getEl<HTMLTextAreaElement>("skill-input");
      textarea.value = text;
      const shareUrl = new URL(window.location.href);
      shareUrl.searchParams.set("url", rawUrl.trim());
      window.history.replaceState(null, "", shareUrl.toString());
      await runScan(text, resolved.skillName);
      return;
    } catch {
      // Try next candidate URL
    }
  }
  setStatus("Could not fetch that URL directly (check the path or CORS headers, or paste the content below).", "error");
}

function wireCopyButton(buttonId: string, getText: () => string): void {
  const btn = getEl<HTMLButtonElement>(buttonId);
  btn.addEventListener("click", async () => {
    const orig = btn.textContent;
    try {
      await navigator.clipboard.writeText(getText());
      btn.textContent = "Copied!";
      setTimeout(() => { btn.textContent = orig; }, 1400);
    } catch {
      btn.textContent = "Copy failed";
      setTimeout(() => { btn.textContent = orig; }, 1400);
    }
  });
}

function init(): void {
  const textarea = getEl<HTMLTextAreaElement>("skill-input");
  const urlInput = getEl<HTMLInputElement>("url-input");
  const sampleBar = getEl<HTMLDivElement>("sample-buttons");

  for (const sample of DEMO_SAMPLES) {
    const btn = el("button", "btn-chip", sample.label);
    btn.type = "button";
    btn.title = sample.description;
    btn.addEventListener("click", () => {
      textarea.value = sample.content;
      void runScan(sample.content);
    });
    sampleBar.appendChild(btn);
  }

  getEl<HTMLButtonElement>("scan-btn").addEventListener("click", () => {
    void runScan(textarea.value);
  });

  getEl<HTMLFormElement>("url-form").addEventListener("submit", (e) => {
    e.preventDefault();
    void fetchFromUrl(urlInput.value);
  });

  getEl<HTMLButtonElement>("theme-toggle").addEventListener("click", () => {
    const next = document.documentElement.dataset.theme === "light" ? "dark" : "light";
    document.documentElement.dataset.theme = next;
  });

  wireCopyButton("copy-badge-btn", () => getEl<HTMLInputElement>("badge-markdown").value);
  wireCopyButton("copy-cli-btn", () => "npm i -g clawvet && clawvet audit");

  const params = new URLSearchParams(window.location.search);
  const initialUrl = params.get("url");
  if (initialUrl) {
    urlInput.value = initialUrl;
    void fetchFromUrl(initialUrl);
  } else {
    // Load the credential exfil rug-pull sample by default so first-time
    // visitors immediately see AST dataflow + Permissions in action.
    textarea.value = DEMO_SAMPLES[1].content;
    void runScan(DEMO_SAMPLES[1].content);
  }
}

document.addEventListener("DOMContentLoaded", init);
