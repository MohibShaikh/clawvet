import { configureDataflowParser, scanSkill } from "@clawvet/shared";
import type { BundledFile, Capability, Finding, RiskGrade, ScanResult, Severity } from "@clawvet/shared";
import { DEMO_SAMPLES } from "./samples.js";
import { resolveSkillFetchUrls } from "./github-url.js";

const REPO_URL = "https://github.com/MohibShaikh/clawvet";
const CLI_COMMAND = "npm i -g clawvet && clawvet audit --summary";
const MAX_BYTES = 256 * 1024;
const THEME_KEY = "clawvet-theme";
const SVG_NS = "http://www.w3.org/2000/svg";

const GRADE_COLORS: Record<RiskGrade, string> = { A: "brightgreen", B: "green", C: "yellow", D: "orange", F: "red" };
const GRADE_LABELS: Record<RiskGrade, string> = { A: "safe", B: "safe", C: "review", D: "risky", F: "dangerous" };
const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];
const SEV_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };

const CAP_ORDER: Capability["kind"][] = ["secret", "persistence", "behavior", "network", "env"];
const CAP_LABELS: Record<Capability["kind"], string> = {
  secret: "Secrets",
  persistence: "Persistence",
  behavior: "High-risk behaviours",
  network: "Network sites",
  env: "Secret env vars",
};

// Static icon geometry. Only these constants ever reach SVG attributes.
const ICONS = {
  secret: ["M14.5 9.5a4.5 4.5 0 1 1-1.3-3.2 4.5 4.5 0 0 1 1.3 3.2Z", "m13.2 12.7 7.3 7.3M17.5 17l2-2M15.5 15l2-2"],
  persistence: ["M4 12a8 8 0 0 1 13.7-5.6L20 9", "M20 4v5h-5", "M20 12a8 8 0 0 1-13.7 5.6L4 15", "M4 20v-5h5"],
  behavior: ["M12 3.5 2.5 20h19L12 3.5Z", "M12 10v4.5M12 17.2v.3"],
  network: ["M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18Z", "M3 12h18M12 3c2.5 2.6 3.7 5.6 3.7 9s-1.2 6.4-3.7 9c-2.5-2.6-3.7-5.6-3.7-9S9.5 5.6 12 3Z"],
  env: ["M8 4H6.5A1.5 1.5 0 0 0 5 5.5V10l-2 2 2 2v4.5A1.5 1.5 0 0 0 6.5 20H8", "M16 4h1.5A1.5 1.5 0 0 1 19 5.5V10l2 2-2 2v4.5a1.5 1.5 0 0 1-1.5 1.5H16", "m9.5 9 5 6M14.5 9l-5 6"],
  check: ["M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18Z", "m8.5 12.2 2.4 2.4 4.6-4.8"],
  wrench: ["M14.7 6.3a4 4 0 0 0 5 5L21 13l-8 8-3-3 1.7-1.3a4 4 0 0 0-5-5L5 13 3 11l8-8 2 2-1.3 1.3Z"],
  flow: ["M7 6h5a3 3 0 0 1 3 3v6a3 3 0 0 0 3 3", "M5 8.2a2.2 2.2 0 1 0 0-4.4 2.2 2.2 0 0 0 0 4.4ZM19 20.2a2.2 2.2 0 1 0 0-4.4 2.2 2.2 0 0 0 0 4.4Z"],
} as const;
type IconName = keyof typeof ICONS;

const PERM_VISIBLE = 5;
const SAMPLE_TONE: Record<string, "safe" | "danger"> = { clean: "safe" };
const SCRIPT_EXT = /\.(?:sh|bash|zsh|py|js|mjs|cjs|ts)$/i;
const ACCEPTED_FILE = /(?:^|\/)(?:SKILL\.md|AGENTS\.md|CLAUDE\.md|\.cursorrules|\.windsurfrules)$|\.(?:md|mdc|txt|sh|bash|zsh|py|js|mjs|cjs|ts)$/i;

// Gauge geometry: a 270° arc of radius 50 centred in a 120×120 box.
const GAUGE_R = 50;
const GAUGE_C = 2 * Math.PI * GAUGE_R;
const GAUGE_ARC = GAUGE_C * 0.75;

configureDataflowParser({
  locateWasm: () => new URL("./wasm/web-tree-sitter.wasm", window.location.href).href,
  resolveGrammar: (grammar) => new URL(`./grammars/tree-sitter-${grammar}.wasm`, window.location.href).href,
});

/* ───────── DOM helpers (textContent only, never innerHTML) ───────── */

function el<K extends keyof HTMLElementTagNameMap>(tag: K, className?: string, text?: string): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function $<T extends HTMLElement>(id: string): T {
  const found = document.getElementById(id);
  if (!found) throw new Error(`Missing element #${id}`);
  return found as T;
}

function icon(name: IconName, size = 14): SVGSVGElement {
  const svg = document.createElementNS(SVG_NS, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("width", String(size));
  svg.setAttribute("height", String(size));
  svg.setAttribute("aria-hidden", "true");
  for (const d of ICONS[name]) {
    const path = document.createElementNS(SVG_NS, "path");
    path.setAttribute("d", d);
    path.setAttribute("fill", "none");
    path.setAttribute("stroke", "currentColor");
    path.setAttribute("stroke-width", "1.8");
    path.setAttribute("stroke-linecap", "round");
    path.setAttribute("stroke-linejoin", "round");
    svg.appendChild(path);
  }
  return svg;
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  return `${(n / 1024).toFixed(n < 10 * 1024 ? 1 : 0)} KB`;
}

/* ───────── State ───────── */

interface SourceState {
  kind: "sample" | "url" | "file" | "pasted";
  fileName: string;
  url?: string;
  sampleId?: string;
}

let source: SourceState = { kind: "pasted", fileName: "SKILL.md" };
let scanning = false;
let lastLineCount = -1;

function setStatus(message: string, tone: "idle" | "busy" | "error" | "ok" = "idle"): void {
  const box = $<HTMLSpanElement>("status-bar");
  box.textContent = message;
  box.dataset.tone = tone;
}

function setEngine(state: "idle" | "loading" | "ready" | "flow" | "error", text: string): void {
  const box = $<HTMLDivElement>("engine-status");
  box.dataset.state = state;
  $<HTMLSpanElement>("engine-text").textContent = text;
}

function loadedGrammars(): string[] {
  const names = new Set<string>();
  for (const entry of performance.getEntriesByType("resource")) {
    const m = /\/grammars\/tree-sitter-([a-z]+)\.wasm/.exec(entry.name);
    if (m) names.add(m[1]);
  }
  return [...names].sort();
}

function setSource(next: SourceState): void {
  source = next;
  const label =
    next.kind === "sample" ? "sample"
      : next.kind === "url" ? (next.url ? new URL(next.url).hostname : "url")
        : next.kind === "file" ? "local file"
          : "pasted";
  $<HTMLSpanElement>("source-label").textContent = label;
  $<HTMLSpanElement>("editor-filename").textContent = next.fileName;
  for (const btn of document.querySelectorAll<HTMLButtonElement>(".sample-pill")) {
    btn.setAttribute("aria-pressed", String(next.kind === "sample" && btn.dataset.id === next.sampleId));
  }
  if (next.kind !== "url") {
    const here = new URL(window.location.href);
    if (here.searchParams.has("url")) {
      here.searchParams.delete("url");
      window.history.replaceState(null, "", here.toString());
    }
  }
}

/* ───────── Editor: gutter, counter, line highlight ───────── */

function editor(): HTMLTextAreaElement {
  return $<HTMLTextAreaElement>("skill-input");
}

function lineHeight(): number {
  return parseFloat(getComputedStyle(editor()).lineHeight) || 20;
}

function padTop(): number {
  return parseFloat(getComputedStyle(editor()).paddingTop) || 12;
}

function refreshEditorMeta(): void {
  const value = editor().value;
  const lines = value.length === 0 ? 0 : value.split("\n").length;
  const shown = Math.max(1, lines);
  if (shown !== lastLineCount) {
    lastLineCount = shown;
    const nums = new Array<string>(shown);
    for (let i = 0; i < shown; i++) nums[i] = String(i + 1);
    $<HTMLPreElement>("gutter").textContent = nums.join("\n");
  }
  const bytes = new TextEncoder().encode(value).length;
  $<HTMLSpanElement>("char-count").textContent =
    `${lines} ${lines === 1 ? "line" : "lines"} · ${formatBytes(bytes)}${bytes > MAX_BYTES ? " · over 256 KB limit" : ""}`;
  syncScroll();
}

let highlightedLine: number | null = null;

function syncScroll(): void {
  const ta = editor();
  const gutter = $<HTMLPreElement>("gutter");
  gutter.scrollTop = ta.scrollTop;
  const hl = $<HTMLDivElement>("line-hl");
  if (highlightedLine == null) return;
  hl.style.transform = `translate(${-ta.scrollLeft}px, ${padTop() + (highlightedLine - 1) * lineHeight() - ta.scrollTop}px)`;
}

function clearHighlight(): void {
  highlightedLine = null;
  $<HTMLDivElement>("line-hl").hidden = true;
}

function jumpToLine(line: number): void {
  const ta = editor();
  const total = ta.value.split("\n").length;
  if (line < 1 || line > total) return;
  const lh = lineHeight();
  ta.scrollTop = Math.max(0, (line - 1) * lh - ta.clientHeight / 2 + lh);
  highlightedLine = line;
  const hl = $<HTMLDivElement>("line-hl");
  hl.hidden = false;
  hl.style.animation = "none";
  void hl.offsetWidth; // restart the flash animation
  hl.style.animation = "";
  syncScroll();

  // Scroll the page only when the highlighted line itself is off screen (stacked mobile layout).
  const lineY = ta.getBoundingClientRect().top + padTop() + (line - 1) * lh - ta.scrollTop;
  if (lineY < 64 || lineY > window.innerHeight - lh) {
    window.scrollBy({ top: lineY - window.innerHeight / 2, behavior: "smooth" });
  }
}

function lineChip(line: number): HTMLButtonElement {
  const chip = el("button", "line-chip", `L${line}`);
  chip.type = "button";
  chip.title = `Jump to line ${line}`;
  chip.addEventListener("click", () => jumpToLine(line));
  return chip;
}

/* ───────── Rendering ───────── */

function buildGauge(): void {
  const svg = document.getElementById("gauge");
  if (!svg) return;
  const mk = (cls: string): SVGCircleElement => {
    const c = document.createElementNS(SVG_NS, "circle");
    c.setAttribute("class", cls);
    c.setAttribute("cx", "60");
    c.setAttribute("cy", "60");
    c.setAttribute("r", String(GAUGE_R));
    c.setAttribute("fill", "none");
    c.setAttribute("stroke-width", "9");
    c.setAttribute("stroke-linecap", "round");
    c.setAttribute("transform", "rotate(135 60 60)");
    c.setAttribute("stroke-dasharray", `${GAUGE_ARC} ${GAUGE_C}`);
    return c;
  };
  const track = mk("track");
  const fill = mk("fill");
  fill.id = "gauge-fill";
  fill.setAttribute("stroke-dashoffset", String(GAUGE_ARC));
  svg.append(track, fill);
}

function setGauge(score: number): void {
  const fill = document.getElementById("gauge-fill");
  if (!fill) return;
  const pct = Math.min(100, Math.max(0, score)) / 100;
  // A sliver stays visible at score 0 so the arc reads as a gauge, not a ring.
  fill.setAttribute("stroke-dashoffset", String(GAUGE_ARC * (1 - Math.max(pct, 0.012))));
}

function renderSeverity(result: ScanResult): void {
  const fc = result.findingsCount;
  const bar = $<HTMLDivElement>("sev-bar");
  bar.replaceChildren();
  const total = fc.critical + fc.high + fc.medium + fc.low;
  for (const sev of SEVERITIES) {
    $<HTMLElement>(`count-${sev}`).textContent = String(fc[sev]);
    const li = document.querySelector<HTMLLIElement>(`.sev-legend li[data-sev="${sev}"]`);
    if (li) li.dataset.zero = String(fc[sev] === 0);
    if (fc[sev] > 0) {
      const seg = el("i");
      seg.dataset.sev = sev;
      seg.style.flexGrow = String(fc[sev]);
      seg.title = `${fc[sev]} ${sev}`;
      bar.appendChild(seg);
    }
  }
  if (total === 0) {
    const seg = el("i");
    seg.dataset.sev = "none";
    seg.style.flexGrow = "1";
    bar.appendChild(seg);
  }
  bar.setAttribute("aria-label", `${fc.critical} critical, ${fc.high} high, ${fc.medium} medium, ${fc.low} low`);
}

function verdictSummary(result: ScanResult): string {
  const fc = result.findingsCount;
  const serious = fc.critical + fc.high;
  const total = serious + fc.medium + fc.low;
  const plural = (n: number, w: string) => `${n} ${w}${n === 1 ? "" : "s"}`;
  switch (result.recommendation) {
    case "block":
      return `Do not install. ${plural(serious, "critical or high finding")} in this skill.`;
    case "warn":
      return `Review before installing. ${plural(total, "finding")} need a human look.`;
    default:
      return total === 0 ? "No findings. Nothing in this skill's code reaches for secrets or persistence." : `Safe to install. ${plural(total, "low-impact finding")}.`;
  }
}

function capTone(c: Capability): "danger" | "warn" | "safe" | "neutral" {
  if (c.kind === "secret" || c.kind === "persistence" || c.risky || c.severity === "critical") return "danger";
  if (c.kind === "behavior") return "warn";
  if (c.kind === "env") return c.declared ? "safe" : "warn";
  return "neutral";
}

function renderPermissions(caps: Capability[] | undefined): void {
  const container = $<HTMLDivElement>("permissions-grid");
  container.replaceChildren();
  const list = caps ?? [];

  if (list.length === 0) {
    const empty = el("div", "empty-ok");
    empty.append(icon("check", 16), el("span", undefined, "No network sites, credential stores, secret env vars, persistence writes or high-risk behaviours found in code."));
    container.appendChild(empty);
    return;
  }

  for (const kind of CAP_ORDER) {
    const items = list.filter((c) => c.kind === kind);
    if (items.length === 0) continue;
    const tones = items.map(capTone);
    const group = el("div", "perm-group");
    group.dataset.tone = tones.includes("danger") ? "danger" : tones.includes("warn") ? "warn" : "neutral";

    const label = el("div", "perm-label");
    label.append(icon(kind, 15), el("span", undefined, CAP_LABELS[kind]), el("span", "n", String(items.length)));

    if (kind === "behavior") items.sort((a, b) => (SEV_RANK[a.severity ?? "low"] ?? 9) - (SEV_RANK[b.severity ?? "low"] ?? 9));

    const chips = el("div", "perm-items");
    const extra: HTMLElement[] = [];
    for (const [i, c] of items.entries()) {
      const item = el("span", "perm-item");
      if (items.length > PERM_VISIBLE + 1 && i >= PERM_VISIBLE) {
        item.hidden = true;
        extra.push(item);
      }
      item.dataset.tone = capTone(c);
      item.appendChild(el("span", "v", c.value));
      if (c.kind === "network" && c.risky) item.appendChild(el("span", "tag tag-risky", "risky host"));
      if (c.kind === "env") {
        item.appendChild(c.declared ? el("span", "tag tag-declared", "declared") : el("span", "tag tag-undeclared", "undeclared"));
      }
      if (c.line) item.appendChild(lineChip(c.line));
      chips.appendChild(item);
    }
    if (extra.length) {
      const more = el("button", "perm-more", `+${extra.length} more`);
      more.type = "button";
      more.addEventListener("click", () => {
        for (const item of extra) item.hidden = false;
        more.remove();
      });
      chips.appendChild(more);
    }
    group.append(label, chips);
    container.appendChild(group);
  }
}

function renderFindings(findings: Finding[]): void {
  const container = $<HTMLDivElement>("findings-list");
  container.replaceChildren();
  const sorted = [...findings].sort(
    // Within a severity, AST-proven flows lead, then higher confidence.
    (a, b) =>
      (SEV_RANK[a.severity] ?? 9) - (SEV_RANK[b.severity] ?? 9) ||
      Number(b.analysisPass === "dataflow") - Number(a.analysisPass === "dataflow") ||
      (b.confidence ?? 0) - (a.confidence ?? 0),
  );
  $<HTMLSpanElement>("findings-heading-count").textContent = String(sorted.length);

  if (sorted.length === 0) {
    const empty = el("div", "empty-ok");
    empty.append(icon("check", 16), el("span", undefined, "No security findings in the scanned content."));
    container.appendChild(empty);
    return;
  }

  for (const f of sorted) {
    const card = el("article", "finding");
    card.dataset.sev = f.severity;

    const head = el("div", "finding-head");
    head.append(el("span", "sev-badge", f.severity.toUpperCase()), el("span", "finding-title", f.title));

    const meta = el("span", "finding-meta");
    if (f.analysisPass) {
      const pass = el("span", "pass-badge");
      pass.dataset.pass = f.analysisPass;
      if (f.analysisPass === "dataflow") {
        pass.title = "Tree-sitter AST taint tracking traced this source to a sink";
        pass.append(icon("flow", 11), document.createTextNode("dataflow"));
      } else {
        pass.textContent = f.analysisPass;
      }
      meta.appendChild(pass);
    }
    if (f.confidence != null) meta.appendChild(el("span", "conf", `${Math.round(f.confidence * 100)}%`));
    if (f.lineNumber) meta.appendChild(lineChip(f.lineNumber));
    head.appendChild(meta);
    card.appendChild(head);

    if (f.description && f.description.trim() !== f.title.trim()) card.appendChild(el("p", "finding-desc", f.description));
    if (f.evidence) card.appendChild(el("pre", "finding-evidence", f.evidence.trim()));
    if (f.fix) {
      const fix = el("div", "finding-fix");
      const text = el("span");
      text.append(el("b", undefined, "Fix "), document.createTextNode(f.fix));
      fix.append(icon("wrench", 13), text);
      card.appendChild(fix);
    }
    container.appendChild(card);
  }
}

function renderShare(result: ScanResult): void {
  const grade = result.riskGrade;
  const badgeUrl = `https://img.shields.io/badge/clawvet-${grade}%20${GRADE_LABELS[grade]}-${GRADE_COLORS[grade]}`;
  const img = $<HTMLImageElement>("badge-preview-img");
  img.hidden = false;
  img.onerror = () => { img.hidden = true; };
  img.src = badgeUrl;
  img.alt = `ClawVet ${grade} ${GRADE_LABELS[grade]}`;
  $<HTMLInputElement>("badge-markdown").value = `[![ClawVet ${grade}](${badgeUrl})](${REPO_URL})`;

  const shareable = source.kind === "url" && source.url;
  $<HTMLDivElement>("share-row").hidden = !shareable;
  $<HTMLParagraphElement>("share-hint").hidden = Boolean(shareable);
  if (shareable) {
    const link = new URL(window.location.href);
    link.hash = "";
    link.search = "";
    link.searchParams.set("url", source.url!);
    $<HTMLInputElement>("share-link").value = link.toString();
  }
}

function renderResult(result: ScanResult, elapsedMs: number): void {
  $<HTMLDivElement>("empty-state").hidden = true;
  const panel = $<HTMLDivElement>("results-panel");
  panel.hidden = false;
  panel.classList.remove("is-fresh");
  void panel.offsetWidth;
  panel.classList.add("is-fresh");

  const card = panel.querySelector<HTMLElement>(".verdict-card");
  if (card) card.dataset.grade = result.riskGrade;
  $<HTMLSpanElement>("grade-letter").textContent = result.riskGrade;
  setGauge(result.riskScore);

  const score = $<HTMLSpanElement>("result-score");
  score.replaceChildren(document.createTextNode(String(Math.round(result.riskScore))), el("span", undefined, "/100 risk"));

  const rec = result.recommendation ?? "approve";
  const verdict = $<HTMLSpanElement>("result-verdict");
  verdict.textContent = rec.toUpperCase();
  verdict.dataset.verdict = rec;

  $<HTMLHeadingElement>("result-name").textContent = result.skillName || "unknown";
  $<HTMLParagraphElement>("result-summary").textContent = verdictSummary(result);
  renderSeverity(result);

  const dataflowHit = result.findings.some((f) => f.analysisPass === "dataflow");
  const grammars = loadedGrammars();
  $<HTMLSpanElement>("result-timing").textContent =
    `${Math.max(1, Math.round(elapsedMs))} ms · in-browser${grammars.length ? ` · AST: ${grammars.join(", ")}` : ""}`;
  $<HTMLSpanElement>("result-dataflow").hidden = !dataflowHit;
  if (dataflowHit) setEngine("flow", "AST taint flow found");
  else if (grammars.length) setEngine("ready", `Tree-sitter ready · ${grammars.length} grammar${grammars.length === 1 ? "" : "s"}`);
  else setEngine("ready", "No code to parse");

  renderPermissions(result.capabilities);
  renderFindings(result.findings);
  renderShare(result);
}

/* ───────── Scanning & loading ───────── */

function bundledFiles(lineCount: number): BundledFile[] | undefined {
  // A bare script is all code; markdown leaves only fenced blocks as code.
  return SCRIPT_EXT.test(source.fileName) ? [{ path: source.fileName, startLine: 1, endLine: lineCount }] : undefined;
}

function fallbackName(): string | undefined {
  if (source.kind === "sample") return undefined;
  const base = source.fileName.replace(/\.[^.]+$/, "");
  return /^(?:SKILL|AGENTS|CLAUDE|untitled)$/i.test(base) || !base ? undefined : base;
}

async function runScan(content: string, skillName?: string): Promise<void> {
  if (scanning) return;
  if (!content.trim()) {
    setStatus("Paste a skill, drop a file or fetch a URL first.", "error");
    return;
  }
  if (new TextEncoder().encode(content).length > MAX_BYTES) {
    setStatus("Content exceeds the 256 KB in-browser scan limit. Use the CLI for large bundles.", "error");
    return;
  }
  scanning = true;
  const btn = $<HTMLButtonElement>("scan-btn");
  btn.disabled = true;
  setStatus("Scanning in your browser…", "busy");
  if (loadedGrammars().length === 0) setEngine("loading", "Loading Tree-sitter…");
  const start = performance.now();
  try {
    const result = await scanSkill(content, {
      skillName: skillName ?? fallbackName(),
      skipCache: true,
      files: bundledFiles(content.split("\n").length),
    });
    const elapsed = performance.now() - start;
    renderResult(result, elapsed);
    setStatus(`Scanned in ${Math.max(1, Math.round(elapsed))} ms. Nothing left your browser.`, "ok");
  } catch (err) {
    setEngine("error", "Scan error");
    setStatus(`Scan failed: ${err instanceof Error ? err.message : String(err)}`, "error");
  } finally {
    scanning = false;
    btn.disabled = false;
  }
}

function loadContent(text: string, next: SourceState): void {
  const ta = editor();
  ta.value = text;
  ta.scrollTop = 0;
  ta.scrollLeft = 0;
  clearHighlight();
  setSource(next);
  refreshEditorMeta();
}

async function fetchFromUrl(rawUrl: string): Promise<void> {
  const resolved = resolveSkillFetchUrls(rawUrl);
  if (resolved.error || resolved.urls.length === 0) {
    setStatus(resolved.error ?? "Invalid URL.", "error");
    return;
  }
  setStatus(`Fetching ${new URL(resolved.urls[0]).hostname}…`, "busy");
  for (const url of resolved.urls) {
    try {
      const res = await fetch(url, { credentials: "omit", referrerPolicy: "no-referrer" });
      if (!res.ok) continue;
      const text = await res.text();
      if (new TextEncoder().encode(text).length > MAX_BYTES) {
        setStatus("Remote file exceeds the 256 KB in-browser scan limit.", "error");
        return;
      }
      const trimmedUrl = rawUrl.trim();
      const fileName = new URL(url).pathname.split("/").filter(Boolean).pop() || "SKILL.md";
      loadContent(text, { kind: "url", url: trimmedUrl, fileName: fileName === "raw" ? "SKILL.md" : fileName });
      const here = new URL(window.location.href);
      here.searchParams.set("url", trimmedUrl);
      window.history.replaceState(null, "", here.toString());
      await runScan(text, resolved.skillName);
      return;
    } catch {
      // Try the next candidate URL.
    }
  }
  setStatus("Couldn't fetch that URL. Check the path or CORS, or paste the file contents instead.", "error");
}

async function loadFile(file: File): Promise<void> {
  if (!ACCEPTED_FILE.test(file.name)) {
    setStatus(`Unsupported file "${file.name}". Use SKILL.md, .cursorrules, AGENTS.md, .sh, .py or .js.`, "error");
    return;
  }
  if (file.size > MAX_BYTES) {
    setStatus("File exceeds the 256 KB in-browser scan limit. Use the CLI for large bundles.", "error");
    return;
  }
  const text = await file.text();
  if (text.includes("\u0000")) {
    setStatus("That looks like a binary file. Drop a text skill or script.", "error");
    return;
  }
  loadContent(text, { kind: "file", fileName: file.name });
  await runScan(text);
}

/* ───────── Wiring ───────── */

function wireCopy(buttonId: string, getText: () => string): void {
  const btn = $<HTMLButtonElement>(buttonId);
  const orig = btn.textContent ?? "Copy";
  let timer = 0;
  btn.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(getText());
      btn.textContent = "Copied";
    } catch {
      btn.textContent = "Copy failed";
    }
    window.clearTimeout(timer);
    timer = window.setTimeout(() => { btn.textContent = orig; }, 1400);
  });
}

function applyTheme(theme: "light" | "dark", persist: boolean): void {
  document.documentElement.dataset.theme = theme;
  $<HTMLButtonElement>("theme-toggle").setAttribute("aria-label", `Switch to ${theme === "dark" ? "light" : "dark"} theme`);
  if (persist) {
    try { localStorage.setItem(THEME_KEY, theme); } catch { /* storage blocked */ }
  }
}

function wireDragAndDrop(): void {
  const zone = $<HTMLDivElement>("drop-zone");
  let depth = 0;
  const hasFiles = (e: DragEvent) => Array.from(e.dataTransfer?.types ?? []).includes("Files");

  document.addEventListener("dragenter", (e) => {
    if (!hasFiles(e)) return;
    e.preventDefault();
    depth++;
    zone.hidden = false;
  });
  document.addEventListener("dragover", (e) => {
    if (!hasFiles(e)) return;
    e.preventDefault();
    if (e.dataTransfer) e.dataTransfer.dropEffect = "copy";
  });
  document.addEventListener("dragleave", (e) => {
    if (!hasFiles(e)) return;
    depth = Math.max(0, depth - 1);
    if (depth === 0) zone.hidden = true;
  });
  document.addEventListener("drop", (e) => {
    if (!hasFiles(e)) return;
    e.preventDefault();
    depth = 0;
    zone.hidden = true;
    const file = e.dataTransfer?.files?.[0];
    if (file) void loadFile(file);
  });
}

function init(): void {
  const ta = editor();
  const urlInput = $<HTMLInputElement>("url-input");

  buildGauge();
  applyTheme(document.documentElement.dataset.theme === "light" ? "light" : "dark", false);

  const isMac = /Mac|iPhone|iPad/i.test(navigator.platform || navigator.userAgent);
  $<HTMLElement>("scan-kbd").textContent = isMac ? "⌘ ↵" : "Ctrl ↵";

  const sampleBar = $<HTMLDivElement>("sample-buttons");
  for (const sample of DEMO_SAMPLES) {
    const btn = el("button", "sample-pill");
    btn.type = "button";
    btn.dataset.id = sample.id;
    btn.dataset.tone = SAMPLE_TONE[sample.id] ?? "danger";
    btn.title = sample.description;
    btn.setAttribute("aria-pressed", "false");
    btn.append(
      el("span", "dot"),
      el("span", "name", sample.label.replace(/\s*\(Grade [A-F]\)\s*$/, "")),
      el("span", "intent", sample.description),
    );
    btn.addEventListener("click", () => {
      loadContent(sample.content, { kind: "sample", sampleId: sample.id, fileName: "SKILL.md" });
      urlInput.value = "";
      void runScan(sample.content);
    });
    sampleBar.appendChild(btn);
  }

  ta.addEventListener("input", () => {
    clearHighlight();
    if (source.kind !== "pasted" || source.url) setSource({ kind: "pasted", fileName: source.fileName });
    refreshEditorMeta();
  });
  ta.addEventListener("scroll", syncScroll, { passive: true });
  ta.addEventListener("keydown", (e) => {
    if (e.key === "Tab" && !e.shiftKey && !e.metaKey && !e.ctrlKey && !e.altKey) {
      e.preventDefault();
      ta.setRangeText("  ", ta.selectionStart, ta.selectionEnd, "end");
      ta.dispatchEvent(new Event("input"));
    }
  });

  document.addEventListener("keydown", (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key === "Enter") {
      e.preventDefault();
      if (document.activeElement === urlInput && urlInput.value.trim()) void fetchFromUrl(urlInput.value);
      else void runScan(ta.value);
    }
  });

  $<HTMLButtonElement>("scan-btn").addEventListener("click", () => void runScan(ta.value));
  $<HTMLFormElement>("url-form").addEventListener("submit", (e) => {
    e.preventDefault();
    void fetchFromUrl(urlInput.value);
  });
  $<HTMLButtonElement>("clear-btn").addEventListener("click", () => {
    loadContent("", { kind: "pasted", fileName: "SKILL.md" });
    setStatus("Cleared.", "idle");
    ta.focus();
  });

  const fileInput = $<HTMLInputElement>("file-input");
  fileInput.addEventListener("change", () => {
    const file = fileInput.files?.[0];
    if (file) void loadFile(file);
    fileInput.value = "";
  });
  wireDragAndDrop();

  $<HTMLButtonElement>("theme-toggle").addEventListener("click", () => {
    applyTheme(document.documentElement.dataset.theme === "light" ? "dark" : "light", true);
  });

  wireCopy("copy-badge-btn", () => $<HTMLInputElement>("badge-markdown").value);
  wireCopy("copy-share-btn", () => $<HTMLInputElement>("share-link").value);
  wireCopy("copy-cli-btn", () => CLI_COMMAND);

  refreshEditorMeta();

  const initialUrl = new URLSearchParams(window.location.search).get("url");
  if (initialUrl) {
    urlInput.value = initialUrl;
    void fetchFromUrl(initialUrl);
  } else {
    // Open on the rug-pull sample so a first visit shows AST dataflow and Permissions.
    const sample = DEMO_SAMPLES[1];
    loadContent(sample.content, { kind: "sample", sampleId: sample.id, fileName: "SKILL.md" });
    void runScan(sample.content);
  }
}

document.addEventListener("DOMContentLoaded", init);
