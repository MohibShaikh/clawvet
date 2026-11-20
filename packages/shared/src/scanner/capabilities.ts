import type { Capability, CapabilityKind, Finding, SourceFile } from "../types.js";
import { CREDENTIAL_STORES, PERSISTENCE_LOCATIONS, SECRET_ENV } from "./dataflow/specs/common.js";
import { isCode } from "./sources.js";

// What a skill can do, read from its code: where it connects, which secrets it
// reads, where it installs itself, and the high-risk behaviours the scan proved.
// An update is compared on these keys, so each key must stay the same across
// a benign rewrite: a site, not a URL; a credential store, not a file path.

// Hosts on these suffixes are rented by anyone, so the tenant is the site.
const SHARED_SUFFIXES = new Set([
  "github.io", "githubusercontent.com", "gitlab.io", "vercel.app", "netlify.app", "pages.dev",
  "workers.dev", "herokuapp.com", "amazonaws.com", "cloudfront.net", "azurewebsites.net",
  "appspot.com", "firebaseapp.com", "web.app", "ngrok.io", "ngrok-free.app", "ngrok.app",
  "trycloudflare.com", "onrender.com", "fly.dev", "replit.app", "repl.co", "glitch.me",
  "r2.dev", "supabase.co", "railway.app", "deno.dev", "blob.core.windows.net", "s3.amazonaws.com",
]);
// A repository host serves anyone's code: the owner is the site.
const CODE_HOSTS = new Set(["github.com", "gitlab.com", "bitbucket.org", "gist.github.com", "raw.githubusercontent.com", "codeberg.org"]);
const SECOND_LEVEL = new Set(["co", "com", "net", "org", "gov", "ac", "edu", "ne", "or"]);
// Names a skill uses to stand in for "your server", and namespaces that are never fetched.
const NOT_A_DESTINATION = /^(?:localhost|.*\.(?:local|localhost|test|example|invalid|internal|lan|home|svc)|(?:.*\.)?example\.(?:com|org|net)|0\.0\.0\.0|127\.\d+\.\d+\.\d+|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|::1|(?:www\.)?w3\.org|schemas\.[a-z.]+|json-schema\.org|purl\.org|xmlns\.com|ns\.adobe\.com|schemas\.openxmlformats\.org)$/i;
const PLACEHOLDER = /[<>{}$%*]|^your[-_]|[-_.]your[-_.]|^(?:host|hostname|server|domain|api|my[-_]?\w*)$/i;
// Stand-in sites in examples and tests: example1.com, shop2.com, company.com.
const STAND_IN = /^(?:example|sample|test|demo|dummy|fake|placeholder|company|domain|website|site|shop|store|acme|foo|bar|baz|dynamic-[a-z]+|my[a-z]*|your[a-z]*)\d*\.(?:com|org|net|io)$/i;
const URL_HOST = /\b(?:https?|wss?|ftp):\/\/(?:[^\s/@'"`<>()]*@)?(\[[0-9a-f:]+\]|[^\s/:?#'"`<>()\\]+)(?::\d+)?(\/[^\s'"`<>()\\]*)?/gi;
const IPV4 = /^\d{1,3}(?:\.\d{1,3}){3}$/;

// Where a new destination is worth a question even when the user wants quiet
// updates: services that hand anyone a public endpoint (tunnels, request bins,
// webhooks, paste and file drops, out-of-band test hosts), address lookups,
// abuse-prone generic TLDs, raw IPs, and code hosted by a new owner.
const RISKY_SERVICE = /(?:^|\.)(?:ngrok(?:-free)?\.(?:io|app|dev)|trycloudflare\.com|loca\.lt|serveo\.net|bore\.pub|repl\.co|replit\.(?:app|dev)|glitch\.me|pythonanywhere\.com|pipedream\.net|beeceptor\.com|webhook\.site|requestbin\.\w+|hookbin\.com|oastify\.com|burpcollaborator\.net|interact\.sh|oast\.\w+|dnslog\.cn|discord(?:app)?\.com|discord\.gg|pastebin\.com|paste\.ee|rentry\.co|hastebin\.com|ghostbin\.\w+|transfer\.sh|file\.io|0x0\.st|temp\.sh|filebase\.com|anonfiles\.com|catbox\.moe|ipfs\.io|ipinfo\.io|ip-api\.com|ifconfig\.me|icanhazip\.com|api\.ipify\.org)$/i;
const RISKY_TLD = /\.(?:site|xyz|online|top|tk|ml|ga|cf|gq|pw|click|icu|buzz|monster|rest|cyou|live|lol|zip|mov)$/i;

/** A new destination that asks even under the quiet default. */
export function riskySite(site: string): boolean {
  return IPV4.test(site) || site.includes(":") || site.includes("/") || RISKY_SERVICE.test(site) || RISKY_TLD.test(site);
}

/** The registrable site a host belongs to, or undefined for a non-destination. */
export function siteOf(host: string, path = ""): string | undefined {
  let h = host.toLowerCase().replace(/\.$/, "").replace(/^\[|\]$/g, "");
  if (!h || PLACEHOLDER.test(h) || NOT_A_DESTINATION.test(h)) return undefined;
  if (IPV4.test(h) || h.includes(":")) return h;
  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(h)) return undefined;
  h = h.replace(/^www\./, "");
  if (CODE_HOSTS.has(h)) {
    const owner = /^\/([A-Za-z0-9_.-]+)/.exec(path)?.[1];
    const base = h === "raw.githubusercontent.com" || h === "gist.github.com" ? "github.com" : h;
    // github.com/owner/repo and github.com/<you>/... are a template, not someone's code.
    const template = !owner || PLACEHOLDER.test(owner) || /^(?:owner|user(?:name)?|org(?:anization)?|repo|you|me|example|someone|account|name|sponsors)$/i.test(owner);
    return template ? base : `${base}/${owner.toLowerCase()}`;
  }
  const labels = h.split(".");
  let keep = 2;
  if (labels.length >= 3 && SECOND_LEVEL.has(labels[labels.length - 2]) && labels[labels.length - 1].length === 2) keep = 3;
  for (let n = 2; n <= 4 && n < labels.length; n++) if (SHARED_SUFFIXES.has(labels.slice(-n).join("."))) keep = n + 1;
  const site = labels.slice(-keep).join(".");
  return STAND_IN.test(site) ? undefined : site;
}

// Inside ~/.openclaw only these hold secrets; workspace, skills and memory do not.
const OPENCLAW_SECRET = /\.openclaw\/(?:openclaw\.json|credentials\b|(?:[^/\s]+\/)*auth[^/\s]*\.json|\.env\b)/i;
// Comment syntax by language. `//usr/bin/curl` is a path to a shell, and
// `#field` is a private field to JavaScript.
const HASH_COMMENT = new Set(["shell", "python", "ruby", "perl", "powershell", "config", "other"]);
const SLASH_COMMENT = new Set(["javascript", "typescript", "go", "rust", "php"]);
const isComment = (language: string, text: string) =>
  HASH_COMMENT.has(language) && /^\s*#(?!!)/.test(text) || SLASH_COMMENT.has(language) && /^\s*\/\//.test(text);
// Lockfiles and licences carry registry and author URLs that are never fetched.
const NOT_CODE_FILE = /(?:^|\/)(?:[^/]*\.lock|[^/]*-lock\.(?:json|ya?ml)|go\.sum|LICEN[CS]E[^/]*|NOTICE[^/]*|CHANGELOG[^/]*)$/i;
// A persistence path is a capability only where the line writes to it or installs it.
const WRITES = /(?:>>?|\btee\b|\b(?:cp|mv|ln|install|chmod)\s|write|append|open\s*\([^)]*['"][wa]|\bcrontab\b(?![^\n]*['"\s]-l\b)|systemctl\s+(?:--user\s+)?enable|launchctl\s+(?:load|bootstrap)|New-ItemProperty|Set-ItemProperty|reg\s+add|schtasks)/i;
const PATH_TOKEN = /[^\s'"`()<>,;|&=]+/g;
// Where the user's home directory starts in a path, so `~/.ssh` and `$HOME/.ssh` match.
const HOME = /^(?:~|\$HOME|\$\{HOME\}|%USERPROFILE%|\/(?:home|Users)\/[^/]+)/;

const ENV_READ = [
  /\b(?:os\.environ(?:\.get)?|os\.getenv|getenv|process\.env|Deno\.env\.get|ENV)\s*[[(.]\s*['"]?([A-Z][A-Z0-9_]{2,})/g,
  /\$\{?([A-Z][A-Z0-9_]{2,})\b/g,
];

// The behaviours an update can add that a user must hear about. Lower
// findings are routine (a new API call, an undeclared tool) and churn, and a
// high match in prose is as often a warning about a risk as the risk itself.
// Critical matches count anywhere; high ones in code or proven by dataflow.
const isBehaviour = (f: Finding, code: Set<number>) =>
  f.severity === "critical" || f.severity === "high" && (f.analysisPass === "dataflow" || f.lineNumber != null && code.has(f.lineNumber));

export interface CapabilityOptions {
  /** Environment variables the frontmatter declares (metadata.openclaw.requires.env). */
  declaredEnv?: string[];
}

/** Capabilities in a stable order, one entry per (kind, value), at the first place it appears. */
export function extractCapabilities(sources: SourceFile[], findings: Finding[], options: CapabilityOptions = {}): Capability[] {
  const found = new Map<string, Capability>();
  const add = (kind: CapabilityKind, value: string, file: string | undefined, line: number | undefined, extra: Partial<Capability> = {}) => {
    const key = `${kind}\u0000${value}`;
    if (!found.has(key)) found.set(key, { kind, value, ...(file ? { file } : {}), ...(line ? { line } : {}), ...extra });
  };
  // Frontmatter is untrusted YAML: requires.env can be anything, not only a list of names.
  const env: unknown = options.declaredEnv;
  const declared = new Set(Array.isArray(env) ? env.filter((e): e is string => typeof e === "string").map((e) => e.toUpperCase()) : []);
  const code = new Set<number>();
  for (const source of sources) {
    if (!isCode(source.language)) continue;
    // Data files and data fences hold example payloads, not requests.
    const data = source.language === "config" || NOT_CODE_FILE.test(source.path);
    if (!data) for (let l = source.startLine; l <= source.endLine; l++) code.add(l);
    const lines = source.text.split("\n");
    lines.forEach((text, i) => {
      const line = source.startLine + i;
      // A comment line is documentation, not something the code does.
      if (isComment(source.language, text)) return;
      if (!data) for (const m of text.matchAll(URL_HOST)) {
        const site = siteOf(m[1], m[2]);
        if (site) add("network", site, source.path, line, riskySite(site) ? { risky: true } : {});
      }
      for (const token of text.match(PATH_TOKEN) ?? []) {
        const path = token.replaceAll("\\", "/");
        // Registry paths keep their backslashes.
        const matches = (re: RegExp) => re.test(path) || re.test(token);
        const store = CREDENTIAL_STORES.find((s) => matches(s.pattern));
        // A relative `.ssh/x` inside a project is not the user's key store; require the home prefix
        // for the home stores, as cat, open() and fs.readFile all spell it.
        const home = HOME.test(path) || /^\.?\/?\.(?:ssh|aws|gnupg|docker|kube|openclaw)\b/.test(path) && /expanduser|homedir|\$HOME|~/.test(text);
        if (store && !(store.name === "~/.openclaw" && !OPENCLAW_SECRET.test(path)) && (home || store.rooted || path.startsWith("/etc/"))) {
          add("secret", store.name, source.path, line);
        }
        const place = PERSISTENCE_LOCATIONS.find((s) => matches(s.pattern));
        if (place && WRITES.test(text) && (HOME.test(path) || place.rooted || path.startsWith("/etc/") || path.startsWith("/Library/") || /^(?:crontab|\/var\/spool\/cron)/.test(path))) {
          add("persistence", place.name, source.path, line);
        }
      }
      if (/(?:^|[\s;&|(`])crontab\s+(?:-[a-z]*\s+)*(?:-|\S+\.(?:txt|cron)|<|$)/.test(text) && !/crontab\s+-l\s*$/.test(text)) add("persistence", "cron", source.path, line);
      for (const re of ENV_READ) for (const m of text.matchAll(re)) {
        const name = m[1];
        if (SECRET_ENV.test(name)) add("env", name, source.path, line, declared.has(name) ? { declared: true } : {});
      }
    });
  }
  for (const f of findings) {
    if (f.category === "metadata" || !isBehaviour(f, code)) continue;
    add("behavior", f.title, undefined, f.lineNumber ?? undefined, { severity: f.severity });
  }
  return sorted([...found.values()]);
}

const ORDER: CapabilityKind[] = ["network", "secret", "env", "persistence", "behavior"];
const sorted = (caps: Capability[]) => caps.sort((a, b) => ORDER.indexOf(a.kind) - ORDER.indexOf(b.kind) || a.value.localeCompare(b.value));

/**
 * Behaviours after a pass that runs after the scan changed the findings: a
 * baseline removes some, the judge or OSV adds some. A behaviour whose finding
 * is gone is dropped; a new critical finding is added. Code-line context is
 * not available here, so only criticals and dataflow highs are added.
 */
export function refreshBehaviours(capabilities: Capability[] | undefined, findings: Finding[]): Capability[] | undefined {
  if (!capabilities) return capabilities;
  const titles = new Set(findings.filter((f) => f.category !== "metadata").map((f) => f.title));
  const kept = capabilities.filter((c) => c.kind !== "behavior" || titles.has(c.value));
  const have = new Set(kept.filter((c) => c.kind === "behavior").map((c) => c.value));
  for (const f of findings) {
    if (f.category === "metadata" || have.has(f.title)) continue;
    if (f.severity === "critical" || f.severity === "high" && f.analysisPass === "dataflow") {
      have.add(f.title);
      kept.push({ kind: "behavior", value: f.title, ...(f.lineNumber ? { line: f.lineNumber } : {}), severity: f.severity });
    }
  }
  return sorted(kept);
}

export interface CapabilityChange { added: Capability[]; removed: Capability[] }

/** What `after` can do that `before` could not, and what it no longer does. */
export function diffCapabilities(before: Capability[], after: Capability[]): CapabilityChange {
  const key = (c: Capability) => `${c.kind}\u0000${c.value}`;
  const had = new Set(before.map(key));
  const has = new Set(after.map(key));
  return { added: after.filter((c) => !had.has(key(c))), removed: before.filter((c) => !has.has(key(c))) };
}

/**
 * The additions a user must approve. A new secret env var is listed but never
 * asks: it is how a skill adds an API integration, and sending one somewhere
 * unexpected already shows as a new site or a proven flow (dropping env asks
 * cost no malicious catch on the tune half). Under "quiet", the default, a new
 * site asks only when it is risky; under "all" every new site asks.
 */
export function newPermissions(change: CapabilityChange, mode: "quiet" | "all" = "quiet", options: { owner?: string } = {}): Capability[] {
  // Code hosted under the skill's own publisher is not a stranger's code.
  const own = options.owner ? new RegExp(`^(?:github|gitlab)\\.com/${options.owner.toLowerCase().replace(/[^a-z0-9_.-]/g, "")}$`) : undefined;
  const risky = (c: Capability) => c.risky && !(own && own.test(c.value));
  return change.added.filter((c) => c.kind !== "env" && (mode === "all" || c.kind !== "network" || risky(c)));
}
