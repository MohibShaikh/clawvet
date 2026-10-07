import type { Finding } from "../types.js";

// A static context pass over the whole finding set, run before scoring.
//
// Many rules fire on a capability that is only dangerous once it is paired with
// a way to get data out or run remote code. Reading ~/.aws/credentials is theft
// when it is piped to a webhook and configuration when it is not. The regex
// stage can't see that difference; this pass can, because it sees every finding
// in the skill at once.
//
// Rule: if the skill contains no exfiltration/remote-exec SINK, downweight the
// dual-use capability findings so a lone capability no longer reaches the warn
// band. Skills that pair the same capability with a sink keep full weight, so
// this costs no recall on the corpus (every credential/persistence-based
// malicious fixture also carries an exfil or curl-pipe-bash sink).

// Capabilities that are common in legitimate skills and only incriminating in
// combination. Deliberately excludes remote_code_execution / obfuscation:
// a lone inline interpreter or eval is left for the semantic stage to judge,
// because static rules can't tell a REPL from an obfuscated dropper.
const DUAL_USE_CATEGORIES = new Set([
  "credential_theft",
  "container_escape",
  "privilege_escalation",
  "persistence",
]);

// Signals that a capability is actually being weaponised: data leaving the box,
// or remote code being pulled and run.
const SINK_CATEGORIES = new Set(["data_exfiltration"]);
const SINK_TITLES = new Set([
  "Curl piped to shell",
  "Wget with shell execution",
  "Shell execution API",
  "Reverse shell",
  "Known malicious IP",
]);

const DOWNWEIGHT = 0.3;

function inCode(line: number | null | undefined, codeLines: Set<number>): boolean {
  return line !== null && line !== undefined && codeLines.has(line);
}

// The install-me envelope. Real malicious skills keep the payload in a
// referenced script or binary and leave only the instructions that get a user
// to run it in the markdown. Each half is common on its own: 48 of 400 clean
// ClawHub skills say "install X first", and legitimate READMEs tell you to run
// a command. Together they are not: on the 500-skill real corpus this pair
// fires on 48 of 50 malicious skills and 0 of 450 benign ones.
//
// Each half is medium severity, so an envelope-only skill tops out at 24 and
// never crosses the warn line at 26. Promoting the pair is what closes that
// two-point gap on the threat class where the payload is out of file.
const ENVELOPE_TITLES = ["Prerequisite install trick", "Copy-paste command instruction"];

// Hosts whose whole purpose is a documented one-line installer. `curl | sh` off
// one of these is the vendor's own published instruction, not a dropper, and it
// was the single most common cause of a real clean skill being flagged. An
// attacker cannot use this without first compromising the vendor, in which case
// the install script is the least of anyone's problems.
//
// Matched as exact hosts, plus an exact path prefix where the host is shared,
// on a parsed https URL. A substring match let "astral.sh.evil.example" and
// "evil.example/?source=astral.sh" borrow the vendor's trust.
const TRUSTED_INSTALLERS: Array<{ host: string; path?: string }> = [
  { host: "astral.sh" },
  { host: "sh.rustup.rs" },
  { host: "get.docker.com" },
  { host: "install.python-poetry.org" },
  { host: "get.pnpm.io" },
  { host: "bun.sh" },
  { host: "ollama.com" },
  { host: "deb.nodesource.com" },
  { host: "raw.githubusercontent.com", path: "/Homebrew/" },
  { host: "get.volta.sh" },
];

export function isTrustedInstallerUrl(value: string): boolean {
  let url: URL;
  try { url = new URL(value); } catch { return false; }
  if (url.protocol !== "https:") return false;
  return TRUSTED_INSTALLERS.some(({ host, path }) =>
    url.hostname.toLowerCase() === host && (!path || url.pathname.startsWith(path)));
}

/** True when a command fetches only from trusted installer URLs. */
export function onlyTrustedInstallers(text: string): boolean {
  const urls = text.match(/https?:\/\/[^\s'"`|;&)<>]+/g) ?? [];
  return urls.length > 0 && urls.every(isTrustedInstallerUrl);
}

const PIPE_TO_SHELL = new Set(["Curl piped to shell", "Wget with shell execution"]);

function fromTrustedInstaller(f: Finding): boolean {
  return PIPE_TO_SHELL.has(f.title) && onlyTrustedInstallers(f.evidence ?? "");
}

function isSink(f: Finding): boolean {
  if (fromTrustedInstaller(f)) return false;
  return SINK_CATEGORIES.has(f.category) || SINK_TITLES.has(f.title);
}

function isDualUse(f: Finding): boolean {
  return DUAL_USE_CATEGORIES.has(f.category);
}

function promoteEnvelope(findings: Finding[]): Finding[] {
  const titles = new Set(findings.map((f) => f.title));
  if (!ENVELOPE_TITLES.every((t) => titles.has(t))) return findings;

  // The pair is its own concern, not a louder version of either half, so it is
  // reported as a separate finding and the halves stay as the evidence for it.
  // Confidence is 1.0 for the same reason a curated indicator of compromise is:
  // this is an exact co-occurrence, not a fuzzy heuristic that gets less
  // certain depending on where in the file it matched.
  const anchor = findings.find((f) => f.title === ENVELOPE_TITLES[0])!;
  const envelope: Finding = {
    category: "social_engineering",
    severity: "high",
    title: "Install-me envelope",
    description:
      "The skill tells the user to install a prerequisite and run a command, without the payload being in SKILL.md. This is how a skill gets code it does not contain executed.",
    evidence: anchor.evidence,
    lineNumber: anchor.lineNumber,
    analysisPass: "context-classifier",
    confidence: 1.0,
    fix: "Declare dependencies in `metadata.openclaw.requires.bins` and ship the code you run, so it can be reviewed before it executes.",
  };
  return [...findings, envelope];
}

// A credential read on its own is configuration, and an outbound request on its
// own is an API call. Together in one skill they are the exfiltration pattern:
// a secret is read and something sends data out. This is the mirror of the
// downweight below, and the reason it can be stated with confidence 1.0 is the
// same: the co-occurrence is exact, not a guess about any single line.
function taintExfiltration(findings: Finding[], codeLines: Set<number>): Finding[] {
  const source = findings.find((f) => f.category === "credential_theft");
  const sink = findings.find((f) => f.category === "data_exfiltration");
  if (!source || !sink) return findings;
  // Both halves must be actual uses: a declaration in frontmatter or a prose
  // threat-table mention is documenting, not doing. An OAuth client declaring
  // its API key and posting to the user's own webhook, or a security scanner
  // listing exfiltration patterns, is not the exfiltration pattern.
  if (!inCode(source.lineNumber, codeLines) || !inCode(sink.lineNumber, codeLines)) {
    return findings;
  }

  return [
    ...findings,
    {
      category: "data_exfiltration",
      severity: "critical",
      title: "Credential exfiltration",
      description: `The skill reads credentials (${source.title}) and sends data out (${sink.title}). Together these are the pattern used to steal secrets.`,
      evidence: source.evidence,
      lineNumber: source.lineNumber,
      analysisPass: "context-classifier",
      confidence: 1.0,
      fix: "Remove the outbound send, or document exactly what is transmitted and let the user supply their own endpoint.",
    },
  ];
}

export function applyContext(findings: Finding[], codeLines?: Set<number>): Finding[] {
  const withEnvelope = promoteEnvelope(findings).map((f) =>
    fromTrustedInstaller(f)
      ? { ...f, severity: "low" as const, confidence: 0.3, description: `${f.description} This one points at a well-known vendor installer.` }
      : f
  );
  const lines = codeLines ?? new Set<number>();
  if (withEnvelope.some(isSink)) return taintExfiltration(withEnvelope, lines);
  return withEnvelope.map((f) =>
    isDualUse(f) && !f.disqualifying
      ? { ...f, confidence: Math.round((f.confidence ?? 1.0) * DOWNWEIGHT * 100) / 100 }
      : f
  );
}
