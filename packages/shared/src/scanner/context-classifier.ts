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

function isSink(f: Finding): boolean {
  return SINK_CATEGORIES.has(f.category) || SINK_TITLES.has(f.title);
}

function isDualUse(f: Finding): boolean {
  return DUAL_USE_CATEGORIES.has(f.category);
}

export function applyContext(findings: Finding[]): Finding[] {
  if (findings.some(isSink)) return findings;
  return findings.map((f) =>
    isDualUse(f) && !f.disqualifying
      ? { ...f, confidence: Math.round((f.confidence ?? 1.0) * DOWNWEIGHT * 100) / 100 }
      : f
  );
}
