import type { CallEffect, LanguageSpecs } from "../ir.js";

// These tables describe sensitive locations, independently of language APIs.
export const SECRET_ENV = /(?:TOKEN|KEY|SECRET|PASSWORD|PASSWD|CREDENTIAL)/i;
export const CREDENTIAL_PATHS: RegExp[] = [
  /(?:^|\/)\.ssh\/(?!config(?:$|\/))[^/]+/i,
  // The whole directory, as tar, zip and scp -r take it.
  /(?:^|\/)\.(?:ssh|aws|gnupg)\/?$/i,
  /^\/etc\/g?shadow$/,
  /(?:^|\/)\.aws\/credentials(?:$|\/)/i,
  /(?:^|\/)(?:\.npmrc|\.netrc|\.pypirc|\.git-credentials)(?:$|\/)/i,
  /(?:^|\/)\.docker\/config\.json$/i,
  /(?:^|\/)\.kube\/config$/i,
  /(?:^|\/)(?:cookies(?:\.sqlite)?|login data|logins\.json|key[34]\.db|wallet\.dat|keystore)(?:$|\/)/i,
  /(?:^|\/)(?:\.openclaw|\.clawdbot|\.moltbot)(?:$|\/)/i,
  /(?:^|\/)(?:\.config\/)?(?:solana|electrum|ethereum|exodus|metamask)(?:$|\/)/i,
];
export const PERSISTENCE_PATHS: RegExp[] = [
  /(?:^|\/)(?:crontab|cron\.(?:d|daily|hourly|weekly|monthly))(?:$|\/)/i,
  /(?:^|\/)(?:systemd\/(?:system|user)|LaunchAgents|LaunchDaemons|autostart)(?:$|\/)/i,
  /(?:^|\/)(?:\.(?:bashrc|bash_profile|profile|zshrc|zprofile)|profile\.d)(?:$|\/)/i,
  // A key appended here can log in from then on.
  /(?:^|\/)\.ssh\/authorized_keys2?$/i,
  /(?:^|\/)Microsoft\/Windows\/Start Menu\/Programs\/Startup(?:$|\/)/i,
  /(?:^|\\)Software\\Microsoft\\Windows\\CurrentVersion\\Run(?:Once)?(?:$|\\)/i,
];
// A project's .env holds the same secrets as its environment, read the way
// dotenv does. Treat it as environment taint: sending the whole file is a dump
// of every secret, while one key in an auth header is the ordinary API client
// it usually is. Home credential stores (~/.ssh, ~/.aws, wallets) stay credentials.
const PROJECT_SECRET = /(?:^|\/)\.env(?:\.[^/]*)?$/i;
export function projectSecretPath(path: string): boolean {
  return PROJECT_SECRET.test(path.replaceAll("\\", "/"));
}
export function credentialPath(path: string): boolean {
  return CREDENTIAL_PATHS.some((pattern) => pattern.test(path.replaceAll("\\", "/")));
}
export function persistencePath(path: string): boolean {
  return PERSISTENCE_PATHS.some((pattern) => pattern.test(path));
}
export const TRANSFER_COMMAND = /(?:^|[\s/|;&])(?:curl|wget|nc|ncat|scp|ssh)(?:\s|$)/;

// Effects a finding cannot exist without: a sink, or the only producers of the
// data an execution sink reports (a response, a decode). Rules with a resultApi
// are the constructors whose receivers those sinks are called on.
const NEEDED: CallEffect[] = ["network", "dns", "command", "write", "mutate", "open", "network_read", "decode"];

/**
 * The first name of every API a rule can match: `fs` for `^fs\.writeFile$`,
 * `decode` for the member rule `\.decode$`. Undefined when a rule can start
 * with anything, because then no text can be ruled out.
 */
export function ruleRoots(names: RegExp): string[] | undefined {
  const source = names.source, roots = new Set<string>();
  // What held when each group opened: could a name still be at its first
  // identifier, and was that identifier a member name (after a leading dot).
  const open: [boolean, boolean][] = [];
  let start = true, member = false;
  for (let i = 0; i < source.length;) {
    const rest = source.slice(i);
    const word = /^[A-Za-z_][A-Za-z0-9_]*/.exec(rest)?.[0];
    if (word) {
      if (start || member) {
        roots.add(word);
        // `https?` matches both spellings.
        if (source[i + word.length] === "?") roots.add(word.slice(0, -1));
      }
      start = false; member = false; i += word.length;
    } else if (rest.startsWith("(?:")) { open.push([start, member]); i += 3; }
    else if (rest[0] === "(") return undefined;
    else if (rest[0] === ")") {
      const [before, beforeMember] = open.pop() ?? [false, false];
      // An optional group may be absent, so what follows can still be first.
      const optional = /^[?*]/.test(source.slice(i + 1));
      start = optional && before; member = optional && beforeMember; i++;
    } else if (rest[0] === "|") { [start, member] = open.length ? open[open.length - 1] : [true, false]; i++; }
    else if (rest[0] === "^") { start = true; i++; }
    // A rule that begins with a dot matches by member name, whatever the receiver.
    else if (rest.startsWith("\\.") && start) { member = true; start = false; i += 2; }
    else if (rest[0] === "\\") { if (start) return undefined; i += 2; }
    else if (rest[0] === "." || rest[0] === "[") { if (start) return undefined; i++; }
    else i++;
  }
  return [...roots];
}

/**
 * A cheap test for "this text names an API some finding needs". Canonical API
 * names come from identifiers and module strings in the source, so a source
 * that spells none of these roots cannot reach a sink and is not worth parsing.
 */
export function sinkHint(specs: LanguageSpecs): RegExp | undefined {
  const roots = new Set<string>();
  for (const rule of specs.calls) {
    if (!rule.resultApi && !rule.effects.some((effect) => NEEDED.includes(effect))) continue;
    const found = ruleRoots(rule.names);
    if (!found) return undefined;
    for (const root of found) roots.add(root);
  }
  return roots.size ? new RegExp(`(?<![A-Za-z0-9_$])(?:${[...roots].join("|")})(?![A-Za-z0-9_$])`) : undefined;
}
