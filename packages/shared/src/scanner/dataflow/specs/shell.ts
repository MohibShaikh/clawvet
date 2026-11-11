import type { LanguageSpecs } from "../ir.js";

// The frontend resolves CLI positions and redirections before applying effects.
export const shellSpecs: LanguageSpecs = {
  accesses: [
    { names: /^shell\.environment$/, source: "environment_all" },
    { names: /^shell\.secret\./, source: "environment" },
  ],
  calls: [
    { names: /^shell\.read$/, effects: ["read"] },
    { names: /^shell\.env$/, effects: ["environment"] },
    { names: /^shell\.clipboard$/, effects: ["clipboard"] },
    { names: /^shell\.host$/, effects: ["host"] },
    { names: /^shell\.walk$/, effects: ["walk"] },
    { names: /^shell\.encode$/, effects: ["encode"], clearApi: true },
    { names: /^shell\.decode$/, effects: ["decode"], clearApi: true },
    { names: /^shell\.encrypt$/, effects: ["encrypt"], clearApi: true },
    { names: /^shell\.response$/, effects: ["network_read"] },
    { names: /^shell\.(?:curl|wget|send)$/, effects: ["network"] },
    { names: /^shell\.dns$/, effects: ["dns"] },
    { names: /^shell\.execute$/, effects: ["execute"] },
    { names: /^shell\.write$/, effects: ["write"] },
    { names: /^shell\.mutate$/, effects: ["mutate"] },
  ],
};

export const SHELL_OPTIONS = {
  curlData: /^(?:-d|--data(?:-[\w-]+)?|-F|--form(?:-string)?|-T|--upload-file)$/,
  curlValue: /^(?:-H|--header|-u|--user|-o|--output|-X|--request|-A|--user-agent|-e|--referer|--url|--connect-timeout|--max-time|-m|--retry|--proxy|-x|--cacert|--cert|--key|-b|--cookie|-c|--cookie-jar)$/,
  wgetValue: /^(?:-O|--output-document|-P|--directory-prefix|--post-data|--post-file|--header|--user|--password|--timeout|--tries)$/,
  home: /^(?:~|\$HOME|\$\{HOME\}|\/home\/[^/]+|\/Users\/[^/]+)(?:\/|$)/,
  remoteValue: /^(?:-i|-P|-S|-o|-F|-c|-l|-J|--password-file|--exclude|--include|--filter|--rsync-path|--rsh|-e)$/,
  remote: /^(?:[^/@\s]+@)?[^/:\s]+:/,
  interpreters: /^(?:bash|sh|zsh|dash|ksh)$/,
  wrappers: /^(?:command|builtin|env|sudo|doas|nohup|exec|nice)$/,
  sudoValue: /^(?:-[ugUCphT]|--(?:user|group))$/,
  socket: /^\/dev\/(?:tcp|udp)\//,
};

// Every command the frontend turns into a sink, a response or a decode, and the
// handler it gets. The frontend dispatches on this table and the prefilter reads
// its keys, so a command cannot be handled without also keeping its source.
export type ShellSink = "transfer" | "send" | "copy" | "dns" | "codec" | "archive" | "cipher" | "store" | "tee" | "crontab" | "launchctl";
export const SHELL_SINKS: ReadonlyMap<string, ShellSink> = new Map<string, ShellSink>([
  ["curl", "transfer"], ["wget", "transfer"],
  ["nc", "send"], ["ncat", "send"], ["socat", "send"], ["mail", "send"], ["sendmail", "send"], ["ssh", "send"],
  ["scp", "copy"], ["rsync", "copy"],
  ["dig", "dns"], ["nslookup", "dns"], ["host", "dns"],
  ["base64", "codec"], ["xxd", "codec"], ["od", "codec"],
  ["gzip", "archive"], ["zstd", "archive"], ["tar", "archive"], ["zip", "archive"],
  ["openssl", "cipher"], ["gpg", "cipher"], ["tr", "cipher"],
  ["cp", "store"], ["tee", "tee"], ["crontab", "crontab"], ["launchctl", "launchctl"],
]);

/**
 * False for the common fenced one-liner (`npm install x`, `git status`) that
 * can reach no sink. A finding needs a sink command, a redirection, or a name
 * built at run time. Quotes and backslashes are dropped first, because the
 * frontend reads `"cu""rl"` and `c\url` as curl; any expansion or redirection
 * keeps the source, because a command name or a target can be built from it.
 */
export function shellMayFind(text: string): boolean {
  if (/[$`>]/.test(text)) return true;
  const bare = text.replace(/\\\r?\n/g, "").replace(/['"\\]/g, "");
  // `bash < /dev/tcp/host/port` names no sink command: the path is the network.
  return /\/dev\/(?:tcp|udp)\//.test(bare) || bare.split(/[^A-Za-z0-9_]+/).some((word) => SHELL_SINKS.has(word));
}
