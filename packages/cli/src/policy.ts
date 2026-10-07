// Every coverage rule, its message, and what it does under each profile. This
// is the one place gate policy is decided.
//
// strict: anything ClawVet cannot inspect blocks; reviewable gaps ask.
// default: block on clear evidence that code is hidden, swapped, or fetched and
// run; stay quiet on the rest. A gate that asks too often gets switched off or
// approved without reading, which protects no one. Chosen on the tune half of
// MalSkillBench: the quiet rules caught few attacks the blocking rules missed,
// and benchmarks/gate-eval/simulate.mjs replays the comparison.

import type { AssemblyIssue, AssemblyResult } from "./assemble.js";

export type Profile = "default" | "strict";
export type Action = "block" | "ask" | "quiet";

interface Rule {
  message: string;
  strict: "block" | "ask";
  default: Action;
}

export const RULES = {
  // The gate could not read what would run.
  "unreadable": { message: "Cannot read file as UTF-8 text", strict: "block", default: "block" },
  "unreadable-directory": { message: "Cannot read directory", strict: "block", default: "block" },
  "unsafe-directory": { message: "Unsafe or unreadable directory", strict: "block", default: "block" },
  "not-regular-file": { message: "Not a readable regular file", strict: "block", default: "block" },
  "special-file": { message: "Symlinks and special files are not inspected", strict: "block", default: "block" },
  "binary": { message: "Binary content is not inspected", strict: "block", default: "block" },
  "file-limit": { message: "File exceeds 256 KiB inspection limit", strict: "block", default: "block" },
  "total-limit": { message: "Total inspection limit of 2 MiB exceeded", strict: "block", default: "block" },
  "entry-limit": { message: "File/directory count limit exceeded", strict: "block", default: "block" },
  "depth-limit": { message: "Directory depth limit exceeded", strict: "block", default: "block" },
  "manifest-limit": { message: "Manifest exceeds inspection limit or contains binary content", strict: "block", default: "block" },
  "nesting-limit": { message: "Nested inline execution exceeds the static inspection depth limit", strict: "block", default: "block" },
  "missing-skill": { message: "Cannot read skill directory", strict: "block", default: "block" },
  "remote-manifest": { message: "Remote scan fetched only the manifest; stage the full skill locally before approving installation", strict: "block", default: "block" },
  "missing-file": { message: "Referenced file is missing or unsupported", strict: "block", default: "block" },
  // Code outside the skill, or a bundled file swapped at run time.
  "symlink-escape": { message: "Reference escapes the skill root or traverses a symlink", strict: "block", default: "block" },
  "escape": { message: "Reference escapes the skill root or is unresolved", strict: "block", default: "block" },
  "decoy-path": { message: "Path resolves inside the skill from its script's directory but outside it from the skill root; make it relative to the skill root, or cd to the script's directory first", strict: "block", default: "block" },
  "download-executed": { message: "Downloaded file is executed; the staged copy cannot establish coverage of its runtime replacement", strict: "block", default: "block" },
  "download-followed": { message: "Downloaded file is used as instructions; the staged copy cannot establish coverage of its runtime replacement", strict: "block", default: "block" },
  // Code fetched and run, or hidden from inspection.
  "download-and-run": { message: "Instructions to download and execute code require a staged local dependency", strict: "block", default: "block" },
  "pipe-to-shell": { message: "Download-to-execution pipeline is outside local inspection coverage", strict: "block", default: "block" },
  "remote-target": { message: "Remote execution target is outside local inspection coverage", strict: "block", default: "block" },
  "remote-module": { message: "Remote module or code loading is outside local inspection coverage", strict: "block", default: "block" },
  "remote-import": { message: "Remote module loading is outside local inspection coverage", strict: "block", default: "block" },
  "encoded": { message: "Encoded execution cannot be resolved by static file inspection", strict: "block", default: "block" },
  "eval": { message: "Runtime evaluation cannot establish coverage of generated or downloaded code", strict: "block", default: "block" },
  "process": { message: "Process or loader arguments require runtime resolution outside inspection coverage", strict: "block", default: "block" },
  // Unresolved, but rarely the attack on its own.
  "dynamic-module": { message: "Dynamic module name cannot be resolved by static inspection", strict: "block", default: "quiet" },
  "dynamic-loading": { message: "Dynamic code or module loading cannot be resolved; use a literal staged reference", strict: "block", default: "quiet" },
  "python-download": { message: "Python download destination cannot be resolved; stage fixed local dependencies instead", strict: "block", default: "quiet" },
  "dynamic-target": { message: "Dynamic execution target cannot be resolved; use a literal path to a staged file", strict: "ask", default: "quiet" },
  "computed-command": { message: "Computed command or glob cannot be resolved by static file inspection", strict: "ask", default: "quiet" },
  "download-installer": { message: "Downloads an installer or archive; review what it installs", strict: "ask", default: "quiet" },
  "download-unknown": { message: "Downloads code or a file of unknown type; review what uses it", strict: "ask", default: "quiet" },
  "download-destination": { message: "Download destination is unresolved; review what is downloaded", strict: "ask", default: "quiet" },
  "fetch-and-run-package": { message: "Runs a package fetched at install time, outside local inspection coverage; review it before installing", strict: "ask", default: "quiet" },
  "install-from-url": { message: "Installs a package from a URL or archive, outside local inspection coverage; review it before installing", strict: "ask", default: "quiet" },
  "trusted-installer": { message: "Pipes a vendor installer into a shell; review it before installing", strict: "ask", default: "quiet" },
  "outside-document": { message: "Linked document is outside the skill; review it before installing", strict: "ask", default: "quiet" },
} satisfies Record<string, Rule>;

export type RuleId = keyof typeof RULES;

export function action(rule: RuleId, profile: Profile): Action {
  return profile === "strict" ? RULES[rule].strict : RULES[rule].default;
}

/** The coverage issues that block, and those that ask, under a profile. */
export function applyProfile(coverage: AssemblyResult["coverage"], profile: Profile = "default") {
  const all: AssemblyIssue[] = [...coverage.issues, ...coverage.warnings];
  return {
    block: all.filter((i) => action(i.rule, profile) === "block"),
    ask: all.filter((i) => action(i.rule, profile) === "ask"),
  };
}
