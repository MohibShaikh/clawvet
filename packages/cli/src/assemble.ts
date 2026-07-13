import { readFileSync, readdirSync, statSync } from "node:fs";
import { basename, join } from "node:path";

const MAX_REFERENCED_FILE_SIZE = 256 * 1024;
const SHALLOW_DIRECTORIES = new Set(["lib", "scripts"]);

interface CandidateFile {
  absolutePath: string;
  relativePath: string;
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function isReferenced(skillMd: string, relativePath: string): boolean {
  // ponytail: basename substring match; upgrade to real reference parsing
  // (Markdown links + shell tokens) if benchmark false-negatives appear.
  const names = new Set([basename(relativePath), relativePath]);
  return [...names].some((name) =>
    new RegExp(`\\b${escapeRegExp(name)}\\b`).test(skillMd)
  );
}

function listCandidates(skillDir: string): CandidateFile[] {
  const candidates: CandidateFile[] = [];

  let entries;
  try {
    entries = readdirSync(skillDir, { withFileTypes: true });
  } catch {
    return candidates;
  }

  for (const entry of entries) {
    if (entry.isFile()) {
      if (entry.name !== "SKILL.md") {
        candidates.push({
          absolutePath: join(skillDir, entry.name),
          relativePath: entry.name,
        });
      }
      continue;
    }

    if (!entry.isDirectory() || !SHALLOW_DIRECTORIES.has(entry.name)) {
      continue;
    }

    try {
      for (const child of readdirSync(join(skillDir, entry.name), {
        withFileTypes: true,
      })) {
        if (child.isFile()) {
          candidates.push({
            absolutePath: join(skillDir, entry.name, child.name),
            relativePath: `${entry.name}/${child.name}`,
          });
        }
      }
    } catch {
      // A missing or unreadable optional directory should not abort the scan.
    }
  }

  return candidates.sort((a, b) =>
    a.relativePath.localeCompare(b.relativePath)
  );
}

/**
 * Appends local files explicitly referenced by a skill manifest so the shared
 * string-only scanner can inspect cross-file payloads without filesystem access.
 */
export function assembleSkill(skillDir: string, skillMd: string): string {
  let assembled = skillMd;

  for (const candidate of listCandidates(skillDir)) {
    if (!isReferenced(skillMd, candidate.relativePath)) {
      continue;
    }

    try {
      const stat = statSync(candidate.absolutePath);
      if (stat.size > MAX_REFERENCED_FILE_SIZE) {
        continue;
      }

      const contents = readFileSync(candidate.absolutePath);
      if (contents.includes(0)) {
        continue;
      }

      const separator = assembled.endsWith("\n") ? "\n" : "\n\n";
      assembled += `${separator}# [clawvet] referenced file: ${candidate.relativePath}\n${contents.toString("utf-8")}`;
    } catch {
      // Files may disappear or become unreadable between listing and reading.
    }
  }

  return assembled;
}
