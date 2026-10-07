#!/usr/bin/env node
// Writes each corpus500 SKILL.md (decoding .b64 copies) into its own folder,
// so the gate can be run on it. The corpus stores SKILL.md only.
// Usage: node prepare-corpus500.mjs <out dir>
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const corpus = resolve(dirname(fileURLToPath(import.meta.url)), "../corpus500");
const out = process.argv[2];
const dirs = [];
for (const tier of ["malicious", "benign", "hard-negatives"]) {
  for (const author of readdirSync(join(corpus, tier))) {
    for (const skill of readdirSync(join(corpus, tier, author))) {
      const md = join(corpus, tier, author, skill, "SKILL.md");
      const text = existsSync(md) ? readFileSync(md) : Buffer.from(readFileSync(md + ".b64", "utf8"), "base64");
      const dir = join(out, tier, `${author}__${skill}`);
      mkdirSync(dir, { recursive: true });
      writeFileSync(join(dir, "SKILL.md"), text);
      dirs.push(dir);
    }
  }
}
writeFileSync(join(out, "corpus500-dirs.txt"), dirs.join("\n") + "\n");
console.log(`${dirs.length} skills`);
