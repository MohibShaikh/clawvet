import { access } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { Parser, Language, LANGUAGE_VERSION, MIN_COMPATIBLE_VERSION } from "web-tree-sitter";

let initialized: Promise<void> | undefined;
const languages = new Map<string, Promise<Language>>();

export async function grammarPath(grammar: string): Promise<string> {
  if (!/^[a-z-]+$/.test(grammar)) throw new Error("Invalid grammar name");
  const name = `tree-sitter-${grammar}.wasm`;
  // Source, shared tsc output, then the self-contained CLI dist layout.
  for (const relative of [`../../../grammars/${name}`, `../../../../grammars/${name}`, `./grammars/${name}`]) {
    const path = fileURLToPath(new URL(relative, import.meta.url));
    try { await access(path); return path; } catch { /* Try the next package layout. */ }
  }
  throw new Error(`Dataflow grammar unavailable: ${name}`);
}

export async function createParser(grammar: string): Promise<Parser> {
  initialized ??= Parser.init();
  await initialized;
  let loading = languages.get(grammar);
  if (!loading) {
    loading = grammarPath(grammar).then((path) => Language.load(path)).then((language) => {
      if (language.abiVersion < MIN_COMPATIBLE_VERSION || language.abiVersion > LANGUAGE_VERSION) {
        throw new Error(`Unsupported dataflow grammar ABI: ${language.abiVersion}`);
      }
      return language;
    });
    languages.set(grammar, loading);
  }
  const language = await loading;
  const parser = new Parser();
  parser.setLanguage(language);
  return parser;
}
