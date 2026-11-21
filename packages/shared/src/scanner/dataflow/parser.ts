import { Parser, Language, LANGUAGE_VERSION, MIN_COMPATIBLE_VERSION } from "web-tree-sitter";

export interface DataflowParserConfig {
  /** Return URL or filesystem path for `tree-sitter-<grammar>.wasm`. */
  resolveGrammar?: (grammar: string) => string | Promise<string>;
  /** Emscripten locateFile hook for `web-tree-sitter.wasm` in browser builds. */
  locateWasm?: (scriptName: string, scriptDirectory: string) => string;
}

let initialized: Promise<void> | undefined;
let config: DataflowParserConfig = {};
const languages = new Map<string, Promise<Language>>();

/**
 * Configure WASM loading paths for non-Node hosts (such as static browser
 * bundles). Calling this clears any cached language promises.
 */
export function configureDataflowParser(next: DataflowParserConfig): void {
  config = { ...next };
  languages.clear();
  initialized = undefined;
}

export async function grammarPath(grammar: string): Promise<string> {
  if (!/^[a-z-]+$/.test(grammar)) throw new Error("Invalid grammar name");
  if (config.resolveGrammar) {
    return await config.resolveGrammar(grammar);
  }
  const name = `tree-sitter-${grammar}.wasm`;
  // Dynamic Node imports keep this module bundleable for browsers when
  // `configureDataflowParser` supplies URL resolvers.
  const [{ access }, { fileURLToPath }] = await Promise.all([
    import("node:fs/promises"),
    import("node:url"),
  ]);
  // Source, shared tsc output, then the self-contained CLI dist layout.
  for (const relative of [`../../../grammars/${name}`, `../../../../grammars/${name}`, `./grammars/${name}`]) {
    const path = fileURLToPath(new URL(relative, import.meta.url));
    try { await access(path); return path; } catch { /* Try the next package layout. */ }
  }
  throw new Error(`Dataflow grammar unavailable: ${name}`);
}

export async function createParser(grammar: string): Promise<Parser> {
  if (!initialized) {
    const initOpts = config.locateWasm ? { locateFile: config.locateWasm } : undefined;
    initialized = Parser.init(initOpts).catch((err) => {
      initialized = undefined;
      throw err;
    });
  }
  await initialized;
  let loading = languages.get(grammar);
  if (!loading) {
    loading = grammarPath(grammar).then((path) => Language.load(path)).then((language) => {
      if (language.abiVersion < MIN_COMPATIBLE_VERSION || language.abiVersion > LANGUAGE_VERSION) {
        throw new Error(`Unsupported dataflow grammar ABI: ${language.abiVersion}`);
      }
      return language;
    }).catch((err) => {
      languages.delete(grammar);
      throw err;
    });
    languages.set(grammar, loading);
  }
  const language = await loading;
  const parser = new Parser();
  parser.setLanguage(language);
  return parser;
}
