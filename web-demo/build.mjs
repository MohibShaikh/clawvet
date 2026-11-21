import { cp, mkdir, rm } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..");
const dist = resolve(here, "dist");

await rm(dist, { recursive: true, force: true });
await mkdir(resolve(dist, "grammars"), { recursive: true });
await mkdir(resolve(dist, "wasm"), { recursive: true });

// Stub Node-only builtins that live behind dynamic branches in web-tree-sitter
// and parser.ts; the browser demo configures URL-based WASM loading instead.
const browserNodeStubPlugin = {
  name: "browser-node-stub",
  setup(b) {
    b.onResolve({ filter: /^(?:node:)?(?:fs|fs\/promises|path|url|module)$/ }, (args) => ({
      path: args.path,
      namespace: "node-stub",
    }));
    b.onLoad({ filter: /.*/, namespace: "node-stub" }, () => ({
      contents: "export const access = async () => { throw new Error('Node fs unavailable in browser'); }; export const fileURLToPath = (u) => String(u); export default {};",
      loader: "js",
    }));
  },
};

await build({
  entryPoints: [resolve(here, "src/app.ts")],
  bundle: true,
  format: "esm",
  platform: "browser",
  target: "es2022",
  minify: true,
  sourcemap: false,
  outfile: resolve(dist, "app.js"),
  plugins: [browserNodeStubPlugin],
  alias: {
    "@clawvet/shared": resolve(root, "packages/shared/src/index.ts"),
  },
});

await cp(resolve(here, "src/index.html"), resolve(dist, "index.html"));
await cp(resolve(here, "src/style.css"), resolve(dist, "style.css"));
await cp(
  resolve(root, "node_modules/web-tree-sitter/web-tree-sitter.wasm"),
  resolve(dist, "wasm/web-tree-sitter.wasm"),
);

const grammars = [
  "tree-sitter-bash.wasm",
  "tree-sitter-javascript.wasm",
  "tree-sitter-python.wasm",
  "tree-sitter-typescript.wasm",
  "tree-sitter-tsx.wasm",
];
for (const file of grammars) {
  await cp(resolve(root, "packages/shared/grammars", file), resolve(dist, "grammars", file));
}

console.log(`Built static ClawVet Web Demo -> ${dist}`);
