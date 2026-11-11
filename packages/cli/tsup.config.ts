import { cp, mkdir } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm"],
  target: "node22",
  outDir: "dist",
  clean: true,
  splitting: false,
  sourcemap: true,
  dts: true,
  banner: {
    js: "#!/usr/bin/env node",
  },
  noExternal: ["@clawvet/shared"],
  external: ["commander", "chalk", "yaml", "fastest-levenshtein", "web-tree-sitter"],
  async onSuccess() {
    const target = fileURLToPath(new URL("./dist/grammars/", import.meta.url));
    await mkdir(target, { recursive: true });
    await cp(fileURLToPath(new URL("../shared/grammars/", import.meta.url)), target, { recursive: true });
  },
});
