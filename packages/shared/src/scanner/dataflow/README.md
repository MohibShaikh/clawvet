# Dataflow pass

`analyzeDataflow(sources, { budgetMs? })` returns findings with the `dataflow`
analysis pass and maps sink lines back to `SourceFile.startLine`. It never
imports or executes the analysed source. Python is registered in `index.ts`;
unsupported languages are skipped before initialising tree-sitter.

The parser runtime initialises lazily and caches grammar loading. Individual
parsers and trees are released after each file. `parser.ts` resolves assets
relative to `import.meta.url`, including the bundled CLI's `dist/grammars`.
The vendored grammar's provenance, hash, license and restoration instructions
are in `../../../grammars/README.md`.

## Frontend contract

Implement `DataflowFrontend` from `ir.ts` in `frontends/javascript.ts` or
`frontends/shell.ts`, add a corresponding `specs/*.ts` data table and vendored
grammar, and register the language in `index.ts`. The engine needs no edits.

- Return a module and intra-file functions with local, dense node IDs.
- Canonicalise import aliases into `symbol.name`. `attribute` extends the
  receiver's API; constructor `resultApi` rules type subsequent method calls.
- `call.inputs` begins with its callee, followed by argument value IDs. Put
  named arguments in `args` and the receiver value ID in `receiver`.
- Use `merge` for control-flow joins and containers, `concat` for string
  construction, and `xor` for XOR transformations. Loop-carried `merge`
  nodes may refer back to later nodes. `mutations` taint all aliases of a value.
- Record enclosing lexical loop IDs on nodes. Populate module `globals` with
  final module bindings so function summaries can read module constants.
- Call rules declare effects and target positions. `network` emits send
  events, `network_read` creates response taint, and `request` constructs a
  request while retaining authentication exceptions. `target: "receiver"`
  models handle and Path-style I/O. Path separators, URL positions and shell
  options belong in spec tables, alongside API names.

The engine uses bounded worklists and iterative intra-file summaries for
parameter-to-return and parameter-to-sink flows. Taint origins, strings,
propagated events per helper call, updates, summary rounds and frontend recursion
have fixed caps. Direct events are retained in linear space.
This bounds work in the size of the lowered graph. It models whole objects,
not individual keys, and does not model inter-file calls, arbitrary reflection,
full class dispatch, filesystem content across separate write/read operations,
or complete Python execution semantics. Large graphs can hit a worklist or
summary cap before all flows are discovered. The time budget stops subsequent
files and emits a low-severity truncation finding; parsing and lowering of the
current file can finish after its deadline.

Authentication exceptions suppress only single-variable environment taint in
headers or `api_key`; credential-file and whole-environment flows stay visible.
A single secret environment variable sent in a body to a literal host is medium.
API keys placed in URLs can still produce critical findings.

## Verification and measured corpus results

Run from the repository root:

```sh
cd packages/shared && npx vitest run test/dataflow-python.test.ts
```

Measured result: 66 tests passed. The shared typecheck passes. CLI packaging
was verified with `cd packages/cli && npx tsup`, an inert built-CLI `scan`, and
an independently bundled dataflow entry placed beside the CLI to exercise its
WASM fallback. The generated CLI `dist` directory was deleted before the last
test run. The CLI typecheck subsequently encountered an unrelated concurrent
edit's `TS2304` at `packages/cli/src/commands/scan.ts:262` (`semanticAnalyzer`).

To repeat the read-only corpus measurement:

```sh
npx tsx packages/shared/src/scanner/dataflow/benchmark.ts
```

`benchmark-results.json` records measured results, runtime, sample seeds and
cohort hashes. Filesystem reading occurs outside the latency timing; each
measured skill invokes the public API with its Python files. Files exceeding
the scanner's input caps are omitted. The latency cohort samples Python-bearing
skills across both corpus labels; the benign cohort randomly samples benign
skill directories, including those without Python files. No corpus source is
copied into this repository.

Measured latency across 500 skills containing 630 Python files: median
6.47 ms, p95 40.24 ms, maximum 265.04 ms, cold initialisation 42.61 ms.
Measured budget truncations: 3 skills. The random benign sample measured
2 high/critical-positive skills out of 500; 52 sampled skills contained Python.
Read-only inspection of both found API-key authentication in URLs, outside
the specified header exception. This is a finding count against corpus labels, not a human
adjudication of maliciousness.

## Scanner integration

Add the pass after the regex context pass and before scoring so capability
confidence discounts do not downweight established dataflow. Keep the existing
ignore-pattern behavior for the added findings. The implementation task leaves
`scanner/index.ts` to the lead engineer.

The standalone shared npm package currently publishes only `dist`; publishing
this pass independently of the CLI also requires including `grammars` in that
package's `files` list. The CLI build already ships those assets.

In `scanner/index.ts`, import `collectSources` beside `codeLines`, import
`analyzeDataflow` from `./dataflow/index.js`, and replace the existing
`contextFindings` declaration with:

```ts
const dataflow = await analyzeDataflow(collectSources(skill, files));
const contextFindings = [
  ...applyContext(filteredFindings, codeLines(skill, files)),
  ...dataflow.filter((f) => !options.ignorePatterns?.some(
    (ig) => f.title === ig || f.category === ig
  )),
];
```

Existing scoring, counts, result construction and caching then include the pass.
