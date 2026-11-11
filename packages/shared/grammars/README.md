# Vendored tree-sitter grammars

No native grammar package is installed. The CLI copies this directory to
`dist/grammars`; `web-tree-sitter` supplies its own runtime WASM through its
exactly pinned dependency.

| File | Upstream package | Version | SHA-256 |
| --- | --- | --- | --- |
| `tree-sitter-python.wasm` | [`tree-sitter-python`](https://registry.npmjs.org/tree-sitter-python/-/tree-sitter-python-0.25.0.tgz) | `0.25.0` | `16108b50df4ee9a30168794252ab55e7c93bfc5765d7fa0aa3e335752c515f47` |
| `tree-sitter-javascript.wasm` | [`tree-sitter-javascript`](https://registry.npmjs.org/tree-sitter-javascript/-/tree-sitter-javascript-0.25.0.tgz) | `0.25.0` | `5fb488d0cabb4775a594bab85682de5ad6ce83c0d6ac997a9f82dd084d571240` |
| `tree-sitter-typescript.wasm` | [`tree-sitter-typescript`](https://registry.npmjs.org/tree-sitter-typescript/-/tree-sitter-typescript-0.23.2.tgz) | `0.23.2` | `778025db5a8be0e70f8ccc3671e486dfeddd048c25d9e8a70c26de2e1bf6f97d` |
| `tree-sitter-tsx.wasm` | [`tree-sitter-typescript`](https://registry.npmjs.org/tree-sitter-typescript/-/tree-sitter-typescript-0.23.2.tgz) | `0.23.2` | `79e5da75ea62855a0cd67177685f0164eac87d5f630b3cbe1e0a099751ad30f8` |
| `tree-sitter-bash.wasm` | [`tree-sitter-bash`](https://registry.npmjs.org/tree-sitter-bash/-/tree-sitter-bash-0.25.1.tgz) | `0.25.1` | `8292919c88a0f7d3fb31d0cd0253ca5a9531bc1ede82b0537f2c63dd8abe6a7a` |

Measured archive SHA-256s: tree-sitter-python 0.25.0
`63b76b3fa8181fd79eaad4abcdb21e2babcb504dbfc7710a89934fa456d26096`, tree-sitter-javascript
0.25.0 `6214ce23d03aba525ba8edd6ca7caf365c969f2c2dbfc353e376ca54507ffb92`,
tree-sitter-typescript 0.23.2 (both `typescript` and `tsx`)
`0fdf63c35930a75885145d75ee63cb879da2d49db9bfe454bd8e60b08ba778a1`, tree-sitter-bash 0.25.1
`d4b2819508ea97cb8953fff7e304a610d443007bd395c8f03a15de9a8ae4a6f9`.
Each upstream MIT license is preserved as `LICENSE.tree-sitter-<name>`.
Measured ABIs: python, javascript and bash 15, typescript and tsx 14; the pinned `web-tree-sitter@0.27.1` runtime's
measured accepted ABI range is 13–15. Loading, setting the language and parsing
are exercised in `test/dataflow-python.test.ts` (test named
`loads the vendored grammar with the pinned runtime`).

To restore the exact artifact, from this directory:

```sh
curl -fsSL https://registry.npmjs.org/tree-sitter-python/-/tree-sitter-python-0.25.0.tgz -o /tmp/tree-sitter-python-0.25.0.tgz
printf '%s  %s\n' 63b76b3fa8181fd79eaad4abcdb21e2babcb504dbfc7710a89934fa456d26096 /tmp/tree-sitter-python-0.25.0.tgz | sha256sum -c -
tar -xOf /tmp/tree-sitter-python-0.25.0.tgz package/tree-sitter-python.wasm > tree-sitter-python.wasm
sha256sum tree-sitter-python.wasm
```

To rebuild from source, extract that archive into a temporary directory, enter
`package`, then run `npx --yes tree-sitter-cli@0.25.9 build --wasm` with an
Emscripten toolchain (or Docker) available. That is the upstream package's
`prestart` command, using the minimum CLI version in its `^0.25.9`
`devDependencies` range, recorded in its `package.json`.
Compiler/toolchain changes can change the binary hash; recheck the ABI, tests,
and SHA-256 before replacing the vendored file. This command is a maintenance
step, never an install hook or a repository dependency.
