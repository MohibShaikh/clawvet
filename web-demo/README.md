# ClawVet Static Web Playground

Zero-backend, 100% client-side ClawVet playground powered by `@clawvet/shared` and WebAssembly Tree-sitter AST dataflow. No database, no API server, and no data leaves the visitor's browser.

## Build locally

From the repository root (after `npm install`):

```bash
node web-demo/build.mjs
```

This emits a static bundle in `web-demo/dist/` (`index.html`, `style.css`, `app.js`, `wasm/web-tree-sitter.wasm`, and `grammars/tree-sitter-*.wasm`).

Preview locally with any static file server (note: WASM requires HTTP, not `file://`):

```bash
npx serve web-demo/dist
```

## Deploy for $0

- **Vercel (recommended):** import the repository root in Vercel. The root [`vercel.json`](../vercel.json) automatically sets `npm ci`, `node web-demo/build.mjs`, `web-demo/dist`, and `application/wasm` headers (leave Root Directory as `.`).
- **Cloudflare Pages:** `npx wrangler pages deploy web-demo/dist --project-name clawvet`
- **GitHub Pages:** publish `web-demo/dist/` via `actions/upload-pages-artifact`

## Shareable skill links

Append `?url=<encoded-github-or-raw-url>` to auto-fetch and scan a public `SKILL.md` on page load:

```text
https://your-site.pages.dev/?url=https://github.com/owner/repo/blob/main/SKILL.md
```
