import type { LanguageSpecs } from "../ir.js";

// Frontend-only normalizations keep argument layout and API spellings out of the engine.
export const javascriptApis = {
  // Bun and Deno are globals, and skills run TypeScript under both.
  read: /^(?:fs(?:\.promises)?\.(?:readFile|readFileSync|createReadStream)|Bun\.file|Deno\.(?:readTextFile|readFile)(?:Sync)?)$/,
  write: /^(?:fs(?:\.promises)?\.(?:writeFile|writeFileSync|appendFile|appendFileSync)|Bun\.write|Deno\.(?:writeTextFile|writeFile)(?:Sync)?)$/,
  command: /^(?:child_process\.(?:exec|execSync|spawn|spawnSync|execFile|execFileSync)|Bun\.(?:spawn|spawnSync|\$)|Deno\.Command|(?:bun|zx)\.\$)$/,
  // `$` is the tagged-template shell of bun and zx.
  shell: /^(?:child_process\.(?:exec|execSync)|Bun\.\$|(?:bun|zx)\.\$)$/,
  env: /^(?:process|Bun)\.env$/,
  request: /^(?:fetch|axios(?:\.(?:request|get|post|put|patch|delete|head|options|postForm|putForm|patchForm))?|https?\.(?:request|get))$/,
  axiosBody: /^axios\.(?:post|put|patch|postForm|putForm|patchForm)$/,
  sdk: /^(?:openai(?:\.OpenAI)?|OpenAI|@anthropic-ai\/sdk(?:\.Anthropic)?|Anthropic)$/,
  callbackRead: /^fs\.(?:readFile|readdir)$/,
  walk: /^(?:fs(?:\.promises)?\.(?:readdir|readdirSync)|glob(?:\.(?:glob|globSync|sync|iterate|iterateSync))?)$/,
  iteration: /\.(?:forEach|map|flatMap|filter|reduce|some|every)$/,
  clipboard: /(?:^|[|;&]\s*)(?:[^\s]*\/)?(?:pbpaste|xclip)(?:\s|$)/,
};

export const javascriptSpecs: LanguageSpecs = {
  accesses: [{ names: /^(?:process|Bun|Deno)\.env$/, source: "environment_all" }],
  calls: [
    { names: javascriptApis.read, effects: ["read"], clearApi: true },
    { names: javascriptApis.write, effects: ["write"] },
    { names: /^fs(?:\.promises)?\.(?:unlink|unlinkSync|rename|renameSync|rm|rmSync|truncate|truncateSync)$/, effects: ["mutate"] },
    { names: /^path\.(?:join|resolve)$/, effects: ["path"], pathSeparator: "/", clearApi: true },
    { names: /^os\.homedir$/, effects: ["path"], clearApi: true },
    { names: javascriptApis.walk, effects: ["walk"], clearApi: true },
    { names: /^Deno\.env\.get$/, effects: ["environment"], clearApi: true },
    { names: /^clawvet\.clipboard$/, effects: ["clipboard"], clearApi: true },
    { names: /^os\.(?:hostname|userInfo|networkInterfaces)$/, effects: ["host"], clearApi: true },
    { names: /^fetch$|^axios(?:\.(?:request|get|post|put|patch|delete|head|options|postForm|putForm|patchForm))?$/, effects: ["network", "network_read"], resultApi: "response" },
    { names: /^axios\.create$/, effects: ["request"], resultApi: "axios" },
    { names: /^https?\.(?:request|get)$/, effects: ["network", "request"], resultApi: "httpRequest" },
    { names: /^httpRequest\.(?:write|end)$/, effects: ["network"] },
    { names: /^(?:net\.(?:connect|createConnection)|net\.Socket)$/, effects: [], resultApi: "socket" },
    { names: /^socket\.(?:write|end)$/, effects: ["network"] },
    { names: /^dgram\.createSocket$/, effects: [], resultApi: "datagram" },
    { names: /^datagram\.send$/, effects: ["network"] },
    { names: /^dns(?:\.promises)?\.(?:resolve\w*|lookup|lookupService)$/, effects: ["dns"] },
    { names: /^(?:WebSocket|ws(?:\.WebSocket)?)$/, effects: [], resultApi: "websocket" },
    { names: /^websocket\.send$/, effects: ["network"] },
    { names: /^response\.(?:text|json|arrayBuffer|buffer|blob)$/, effects: ["identity"], clearApi: true },
    { names: /^Buffer\.from\.base64$|^atob$/, effects: ["decode"], clearApi: true },
    { names: /^btoa$|^JSON\.stringify$|\.toString\.base64$/, effects: ["encode"], clearApi: true },
    { names: /^crypto\.createCipher(?:iv)?$/, effects: [], resultApi: "cipher" },
    { names: /^cipher\.(?:update|final)$/, effects: ["encrypt"], resultApi: "cipher" },
    { names: /^(?:eval|Function|require|import)$|^vm\.(?:runIn\w*|compileFunction|Script)$/, effects: ["execute"] },
    { names: javascriptApis.command, effects: ["command"], commandShell: "option", shellOption: "shell", truthy: ["true"] },
    { names: javascriptApis.shell, effects: [], commandShell: "always" },
    { names: /^clawvet\.persistence$/, effects: ["write"] },
    { names: /^clawvet\.execute$/, effects: ["execute"] },
    { names: /^fs\.createWriteStream$/, effects: ["path"], resultApi: "fileWriter" },
    { names: /^fileWriter\.(?:write|end)$/, effects: ["write"], target: "receiver" },
  ],
};
