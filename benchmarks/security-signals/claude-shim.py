# Minimal OpenAI-compatible chat endpoint on localhost that answers with
# Claude through Claude Code, isolated (no tools, settings, hooks, CLAUDE.md).
# For testing clawvet's own --semantic client path without an API key.
import json, subprocess, sys, tempfile
from http.server import BaseHTTPRequestHandler, HTTPServer
MODEL = sys.argv[2] if len(sys.argv) > 2 else "haiku"
EMPTY = tempfile.mkdtemp()
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["content-length"])))
        system = next(m["content"] for m in body["messages"] if m["role"] == "system")
        user = next(m["content"] for m in body["messages"] if m["role"] == "user")
        r = subprocess.run(["claude", "-p", "--bare", "--model", MODEL, "--tools", "", "--strict-mcp-config", "--disable-slash-commands",
            "--no-session-persistence", "--setting-sources", "", "--system-prompt", system, "--output-format", "json"],
            input=user, capture_output=True, text=True, timeout=300, cwd=EMPTY)
        text = json.loads(r.stdout)["result"]
        out = json.dumps({"choices": [{"message": {"content": text}}]}).encode()
        self.send_response(200); self.send_header("content-type", "application/json"); self.send_header("content-length", str(len(out))); self.end_headers(); self.wfile.write(out)
        sys.stderr.write(f"answered {len(user)} chars\n")
    def log_message(self, *a): pass
HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
