# Send each captured judge prompt to Claude through Claude Code, text only:
# no tools, no settings, hooks, plugins, MCP or CLAUDE.md (--bare), an empty
# working directory, nothing saved. The skill text arrives as a prompt, never
# as something to run.
import json, os, subprocess, sys, tempfile, concurrent.futures as cf
out, model, width = sys.argv[1], sys.argv[2], int(sys.argv[3])
pdir, rdir = (sys.argv[4], sys.argv[5]) if len(sys.argv) > 5 else ("prompts", "replies")
os.makedirs(f"{out}/{rdir}", exist_ok=True)
todo = [f for f in sorted(os.listdir(f"{out}/{pdir}")) if not os.path.exists(f"{out}/{rdir}/{f}")]
empty = tempfile.mkdtemp()
import time
def ask(f):
    for attempt in range(8):
        f2, status = ask_once(f)
        if "429" not in status and "rate" not in status.lower(): return f2, status
        time.sleep(300)  # cooldown before retrying
    return f2, status
def ask_once(f):
    p = json.load(open(f"{out}/{pdir}/{f}"))
    cmd = ["claude", "-p", "--bare", "--model", model, "--tools", "", "--strict-mcp-config", "--disable-slash-commands",
           "--no-session-persistence", "--setting-sources", "", "--system-prompt", p["system"], "--output-format", "json"]
    try:
        r = subprocess.run(cmd, input=p["user"], capture_output=True, text=True, timeout=600, cwd=empty)
        d = json.loads(r.stdout)
        if d.get("is_error"): return f, "error: " + str(d.get("result"))[:120]
        json.dump({"id": p["id"], "key": p["key"], "text": d["result"], "model": list((d.get("modelUsage") or {}).keys())}, open(f"{out}/{rdir}/{f}", "w"))
        return f, "ok"
    except Exception as e:
        return f, f"fail: {e}"[:160]
ok = 0
with cf.ThreadPoolExecutor(width) as pool:
    for f, status in pool.map(ask, todo):
        ok += status == "ok"
        if status != "ok": print(f, status, flush=True)
print(f"{ok}/{len(todo)} replies written", flush=True)
