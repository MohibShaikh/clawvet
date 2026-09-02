# Gate demo for ClawVet: the install-time enforcement half. Three commands,
# nothing narrated between them. The point is the third line firing without
# anyone running `clawvet gate` by hand.
#
# Regenerate with `vhs demo/gate.tape` from the repo root; writes
# docs/gate-demo.gif, roughly 18 seconds.
#
# The machine that records needs:
#   - clawvet and openclaw on PATH. `openclaw skills install` (plural) is the
#     real subcommand; `openclaw skill install` does not exist.
#   - the installPolicy block from `clawvet gate --print-config` pasted into
#     the openclaw config, as the README describes under "Install-time
#     enforcement". The paste is not on screen; `openclaw config validate`
#     proving the config valid is how the video shows it happened. The block
#     validates as-is: `--print-config` emits the required `source: "exec"`.
#   - openclaw requires the policy paths and every parent directory above them
#     to be non-group, non-world writable. If an install reports "permissions
#     are too open", chmod the named directory before recording.
#   - this repo checked out at the top level. The fixture path is expanded
#     with $(pwd) because openclaw treats a bare relative path as a skill slug,
#     not a filesystem path. On a box without this checkout, point the command
#     at any hostile skill origin you trust.
#
# Without openclaw the tape refuses to record (Require below) rather than
# capture a `command not found`. The piped-fixture fallback renders
# `"decision": "block"` but reads like a command you ran, not a gate that
# fired; prefer the real install.

Output docs/gate-demo.gif

Require clawvet
Require openclaw

Set Shell bash
Set FontSize 18
Set Width 1280
Set Height 560
Set Padding 16
Set Margin 20
Set MarginFill "#16161E"
Set BorderRadius 10
Set Theme "tokyonight-storm"
Set WindowBar Colorful
Set Framerate 12
Set TypingSpeed 35ms
Set CursorBlink false

# Clean prompt regardless of the shell rc that the record session sources.
Hide
Type "unset PROMPT_COMMAND; PS1='\\$ '; clear"
Enter
Show

Sleep 400ms

# 1. Print the installPolicy config with paths already resolved.
Type "clawvet gate --print-config"
Enter
Sleep 4s

# 2. The config, with that block pasted in, is valid.
Type "openclaw config validate"
Enter
Sleep 2.5s

# 3. Install a hostile skill. OpenClaw stages it, the gate runs unprompted,
#    and the install stops. No agent remembered to scan; the gate did.
Type "openclaw skills install $(pwd)/apps/api/test/fixtures/malicious-stealer"
Enter
Sleep 6s