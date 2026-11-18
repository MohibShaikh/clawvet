#!/bin/bash
# Run a command over downloaded skills in a container with no network. The repo
# and the skills are mounted read-only and nothing else from $HOME is visible,
# so even a scanner bug that ran skill content could neither read local secrets
# nor send anything. Only OUT is writable.
#
#   SKILLS=<skills dir> OUT=/tmp/out \
#     benchmarks/security-signals/sandbox.sh npx tsx benchmarks/security-signals/run.mts /skills /out/run.jsonl
set -euo pipefail
repo=$(cd "$(dirname "$0")/../.." && pwd)
: "${SKILLS:?set SKILLS}" "${OUT:?set OUT}"
mkdir -p "$OUT"
args=(--rm --network none --read-only --tmpfs /tmp:exec --user "$(id -u):$(id -g)" -e HOME=/tmp
  --memory "${MEM:-4g}" --pids-limit 256 --cap-drop ALL --security-opt no-new-privileges
  -v "$repo:$repo:ro" -w "$repo" -v "$SKILLS:/skills:ro" -v "$OUT:/out")
[ -n "${MSB:-}" ] && args+=(-v "$MSB:/msb:ro")
# Host-recorded git provenance for gate-eval, which cannot run git in here.
[ -n "${PROVENANCE:-}" ] && args+=(-e PROVENANCE)
exec docker run "${args[@]}" node:22.16.0-slim "$@"
