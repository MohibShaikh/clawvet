#!/bin/bash
# Like sandbox.sh, but with the network on so clawvet's semantic judge can reach
# its API. Everything else is the same: the repo and the skills read-only,
# nothing else from $HOME visible, only OUT writable. Only the CLAWVET_LLM_*
# variables go in, by name, so the key never appears on a command line.
#
#   SKILLS=<skills dir> OUT=/tmp/out CLAWVET_LLM_PROVIDER=... CLAWVET_LLM_BASE_URL=... \
#     CLAWVET_LLM_MODEL=... CLAWVET_LLM_API_KEY=... \
#     benchmarks/security-signals/sandbox-api.sh npx tsx benchmarks/security-signals/run-semantic.mts /skills /out/run.jsonl
set -euo pipefail
repo=$(cd "$(dirname "$0")/../.." && pwd)
: "${SKILLS:?set SKILLS}" "${OUT:?set OUT}"
mkdir -p "$OUT"
args=(--rm --network bridge --read-only --tmpfs /tmp:exec --user "$(id -u):$(id -g)" -e HOME=/tmp
  --memory "${MEM:-4g}" --pids-limit 256 --cap-drop ALL --security-opt no-new-privileges
  -v "$repo:$repo:ro" -w "$repo" -v "$SKILLS:/skills:ro" -v "$OUT:/out")
[ -n "${MSB:-}" ] && args+=(-v "$MSB:/msb:ro")
# Host-recorded git provenance for gate-eval, which cannot run git in here.
[ -n "${PROVENANCE:-}" ] && args+=(-e PROVENANCE)
args+=(-e CLAWVET_LLM_PROVIDER -e CLAWVET_LLM_BASE_URL -e CLAWVET_LLM_MODEL -e CLAWVET_LLM_API_KEY -e XDG_CACHE_HOME=/out/cache)
exec docker run "${args[@]}" node:22.16.0-slim "$@"
