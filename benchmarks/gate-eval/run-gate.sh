#!/bin/bash
# Feed one staged skill folder to `clawvet gate` and print one TSV row:
#   tier<TAB>id<TAB>decision<TAB>reason
# tier and id are the folder's last two path segments. The gate only reads
# files; nothing in the skill is executed.
# Usage: run-gate.sh <path to clawvet dist/index.js> <skill folder>
out=$(printf '{"protocolVersion":1,"targetType":"skill","targetName":"x","sourcePath":"%s","sourcePathKind":"directory"}' "$2" \
  | CLAWVET_TELEMETRY=off timeout 30 node "$1" gate 2>/dev/null)
node -e 'let j;try{j=JSON.parse(process.argv[1])}catch{j={decision:"PARSE-FAIL",reason:process.argv[1].slice(0,60)}};const p=process.argv[2].replace(/\/$/,"").split("/");console.log([p.at(-2),p.at(-1),j.decision,(j.reason||"").replace(/\s+/g," ").slice(0,1000)].join("\t"))' "$out" "$2"
