#!/usr/bin/env bash
# pre-commit hook: scan every skill a changed file belongs to, once each.
# Options before the file names (pre-commit `args:`) go to `clawvet scan`.
# A threshold always applies: --fail-on high unless args set another, so
# adding --strict never turns failures off. Runs the npm release this hook
# was tagged with. Plain bash 3 (macOS): no associative arrays.
set -euo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"
version="$(node -p 'require(process.argv[1]).version' "$here/packages/cli/package.json")"

options=()
fail_on=high
while [ $# -gt 0 ]; do
  # A committed file named "--help" or "--fail-on=low" is a file, not an option.
  [ -e "$1" ] && break
  case "$1" in
    --fail-on) fail_on="${2-}"; shift; [ $# -gt 0 ] && shift ;;
    --fail-on=*) fail_on="${1#*=}"; shift ;;
    # Options that take a separate value.
    --format|--baseline|--write-baseline|--reason|--expires|--semantic-runs|--semantic-timeout)
      options+=("$1" "${2-}"); shift; [ $# -gt 0 ] && shift ;;
    -*) options+=("$1"); shift ;;
    *) break ;;
  esac
done
options+=(--fail-on "$fail_on")

skills=""
for file in "$@"; do
  dir="$(dirname -- "$file")"
  while [ ! -f "$dir/SKILL.md" ]; do
    if [ "$dir" = . ] || [ "$dir" = / ]; then dir=""; break; fi
    dir="$(dirname -- "$dir")"
  done
  [ -n "$dir" ] || continue
  printf '%s\n' "$skills" | grep -Fxq -- "$dir" || skills="$skills$dir"$'\n'
done

# npx installs from this hook's own checkout, so an .npmrc committed to the
# repository being scanned cannot choose the registry clawvet comes from. The
# scan itself runs back in the repository, where .clawvetban, .clawvetignore
# and relative --baseline paths live. No install scripts, as in the Action.
repo="$PWD"
status=0
while IFS= read -r skill; do
  [ -n "$skill" ] || continue
  (cd "$here" && CLAWVET_TELEMETRY=off npm_config_ignore_scripts=true \
    npx --yes --package "clawvet@$version" -- \
    sh -c 'cd "$1" && shift && exec clawvet scan "$@"' sh "$repo" "${options[@]}" -- "$skill") || status=1
done <<< "$skills"
exit "$status"
