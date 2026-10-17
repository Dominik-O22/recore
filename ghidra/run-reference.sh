#!/usr/bin/env bash
# Runs Ghidra headless over every corpus binary and exports its analysis as JSON.
# Usage: run-reference.sh <ghidra-home> <out-dir> [jobs] [extra java opts]
# Skips binaries whose JSON already exists, so it can be re-run after an interruption.
# A Cortex-M layout is loaded as its raw image at its flash base, with the handlers of its vector
# table as the entry points, and its JSON is named after the layout.
set -uo pipefail
GHIDRA="$1"; OUT="$(realpath -m "$2")"; JOBS="${3:-4}"; EXTRA="${4:-}"
HERE="$(cd "$(dirname "$0")" && pwd)"; CORPUS="${CORPUS:-$HERE/../corpus}"
mkdir -p "$OUT/logs" "$OUT/proj"

one() {
  local bin="$1" name; name="$(basename "$bin")"
  local import=("$bin") seed=()
  if [[ "$name" == *.toml ]]; then
    local raw; read -ra raw <<< "$(python3 "$HERE/cortex_m.py" "$bin")"
    [ ${#raw[@]} -gt 0 ] || return 0
    name="${name%.toml}"
    import=("${raw[0]}" -loader BinaryLoader -loader-baseAddr "${raw[1]}" -processor ARM:LE:32:Cortex -cspec default)
    seed=(-preScript SeedEntries.java "${raw[@]:2}")
  fi
  [ -s "$OUT/$name.json" ] && return 0
  local start=$SECONDS
  rm -rf "$OUT/proj/$name"; mkdir -p "$OUT/proj/$name"
  GHIDRA_HEADLESS_MAXMEM=6G GHIDRA_HEADLESS_JAVA_OPTIONS="-Dcpu.core.override=4 $EXTRA" \
    "$GHIDRA/support/analyzeHeadless" "$OUT/proj/$name" p -import "${import[@]}" \
    -scriptPath "$HERE" "${seed[@]}" -postScript ExportRef.java "$OUT/$name.json" -deleteProject \
    > "$OUT/logs/$name.log" 2>&1
  local total; total=$(grep -o 'Total Time *[0-9]* secs' "$OUT/logs/$name.log" | grep -o '[0-9]*' | tail -1)
  echo "$name ${total:-NA} $((SECONDS - start))" >> "$OUT/times.txt"
  rm -rf "$OUT/proj/$name"
}
export -f one; export GHIDRA OUT HERE EXTRA
# Largest first so the long ones do not all land at the end.
ls -S "$CORPUS"/bin/* | xargs -P "$JOBS" -I{} bash -c 'one {}'
echo "done: $(ls "$OUT"/*.json 2>/dev/null | wc -l) exported"
