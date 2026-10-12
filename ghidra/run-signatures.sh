#!/usr/bin/env bash
# Analyzes binaries with stock Ghidra and writes each one's decompiled signatures.
# Usage: run-signatures.sh <ghidra-home> <corpus-dir> <jobs> <binary name>...
# Reports go to <corpus-dir>/ghidra-decomp/<name>.json, with the wall time in <name>.time.
set -euo pipefail
ghidra=$1 corpus=$(realpath "$2") jobs=$3
shift 3
scripts=$(dirname "$(realpath "$0")")
out=$corpus/ghidra-decomp
mkdir -p "$out"
run() {
    local name=$1 project
    project=$(mktemp -d)
    local start=$SECONDS
    "$ghidra/support/analyzeHeadless" "$project" p -import "$corpus/bin/$name" -scriptPath "$scripts" \
        -postScript ExportSignatures.java "$out/$name.json" > "$out/$name.log" 2>&1 || true
    echo $((SECONDS - start)) > "$out/$name.time"
    rm -rf "$project"
}
export -f run
export ghidra corpus scripts out
printf '%s\n' "$@" | xargs -P "$jobs" -I{} bash -c 'run {}'
