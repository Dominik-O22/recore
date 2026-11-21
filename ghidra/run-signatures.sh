#!/usr/bin/env bash
# Analyzes binaries with stock Ghidra and writes each one's decompiled signatures.
# Usage: run-signatures.sh <ghidra-home> <corpus-dir> <jobs> <binary name>...
# Reports go to <name>.json in OUT, <corpus-dir>/ghidra-decomp unless set, with the wall time in
# <name>.time. A report that exists is kept, so an interrupted run resumes.
set -euo pipefail
ghidra=$1 corpus=$(realpath "$2") jobs=$3
shift 3
scripts=$(dirname "$(realpath "$0")")
out=$(realpath -m "${OUT:-$corpus/ghidra-decomp}")
# Ghidra refuses a project under a directory whose name starts with a dot, and every binary
# would fail with only its log to say so.
case "$out/" in */.*) echo "run-signatures.sh: $out has a part that starts with a dot, which Ghidra refuses" >&2; exit 1 ;; esac
mkdir -p "$out/proj"
run() {
    local name=$1 project=$out/proj/$1
    [ -s "$out/$name.json" ] && return 0
    rm -rf "$project"; mkdir -p "$project"
    local start=$SECONDS
    "$ghidra/support/analyzeHeadless" "$project" p -import "$corpus/bin/$name" -scriptPath "$scripts" \
        -postScript ExportSignatures.java "$out/$name.json" -deleteProject > "$out/$name.log" 2>&1 || true
    echo $((SECONDS - start)) > "$out/$name.time"
    rm -rf "$project"
}
export -f run
export ghidra corpus scripts out
printf '%s\n' "$@" | xargs -P "$jobs" -I{} bash -c 'run {}'
