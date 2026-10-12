#!/usr/bin/env bash
# Analyzes binaries with stock Ghidra and writes each one's data references.
# Usage: run-refs.sh <ghidra-home> <corpus-dir> <jobs> <binary name>...
# References go to <corpus-dir>/ghidra-refs/<name>.refs, the log next to them.
set -euo pipefail
ghidra=$1 corpus=$(realpath "$2") jobs=$3
shift 3
scripts=$(dirname "$(realpath "$0")")
out=$corpus/ghidra-refs
mkdir -p "$out"
run() {
    local name=$1 project
    project=$(mktemp -d)
    "$ghidra/support/analyzeHeadless" "$project" p -import "$corpus/bin/$name" -readOnly -scriptPath "$scripts" \
        -postScript ExportDataRefs.java "$out/$name.refs" > "$out/$name.log" 2>&1 || true
    rm -rf "$project"
}
export -f run
export ghidra corpus scripts out
printf '%s\n' "$@" | xargs -P "$jobs" -I{} bash -c 'run {}'
