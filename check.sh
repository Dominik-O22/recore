#!/usr/bin/env bash
# The inner loop: build, analyze each corpus with and without unwind info, and score.
# Extra arguments go to the scorer, e.g. `./check.sh --detail`.
set -euo pipefail
cd "$(dirname "$0")"
# Only the crates the loop needs; other crates may be mid-change.
cargo build --release -q -p recore -p recore-corpus
for corpus in corpus corpus-arm64 corpus-pe32 corpus-pe corpus-macho corpus-macho-x86 corpus-8051 corpus-thumb; do
  [ -d "$corpus/truth" ] || continue
  ./target/release/recore corpus "$corpus/bin" "$corpus/recore" 2>/dev/null
  dirs=("$corpus/recore")
  # A raw image has no unwind info to leave out.
  if [ "$corpus" != corpus-8051 ] && [ "$corpus" != corpus-thumb ]; then
    ./target/release/recore corpus "$corpus/bin" "$corpus/recore-noframes" --no-frames 2>/dev/null
    dirs+=("$corpus/recore-noframes")
  fi
  # Mach-O truth is mostly the linker's list of function starts, which the first run reads.
  # This one gets the same binaries without that list.
  if [ -d "$corpus/nostarts" ]; then
    ./target/release/recore corpus "$corpus/nostarts" "$corpus/recore-nostarts" 2>/dev/null
    dirs+=("$corpus/recore-nostarts")
  fi
  ./target/release/recore-corpus --corpus "$corpus" score "${dirs[@]}" "$@"
done
