#!/usr/bin/env bash
# The inner loop: build, analyze each corpus with and without unwind info, and score.
# Extra arguments go to the scorer, e.g. `./check.sh --detail`. The corpora are read where
# corpus/store.py says, and recore's output goes to target/corpus/<corpus>.
set -euo pipefail
cd "$(dirname "$0")"
# Only the crates the loop needs; other crates may be mid-change.
cargo build --release -q -p recore -p recore-corpus
# Only crates/*/tests may name the program a test needs. CI runs this scan with the other
# tests; the loop runs it first, so a leaked name fails before the corpora are scored.
cargo test --release -q -p recore --test general_naming
corpora="${RECORE_CORPORA:-$HOME/recore-corpora}"
for corpus in corpus corpus-arm64 corpus-armhf corpus-armel corpus-pe32 corpus-pe corpus-macho corpus-macho-x86 corpus-8051 corpus-thumb; do
  in="$corpora/$corpus" out="target/corpus/$corpus"
  [ -d "$in/truth" ] || continue
  ./target/release/recore corpus "$in/bin" "$out/recore" 2>/dev/null
  dirs=("$out/recore")
  # A raw image has no unwind info to leave out.
  if [ "$corpus" != corpus-8051 ] && [ "$corpus" != corpus-thumb ]; then
    ./target/release/recore corpus "$in/bin" "$out/recore-noframes" --no-frames 2>/dev/null
    dirs+=("$out/recore-noframes")
  fi
  # Mach-O truth is mostly the linker's list of function starts, which the first run reads.
  # This one gets the same binaries without that list.
  if [ -d "$in/nostarts" ]; then
    ./target/release/recore corpus "$in/nostarts" "$out/recore-nostarts" 2>/dev/null
    dirs+=("$out/recore-nostarts")
  fi
  # The same PE images with their base relocations stripped, as corpus/strip_relocs.py writes them.
  if [ -d "$in/norelocs" ]; then
    ./target/release/recore corpus "$in/norelocs" "$out/recore-norelocs" 2>/dev/null
    dirs+=("$out/recore-norelocs")
  fi
  ./target/release/recore-corpus --corpus "$in" score "${dirs[@]}" "$@"
done
