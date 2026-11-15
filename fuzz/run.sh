#!/usr/bin/env bash
# Fuzzes for <seconds> (600 by default) each target named after it, or both, seeded from the
# corpora in the store, the held-out ones excepted:
#   load      Image::parse then analyze, from the three smallest binaries under 256 KiB of
#             each corpus
#   metadata  the IL2CPP metadata parser, from every global-metadata.dat
# Inputs and crashes go under target/fuzz/<target>. A crash prints its input's path; rerun one
# with
#   cargo fuzz run --fuzz-dir fuzz -s none --debug-assertions <target> <path>
set -euo pipefail
cd "$(dirname "$0")/.."
seconds=${1:-600}
targets=("${@:2}")
[ ${#targets[@]} -gt 0 ] || targets=(load metadata)
corpora=${RECORE_CORPORA:-$HOME/recore-corpora}
# The seeds of target $1 in corpus $2.
seeds() {
  if [ "$1" = metadata ]; then
    find "$2" -name global-metadata.dat
  elif [ -d "$2/bin" ]; then
    find "$2/bin" -type f -size -256k -printf '%s %p\n' | sort -n | sed -n 1,3p | cut -d' ' -f2-
  fi
}
# libFuzzer's jobs work in TMPDIR, kept under target/ with the rest.
mkdir -p target/fuzz/tmp
export TMPDIR=$PWD/target/fuzz/tmp
# libFuzzer goes on past a crash and exits 0, so what it saved during this run is what failed.
stamp=$(mktemp -p target/fuzz stamp.XXXXXX)
trap 'rm -f "$stamp"' EXIT
for target in "${targets[@]}"; do
  out=target/fuzz/$target
  mkdir -p "$out/seeds" "$out/inputs" "$out/crashes"
  for corpus in "$corpora"/*/; do
    case $corpus in *-holdout/) continue ;; esac
    seeds "$target" "$corpus" | while read -r path; do
      cp "$path" "$out/seeds/$(basename "$corpus")-$(echo "$path" | md5sum | cut -c1-8)-$(basename "$path")"
    done
  done
  # -s none: no sanitizer, which needs nightly; Rust's own bounds and overflow checks catch what
  # matters here. One job per core but two, so the machine stays usable.
  cargo fuzz run --fuzz-dir fuzz --target-dir "$PWD/target/fuzz/build" -s none --debug-assertions "$target" \
    "$out/inputs" "$out/seeds" -- \
    -max_total_time="$seconds" -artifact_prefix="$out/crashes/" -timeout=10 -rss_limit_mb=4096 \
    -fork="$(( $(nproc) > 2 ? $(nproc) - 2 : 1 ))" -ignore_crashes=1
done
found=$(find target/fuzz/*/crashes -type f -newer "$stamp")
if [ -n "$found" ]; then
  echo "the fuzzer found these:" >&2
  echo "$found" >&2
  exit 1
fi
