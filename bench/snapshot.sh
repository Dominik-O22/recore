#!/usr/bin/env bash
# Guards speed work: `bench/snapshot.sh save` keeps the analysis of every corpus binary, with
# and without unwind info, and the decompiled C of a few binaries; `bench/snapshot.sh check`
# reports what has changed since. A change that is only meant to be faster must change nothing.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build --release -q -p recore -p recore-decomp
# The corpora are where corpus/store.py says.
corpora="${RECORE_CORPORA:-$HOME/recore-corpora}"
out=target/bench/snapshot/${1:?save or check}
for corpus in corpus corpus-arm64 corpus-pe32 corpus-pe; do
  for frames in "" "--no-frames"; do
    dir="$out/$corpus$frames"
    rm -rf "$dir" && mkdir -p "$dir"
    ./target/release/recore corpus "$corpora/$corpus/bin" "$dir" $frames 2>/dev/null
  done
done
# One binary of each kind is enough to catch the decompiler printing something else.
rm -rf "$out/decompile" && mkdir -p "$out/decompile/bin"
for binary in corpus-pe32/bin/dell__DELL_IspLibrary.dll corpus-pe32/bin/php83__php_ldap.dll \
  corpus-pe/bin/obs__obs-browser.dll corpus/bin/htop__htop corpus-arm64/bin/deb__openssh-client__ssh-agent; do
  ln -s "$corpora/$binary" "$out/decompile/bin/"
done
./target/release/recore-decompile corpus "$out/decompile/bin" "$out/decompile/c" --emit-c >/dev/null 2>&1
rm -f "$out"/decompile/c/*.json
[ "$1" = save ] || { diff -rq target/bench/snapshot/save "$out" -x bin && echo "analysis and decompiled C unchanged"; }
