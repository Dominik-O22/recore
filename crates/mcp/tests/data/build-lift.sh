#!/usr/bin/env bash
# Rebuilds lift.exe from lift.c: a 32-bit Windows program with x87 floats (no SSE) and no C
# library. Needs clang and rust-lld, which rustup ships with the toolchain.
set -euo pipefail
cd "$(dirname "$0")"
lld="$(rustc --print sysroot)/lib/rustlib/$(rustc -vV | sed -n 's/^host: //p')/bin/rust-lld"
obj="$(mktemp -d)"
trap 'rm -rf "$obj"' EXIT
clang -target i686-pc-windows-msvc -mno-sse -O1 -fno-math-errno -fno-stack-protector -c lift.c -o "$obj/lift.obj"
"$lld" -flavor link /nodefaultlib /entry:start /subsystem:console /machine:x86 /dynamicbase:no /noimplib /brepro /out:lift.exe "$obj/lift.obj"
chmod -x lift.exe
