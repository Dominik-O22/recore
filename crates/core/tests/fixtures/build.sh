#!/usr/bin/env bash
# Rebuilds the Mach-O fixtures from `shapes.m`. Needs clang and LLVM's Mach-O linker; the
# `.tbd` files stand in for the SDK. `LD64` names the linker when it is not on the path.
set -euo pipefail
cd "$(dirname "$0")"
ld64=${LD64:-ld64.lld}
build() {
  local name=$1 arch=$2
  shift 2
  clang -target "$arch-apple-macos13" -O2 -c shapes.m -o "/tmp/$name.o"
  "$ld64" -arch "$arch" -platform_version macos 13.0 14.0 -e _main "$@" libSystem.tbd libobjc.tbd "/tmp/$name.o" -o "$name"
  chmod -x "$name"
}
# Chained fixups, as current linkers write them, and stripped, as applications ship.
build shapes-arm64 arm64 -fixup_chains
llvm-strip shapes-arm64
# Bind and rebase opcodes with lazy binding, as linkers wrote them before macOS 12, with its
# symbols.
build shapes-x86_64 x86_64 -no_fixup_chains
llvm-lipo -create shapes-arm64 shapes-x86_64 -output shapes-universal
