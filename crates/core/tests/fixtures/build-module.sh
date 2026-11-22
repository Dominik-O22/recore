#!/usr/bin/env bash
# Rebuilds `module.o` and `module-arm64.o` from `module.c` with the code generation flags the
# Linux kernel builds modules with. On x86-64: no PIC, a `call __fentry__` recorded in
# `__mcount_loc` at each function's start, returns and indirect calls through the kernel's
# thunks, and no unwind tables. On AArch64: no PIC, two `nop`s before each function and two at
# its start for ftrace, recorded in `__patchable_function_entries`, return addresses signed, and
# kCFI's type hash before each function, which `$d` marks as data. `module-arm64-unmarked.o` is
# the same without the mapping symbols, as a stripped file has none.
set -euo pipefail
cd "$(dirname "$0")"
gcc -c -O2 -fno-pic -mcmodel=kernel -mno-red-zone -fcf-protection=branch -pg -mfentry -mrecord-mcount \
  -mfunction-return=thunk-extern -mindirect-branch=thunk-extern -mindirect-branch-cs-prefix \
  -fno-asynchronous-unwind-tables module.c -o module.o
clang --target=aarch64-linux-gnu -c -O2 -fno-pic -mgeneral-regs-only -fpatchable-function-entry=4,2 \
  -mbranch-protection=pac-ret -fsanitize=kcfi -fno-asynchronous-unwind-tables module.c -o module-arm64.o
llvm-objcopy --wildcard --strip-symbol='$d*' --strip-symbol='$x*' module-arm64.o module-arm64-unmarked.o
clang --target=aarch64-linux-gnu -c -O2 -g -fno-pic -fno-asynchronous-unwind-tables module-dwarf.c -o module-dwarf-arm64.o
