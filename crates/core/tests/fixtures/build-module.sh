#!/usr/bin/env bash
# Rebuilds `module.o` from `module.c` with the code generation flags the x86-64 Linux kernel
# builds modules with: no PIC, a `call __fentry__` recorded in `__mcount_loc` at each function's
# start, returns and indirect calls through the kernel's thunks, and no unwind tables.
set -euo pipefail
cd "$(dirname "$0")"
gcc -c -O2 -fno-pic -mcmodel=kernel -mno-red-zone -fcf-protection=branch -pg -mfentry -mrecord-mcount \
  -mfunction-return=thunk-extern -mindirect-branch=thunk-extern -mindirect-branch-cs-prefix \
  -fno-asynchronous-unwind-tables module.c -o module.o
