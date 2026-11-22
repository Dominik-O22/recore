#!/usr/bin/env bash
# Writes what the key's derivations read, from the debug files fetch.py put in <dir>/key, to
# <dir>/derive: each module's disassembly with its relocations, the disassembly of the kernel
# functions the key names, and their direct callers.
# Usage: bench/agent/android/derive.sh [<dir>], <dir> being target/agent/android unless given.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
dir=${1:-$(cd "$here/../../.." && pwd)/target/agent/android}
python3 -I "$here/fetch.py" "$dir"
mkdir -p "$dir/derive"
for module in gzvm zram rfkill; do
  llvm-objdump -dr --no-show-raw-insn "$dir/key/$module.ko.debug" > "$dir/derive/$module.dis"
  llvm-objcopy -O binary --only-section=.rodata.str1.1 "$dir/key/$module.ko.debug" "$dir/derive/$module.str"
  llvm-readelf -rs "$dir/key/$module.ko.debug" > "$dir/derive/$module.relocs"
done
# A kernel function runs from its address in System.map to the next one's.
for function in binder_ioctl __arm64_sys_pidfd_open; do
  read -r start end < <(awk -v f="$function" '$3 == f { s = $1; getline; print "0x" s, "0x" $1; exit }' "$dir/key/System.map")
  llvm-objdump -d --no-show-raw-insn --start-address="$start" --stop-address="$end" "$dir/key/vmlinux" > "$dir/derive/$function.dis"
done
python3 -I "$here/callers.py" "$dir" binder_proc_dec_tmpref > "$dir/derive/binder_proc_dec_tmpref.callers"
