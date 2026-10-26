#!/usr/bin/env bash
# Builds target/agent/game/game.exe, Brogue CE's game logic as a 32-bit Windows console program,
# compiled as MSVC would compile a release build but with no Microsoft SDK, and game.pdb, its
# debug information. The PDB is the answer key of key.md and never goes to an agent; the exe holds
# no symbols and no build paths. Never run the exe.
# Needs clang-cl and llvm-dlltool from the system's LLVM, and the zig that mise.corpus.toml pins
# (MISE_ENV=corpus mise install), for its lld-link.
# Usage: bench/agent/game/build.sh
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
out=$root/target/agent/game
src=$out/src
python3 -I "$here/fetch.py" "$out"
zig=$(cd "$root" && MISE_ENV=corpus mise where zig)/zig

rm -rf "$out/obj" && mkdir -p "$out/obj"
cflags=(--target=i686-pc-windows-msvc /c /O2 /Z7 /GS- /GR- /Brepro /X "-I$here/shim/include")
# The game logic, and from the platform layer the entry point, the glue that calls the console
# through its table of function pointers, and the console that draws nothing.
for file in "$src"/brogue/*.c "$src"/variants/*.c "$src"/platform/{main,platformdependent,null-platform}.c; do
  clang-cl "${cflags[@]}" "-I$src/brogue" "-I$src/variants" "-I$src/platform" -DDATADIR=. '-DBROGUE_EXTRA_VERSION=""' \
    -Wno-everything "/Fo$out/obj/$(basename "$file" .c).obj" "$file"
done
clang-cl "${cflags[@]}" /clang:-ffreestanding "/Fo$out/obj/libc.obj" "$here/shim/libc.c"
llvm-dlltool -m i386 -k -d "$here/kernel32.def" -l "$out/obj/kernel32.lib"
"$zig" lld-link /nologo /debug /pdb:"$out/game.pdb" /pdbaltpath:game.pdb /opt:ref /opt:icf /Brepro \
  /entry:mainCRTStartup /subsystem:console /nodefaultlib /machine:x86 /out:"$out/game.exe" "$out"/obj/*.obj "$out/obj/kernel32.lib"
ls -l "$out/game.exe" "$out/game.pdb"
# key.md's addresses are this build's. Another compiler or linker gives another exe, and the key
# does not apply to it.
key=a3240cc14ff9d13a8be712d17e13ae9835337e8d0d87f1e9c0f448a4fb7698d1
if [ "$(sha256sum < "$out/game.exe" | cut -d' ' -f1)" != "$key" ]; then
  echo "$out/game.exe is not the build key.md was written for, whose sha256 is $key" >&2
  exit 1
fi
