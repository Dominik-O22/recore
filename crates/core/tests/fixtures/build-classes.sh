#!/usr/bin/env bash
# Rebuilds the ELF fixtures of the class recovery tests from `classes.cc`. Needs g++.
set -euo pipefail
cd "$(dirname "$0")"
# Loads anywhere and imports the C++ library, as distributions ship programs, and stripped.
g++ -O1 -fno-exceptions -fPIE -pie classes.cc -o classes-x86_64-pie
# Loads at a fixed address without relocations, with the library's type information classes
# linked in and no unwind tables: nothing but the vtables points at the virtual functions.
g++ -O1 -fno-exceptions -fno-asynchronous-unwind-tables -fno-stack-protector -ffreestanding -nostdlib -static -no-pie \
  classes.cc cxxabi.cc -o classes-x86_64-static
# The same with 32-bit pointers.
g++ -m32 -O1 -fno-exceptions -fno-asynchronous-unwind-tables -fno-stack-protector -ffreestanding -nostdlib -static -no-pie -fno-pic \
  classes.cc cxxabi.cc -o classes-x86-static
strip classes-x86_64-pie classes-x86_64-static classes-x86-static
chmod -x classes-x86_64-pie classes-x86_64-static classes-x86-static
