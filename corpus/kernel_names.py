#!/usr/bin/env python3
"""Counts the code symbols of a Linux kernel that recore names the same at the same address, and
those it starts a function at, in a raw `Image` it read by itself.

Usage: python3 -I kernel_names.py <analysis.json> <System.map>
<analysis.json> is what `recore corpus` writes for the Image. <System.map> is the kernel's, or
`llvm-nm -n vmlinux` of the vmlinux it was cut from. A code symbol is one `nm` gives `t`, `T`, `w`
or `W`, but a mapping symbol, whose name has a `$`, and one whose value lies below `_text`, which
is no address in the image: kCFI's `__kcfi_typeid_` hashes. Several symbols at one address are one
address, which recore names right with any of them. recore prints a Rust or C++ name demangled,
and `llvm-cxxfilt` demangles the map's the same way.
"""
import json, subprocess, sys
from collections import defaultdict

analysis = json.load(open(sys.argv[1]))
named = {function["addr"]: function.get("name") for function in analysis["functions"]}

# An undefined symbol has no address.
listed = [line.split()[:3] for line in open(sys.argv[2]) if len(line.split()) >= 3]
text = next(int(address, 16) for address, _, name in listed if name == "_text")
symbols = defaultdict(set)
for address, kind, name in listed:
    if kind in "tTwW" and "$" not in name and int(address, 16) >= text:
        symbols[int(address, 16)].add(name)

mangled = sorted({name for names in symbols.values() for name in names if name.startswith(("_R", "_Z"))})
demangled = subprocess.run(["llvm-cxxfilt"], input="\n".join(mangled), capture_output=True, text=True, check=True).stdout.splitlines()
demangling = dict(zip(mangled, demangled))
for names in symbols.values():
    names.update(demangling[name] for name in list(names) if name in demangling)

started = sum(address in named for address in symbols)
same = sum(named.get(address) in names for address, names in symbols.items())
print(f"{len(symbols)} addresses with a code symbol: recore starts a function at {started}, and names {same} the same")
