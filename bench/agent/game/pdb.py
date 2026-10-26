#!/usr/bin/env python3
"""Prints what game.pdb knows, for checking key.md, from llvm-pdbutil's dumps of the PDB: each
function's address, size and name, each global's address and name, or one struct's size and its
fields' offsets.

Usage: pdb.py <functions|globals|struct NAME> [game.pdb], the PDB build.sh writes by default.
"""
import re, subprocess, sys
from pathlib import Path

PDB = Path(__file__).resolve().parents[3] / "target/agent/game/game.pdb"
IMAGE_BASE = 0x400000


def section_rvas(pdb: Path) -> dict[int, int]:
    """Each section's number and its address relative to the image base."""
    dump = subprocess.run(["llvm-pdbutil", "dump", "-section-headers", str(pdb)], capture_output=True, text=True, check=True).stdout
    rvas = re.findall(r"^\s*([0-9A-Fa-f]+) virtual address$", dump, re.M)
    return {number: int(rva, 16) for number, rva in enumerate(rvas, 1)}


def struct(pdb: Path, name: str) -> None:
    dump = subprocess.run(["llvm-pdbutil", "dump", "-types", str(pdb)], capture_output=True, text=True, check=True).stdout
    records = dict(re.findall(r"^\s+(0x[0-9A-F]+) \| (.*?)(?=^\s+0x[0-9A-F]+ \|)", dump, re.M | re.S))
    for record in records.values():
        found = re.match(rf"LF_STRUCTURE \[size = \d+\] `{re.escape(name)}`\n.*field list: (0x[0-9A-F]+)\n.*sizeof (\d+)", record, re.S)
        if found:
            break
    else:
        sys.exit(f"{pdb}: no struct {name} with fields")
    fields, size = found.groups()
    print(f"{name}: sizeof {int(size):#x} ({size})")
    for member, kind, offset in re.findall(r"LF_MEMBER \[name = `([^`]+)`, Type = (.*?), offset = (\d+)", records[fields]):
        print(f"  {int(offset):#05x}  {member}  {kind}")


def main() -> None:
    kind = sys.argv[1]
    if kind == "struct":
        struct(Path(sys.argv[3]) if len(sys.argv) > 3 else PDB, sys.argv[2])
        return
    pdb = Path(sys.argv[2]) if len(sys.argv) > 2 else PDB
    rvas = section_rvas(pdb)
    dump = subprocess.run(["llvm-pdbutil", "dump", "-symbols", "-globals", str(pdb)], capture_output=True, text=True, check=True).stdout
    found = set()
    if kind == "functions":
        records = re.findall(r"S_[GL]PROC32 \[size = \d+\] `([^`]+)`\n.*addr = (\d+):(\d+), code size = (\d+)", dump)
        for name, section, offset, size in records:
            found.add((IMAGE_BASE + rvas[int(section)] + int(offset), int(size), name))
    else:
        records = re.findall(r"S_[GL]DATA32 \[size = \d+\] `([^`]+)`\n.*addr = (\d+):(\d+)", dump)
        for name, section, offset in records:
            found.add((IMAGE_BASE + rvas[int(section)] + int(offset), None, name))
    for address, size, name in sorted(found):
        print(f"{address:#x}\t{size}\t{name}" if size is not None else f"{address:#x}\t{name}")


if __name__ == "__main__":
    main()
