#!/usr/bin/env python3
"""Lists every instruction in game.exe that stores over a field, for checking key.md: stores
through a register plus the field's offset, and stores to the field of one record at a fixed
address, each with the function the PDB places it in. A store that only overlaps the field, such as
a 16-byte copy, is listed with its width. Stores whose address the instruction does not spell out,
such as rep movs and calls to memcpy or memset, are not found.

Usage: stores.py <offset> <size> [address of a record] [game.exe]
"""
import bisect, re, subprocess, sys
from pathlib import Path

GAME = Path(__file__).resolve().parents[3] / "target/agent/game"
WIDTHS = {"byte": 1, "word": 2, "dword": 4, "qword": 8, "xmmword": 16, "tbyte": 10}
# Instructions whose first operand, when it is memory, is written.
WRITES = re.compile(
    r"^(mov|movs?x?|add|sub|adc|sbb|inc|dec|or|and|xor|neg|not|shl|shr|sar|rol|ror|xchg|cmpxchg|"
    r"set[a-z]+|mov(ups|aps|dqu|dqa|q|d|sd|ss|lps|hps|lpd|hpd|upd|apd)|pextrw|fstp?|fistp?|fisttp)$"
)


def main() -> None:
    offset, size = int(sys.argv[1], 0), int(sys.argv[2], 0)
    record = int(sys.argv[3], 0) if len(sys.argv) > 3 else None
    exe = Path(sys.argv[4]) if len(sys.argv) > 4 else GAME / "game.exe"
    functions = []
    pdb = subprocess.run([sys.executable, "-I", Path(__file__).with_name("pdb.py"), "functions"], capture_output=True, text=True, check=True).stdout
    for line in pdb.splitlines():
        address, length, name = line.split("\t")
        functions.append((int(address, 16), int(length), name))
    starts = [f[0] for f in functions]
    listing = subprocess.run(["llvm-objdump", "-d", "--no-show-raw-insn", "--x86-asm-syntax=intel", str(exe)], capture_output=True, text=True, check=True).stdout
    for line in listing.splitlines():
        found = re.match(r"\s*([0-9a-f]+):\s+(\S+)\s+(\w+) ptr (?:\w+:)?\[([^\]]+)\]", line)
        if not found or not WRITES.match(found.group(2)):
            continue
        address, mnemonic, width, operand = int(found.group(1), 16), found.group(2), WIDTHS.get(found.group(3), 0), found.group(4)
        displacement = re.search(r"([+-]) (0x[0-9a-f]+)$", operand)
        if re.fullmatch(r"0x[0-9a-f]+", operand):
            start, by_register = int(operand, 16), False
        elif displacement and re.match(r"[a-z]{3}", operand):
            start, by_register = int(displacement.group(2), 16) * (-1 if displacement.group(1) == "-" else 1), True
        else:
            continue
        if by_register:
            hit = start < offset + size and offset < start + width
        else:
            hit = record is not None and start < record + offset + size and record + offset < start + width
        if hit:
            i = bisect.bisect_right(starts, address) - 1
            name = functions[i][2] if i >= 0 and address < functions[i][0] + functions[i][1] else "?"
            print(f"{address:#x}\t{name}\t{line.split(':', 1)[1].strip()}")


if __name__ == "__main__":
    main()
