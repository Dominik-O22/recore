#!/usr/bin/env python3
"""Prints 8-byte words of vmlinux's loaded data, for the key: each word at <symbol>+<offset> with
the System.map symbol it holds the address of, if any.

Usage: python3 -I words.py <dir> <symbol> <offset> [<count>], with <dir> as fetch.py laid it out,
and <offset> in bytes, such as `words.py <dir> sys_call_table 0xd90` for system call 434.
"""
import struct, sys
from pathlib import Path

PT_LOAD = 1


def main() -> None:
    dir, symbol, offset = Path(sys.argv[1]), sys.argv[2], int(sys.argv[3], 0)
    count = int(sys.argv[4], 0) if len(sys.argv) > 4 else 1
    symbols = {}
    for line in (dir / "key/System.map").read_text().splitlines():
        address, _, name = line.split()[:3]
        symbols.setdefault(int(address, 16), name)
    names = {name: address for address, name in symbols.items()}
    if symbol not in names:
        sys.exit(f"System.map has no {symbol}")
    vmlinux = (dir / "key/vmlinux").read_bytes()
    phoff, = struct.unpack_from("<Q", vmlinux, 0x20)
    phentsize, phnum = struct.unpack_from("<HH", vmlinux, 0x36)
    segments = [struct.unpack_from("<IIQQQQ", vmlinux, phoff + i * phentsize) for i in range(phnum)]
    for index in range(count):
        address = names[symbol] + offset + index * 8
        segment = next((s for s in segments if s[0] == PT_LOAD and s[3] <= address < s[3] + s[5]), None)
        if segment is None:
            sys.exit(f"{address:#x} is in no segment vmlinux loads")
        word, = struct.unpack_from("<Q", vmlinux, segment[2] + address - segment[3])
        print(f"{address:#x}: {word:#x} {symbols.get(word, '')}")


if __name__ == "__main__":
    main()
