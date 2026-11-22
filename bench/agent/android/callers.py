#!/usr/bin/env python3
"""Lists the direct calls to a kernel function, for the key: every BL and B in vmlinux's .text
whose target is the function's address, with the function of System.map it sits in.

Usage: python3 -I callers.py <dir> <function>, with <dir> as fetch.py laid it out. Calls through
a pointer are not seen, and a tail call by B is listed with `b` before it.
"""
import bisect, struct, sys
from pathlib import Path

SHT_PROGBITS = 1


def text(vmlinux: bytes) -> tuple[int, bytes]:
    """The address and bytes of vmlinux's .text section."""
    shoff, = struct.unpack_from("<Q", vmlinux, 0x28)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", vmlinux, 0x3a)
    headers = [struct.unpack_from("<IIQQQQ", vmlinux, shoff + i * shentsize) for i in range(shnum)]
    names = headers[shstrndx][4]
    for name, kind, _, address, offset, size in headers:
        if kind == SHT_PROGBITS and vmlinux[names + name:names + name + 6] == b".text\0":
            return address, vmlinux[offset:offset + size]
    sys.exit("vmlinux has no .text")


def main() -> None:
    dir, wanted = Path(sys.argv[1]), sys.argv[2]
    symbols = sorted(
        (int(address, 16), name)
        for address, kind, name in (line.split()[:3] for line in (dir / "key/System.map").read_text().splitlines())
        if kind in "tTwW"
    )
    starts = [address for address, _ in symbols]
    target = next((address for address, name in symbols if name == wanted), None)
    if target is None:
        sys.exit(f"System.map has no function {wanted}")
    base, code = text((dir / "key/vmlinux").read_bytes())
    for index, (word,) in enumerate(struct.iter_unpack("<I", code)):
        if word & 0x7C000000 != 0x14000000:
            continue
        site = base + index * 4
        offset = (word & 0x3FFFFFF) - ((word & 0x2000000) << 1)
        if site + offset * 4 != target:
            continue
        address, name = symbols[bisect.bisect_right(starts, site) - 1]
        print(f"{'bl' if word >> 31 else 'b '} {site:#x} in {name} ({address:#x})")


if __name__ == "__main__":
    main()
