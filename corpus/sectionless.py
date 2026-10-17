#!/usr/bin/env python3
"""Copies a corpus with the section headers of every ELF binary removed, as OpenWrt's sstrip
removes them, so recore's score on the copy can be set beside its score on the original.

Usage: python3 -I corpus/sectionless.py <corpus>     e.g. corpus-armhf
Writes <corpus>-sectionless in the corpora's directory, which corpus/store.py names: bin/ holds
the copies and truth/ links to the original's truth. Then score it as check.sh scores a corpus:
  target/release/recore corpus <corpora>/<corpus>-sectionless/bin target/corpus/<corpus>-sectionless/recore
  target/release/recore-corpus --corpus <corpora>/<corpus>-sectionless score target/corpus/<corpus>-sectionless/recore
"""
import struct, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from store import CORPORA  # noqa: E402


def sectionless(data: bytes) -> bytes:
    """The file with e_shoff, e_shnum and e_shstrndx zeroed: no section headers to read."""
    out = bytearray(data)
    if out[4] == 2:
        struct.pack_into("<Q", out, 0x28, 0)
        struct.pack_into("<HHH", out, 0x3A, 0, 0, 0)
    else:
        struct.pack_into("<I", out, 0x20, 0)
        struct.pack_into("<HHH", out, 0x2E, 0, 0, 0)
    return bytes(out)


def main() -> None:
    source = CORPORA / sys.argv[1]
    target = CORPORA / f"{sys.argv[1]}-sectionless"
    (target / "bin").mkdir(parents=True, exist_ok=True)
    if not (target / "truth").exists():
        (target / "truth").symlink_to(source / "truth")
    count = 0
    for binary in sorted((source / "bin").iterdir()):
        data = binary.read_bytes()
        if data[:4] == b"\x7fELF" and data[5] == 1:
            (target / "bin" / binary.name).write_bytes(sectionless(data))
            count += 1
    print(f"{count} binaries in {target / 'bin'}")


if __name__ == "__main__":
    main()
