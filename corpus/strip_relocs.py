#!/usr/bin/env python3
"""Writes a corpus's PE images again with their base relocations stripped, as a linker leaves them.

Usage: strip_relocs.py [corpus]      default: corpus-pe32

Reads <corpus>/bin, in the corpora's directory that corpus/store.py names, and writes each image
to <corpus>/norelocs/<same name>: the relocation directory entry cleared, the bytes it pointed at
zeroed, and IMAGE_FILE_RELOCS_STRIPPED set, which is how a 32-bit program linked with /FIXED
ships. Without relocations nothing in the file tells an address from a number that looks like
one, so this copy shows what an analysis finds from the image alone. It is scored against the
same truth as <corpus>/bin. Run it again after fetch_pe.py or build_pe.py adds binaries.
"""
import struct, sys

from store import CORPORA

RELOCS_STRIPPED = 0x0001
BASERELOC = 5


def without_relocations(data):
    """The PE image `data` with its base relocations gone."""
    data = bytearray(data)
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    sections, optional_size = struct.unpack_from("<H", data, pe + 6)[0], struct.unpack_from("<H", data, pe + 20)[0]
    characteristics = pe + 22
    struct.pack_into("<H", data, characteristics, struct.unpack_from("<H", data, characteristics)[0] | RELOCS_STRIPPED)
    optional = pe + 24
    # PE32 keeps its data directories 96 bytes into the optional header, PE32+ 112.
    directories = optional + (96 if struct.unpack_from("<H", data, optional)[0] == 0x10B else 112)
    entry = directories + 8 * BASERELOC
    rva, size = struct.unpack_from("<II", data, entry)
    struct.pack_into("<II", data, entry, 0, 0)
    table = optional + optional_size
    for i in range(sections):
        header = table + 40 * i
        virtual_address, raw_size, raw_offset = struct.unpack_from("<III", data, header + 12)
        if size and virtual_address <= rva < virtual_address + raw_size:
            start = raw_offset + rva - virtual_address
            data[start:start + size] = bytes(size)
    return bytes(data)


def main():
    corpus = CORPORA / (sys.argv[1] if len(sys.argv) > 1 else "corpus-pe32")
    out = corpus / "norelocs"
    out.mkdir(exist_ok=True)
    for image in sorted((corpus / "bin").iterdir()):
        (out / image.name).write_bytes(without_relocations(image.read_bytes()))
    print(f"{corpus.name}: {len(list(out.iterdir()))} images without relocations")


if __name__ == "__main__":
    main()
