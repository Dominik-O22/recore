#!/usr/bin/env python3
"""Prints how Ghidra loads a Cortex-M layout: the image, the flash base, and the handlers its vector
table names, read as recore reads them, from the second word on to the first that is no pointer to
Thumb code in the image. Prints nothing for a layout of another machine.

Usage: cortex_m.py <layout.toml>"""
import struct, sys, tomllib
from pathlib import Path

path = Path(sys.argv[1])
layout = tomllib.loads(path.read_text())
if layout.get("machine") == "cortex-m":
    (region,) = layout["region"]
    image = path.parent / region["file"]
    data = image.read_bytes()
    assert region["offset"] == 0 and region["length"] == len(data), "the region must be the whole image"
    base = region["address"]
    entries = []
    for (word,) in struct.iter_unpack("<I", data[4:4 * 512]):
        if word and (word & 1 == 0 or not base <= word - 1 < base + len(data)):
            break
        if word and hex(word & ~1) not in entries:
            entries.append(hex(word & ~1))
    print(image.resolve(), hex(base), *entries)
