#!/usr/bin/env python3
"""Scans a corpus's 32-bit PE binaries for the two-instruction stub one release's fixes came
out of, `LEA EDX,[ESP+4]; CALL rel32` in 9 bytes, and measures what follows each of its
calls: another function's start, per the ground truth the corpus is scored with and per
recore's own analysis of the same binaries, or the truth's own continuation of the function
the stub sits in. Both membership questions decide which of a corpus test and an ignored one
the shape would serve, so the run prints every site and totals each reading.

Usage: scan_pe32_difficult_call.py [corpus [recore-output]]
      default: corpus-pe32; recore-output is the directory of recore's analysis JSONs, as
      target/corpus/corpus-pe32/recore is under check.sh's output.
"""
import json, struct, sys
from pathlib import Path

from store import CORPORA

LEA_CALL = bytes.fromhex("8d542404e8")  # the 4 bytes of LEA EDX,[ESP+4] and the CALL's opcode
STUB_LENGTH = len(LEA_CALL) + 4  # the 4 bytes of the CALL's relative address close the stub
I386 = 0x014C  # IMAGE_FILE_MACHINE_I386


def sections(data):
    """Each (file offset, end, image address) of the raw part of a section of `data`, so that
    a file offset turns into its image address. None when `data` is not a 32-bit PE image."""
    try:
        pe = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe:pe + 4] != b"PE\x00\x00" or struct.unpack_from("<H", data, pe + 4)[0] != I386:
            return None
        count = struct.unpack_from("<H", data, pe + 6)[0]
        optional_size = struct.unpack_from("<H", data, pe + 20)[0]
        base = struct.unpack_from("<I", data, pe + 24 + 28)[0]
        out, table = [], pe + 24 + optional_size
        for i in range(count):
            header = table + 40 * i
            _virtual_size, _address, raw_size, raw_offset = struct.unpack_from("<IIII", data, header + 8)
            if raw_size:
                out.append((raw_offset, raw_offset + raw_size, base + _address))
    except struct.error:
        return None
    return out


def image_address(section_parts, offset):
    for start, end, address in section_parts:
        if start <= offset < end:
            return address + offset - start


def starts_and_ranges(path):
    """The (start, end, name) triples a truth file carries, or an empty list when none is
    there; recore's per-function ranges come folded into triples the same shape."""
    if not path.exists():
        return []
    document = json.loads(path.read_text())
    out = []
    for f in document["functions"]:
        rngs = f["ranges"] if "ranges" in f else [(f["addr"], f["addr"] + f.get("size", 0))]
        for start, end in rngs:
            out.append((start, end, f.get("name", "")))
    return out


def container_name(ranges, address):
    for start, end, name in ranges:
        if start <= address < end:
            return name
    return "nothing"


def main():
    corpus = CORPORA / (sys.argv[1] if len(sys.argv) > 1 else "corpus-pe32")
    recore_output = Path(sys.argv[2]) if len(sys.argv) > 2 else None
    total = truth_starts = recore_starts = truth_continues = 0
    for image in sorted((corpus / "bin").iterdir()):
        if not image.is_file():
            continue
        data = image.read_bytes()
        if data[:2] != b"MZ":
            continue
        parts = sections(data)
        if not parts:
            continue
        truth = starts_and_ranges(corpus / "truth" / f"{image.name}.json")
        recore = starts_and_ranges(recore_output / f"{image.name}.json") if recore_output else []
        found = []
        offset = data.find(LEA_CALL)
        while offset >= 0:
            this = image_address(parts, offset)
            if this is not None:
                found.append(this)
            offset = data.find(LEA_CALL, offset + 1)
        if not found:
            continue
        print(f"{image.name}:")
        for this in found:
            after = this + STUB_LENGTH
            total += 1
            in_truth = any(start == after for start, _end, _name in truth)
            in_recore = [name for start, _end, name in recore if start == after]
            carrying = container_name(truth, this)
            continues = any(start <= this < end and after < end for start, end, _name in truth)
            truth_starts += in_truth
            recore_starts += bool(in_recore)
            truth_continues += continues and not in_truth
            if in_truth:
                reading = "a truth function starts"
            elif continues:
                reading = f"the truth's {carrying or 'function'} carries on"
            else:
                reading = "truth has neither a start nor the containing function's code"
            if in_recore:
                reading += "; recore starts " + (in_recore[0] or "a function")
            print(f"  0x{this:x} -> 0x{after:x}: {reading}")
    print(f"TOTAL {total} stubs; truth: {truth_starts} with a function start behind the call and "
          f"{truth_continues} with the containing function carrying on; recore: {recore_starts} starts")


if __name__ == "__main__":
    main()
