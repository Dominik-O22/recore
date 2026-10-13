#!/usr/bin/env python3
"""Writes the lines of a `.lib` list: the routines of a compiler's library, each known by a
hash of its code. See `crates/core/src/library.rs` for what reads them.

A line is `name storage length hash [offset+count[=routine]]...`. The hash is FNV-1a over the
first `length` bytes of the routine with the listed bytes taken as zero: those differ from
program to program, being part of an address. `=routine` says the two bytes are the address
of that routine, which tells apart routines that differ only in what they jump to.

  fingerprint.py sdcc [model...] > sdcc-mcs51.lib
      The library SDCC has installed. Each module of each model is linked twice, at different
      addresses for code and each kind of memory: the bytes that differ are the ones to leave
      out. The names are C's.

  fingerprint.py image <image> <offset> <routines> > keil-c51.lib
      Routines found by hand in an image, whose code memory starts at `offset` of the file.
      `routines` has a line `name storage start end` for each, addresses in hex. The operands
      of LJMP, LCALL, AJMP, ACALL and MOV DPTR,# are left out.
"""
import re, subprocess, sys, tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

SDCC_LIB = Path("/usr/share/sdcc/lib")
MODELS = ["small", "small-stack-auto", "medium", "medium-stack-auto", "large", "large-stack-auto", "huge", "huge-stack-auto"]
# Fewer bytes than this, not counting those left out, say too little to know a routine by.
LEAST = 6
# Where SDCC's routines written in assembly take arguments and leave a result, when that is
# not where a C function does. A generic pointer is in B, DPH and DPL.
SDCC_STORAGE = {
    "__gptrget": "ACC(B:DPTR)",
    "__gptrgetc": "ACC(B:DPTR)",
    "__gptrput": "void(B:DPTR,ACC)",
}


def fnv(data):
    h = 0xcbf29ce484222325
    for byte in data:
        h = ((h ^ byte) * 0x100000001b3) & 0xffffffffffffffff
    return h


def line(name, storage, code, left_out):
    """`left_out` is a list of (offset, count, routine or None)."""
    code = bytearray(code)
    for offset, count, _ in left_out:
        code[offset:offset + count] = bytes(count)
    if len(code) - sum(count for _, count, _ in left_out) < LEAST:
        return None
    spans = " ".join(f"{offset}+{count}" + (f"={routine}" if routine else "") for offset, count, routine in left_out)
    return f"{name} {storage} {len(code)} {fnv(code):016x} {spans}".rstrip()


def read_ihx(path):
    memory = bytearray(0x10000)
    for record in Path(path).read_text().split():
        raw = bytes.fromhex(record[1:])
        if raw[3] == 0:
            address = raw[1] << 8 | raw[2]
            memory[address:address + raw[0]] = raw[4:4 + raw[0]]
    return memory


def members(model):
    """For each module of the model's libraries, the routines it defines: symbol to the bytes
    from it to the next symbol or the end of the module's code."""
    for lib in sorted((SDCC_LIB / model).glob("*.lib")):
        for member in subprocess.run(["ar", "t", lib], capture_output=True, text=True, check=True).stdout.split():
            rel = subprocess.run(["ar", "p", lib, member], capture_output=True, text=True, check=True).stdout
            area, sizes, defined = None, {}, []
            for words in map(str.split, rel.splitlines()):
                if words[:1] == ["A"]:
                    area, sizes[words[1]] = words[1], int(words[3], 16)
                elif words[:1] == ["S"] and words[2].startswith("Def") and area in ("CSEG", "HOME"):
                    defined.append((area, int(words[2][3:], 16), words[1]))
            defined.sort()
            lengths = {}
            for at, (area, offset, symbol) in enumerate(defined):
                following = [o for a, o, _ in defined[at + 1:] if a == area and o > offset]
                lengths[symbol] = (following[0] if following else sizes[area]) - offset
            if lengths:
                yield lengths


def link(model, symbols, shift):
    """Links a program that refers to the symbols, with `shift` bytes ahead of the library in
    code and in each kind of memory. Returns its code memory and where each symbol is, or
    nothing if the program does not link."""
    flags = [f"--model-{model.removesuffix('-stack-auto')}"] + (["--stack-auto"] if model.endswith("stack-auto") else [])
    with tempfile.TemporaryDirectory() as work:
        work = Path(work)
        (work / "main.c").write_text("void main(void) {}\nint putchar(int c) { return c; }\nint getchar(void) { return 0; }\n")
        # The huge model's bank switch needs to be told the register that selects the bank.
        lines = [".module refs", ".globl _PSBANK", "_PSBANK = 0x00b1"] + [f".globl {symbol}" for symbol in symbols]
        for area, kind in [("DSEG", "DATA"), ("ISEG", "DATA"), ("BSEG", "BIT"), ("PSEG", "PAG,XDATA"), ("XSEG", "XDATA")]:
            lines += [f".area {area} ({kind})", f".ds {shift and (0x111 if area == 'XSEG' else 3)}"]
        lines += [".area HOME (CODE)", f".ds {shift and 0x111}", ".area CSEG (CODE)", f".ds {shift and 0x1111}"] + [f".dw {symbol}" for symbol in symbols]
        (work / "refs.asm").write_text("\n".join(lines) + "\n")
        subprocess.run(["sdas8051", "-l", "-o", "refs.rel", "refs.asm"], cwd=work, check=True)
        subprocess.run(["sdcc", "-mmcs51", *flags, "-c", "main.c"], cwd=work, check=True, capture_output=True)
        if subprocess.run(["sdcc", "-mmcs51", *flags, "-l", "liblonglong", "-o", "out.ihx", "refs.rel", "main.rel"], cwd=work, capture_output=True).returncode != 0:
            return None
        where = {}
        for found in re.finditer(r"^C:\s+([0-9A-F]{8})\s+(\S+)", (work / "out.map").read_text(), re.M):
            where.setdefault(found[2], int(found[1], 16) & 0xffff)
        return read_ihx(work / "out.ihx"), where


def c_name(symbol):
    """The name C has for a symbol of the linker's, which has one more underscore in front."""
    return symbol.removeprefix("_")


def module(model, lengths, routines):
    """The lines for one module, whose routines are `lengths`; `routines` are all the model's."""
    links = [link(model, sorted(lengths), shift) for shift in (0, 1)]
    if None in links:
        print(f"{model}: {' '.join(lengths)} did not link", file=sys.stderr)
        return []
    (code, where), (moved, moved_where) = links
    routine_at = {address: symbol for symbol, address in where.items() if symbol in routines}
    lines = []
    for symbol, length in lengths.items():
        start, moved_start = where[symbol], moved_where[symbol]
        body = code[start:start + length]
        left_out = []
        for offset in (offset for offset in range(length) if body[offset] != moved[moved_start + offset]):
            if left_out and sum(left_out[-1][:2]) == offset:
                left_out[-1] = (left_out[-1][0], left_out[-1][1] + 1, None)
            else:
                left_out.append((offset, 1, None))
        # The address an LJMP or LCALL goes to, when that is a routine of the library.
        for at, (offset, count, _) in enumerate(left_out):
            target = routine_at.get(body[offset] << 8 | body[offset + 1]) if count == 2 and offset and body[offset - 1] in (0x02, 0x12) else None
            left_out[at] = (offset, count, c_name(target) if target and target != symbol else None)
        lines.append(line(c_name(symbol), SDCC_STORAGE.get(symbol, "-"), body, left_out))
    return [text for text in lines if text]


def sdcc(models):
    lines = {}
    for model in models:
        modules = list(members(model))
        routines = {symbol for lengths in modules for symbol in lengths}
        with ThreadPoolExecutor(16) as pool:
            for found in pool.map(lambda lengths: module(model, lengths, routines), modules):
                for text in found:
                    lines.setdefault(text, None)
    # Of routines with the same code, the first by name stands for all.
    first = {}
    for text in sorted(lines):
        first.setdefault(text.split(" ", 1)[1], text)
    return sorted(first.values())


# How many bytes each 8051 instruction has, by its first.
def instruction_length(opcode):
    low, high = opcode & 0xf, opcode >> 4
    if opcode in (0x02, 0x12, 0x90, 0x43, 0x53, 0x63, 0x75, 0x85, 0xb4, 0xb5, 0xd5, 0x10, 0x20, 0x30):
        return 3
    if low >= 6:
        return 3 if high == 0xb else 2 if high in (0x7, 0x8, 0xa) or (high == 0xd and low >= 8) else 1
    if low == 1 or low == 5 or opcode in (0x40, 0x50, 0x60, 0x70, 0x80, 0xa0, 0xb0, 0xc0, 0xd0, 0x72, 0x82, 0x92, 0xa2, 0xb2, 0xc2, 0xd2, 0x42, 0x52, 0x62):
        return 2
    return 2 if low == 4 and high in (0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x9) else 1


def image(path, offset, routines):
    memory = Path(path).read_bytes()[offset:offset + 0x10000]
    listed = [(name, storage, int(start, 16), int(end, 16)) for name, storage, start, end in map(str.split, Path(routines).read_text().splitlines())]
    routine_at = {start: name for name, _, start, _ in listed}
    for name, storage, start, end in listed:
        at, left_out = start, []
        while at < end:
            opcode = memory[at]
            if opcode in (0x02, 0x12):
                left_out.append((at + 1 - start, 2, routine_at.get(memory[at + 1] << 8 | memory[at + 2])))
            elif opcode == 0x90:
                left_out.append((at + 1 - start, 2, None))
            elif opcode & 0x1f in (0x01, 0x11):
                left_out.append((at - start, 2, None))
            at += instruction_length(opcode)
        assert at == end, f"{name} does not end at {end:#x}"
        yield line(name, storage, memory[start:end], left_out)


if __name__ == "__main__":
    if sys.argv[1:2] == ["sdcc"]:
        print("\n".join(sdcc(sys.argv[2:] or MODELS)))
    elif sys.argv[1:2] == ["image"]:
        print("\n".join(text for text in image(sys.argv[2], int(sys.argv[3], 0), sys.argv[4]) if text))
    else:
        sys.exit(__doc__)
