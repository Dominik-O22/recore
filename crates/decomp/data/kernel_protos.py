"""Writes kernel.protos: the prototypes of the functions Linux kernels export to their modules.

    python3 -I kernel_protos.py <kernel> <exports> [<kernel> <exports> ...] > kernel.protos

Each kernel is a raw `Image` or a `vmlinux`, both of which carry the kernel's BTF. Its exports
are a `vmlinux.symvers`, or a `System.map` or `nm vmlinux` listing, whose `__ksymtab_` symbols
name them. Where kernels disagree on a function, the first listed wins. kernel.protos is made
from these, newest first:

1. Android's GKI android16-6.12, build 17002073: `Image` and `vmlinux.symvers` from
   https://ci.android.com/builds/submitted/17002073/kernel_aarch64/latest/raw/<name>.
2. The Pixel 9's android14-6.1 kernel of 25Q1: `Image.lz4`, decompressed, and `System.map` from
   https://android.googlesource.com/device/google/caimito-kernels/6.1/+archive/refs/heads/main/25Q1-12919773.tar.gz.

A kernel built with an older pahole, such as Debian's 6.12, gives its assembly functions, such as
`__arch_copy_from_user`, the prototype `void (void)`, so it is not one of them.

Types are reduced as ghidra/ExportPrototypes.java reduces an archive's: sized integers, `long`
and `ulong` by name so that the table serves 32-bit kernels, strings, pointers to numbers, and
every other pointer as `void *`. A function that takes or returns a struct by value has no such
spelling and is left out. Lines read `- <return> <name>(<params>)`, sorted by name.
"""

import re
import struct
import sys

MAGIC = 0xEB9F
INT, PTR, ARRAY, STRUCT, UNION, ENUM, FWD, TYPEDEF, VOLATILE, CONST, RESTRICT, FUNC, FUNC_PROTO, VAR, DATASEC, FLOAT, DECL_TAG, TYPE_TAG, ENUM64 = range(1, 20)
# Bytes that follow a type's 12-byte header, by kind, as (fixed, per member).
TRAILER = {INT: (4, 0), ARRAY: (12, 0), STRUCT: (0, 12), UNION: (0, 12), ENUM: (0, 8), FUNC_PROTO: (0, 8), VAR: (4, 0), DATASEC: (0, 12), DECL_TAG: (4, 0), ENUM64: (0, 12)}
QUALIFIERS = (TYPEDEF, CONST, VOLATILE, RESTRICT, TYPE_TAG)
INT_SIGNED, INT_BOOL = 1, 4

# Typedefs that are as wide as a pointer whatever they are built from.
POINTER_SIZED = {"size_t", "ssize_t", "uintptr_t", "intptr_t", "ptrdiff_t"}
RESERVED = {
    "int", "uint", "char", "void", "bool", "float", "double", "long", "short", "unsigned", "signed", "struct", "union", "enum",
    "const", "typedef", "extern", "code", "size_t", "DWORD", "BOOL", "HANDLE", "wstr", "ulong", "string", "this", "class",
    "template", "default", "register", "volatile", "static", "return", "if", "else", "for", "while", "do", "switch", "case",
    "break", "continue", "goto", "sizeof",
}
ENGINE_TYPE = re.compile(r"u?int[0-9]+|float[0-9]+|wchar[0-9]+|undefined[0-9]+")
IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


class Btf:
    """The types of a little-endian BTF blob as (kind, info, size or type, trailer, name offset),
    indexed by type id. Id 0 is `void`."""

    def __init__(self, blob):
        magic, version, _flags, header, type_off, type_len, str_off, str_len = struct.unpack_from("<HBBIIIII", blob)
        if magic != MAGIC or version != 1:
            raise ValueError("not little-endian BTF")
        self.strings = blob[header + str_off : header + str_off + str_len]
        self.types = [(0, 0, 0, b"", 0)]
        at, end = header + type_off, header + type_off + type_len
        while at < end:
            name_off, info, size_or_type = struct.unpack_from("<III", blob, at)
            kind, vlen = (info >> 24) & 0x1F, info & 0xFFFF
            fixed, member = TRAILER.get(kind, (0, 0))
            trailer = blob[at + 12 : at + 12 + fixed + member * vlen]
            self.types.append((kind, info, size_or_type, trailer, name_off))
            at += 12 + fixed + member * vlen

    def name(self, offset):
        return self.strings[offset : self.strings.index(b"\0", offset)].decode()

    def kind(self, id):
        return self.types[id][0]

    def type_name(self, id):
        return self.name(self.types[id][4])

    def functions(self):
        """Every function as (name, prototype id, global): a static one may share a name."""
        for kind, info, proto, _, name_off in self.types:
            if kind == FUNC:
                yield self.name(name_off), proto, (info & 0xFFFF) != 0

    def params(self, proto):
        """The parameters of a prototype as (name, type id). A last one of type 0 is `...`."""
        return [(self.name(name), type) for name, type in struct.iter_unpack("<II", self.types[proto][3])]

    def returns(self, proto):
        return self.types[proto][2]

    def strip(self, id):
        while self.kind(id) in QUALIFIERS:
            id = self.types[id][2]
        return id

    def spell(self, id):
        """The reduced spelling of a type, or None for one passed by value that has none."""
        while self.kind(id) in QUALIFIERS:
            if self.kind(id) == TYPEDEF and self.type_name(id) in POINTER_SIZED:
                return "size_t"
            id = self.types[id][2]
        kind, _, size, trailer, _ = self.types[id]
        if id == 0:
            return "void"
        if kind == PTR:
            target = self.strip(size)
            if self.kind(target) == INT and self.type_name(target) in ("char", "signed char"):
                return "char *"
            pointee = self.spell(target) if self.kind(target) in (INT, FLOAT, ENUM, ENUM64) else None
            return "void *" if pointee is None else pointee + " *"
        if kind in (ENUM, ENUM64):
            return f"uint{max(size, 1)}"
        if kind == FLOAT:
            return f"float{size}"
        if kind == INT:
            encoding = struct.unpack("<I", trailer)[0] >> 24
            name = self.type_name(id)
            if encoding & INT_BOOL:
                return "bool"
            # GCC and Clang spell C's long differently.
            if name in ("long", "long int"):
                return "long"
            if name in ("unsigned long", "long unsigned int"):
                return "ulong"
            return f"{'int' if encoding & INT_SIGNED else 'uint'}{size}"
        return None

    def prototype(self, name, proto):
        """The table's line for a function, or None if a type has no reduced spelling."""
        returns = self.spell(self.returns(proto))
        if returns is None:
            return None
        params = []
        for index, (param, type) in enumerate(self.params(proto)):
            if type == 0:
                params.append("...")
                continue
            spelling = self.spell(type)
            if spelling is None or spelling == "void":
                return None
            if not IDENTIFIER.fullmatch(param) or param in RESERVED or ENGINE_TYPE.fullmatch(param):
                param = f"param_{index + 1}"
            params.append(spelling + param if spelling.endswith("*") else f"{spelling} {param}")
        space = "" if returns.endswith("*") else " "
        return f"- {returns}{space}{name}({', '.join(params) or 'void'})"


def find_btf(data):
    """The kernel's BTF in an `Image` or a `vmlinux`: the largest blob whose header holds."""
    header = struct.pack("<HBBI", MAGIC, 1, 0, 24)
    best = None
    at = data.find(header)
    while at >= 0:
        type_off, type_len, str_off, str_len = struct.unpack_from("<IIII", data, at + 8)
        size = 24 + max(type_off + type_len, str_off + str_len)
        if type_off == 0 and str_off == type_len and at + size <= len(data) and (best is None or size > best[1]):
            best = (at, size)
        at = data.find(header, at + 1)
    if best is None:
        raise ValueError("no BTF found")
    return data[best[0] : best[0] + best[1]]


def exports(path):
    """The names a kernel exports to its modules."""
    names = set()
    with open(path) as file:
        for line in file:
            fields = line.split()
            if len(fields) >= 4 and fields[3].startswith("EXPORT_SYMBOL"):
                names.add(fields[1])
            elif len(fields) == 3 and fields[2].startswith("__ksymtab_"):
                names.add(fields[2][len("__ksymtab_") :])
    return names


def table(btf, exported):
    """The line of every exported function, by name. Where several functions share a name, the
    global one is the export."""
    found = {}
    for name, proto, is_global in btf.functions():
        if name in exported and (name not in found or is_global):
            found[name] = proto
    lines = {name: btf.prototype(name, proto) for name, proto in found.items()}
    return {name: line for name, line in lines.items() if line is not None}


def main():
    lines = {}
    for kernel, exported in zip(sys.argv[1::2], sys.argv[2::2]):
        with open(kernel, "rb") as file:
            btf = Btf(find_btf(file.read()))
        for name, line in table(btf, exports(exported)).items():
            lines.setdefault(name, line)
    for name in sorted(lines):
        print(lines[name])


if __name__ == "__main__":
    main()
