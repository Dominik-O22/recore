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

With `--kcfi`, writes kcfi.protos instead: every function type a kernel's BTF holds, by its kCFI
hash, so that the hash clang puts before a module's function names that function's type.

    python3 -I kernel_protos.py --kcfi <kernel> <normalized|plain> [...] > kcfi.protos

The hash is the low 32 bits of xxHash64 of `_ZTS` and the type's Itanium mangling, with
`.normalized` after it where the kernel is built with CONFIG_CFI_ICALL_NORMALIZE_INTEGERS: then
every integer is spelled by its width and sign, `u3i32` for `int`. Each kernel's types are hashed
in its own spelling. Every FUNC_PROTO counts, since a module's function may have the type of a
pointer in a kernel struct that no kernel function has. kcfi.protos is made from the two kernels
above: the GKI 6.12 normalizes and the Pixel's 6.1 does not.

Lines read `<hash> <n|p> <return> (<params>)`, sorted, where `n` is the normalized spelling and
`p` the plain one. A type is spelled with sized numbers, and a pointer to a struct or union keeps
its name: `int4 (struct platform_device *)`. A normalized hash knows an integer's width and sign
and nothing more, so only `p` lines say `char` and `bool`: `n` lines say `uint1` for `_Bool`,
`char` and `unsigned char` alike. An enum is the integer it is stored in, and a pointer to a
function is `void *`. A type that passes a struct or union by value is left out, as is a hash two
types share and one whose types the table would spell two ways.

Both tables are made from Linux kernels, and Linux is licensed under the GPL-2.0.
"""

import collections
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


def xxh64(data):
    """xxHash64 of `data` with seed 0."""
    p1, p2, p3, p4, p5, mask = 0x9E3779B185EBCA87, 0xC2B2AE3D27D4EB4F, 0x165667B19E3779F9, 0x85EBCA77C2B2AE63, 0x27D4EB2F165667C5, (1 << 64) - 1

    def rotl(value, bits):
        return ((value << bits) | (value >> (64 - bits))) & mask

    def mix(acc, lane):
        return rotl((acc + lane * p2) & mask, 31) * p1 & mask

    def lane(at, size):
        return int.from_bytes(data[at : at + size], "little")

    at, size = 0, len(data)
    if size >= 32:
        acc = [(p1 + p2) & mask, p2, 0, -p1 & mask]
        while at + 32 <= size:
            acc = [mix(value, lane(at + 8 * index, 8)) for index, value in enumerate(acc)]
            at += 32
        digest = (rotl(acc[0], 1) + rotl(acc[1], 7) + rotl(acc[2], 12) + rotl(acc[3], 18)) & mask
        for value in acc:
            digest = ((digest ^ mix(0, value)) * p1 + p4) & mask
    else:
        digest = p5
    digest = (digest + size) & mask
    while at + 8 <= size:
        digest = (rotl(digest ^ mix(0, lane(at, 8)), 27) * p1 + p4) & mask
        at += 8
    if at + 4 <= size:
        digest = (rotl(digest ^ (lane(at, 4) * p1 & mask), 23) * p2 + p3) & mask
        at += 4
    for byte in data[at:]:
        digest = rotl(digest ^ (byte * p5 & mask), 11) * p1 & mask
    for shift, prime in ((33, p2), (29, p3)):
        digest = (digest ^ (digest >> shift)) * prime & mask
    return digest ^ (digest >> 32)


# The Itanium ABI's codes for C's arithmetic types, by the names BTF gives them.
BUILTIN = {
    "_Bool": "b", "char": "c", "signed char": "a", "unsigned char": "h", "short": "s", "short int": "s", "unsigned short": "t",
    "short unsigned int": "t", "int": "i", "unsigned int": "j", "long": "l", "long int": "l", "unsigned long": "m",
    "long unsigned int": "m", "long long": "x", "long long int": "x", "unsigned long long": "y", "long long unsigned int": "y",
    "__int128": "n", "__int128 unsigned": "o", "unsigned __int128": "o", "float": "f", "double": "d", "long double": "e",
}


class Canonical:
    """A kernel's types as clang mangles them, with typedefs and type tags seen through. A type is
    a tuple: `("void",)`, `("int", code, size, signed)`, `("float", code, size)`, `("enum", name,
    size, signed)`, `("struct", name)`, `("union", name)`, `("ptr", type)`, `("qual", "rVK"
    subset, type)`, `("array", count, type)` or `("func", return, params, variadic)`."""

    def __init__(self, btf):
        self.btf = btf
        # An anonymous struct, union or enum mangles as the first typedef that names it.
        self.typedef_names = {}
        for kind, _, target, _, name in btf.types:
            if kind == TYPEDEF and btf.kind(target) in (STRUCT, UNION, ENUM, ENUM64) and btf.types[target][4] == 0:
                self.typedef_names.setdefault(target, btf.name(name))
        self.memo = {}

    def type(self, id):
        if id not in self.memo:
            self.memo[id] = self.convert(id)
        return self.memo[id]

    def convert(self, id):
        if id == 0:
            return ("void",)
        kind, info, size, trailer, name = self.btf.types[id]
        if kind == INT:
            return ("int", BUILTIN[self.btf.name(name)], size, bool(struct.unpack("<I", trailer)[0] >> 24 & INT_SIGNED))
        if kind == FLOAT:
            return ("float", BUILTIN[self.btf.name(name)], size)
        if kind in (TYPEDEF, TYPE_TAG):
            return self.type(size)
        if kind in (CONST, VOLATILE, RESTRICT):
            qualifiers, inner = {CONST: "K", VOLATILE: "V", RESTRICT: "r"}[kind], self.type(size)
            if inner[0] == "func":
                return inner
            if inner[0] == "qual":
                qualifiers, inner = qualifiers + inner[1], inner[2]
            return ("qual", "".join(q for q in "rVK" if q in qualifiers), inner)
        if kind == PTR:
            return ("ptr", self.type(size))
        if kind in (STRUCT, UNION, FWD, ENUM, ENUM64):
            label = self.btf.name(name) or self.typedef_names.get(id)
            if not label:
                raise ValueError("an anonymous type without a typedef")
            if kind in (ENUM, ENUM64):
                return ("enum", label, size, bool(info >> 31))
            return ("union" if kind == UNION or (kind == FWD and info >> 31) else "struct", label)
        if kind == ARRAY:
            element, _, count = struct.unpack("<III", trailer)
            return ("array", count, self.type(element))
        if kind == FUNC_PROTO:
            params = self.btf.params(id)
            variadic = bool(params) and params[-1][1] == 0
            params = params[:-1] if variadic else params
            return ("func", self.type(self.btf.returns(id)), tuple(decayed(self.type(type)) for _, type in params), variadic)
        raise ValueError(f"BTF kind {kind}")


def decayed(type):
    """A parameter's type as its function's type holds it: without qualifiers, and an array or
    a function as a pointer."""
    if type[0] == "qual":
        type = type[2]
    if type[0] == "array":
        return ("ptr", type[2])
    if type[0] == "func":
        return ("ptr", type)
    return type


def substitution(index):
    """How the `index`th component written so far is referred to again: `S_`, `S0_` to `SZ_`,
    `S10_` and on."""
    if index == 0:
        return "S_"
    digits, index = "", index - 1
    while True:
        digits = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"[index % 36] + digits
        index //= 36
        if index == 0:
            return f"S{digits}_"


def mangle(function, normalized):
    """The string whose hash kCFI puts before a function of type `function`."""
    out, seen = [], {}

    def component(type):
        kind = type[0]
        if kind == "int" and normalized:
            # Normalized integers are candidates for substitution, one per width and sign.
            key = ("int", type[2], type[3])
            if key in seen:
                out.append(substitution(seen[key]))
            else:
                width = f"{'i' if type[3] else 'u'}{8 * type[2]}"
                out.append(f"u{len(width)}{width}")
                seen[key] = len(seen)
            return
        if kind in ("void", "int", "float"):
            out.append("v" if kind == "void" else type[1])
            return
        if type in seen:
            out.append(substitution(seen[type]))
            return
        if kind == "qual":
            out.append(type[1])
            component(type[2])
        elif kind == "ptr":
            out.append("P")
            component(type[1])
        elif kind in ("struct", "union", "enum"):
            # AArch64's va_list is std::__va_list.
            out.append("St9__va_list" if type[1] == "__va_list" else f"{len(type[1])}{type[1]}")
        elif kind == "array":
            out.append(f"A{type[1] or ''}_")
            component(type[2])
        else:
            signature(type)
        seen[type] = len(seen)

    def signature(type):
        _, returns, params, variadic = type
        out.append("F")
        component(returns)
        if not params and not variadic:
            out.append("v")
        for param in params:
            component(param)
        if variadic:
            out.append("z")
        out.append("E")

    out.append("_ZTS")
    signature(function)
    return "".join(out) + (".normalized" if normalized else "")


def spell(type, normalized, pointed_to=False):
    """How kcfi.protos writes a type, or None for a struct or union passed by value. A normalized
    hash knows an integer's width and sign and no more, so only the plain spelling says `bool` or
    `char`."""
    kind = type[0]
    if kind == "qual":
        return spell(type[2], normalized, pointed_to)
    if kind == "void":
        return "void"
    if kind == "int":
        _, code, size, signed = type
        plain = {} if normalized else {"b": "bool", "c": "char"}
        return plain.get(code, f"{'int' if signed else 'uint'}{size}")
    if kind == "float":
        return f"float{type[2]}"
    if kind == "enum":
        return f"{'int' if type[3] else 'uint'}{type[2]}"
    if kind in ("struct", "union"):
        return f"{kind} {type[1]}" if pointed_to else None
    if kind == "ptr":
        target = type[1][2] if type[1][0] == "qual" else type[1]
        target = target[2] if target[0] == "array" else target
        if target[0] == "func":
            return "void *"
        inner = spell(target, normalized, True)
        return inner + ("*" if inner.endswith("*") else " *")
    raise ValueError(f"no spelling for {kind}")


def kcfi_table(btf, normalized):
    """The line of every function type of the kernel, by its kCFI hash."""
    canonical = Canonical(btf)
    spellings = collections.defaultdict(set)
    for id, record in enumerate(btf.types):
        if record[0] != FUNC_PROTO:
            continue
        try:
            function = canonical.type(id)
        except (KeyError, ValueError):
            continue
        _, returns, params, variadic = function
        spelled = [spell(returns, normalized)] + [spell(param, normalized) for param in params]
        if None in spelled:
            continue
        listed = ", ".join(spelled[1:] + ["..."] * variadic) or "void"
        spellings[mangle(function, normalized)].add(f"{spelled[0]} ({listed})")
    by_hash = collections.defaultdict(list)
    for mangled in spellings:
        by_hash[xxh64(mangled.encode()) & 0xFFFFFFFF].append(mangled)
    return {hash: line for hash, (mangled, *others) in by_hash.items() if not others for line in spellings[mangled] if len(spellings[mangled]) == 1}


def kcfi_main(args):
    lines = {}
    for kernel, spelling in zip(args[::2], args[1::2]):
        if spelling not in ("normalized", "plain"):
            sys.exit(f"{spelling}: a kernel's spelling is `normalized` or `plain`")
        with open(kernel, "rb") as file:
            btf = Btf(find_btf(file.read()))
        for hash, line in kcfi_table(btf, spelling == "normalized").items():
            lines.setdefault((hash, spelling[0]), line)
    for (hash, spelling), line in sorted(lines.items()):
        print(f"{hash:08x} {spelling} {line}")


def main():
    if sys.argv[1:2] == ["--kcfi"]:
        return kcfi_main(sys.argv[2:])
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
