"""Writes kernel.protos: the prototypes of the functions Linux kernels export to their modules.

    python3 -I kernel_protos.py <kernel> <exports> [--modules <dir>] [<kernel> <exports> ...] [--headers <file>] > kernel.protos

Each kernel is a raw `Image` or a `vmlinux`, both of which carry the kernel's BTF. Its exports
are a `vmlinux.symvers`, or a `System.map` or `nm vmlinux` listing, whose `__ksymtab_` symbols
name them. `--modules` after a kernel adds every `.ko` in a directory: modules built with that
kernel, whose `.BTF` is split BTF on top of the kernel's own, and whose `__ksymtab_` symbols name
what they export. Where sources disagree on a function, the first listed wins. kernel.protos is
made from these, newest first:

1. Android's GKI android16-6.12, build 17002073: `Image` and `vmlinux.symvers` from
   https://ci.android.com/builds/submitted/17002073/kernel_aarch64/latest/raw/<name>, and with
   `--modules` the 112 modules of `unstripped_modules.tar.gz` from the same place, such as
   bluetooth, usbnet and can-dev.
2. The Pixel 9's android14-6.1 kernel of 25Q1: `Image.lz4`, decompressed, and `System.map` from
   https://android.googlesource.com/device/google/caimito-kernels/6.1/+archive/refs/heads/main/25Q1-12919773.tar.gz.
3. The Pixel 7's android13-5.10 kernel: `Image.lz4`, decompressed, and `System.map` from the
   archive corpus/fetch_android_kmod.py fetches for `pantah`. It gives the names the newer two
   dropped or renamed, such as `printk`, which 5.15 made `_printk`.

An old module's call to a function whose prototype changed takes the newest kernel's line. Of the
4,244 names the 5.10 kernel shares with the newer two, 95 differ in their parameter count or in
whether they return a value.

GKI's modules add 416 names and change 5 lines the 5.10 kernel gave, such as `can_put_echo_skb`,
which gained a frame length. GKI builds no mac80211 or cfg80211 and the Pixel 9's modules have no
BTF, so the 5.10 line is still the only one a 6.x module's call to those gets. Against the DWARF
of the modules that import them, 9 of the 169 (module, name) pairs of Debian's 6.12 arm64 modules
that take a line only the 5.10 kernel gives differ: 8 mac80211 and cfg80211 names that 6.x gave
more parameters, six a `link_id`, such as `ieee80211_nullfunc_get`, one a channel context, and
`cfg80211_port_authorized` two.

Kernels before 5.2 carry no BTF. `--headers kernel_headers.txt` adds, after every kernel, the
lines of that file, written by hand from the headers of the Pixel 5's 4.19 and the Pixel 2's 4.4
in this table's spelling, each under the header it came from.

A kernel built with an older pahole, such as Debian's 6.12, gives its assembly functions, such as
`__arch_copy_from_user`, the prototype `void (void)`, so it is not one of them.

Types are reduced as ghidra/ExportPrototypes.java reduces an archive's: numbers as both tables
spell them, `long`, `ulong` and `size_t` by name, with `ssize_t` as `long`, pointers to numbers,
and every other pointer as `void *`. Every other width is a 64-bit kernel's, such as the 8 bytes
of `phys_addr_t`, so the table does not describe a 32-bit kernel. A function that takes or returns a
struct by value has no such spelling and is left out. Lines read `- <return> <name>(<params>)`,
sorted by name.

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
`p` the plain one. A pointer to a struct or union keeps its name: `int4 (struct platform_device
*)`. A normalized hash knows an integer's width and sign and nothing more, so only `p` lines say
`bool` and `char`, and `n` lines say `uint1` for `_Bool`, `char` and `unsigned char` alike. Behind
a pointer `n` lines guess `char`, so that strings print. A pointer to a function is `void *`. A type that passes a struct or union by value is left
out, as is a hash two types share and one whose types the table would spell two ways.

Both tables spell `_Bool` as `bool`, `char` as `char`, any other integer by its width and sign,
such as `uint4` for `unsigned int`, an enum as the integer it is stored in, and a float by its
width.

Both tables are made from Linux kernels and their modules, their BTF and their headers, and Linux
is licensed under the GPL-2.0.
"""

import collections
import os
import re
import struct
import sys

MAGIC = 0xEB9F
INT, PTR, ARRAY, STRUCT, UNION, ENUM, FWD, TYPEDEF, VOLATILE, CONST, RESTRICT, FUNC, FUNC_PROTO, VAR, DATASEC, FLOAT, DECL_TAG, TYPE_TAG, ENUM64 = range(1, 20)
# Bytes that follow a type's 12-byte header, by kind, as (fixed, per member).
TRAILER = {INT: (4, 0), ARRAY: (12, 0), STRUCT: (0, 12), UNION: (0, 12), ENUM: (0, 8), FUNC_PROTO: (0, 8), VAR: (4, 0), DATASEC: (0, 12), DECL_TAG: (4, 0), ENUM64: (0, 12)}
QUALIFIERS = (TYPEDEF, CONST, VOLATILE, RESTRICT, TYPE_TAG)
INT_SIGNED = 1

# Typedefs that are as wide as a pointer whatever they are built from, and the name of that width
# with their sign.
POINTER_SIZED = {"size_t": "size_t", "uintptr_t": "size_t", "ssize_t": "long", "intptr_t": "long", "ptrdiff_t": "long"}
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
    indexed by type id. Id 0 is `void`. A module's BTF is split: its type ids and string offsets
    go on from the end of its kernel's, the `base`, so its types and strings follow the base's."""

    def __init__(self, blob, base=None):
        magic, version, _flags, header, type_off, type_len, str_off, str_len = struct.unpack_from("<HBBIIIII", blob)
        if magic != MAGIC or version != 1:
            raise ValueError("not little-endian BTF")
        self.strings = (base.strings if base else b"") + blob[header + str_off : header + str_off + str_len]
        self.types = list(base.types) if base else [(0, 0, 0, b"", 0)]
        # The first id this blob defines, so that a module lists its own functions only.
        self.first = len(self.types)
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
        for kind, info, proto, _, name_off in self.types[self.first :]:
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
                return POINTER_SIZED[self.type_name(id)]
            id = self.types[id][2]
        kind, info, size, trailer, _ = self.types[id]
        if id == 0:
            return "void"
        if kind == PTR:
            target = self.strip(size)
            pointee = self.spell(target) if self.kind(target) in (INT, FLOAT, ENUM, ENUM64) else None
            return "void *" if pointee is None else pointee + " *"
        if kind in (ENUM, ENUM64):
            return integer(max(size, 1), bool(info >> 31))
        if kind == FLOAT:
            return f"float{size}"
        if kind == INT:
            code = BUILTIN.get(self.type_name(id))
            if code in ("l", "m"):
                return "long" if code == "l" else "ulong"
            return integer(size, bool(struct.unpack("<I", trailer)[0] >> 24 & INT_SIGNED), code)
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


def module(path, kernel):
    """A module's BTF, read on top of its kernel's, and the names it exports: its `__ksymtab_`
    symbols."""
    with open(path, "rb") as file:
        data = file.read()
    if data[:6] != b"\x7fELF\x02\x01":
        raise ValueError(f"{path}: not a little-endian 64-bit ELF")
    sections_at, = struct.unpack_from("<Q", data, 0x28)
    size, count, names_index = struct.unpack_from("<HHH", data, 0x3A)
    sections = [struct.unpack_from("<IIQQQQIIQQ", data, sections_at + index * size) for index in range(count)]
    contents = [data[offset : offset + length] for _, _, _, _, offset, length, *_ in sections]

    def string(table, at):
        return table[at : table.index(b"\0", at)].decode()

    by_name = {string(contents[names_index], section[0]): index for index, section in enumerate(sections)}
    symbols = by_name[".symtab"]
    names = contents[sections[symbols][6]]
    exported = set()
    for name, *_ in struct.iter_unpack("<IBBHQQ", contents[symbols]):
        symbol = string(names, name)
        if symbol.startswith("__ksymtab_"):
            exported.add(symbol[len("__ksymtab_") :])
    return Btf(contents[by_name[".BTF"]], kernel), exported


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


def integer(size, signed, code=None):
    """How both tables spell an integer or an enum of `size` bytes: `_Bool` and `char` by name
    where their builtin `code` is known, and any other by its width and sign."""
    return {"b": "bool", "c": "char"}.get(code, f"{'int' if signed else 'uint'}{size}")


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
    hash knows an integer's width and sign and no more, so only the plain spelling says `bool`, and
    the normalized one says `char` only for a 1-byte unsigned integer pointed to. That one is a
    guess: the decompiler prints a string literal only through a `char` pointer, and a `u8` buffer
    typed `char *` still prints as bytes unless it points at string data."""
    kind = type[0]
    if kind == "qual":
        return spell(type[2], normalized, pointed_to)
    if kind == "void":
        return "void"
    if kind == "int":
        _, code, size, signed = type
        if normalized and pointed_to and size == 1 and not signed:
            return "char"
        return integer(size, signed, None if normalized else code)
    if kind == "float":
        return f"float{type[2]}"
    if kind == "enum":
        return integer(type[2], type[3])
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


def written(path):
    """The lines of a file of prototypes written by hand, by name."""
    with open(path) as file:
        lines = [line.rstrip("\n") for line in file if line.startswith("- ")]
    return {line.split("(")[0].rsplit(" ", 1)[-1].lstrip("*"): line for line in lines}


def main():
    if sys.argv[1:2] == ["--kcfi"]:
        return kcfi_main(sys.argv[2:])
    args, headers = sys.argv[1:], None
    if args[-2:-1] == ["--headers"]:
        args, headers = args[:-2], args[-1]
    lines = {}
    while args:
        if args[0] == "--modules":
            modules = sorted(os.path.join(args[1], name) for name in os.listdir(args[1]) if name.endswith(".ko"))
            sources, args = [module(path, btf) for path in modules], args[2:]
        else:
            with open(args[0], "rb") as file:
                btf = Btf(find_btf(file.read()))
            sources, args = [(btf, exports(args[1]))], args[2:]
        for source, exported in sources:
            for name, line in table(source, exported).items():
                lines.setdefault(name, line)
    for name, line in (written(headers) if headers else {}).items():
        lines.setdefault(name, line)
    for name in sorted(lines):
        print(lines[name])


if __name__ == "__main__":
    main()
