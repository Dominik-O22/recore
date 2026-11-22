"""Reads the regular files of an EROFS image, following the kernel's fs/erofs (v6.12).

`Image(f).files(suffix)` yields (path, bytes) of each regular file whose name ends in `suffix`,
from an image opened for reading in binary. Plain, inline and LZ4-compressed files are read,
with full or compact indexes, big pclusters and tail packing. LZ4 is the system's liblz4.
Anything else, such as fragments, chunked files or another algorithm, raises ValueError, as does
any offset, size or name the image gives that would read past it, loop, or leave the tree.
"""
import ctypes, ctypes.util, stat, struct

MAGIC = 0xE0F5E1E2
# Larger than any file read here: modules are at most a few MB, directories a few KB.
MAX_FILE = 256 << 20
MAX_DEPTH = 32
INCOMPAT_ZERO_PADDING = 0x1
# The version bit and the three of the data layout (EROFS_I_ALL).
I_FORMAT_BITS = 0xF
PLAIN, HEAD1, NONHEAD, HEAD2 = 0, 1, 2, 3
FLAT_PLAIN, COMPRESSED_FULL, FLAT_INLINE, COMPRESSED_COMPACT = 0, 1, 2, 3
ADVISE_COMPACTED_2B, ADVISE_BIG_PCLUSTER_1, ADVISE_BIG_PCLUSTER_2 = 0x1, 0x2, 0x4
ADVISE_INLINE_PCLUSTER, ADVISE_INTERLACED_PCLUSTER, ADVISE_FRAGMENT_PCLUSTER = 0x8, 0x10, 0x20
D0_CBLKCNT = 1 << 11
ALG_LZ4 = 0


def load_lz4():
    name = ctypes.util.find_library("lz4")
    if name is None:
        raise OSError("liblz4 is not installed")
    lib = ctypes.CDLL(name)
    lib.LZ4_decompress_safe.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int, ctypes.c_int]
    lib.LZ4_decompress_safe_partial.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int, ctypes.c_int, ctypes.c_int]
    return lib


LZ4 = load_lz4()


class Image:
    def __init__(self, f):
        self.f = f
        f.seek(0, 2)
        self.length = f.tell()
        sb = self.read(1024, 128)
        magic, = struct.unpack_from("<I", sb, 0)
        if magic != MAGIC:
            raise ValueError(f"not EROFS: magic {magic:#x}")
        self.blkbits = sb[12]
        if not 9 <= self.blkbits <= 16:
            raise ValueError(f"block size 2^{self.blkbits}")
        self.blksz = 1 << self.blkbits
        self.root, = struct.unpack_from("<H", sb, 14)
        self.meta, = struct.unpack_from("<I", sb, 40)
        self.incompat, = struct.unpack_from("<I", sb, 80)
        if self.incompat & ~0x7F:
            raise ValueError(f"incompatible features {self.incompat:#x}")
        self.zero_padding = bool(self.incompat & INCOMPAT_ZERO_PADDING)
        extra_devices, = struct.unpack_from("<H", sb, 86)
        if extra_devices:
            raise ValueError(f"{extra_devices} extra devices")

    def read(self, offset, n):
        if n == 0:
            return b""  # an inline file without a full block has no block address
        if offset < 0 or n < 0 or offset + n > self.length:
            raise ValueError(f"{n} bytes at {offset} run past the image")
        self.f.seek(offset)
        return self.f.read(n)

    def inode(self, nid):
        iloc = self.meta * self.blksz + nid * 32
        h = self.read(iloc, 32)
        fmt, xcount, mode = struct.unpack_from("<HHH", h, 0)
        if fmt & ~I_FORMAT_BITS:
            raise ValueError(f"inode {nid}: i_format {fmt:#x}")
        if fmt & 1:
            h = self.read(iloc, 64)
            size, = struct.unpack_from("<Q", h, 8)
        else:
            size, = struct.unpack_from("<I", h, 8)
        u, = struct.unpack_from("<I", h, 16)
        if size > MAX_FILE:
            raise ValueError(f"inode {nid}: {size} bytes")
        isize = 64 if fmt & 1 else 32
        xsize = 12 + 4 * (xcount - 1) if xcount else 0
        return dict(nid=nid, layout=(fmt >> 1) & 7, mode=mode, size=size, u=u, end=iloc + isize + xsize)

    def data(self, ino):
        layout, size = ino["layout"], ino["size"]
        if layout == FLAT_PLAIN:
            return self.read(ino["u"] * self.blksz, size)
        if layout == FLAT_INLINE:
            full = size // self.blksz * self.blksz
            if ino["end"] % self.blksz + size - full > self.blksz:
                raise ValueError(f"inode {ino['nid']}: its inline tail crosses a block")
            return self.read(ino["u"] * self.blksz, full) + self.read(ino["end"], size - full)
        if layout in (COMPRESSED_FULL, COMPRESSED_COMPACT):
            return Compressed(self, ino).data()
        raise ValueError(f"inode {ino['nid']}: layout {layout} is not read")

    def entries(self, ino):
        """Yields (name, nid) of each entry of the directory `ino` but . and .."""
        d = self.data(ino)
        for b in range(0, len(d), self.blksz):
            blk = d[b:b + self.blksz]
            first = struct.unpack_from("<H", blk, 8)[0] if len(blk) >= 12 else 0
            if first < 12 or first % 12 or first > len(blk):
                raise ValueError(f"directory {ino['nid']}: a block's first name at {first}")
            offsets = [struct.unpack_from("<QH", blk, 12 * k) for k in range(first // 12)]
            for k, (nid, nameoff) in enumerate(offsets):
                end = offsets[k + 1][1] if k + 1 < len(offsets) else len(blk)
                if not first <= nameoff < end <= len(blk):
                    raise ValueError(f"directory {ino['nid']}: a name at {nameoff} to {end}")
                name = blk[nameoff:end].split(b"\0")[0]
                if name in (b".", b".."):
                    continue
                if not name or b"/" in name:
                    raise ValueError(f"directory {ino['nid']}: the name {name!r}")
                yield name.decode(), nid

    def files(self, suffix=""):
        """Yields (path, bytes) of every regular file below the root whose name ends in `suffix`."""
        seen = set()

        def walk(directory, path, depth):
            if directory["nid"] in seen:
                raise ValueError(f"directory {directory['nid']} at {path or '/'} is reached twice")
            if depth > MAX_DEPTH:
                raise ValueError(f"directory {directory['nid']} at {path} is deeper than {MAX_DEPTH}")
            seen.add(directory["nid"])
            for name, nid in self.entries(directory):
                ino = self.inode(nid)
                p = f"{path}/{name}"
                if stat.S_ISDIR(ino["mode"]):
                    yield from walk(ino, p, depth + 1)
                elif stat.S_ISREG(ino["mode"]) and name.endswith(suffix):
                    yield p, self.data(ino)

        root = self.inode(self.root)
        if not stat.S_ISDIR(root["mode"]):
            raise ValueError("the root is no directory")
        yield from walk(root, "", 0)


class Compressed:
    """A compressed file: its map header, its index of logical clusters, and its pclusters."""

    def __init__(self, img, ino):
        self.img, self.ino = img, ino
        hpos = (ino["end"] + 7) & ~7
        h = img.read(hpos, 8)
        self.idata_size, self.advise = struct.unpack_from("<HH", h, 2)
        self.algs = (h[6] & 15, h[6] >> 4)
        if h[7] & 0x80 or self.advise & ADVISE_FRAGMENT_PCLUSTER:
            raise ValueError(f"inode {ino['nid']}: fragments are not read")
        self.lbits = img.blkbits + (h[7] & 7)
        self.compact = ino["layout"] == COMPRESSED_COMPACT
        # Compact indexes follow the header; full ones leave 8 more bytes (Z_EROFS_FULL_INDEX_ALIGN).
        self.ebase = hpos + 8 if self.compact else hpos + 16
        self.total = -(-ino["size"] // img.blksz)

    def load(self, lcn):
        """(type, clusterofs, pblk, compressedblks, nextpackoff) of logical cluster `lcn`."""
        L = 1 << self.lbits
        if not self.compact:
            pos = self.ebase + lcn * 8
            advise, clusterofs, u = struct.unpack("<HHI", self.img.read(pos, 8))
            t = advise & 3
            if t == NONHEAD:
                d0 = u & 0xFFFF
                return t, L, 0, d0 & ~D0_CBLKCNT if d0 & D0_CBLKCNT else 0, pos + 8
            return t, clusterofs, u, 0, pos + 8
        init4 = (32 - self.ebase % 32) // 4 % 8
        two = (self.total - init4) // 16 * 16 if self.advise & ADVISE_COMPACTED_2B and init4 < self.total else 0
        pos, rel, shift = self.ebase, lcn, 2
        if rel >= init4:
            pos, rel = pos + init4 * 4, rel - init4
            if rel < two:
                shift = 1
            else:
                pos, rel = pos + two * 2, rel - two
        return self.unpack(shift, pos + (rel << shift))

    def unpack(self, shift, pos):
        """A compact index entry, as unpack_compacted_index reads it."""
        if shift == 2 and self.lbits <= 14:
            vcnt = 2
        elif shift == 1 and self.lbits <= 12:
            vcnt = 16
        else:
            raise ValueError(f"inode {self.ino['nid']}: compact index of {1 << shift} bytes for 2^{self.lbits}")
        pack = vcnt << shift
        start = pos // pack * pack
        buf = self.img.read(start, pack)
        nextpack = start + pack
        lobits = max(self.lbits, 12)
        enc = (pack - 4) * 8 // vcnt
        i = (pos - start) >> shift

        def bits(k):
            p = enc * k
            v = int.from_bytes(buf[p // 8:p // 8 + 4].ljust(4, b"\0"), "little") >> (p & 7)
            return v & ((1 << lobits) - 1), (v >> lobits) & 3

        lo, t = bits(i)
        if t == NONHEAD:
            return t, 1 << self.lbits, 0, lo & ~D0_CBLKCNT if lo & D0_CBLKCNT else 0, nextpack
        big = self.advise & ADVISE_BIG_PCLUSTER_1
        nblk = 0 if big else 1
        while i > 0:
            i -= 1
            lo2, t2 = bits(i)
            if not big:
                if t2 == NONHEAD:
                    i -= lo2
                if i >= 0:
                    nblk += 1
            elif t2 == NONHEAD:
                if lo2 & D0_CBLKCNT:
                    i -= 1
                    nblk += lo2 & ~D0_CBLKCNT
                elif lo2 <= 1:
                    raise ValueError(f"inode {self.ino['nid']}: a big pcluster's delta of {lo2}")
                else:
                    i -= lo2 - 2
            else:
                nblk += 1
        base, = struct.unpack_from("<I", buf, pack - 4)
        return t, lo, base + nblk, 0, nextpack

    def data(self):
        img, size, L = self.img, self.ino["size"], 1 << self.lbits
        ents = [self.load(lcn) for lcn in range(-(-size // L))]
        if ents and ents[0][0] == NONHEAD:
            raise ValueError(f"inode {self.ino['nid']}: the first logical cluster is no head")
        heads = []
        for lcn, (t, clusterofs, *_) in enumerate(ents):
            if t != NONHEAD:
                if clusterofs >= L:
                    raise ValueError(f"inode {self.ino['nid']}: cluster offset {clusterofs}")
                heads.append((lcn << self.lbits | clusterofs, lcn))
        out = bytearray(size)
        for k, (la, lcn) in enumerate(heads):
            end = heads[k + 1][0] if k + 1 < len(heads) else size
            llen = min(end, size) - la
            if llen <= 0:
                continue
            t, _, pblk = ents[lcn][:3]
            if self.advise & ADVISE_INLINE_PCLUSTER and k == len(heads) - 1:
                raw = img.read(ents[-1][4], self.idata_size)
            else:
                big = self.advise & (ADVISE_BIG_PCLUSTER_1 if t == HEAD1 else ADVISE_BIG_PCLUSTER_2)
                blocks = 1
                if big and lcn + 1 < len(ents) and ents[lcn + 1][0] == NONHEAD and ents[lcn + 1][3]:
                    blocks = ents[lcn + 1][3]
                raw = img.read(pblk << img.blkbits, blocks << img.blkbits)
            if t == PLAIN:
                if self.advise & ADVISE_INTERLACED_PCLUSTER:
                    o = la % img.blksz
                    raw = raw[o:] + raw[:o]
                if len(raw) < llen:
                    raise ValueError(f"inode {self.ino['nid']}: {len(raw)} plain bytes for {llen}")
                chunk = raw[:llen]
            else:
                alg = self.algs[0 if t == HEAD1 else 1]
                if alg != ALG_LZ4:
                    raise ValueError(f"inode {self.ino['nid']}: compression algorithm {alg} is not read")
                src = raw.lstrip(b"\0") if img.zero_padding else raw
                dst = ctypes.create_string_buffer(llen)
                n = LZ4.LZ4_decompress_safe_partial(src, dst, len(src), llen, llen)
                if n != llen:
                    raise ValueError(f"inode {self.ino['nid']}: lz4 gave {n} of {llen} bytes at {la}")
                chunk = dst.raw
            out[la:la + llen] = chunk
        return bytes(out)
