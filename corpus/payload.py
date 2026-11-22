"""Reads partitions out of an Android A/B OTA's payload.bin, in place in the OTA zip.

`extract(zip, outdir, names)` writes <outdir>/<name>.img for each partition named and returns
their paths. It reads only a full OTA's operations, REPLACE, REPLACE_BZ, REPLACE_XZ, ZSTD, ZERO
and DISCARD, and refuses any other. Every length and offset the file gives is checked against
the payload before it is read, a blob is decompressed only to the size its extents give, each
blob's sha256 and each partition's sha256 must match the manifest, and a partition gets its name
only once it matched. The format is system/update_engine/update_metadata.proto of AOSP.
"""
import bz2, hashlib, lzma, re, struct, zipfile
from compression import zstd
from pathlib import Path

BLOCK = 4096
# The manifest and partitions of the phones read here are a few MB and at most a few hundred.
MAX_MANIFEST = 64 << 20
MAX_PARTITION = 2 << 30
REPLACE, ZERO, DISCARD = 0, 6, 7
DECOMPRESSORS = {1: bz2.BZ2Decompressor, 8: lzma.LZMADecompressor, 14: zstd.ZstdDecompressor}


def varint(b, i):
    value = 0
    for shift in range(0, 70, 7):
        if i >= len(b):
            raise ValueError("a varint runs past its message")
        c = b[i]
        i += 1
        value |= (c & 0x7F) << shift
        if c < 0x80:
            return value, i
    raise ValueError("a varint is longer than 10 bytes")


def fields(b):
    """Yields (field number, value) of one protobuf message. A length-delimited value is bytes,
    a fixed-width one too, a varint an int."""
    i = 0
    while i < len(b):
        key, i = varint(b, i)
        number, wire = key >> 3, key & 7
        if wire == 0:
            value, i = varint(b, i)
        else:
            if wire == 2:
                n, i = varint(b, i)
            elif wire in (1, 5):
                n = 8 if wire == 1 else 4
            else:
                raise ValueError(f"wire type {wire}")
            if i + n > len(b):
                raise ValueError("a field runs past its message")
            value, i = b[i:i + n], i + n
        yield number, value


def message(b):
    """The fields of a message whose fields each occur once, by number."""
    return dict(fields(b))


class Payload:
    """payload.bin as it lies, stored, in the zip."""

    def __init__(self, f, zpath):
        self.f = f
        with zipfile.ZipFile(zpath) as z:
            info = z.getinfo("payload.bin")
        if info.compress_type != zipfile.ZIP_STORED:
            raise ValueError("payload.bin is compressed in the zip")
        local = self.read(info.header_offset, 30)
        if local[:4] != b"PK\x03\x04":
            raise ValueError("payload.bin has no local header")
        n, e = struct.unpack_from("<HH", local, 26)
        self.base, self.size = info.header_offset + 30 + n + e, info.file_size
        f.seek(0, 2)
        if self.base + self.size > f.tell():
            raise ValueError("payload.bin runs past the zip")
        magic, version, msize, sigsize = struct.unpack(">4sQQI", self.at(0, 24))
        if magic != b"CrAU" or version != 2:
            raise ValueError(f"not a version 2 payload: {magic} {version}")
        if msize > MAX_MANIFEST:
            raise ValueError(f"a manifest of {msize} bytes")
        self.manifest = self.at(24, msize)
        self.data = 24 + msize + sigsize

    def read(self, offset, n):
        self.f.seek(offset)
        b = self.f.read(n)
        if len(b) != n:
            raise ValueError(f"{n} bytes at {offset} run past the file")
        return b

    def at(self, offset, n):
        """n bytes at `offset` of the payload, which must hold them."""
        if offset + n > self.size:
            raise ValueError(f"{n} bytes at {offset} run past the payload")
        return self.read(self.base + offset, n)


def operation(payload, op, psize, out):
    """Writes one InstallOperation's blocks to `out`."""
    d, extents = {}, []
    for number, value in fields(op):
        if number == 6:
            e = message(value)
            extents.append((e.get(1, 0), e.get(2, 0)))
        else:
            d[number] = value
    kind = d.get(1)
    if kind not in (REPLACE, ZERO, DISCARD, *DECOMPRESSORS):
        raise ValueError(f"operation type {kind} is not one of a full OTA")
    for start, count in extents:
        if (start + count) * BLOCK > -(-psize // BLOCK) * BLOCK:
            raise ValueError(f"extent {start}+{count} runs past the partition")
    if kind in (ZERO, DISCARD):
        return  # the file is zero there already
    size = sum(count for _, count in extents) * BLOCK
    if size > psize + BLOCK or d.get(3, 0) > MAX_PARTITION:
        raise ValueError("an operation larger than its partition")
    blob = payload.at(payload.data + d.get(2, 0), d.get(3, 0))
    if hashlib.sha256(blob).digest() != d.get(8):
        raise ValueError("a blob's hash does not match the manifest")
    if kind == REPLACE:
        raw = blob
    else:
        decompressor = DECOMPRESSORS[kind]()
        raw = decompressor.decompress(blob, max_length=size + 1)
    if len(raw) != size:
        raise ValueError(f"an operation gives {len(raw)} bytes for {size} of extents")
    pos = 0
    for start, count in extents:
        out.seek(start * BLOCK)
        out.write(raw[pos:pos + count * BLOCK])
        pos += count * BLOCK


def extract(zpath, outdir, names):
    """Writes each partition in `names` to <outdir>/<name>.img and returns {name: path}."""
    outdir.mkdir(parents=True, exist_ok=True)
    written = {}
    with open(zpath, "rb") as f:
        payload = Payload(f, zpath)
        manifest = list(fields(payload.manifest))
        block = dict(manifest).get(3, BLOCK)
        if block != BLOCK:
            raise ValueError(f"block size {block}")
        for number, partition in manifest:
            if number != 13:
                continue
            name, ops, info = None, [], {}
            for n, value in fields(partition):
                if n == 1:
                    name = value.decode()
                elif n == 7:
                    info = message(value)
                elif n == 8:
                    ops.append(value)
            if name not in names:
                continue
            if name in written or not re.fullmatch(r"[a-z0-9_]+", name):
                raise ValueError(f"partition {name!r} twice or misnamed")
            psize = info.get(1, 0)
            if psize > MAX_PARTITION:
                raise ValueError(f"{name}: {psize} bytes")
            part = outdir / f"{name}.img.part"
            with open(part, "wb") as out:
                out.truncate(psize)
                for op in ops:
                    operation(payload, op, psize, out)
            h = hashlib.sha256()
            with open(part, "rb") as i:
                while chunk := i.read(1 << 24):
                    h.update(chunk)
            if h.digest() != info.get(2):
                raise ValueError(f"{name}: the partition's hash does not match the manifest")
            written[name] = part.rename(outdir / f"{name}.img")
    if missing := set(names) - written.keys():
        raise ValueError(f"no partition {sorted(missing)} in the payload")
    return written
