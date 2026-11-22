#!/usr/bin/env python3
"""Tests payload.py, erofs.py and bootimg.py on small images made here, valid and malformed, and
the download and the cap of fetch_android_kmod.py.

Usage: python3 -I corpus/test_android_readers.py
"""
import bz2, contextlib, ctypes, hashlib, io, lzma, random, signal, struct, sys, tempfile, unittest, zipfile
from compression import zstd
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import bootimg, erofs, fetch_android_kmod, payload  # noqa: E402

BLOCK = 4096


@contextlib.contextmanager
def deadline(seconds=10):
    """Fails code that loops, where a guard against a loop is tested, rather than hang the run."""
    def expire(*_):
        raise TimeoutError(f"still running after {seconds}s")
    previous = signal.signal(signal.SIGALRM, expire)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)


def varint(v):
    out = bytearray()
    while True:
        out.append(v & 0x7F | (0x80 if v > 0x7F else 0))
        v >>= 7
        if not v:
            return bytes(out)


def field(number, value):
    if isinstance(value, int):
        return varint(number << 3) + varint(value)
    return varint(number << 3 | 2) + varint(len(value)) + value


def make_payload(directory, partitions):
    """A zip holding payload.bin with `partitions`, {name: (content, [(type, blob, extents)])},
    each operation's extents [(start block, block count)]."""
    blobs, manifest = bytearray(), field(3, BLOCK)
    for name, (content, ops) in partitions.items():
        p = field(1, name.encode()) + field(7, field(1, len(content)) + field(2, hashlib.sha256(content).digest()))
        for kind, blob, extents in ops:
            op = field(1, kind) + field(2, len(blobs)) + field(3, len(blob))
            op += b"".join(field(6, field(1, s) + field(2, n)) for s, n in extents)
            op += field(8, hashlib.sha256(blob).digest())
            p += field(8, op)
            blobs += blob
        manifest += field(13, p)
    body = b"CrAU" + struct.pack(">QQI", 2, len(manifest), 0) + manifest + blobs
    path = directory / "ota.zip"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_STORED) as z:
        z.writestr("payload.bin", body)
    return path


class Payload(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.content = bytes(range(256)) * 16 * 4 + b"\0" * BLOCK + b"x" * BLOCK * 4

    def tearDown(self):
        self.tmp.cleanup()

    def ops(self):
        c = self.content
        return [
            (0, c[:BLOCK], [(0, 1)]),
            (1, bz2.compress(c[BLOCK:2 * BLOCK]), [(1, 1)]),
            (8, lzma.compress(c[2 * BLOCK:4 * BLOCK]), [(2, 2)]),
            (6, b"", [(4, 1)]),
            (14, zstd.compress(c[5 * BLOCK:]), [(5, 2), (7, 2)]),
        ]

    def extract(self, partitions, names=("vendor_dlkm",)):
        return payload.extract(make_payload(self.dir, partitions), self.dir / "out", set(names))

    def test_reads_every_full_ota_operation(self):
        out = self.extract({"boot": (b"b" * BLOCK, [(0, b"b" * BLOCK, [(0, 1)])]), "vendor_dlkm": (self.content, self.ops())})
        self.assertEqual(out["vendor_dlkm"].read_bytes(), self.content)
        self.assertFalse((self.dir / "out" / "boot.img").exists())

    def refuses(self, message, ops, content=None, error=ValueError):
        with self.assertRaisesRegex(error, message):
            self.extract({"vendor_dlkm": (self.content if content is None else content, ops)})
        self.assertEqual(list((self.dir / "out").iterdir()), [])

    def test_refuses_an_operation_of_a_delta_ota(self):
        self.refuses("not one of a full OTA", self.ops() + [(4, b"", [(0, 1)])])

    def test_refuses_a_partition_whose_hash_differs(self):
        self.refuses("hash does not match", self.ops(), self.content[:-1] + b"y")

    def test_refuses_an_extent_past_the_partition(self):
        self.refuses("runs past the partition", self.ops()[:-1] + [(0, self.content[5 * BLOCK:], [(5, 2), (1 << 18, 2)])])

    def test_refuses_a_blob_that_inflates_past_its_extents(self):
        self.refuses("gives 8193 bytes for 8192", self.ops()[:2] + [(8, lzma.compress(b"\0" * (16 << 20)), [(2, 2)])])

    def test_refuses_an_lzma_stream_where_xz_is_due(self):
        alone = lzma.compress(self.content[2 * BLOCK:4 * BLOCK], lzma.FORMAT_ALONE)
        self.refuses("format", self.ops()[:2] + [(8, alone, [(2, 2)])] + self.ops()[3:], error=lzma.LZMAError)

    def test_refuses_a_manifest_larger_than_its_cap(self):
        with mock.patch.object(payload, "MAX_MANIFEST", 64):
            self.refuses("a manifest of", self.ops())

    def test_refuses_a_missing_partition(self):
        with self.assertRaises(ValueError):
            self.extract({"vendor_dlkm": (self.content, self.ops())}, ("vendor_dlkm", "vendor_boot"))


def lz4_compress(data):
    lib = erofs.LZ4
    lib.LZ4_compress_default.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int, ctypes.c_int]
    dst = ctypes.create_string_buffer(len(data) + len(data) // 255 + 16)
    n = lib.LZ4_compress_default(data, dst, len(data), len(dst))
    return dst.raw[:n]


class Erofs:
    """Builds an EROFS image: a superblock, inodes in block 1 on, data blocks after them."""

    def __init__(self):
        self.meta = bytearray()
        self.blocks = []

    def block(self, data):
        self.blocks.append(data.ljust(BLOCK, b"\0"))
        return 1 + 1 + len(self.blocks) - 1  # superblock, one meta block, then data

    def inode(self, layout, mode, size, u, tail=b""):
        nid = len(self.meta) // 32
        self.meta += struct.pack("<HHHHIIIIHHI", layout << 1, 0, mode, 1, size, 0, u, nid, 0, 0, 0) + tail
        self.meta += b"\0" * (-len(self.meta) % 32)
        return nid

    def directory(self, entries):
        """An inline directory of `entries` [(name, nid, type)], whose nid is returned. A nid of
        None is the directory's own."""
        nid = len(self.meta) // 32
        entries = sorted([(b".", nid, 2), (b"..", nid, 2)] + [(n.encode(), nid if c is None else c, t) for n, c, t in entries])
        names, heads = b"", b""
        start = 12 * len(entries)
        for name, child, t in entries:
            heads += struct.pack("<QHBB", child, start + len(names), t, 0)
            names += name
        content = heads + names
        return self.inode(2, 0o40755, len(content), 0xFFFFFFFF, content)

    def compressed(self, data):
        """A file of LZ4 in one block, indexed fully, with zero padding."""
        packed = lz4_compress(data)
        pblk = self.block(packed.rjust(BLOCK, b"\0"))
        nid = len(self.meta) // 32
        end = 1 * BLOCK + nid * 32 + 32
        header = b"\0" * ((-end) % 8) + struct.pack("<HHHBB", 0, 0, 0, 0, 0) + b"\0" * 8
        index = struct.pack("<HHI", 1, 0, pblk)
        for k in range(1, -(-len(data) // BLOCK)):
            index += struct.pack("<HHHH", 2, 0, k, 0)
        return self.inode(1, 0o100644, len(data), 0, header + index)

    def compact(self, data, pclusters, advise, override=None):
        """A file of `data` in LZ4 with compact indexes, of 2 bytes where `advise` says so, and
        zero padding. `pclusters` [(lclusters, blocks)] cover the file in order, each compressed
        into its blocks. `override` {lcn: (type, lo)} replaces index entries. Each pack of the
        index starts at a head here, so its base is that head's block, less one without big
        pclusters, as unpack_compacted_index then counts the head's own block."""
        big = advise & erofs.ADVISE_BIG_PCLUSTER_1
        entries, pblk, la = [], {}, 0
        for lclusters, blocks in pclusters:
            packed = lz4_compress(data[la:la + lclusters * BLOCK])
            assert len(packed) <= blocks * BLOCK and (big or blocks == 1)
            packed = packed.rjust(blocks * BLOCK, b"\0")
            pblk[len(entries)] = self.block(packed[:BLOCK])
            for k in range(1, blocks):
                self.block(packed[k * BLOCK:(k + 1) * BLOCK])
            entries.append((erofs.HEAD1, 0))
            for d in range(1, lclusters):
                first = big and d == 1
                entries.append((erofs.NONHEAD, erofs.D0_CBLKCNT | blocks if first else d))
            la += lclusters * BLOCK
        assert len(entries) == -(-len(data) // BLOCK)
        entries = [(override or {}).get(lcn, e) for lcn, e in enumerate(entries)]
        nid = len(self.meta) // 32
        hpos = -(-(BLOCK + nid * 32 + 32) // 8) * 8
        ebase = hpos + 8
        init4 = (32 - ebase % 32) // 4 % 8
        two = (len(entries) - init4) // 16 * 16 if advise & erofs.ADVISE_COMPACTED_2B else 0
        index, lcn = b"", 0
        for count, vcnt, pack in ((init4, 2, 8), (two, 16, 32), (len(entries) - init4 - two, 2, 8)):
            for start in range(lcn, lcn + count, vcnt):
                part = entries[start:min(start + vcnt, lcn + count)]
                assert start in pblk, f"the pack at lcluster {start} starts with no head"
                bits = (pack - 4) * 8 // vcnt
                v = sum((lo | t << 12) << (bits * k) for k, (t, lo) in enumerate(part))
                index += v.to_bytes(pack - 4, "little") + struct.pack("<I", pblk[start] - (0 if big else 1))
            lcn += count
        header = b"\0" * (hpos - (BLOCK + nid * 32 + 32)) + struct.pack("<HHHBB", 0, 0, advise, 0, 0)
        return self.inode(erofs.COMPRESSED_COMPACT, 0o100644, len(data), 0, header + index)

    def image(self, root):
        sb = struct.pack("<IIIBBHQQIIII", erofs.MAGIC, 0, 0, 12, 0, root, 0, 0, 0, 0, 1, 0)
        sb = sb.ljust(80, b"\0") + struct.pack("<I", 1)
        head = (b"\0" * 1024 + sb).ljust(BLOCK, b"\0")
        assert len(self.meta) <= BLOCK
        return head + bytes(self.meta).ljust(BLOCK, b"\0") + b"".join(self.blocks)


class ErofsImage(unittest.TestCase):
    plain = bytes(range(256)) * 24
    inline = b"inline module"
    packed = b"kernel module text " * 400

    def build(self, name="c.ko", twice=False):
        e = Erofs()
        a = e.inode(0, 0o100644, len(self.plain), e.block(self.plain[:BLOCK]))
        e.block(self.plain[BLOCK:])
        b = e.inode(2, 0o100644, len(self.inline), 0xFFFFFFFF, self.inline)
        c = e.compressed(self.packed)
        txt = e.inode(2, 0o100644, 5, 0xFFFFFFFF, b"notes")
        lib = e.directory([("a.ko", a, 1), ("b.ko", b, 1), (name, c, 1), ("notes.txt", txt, 1)])
        root = e.directory([("lib", lib, 2)] + ([("lib2", lib, 2)] if twice else []))
        return erofs.Image(io.BytesIO(e.image(root)))

    def test_reads_plain_inline_and_compressed_files(self):
        files = dict(self.build().files(".ko"))
        self.assertEqual(files, {"/lib/a.ko": self.plain, "/lib/b.ko": self.inline, "/lib/c.ko": self.packed})

    def test_refuses_a_name_that_leaves_its_directory(self):
        with self.assertRaises(ValueError):
            list(self.build(name="../c.ko").files())

    def test_refuses_a_directory_reached_twice(self):
        with self.assertRaisesRegex(ValueError, "reached twice"):
            list(self.build(twice=True).files())

    def test_refuses_a_directory_deeper_than_its_cap(self):
        e = Erofs()
        nid = e.directory([])
        for _ in range(3):
            nid = e.directory([("d", nid, 2)])
        with mock.patch.object(erofs, "MAX_DEPTH", 2), self.assertRaisesRegex(ValueError, "deeper than 2"):
            list(erofs.Image(io.BytesIO(e.image(nid))).files())

    def test_refuses_an_unknown_i_format_bit(self):
        e = Erofs()
        b = e.inode(2, 0o100644, len(self.inline), 0xFFFFFFFF, self.inline)
        e.meta[b * 32] |= 0x10
        root = e.directory([("b.ko", b, 1)])
        with self.assertRaisesRegex(ValueError, "i_format 0x14"):
            list(erofs.Image(io.BytesIO(e.image(root))).files())

    def test_refuses_extra_devices(self):
        image = bytearray(self.image_of_one_inline_file())
        image[1024 + 86] = 1
        with self.assertRaisesRegex(ValueError, "1 extra devices"):
            erofs.Image(io.BytesIO(bytes(image)))

    def image_of_one_inline_file(self):
        e = Erofs()
        b = e.inode(2, 0o100644, len(self.inline), 0xFFFFFFFF, self.inline)
        return e.image(e.directory([("b.ko", b, 1)]))

    def test_refuses_an_inline_tail_that_crosses_a_block(self):
        e = Erofs()
        last = (BLOCK - 64) // 32
        root = e.directory([("t.ko", last, 1)])
        e.meta += b"\0" * (BLOCK - 64 - len(e.meta))
        self.assertEqual(e.inode(2, 0o100644, 100, 0xFFFFFFFF, b"t" * 32), last)
        e.block(b"t" * 68)
        with self.assertRaisesRegex(ValueError, "crosses a block"):
            list(erofs.Image(io.BytesIO(e.image(root))).files())

    def test_refuses_a_file_larger_than_its_cap(self):
        e = Erofs()
        big = e.inode(0, 0o100644, erofs.MAX_FILE + 1, 0)
        root = e.directory([("big.ko", big, 1)])
        with self.assertRaisesRegex(ValueError, rf"inode {big}: {erofs.MAX_FILE + 1} bytes"):
            list(erofs.Image(io.BytesIO(e.image(root))).files())


class CompactIndex(unittest.TestCase):
    """Files indexed compactly, 4-byte entries before and after a run of 2-byte ones, with and
    without big pclusters, as Android's images are. The file is the first inode, so 6 entries
    of 4 bytes come first, then 16 of 2, then 4 of 4."""
    text = b"".join(b"kernel module %04d text " % (k // 40) for k in range(5000))[:26 * BLOCK - 100]
    noise = random.Random(1).randbytes(5000)
    # Two pclusters take 5000 bytes of noise each, which LZ4 cannot fit in one block.
    data = noise + text[5000:6 * BLOCK] + noise + text[6 * BLOCK + 5000:]
    small = [(2, 1), (1, 1), (1, 1), (2, 1), (3, 1), (1, 1), (4, 1), (2, 1), (3, 1), (3, 1), (2, 1), (1, 1), (1, 1)]
    big = [(2, 2), (1, 1), (1, 1), (2, 1), (3, 2), (1, 1), (2, 1), (4, 1), (1, 1), (5, 1), (2, 1), (1, 1), (1, 1)]

    def read(self, data, pclusters, advise, override=None):
        e = Erofs()
        f = e.compact(data, pclusters, advise, override)
        return dict(erofs.Image(io.BytesIO(e.image(e.directory([("m.ko", f, 1)])))).files())

    def test_reads_compact_indexes(self):
        self.assertEqual(self.read(self.text, self.small, erofs.ADVISE_COMPACTED_2B), {"/m.ko": self.text})

    def test_reads_big_pclusters(self):
        advise = erofs.ADVISE_COMPACTED_2B | erofs.ADVISE_BIG_PCLUSTER_1
        self.assertEqual(self.read(self.data, self.big, advise), {"/m.ko": self.data})

    def test_refuses_a_big_pcluster_delta_that_walks_back_forever(self):
        # Lcluster 8 is the last of the pcluster of 3 at 6, and 9 a head that walks back over it.
        advise = erofs.ADVISE_COMPACTED_2B | erofs.ADVISE_BIG_PCLUSTER_1
        for delta in (0, 1):
            with deadline(), self.assertRaisesRegex(ValueError, f"big pcluster's delta of {delta}"):
                self.read(self.data, self.big, advise, {8: (erofs.NONHEAD, delta)})


def newc(entries):
    out = bytearray()
    for k, (name, mode, data) in enumerate(entries + [("TRAILER!!!", 0, b"")]):
        name = name.encode() + b"\0"
        fields = [k + 1, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(name), 0]
        out += b"070701" + b"".join(b"%08x" % f for f in fields) + name
        out += b"\0" * (-len(out) % 4) + data
        out += b"\0" * (-len(out) % 4)
    return bytes(out)


def lz4_legacy(data, block=1 << 16):
    out = struct.pack("<I", bootimg.LZ4_LEGACY)
    for k in range(0, len(data), block):
        packed = lz4_compress(data[k:k + block])
        out += struct.pack("<I", len(packed)) + packed
    return out


def vendor_boot(ramdisks, table_size=None, page=4096):
    section = b"".join(ramdisks)
    entries, offset = b"", 0
    for r in ramdisks:
        entries += struct.pack("<III", len(r), offset, 1) + b"\0" * 96
        offset += len(r)
    h = struct.pack("<8sIIIII", b"VNDRBOOT", 4, page, 0, 0, len(section)).ljust(2096, b"\0")
    h += struct.pack("<IIQIII", 2128, 0, 0, len(entries) if table_size is None else table_size, len(ramdisks), 108)
    pad = lambda b: b + b"\0" * (-len(b) % page)  # noqa: E731
    return pad(h.ljust(2128, b"\0")) + pad(section) + pad(entries)


class VendorBoot(unittest.TestCase):
    module = bytes(range(256)) * 300
    other = b"other module"

    def ramdisks(self):
        first = newc([("lib", 0o40755, b""), ("lib/modules/a.ko", 0o100644, self.module), ("lib/a.link.ko", 0o120777, b"modules/a.ko")])
        second = newc([("lib/modules/b.ko", 0o100644, self.other), ("init", 0o100755, b"#!")])
        return [lz4_legacy(first), lz4_legacy(second)]

    def test_reads_the_modules_of_every_ramdisk(self):
        files = list(bootimg.ramdisk_files(io.BytesIO(vendor_boot(self.ramdisks())), ".ko"))
        self.assertEqual(files, [("lib/modules/a.ko", self.module), ("lib/modules/b.ko", self.other)])

    def test_reads_a_page_of_8192_bytes(self):
        files = list(bootimg.ramdisk_files(io.BytesIO(vendor_boot(self.ramdisks(), page=8192)), ".ko"))
        self.assertEqual(files, [("lib/modules/a.ko", self.module), ("lib/modules/b.ko", self.other)])

    def test_refuses_a_ramdisk_that_inflates_past_its_cap(self):
        with mock.patch.object(bootimg, "MAX_RAMDISK", 1000), self.assertRaisesRegex(ValueError, "past its cap"):
            list(bootimg.ramdisk_files(io.BytesIO(vendor_boot(self.ramdisks()))))

    def test_refuses_a_cpio_entry_past_its_archive(self):
        archive = bytearray(newc([("a.ko", 0o100644, self.other)]))
        archive[6 + 8 * 6:6 + 8 * 7] = b"%08x" % 0x1000
        with self.assertRaisesRegex(ValueError, "runs past its archive"):
            list(bootimg.cpio(bytes(archive)))

    def test_refuses_a_cpio_field_of_other_than_eight_hex_digits(self):
        # A size of -112 would point the next header back at this one.
        archive = bytearray(newc([("a", 0o100644, b"")]))
        archive[6 + 8 * 6:6 + 8 * 7] = b"-0000070"
        with deadline(), self.assertRaisesRegex(ValueError, "eight hex digits"):
            list(bootimg.cpio(bytes(archive)))

    def test_refuses_a_ramdisk_past_its_section(self):
        first, second = self.ramdisks()
        image = bytearray(vendor_boot([first, second]))
        second_entry = 4096 + -(-(len(first) + len(second)) // 4096) * 4096 + 108
        image[second_entry:second_entry + 4] = struct.pack("<I", len(second) + 1)
        with self.assertRaises(ValueError):
            list(bootimg.ramdisk_files(io.BytesIO(bytes(image))))

    def test_refuses_a_truncated_lz4_block(self):
        first, _ = self.ramdisks()
        with self.assertRaises(ValueError):
            list(bootimg.ramdisk_files(io.BytesIO(vendor_boot([first[:-10]]))))


class Fetch(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_a_download_with_other_bytes_gets_no_name(self):
        source = self.dir / "src" / "ota.zip"
        source.parent.mkdir()
        source.write_bytes(b"not the pinned zip")
        with self.assertRaisesRegex(SystemExit, "sha256"):
            fetch_android_kmod.download(source.as_uri(), self.dir / "pkgs", "x-ota", "0" * 64)
        self.assertEqual(list((self.dir / "pkgs" / "x-ota").iterdir()), [])

    def phone(self, cap):
        """phone() on images made here: a module in vendor_dlkm, and in the ramdisk a copy of it,
        another module and a signed one."""
        images = self.dir / "pkgs" / "p"
        images.mkdir(parents=True)
        e = Erofs()
        a = e.inode(2, 0o100644, 4, 0xFFFFFFFF, b"dlkm")
        (images / "vendor_dlkm.img").write_bytes(e.image(e.directory([("a.ko", a, 1)])))
        ramdisk = newc([("a.ko", 0o100644, b"ramdisk"), ("b.ko", 0o100644, b"b"), ("c.ko", 0o100644, b"c" + fetch_android_kmod.SIGNED)])
        (images / "vendor_boot.img").write_bytes(vendor_boot([lz4_legacy(ramdisk)]))
        with mock.patch.dict(fetch_android_kmod.PHONES, p=("unused", "0" * 64)), mock.patch.object(fetch_android_kmod, "MAX_PHONE_MODULES", cap):
            return fetch_android_kmod.phone("p", self.dir / "pkgs")

    def test_a_phone_takes_vendor_dlkm_s_copy_and_leaves_out_a_signed_module(self):
        self.assertEqual(self.phone(1 << 20), {"a": b"dlkm", "b": b"b"})

    def test_refuses_a_phone_with_more_modules_than_its_cap(self):
        with self.assertRaisesRegex(SystemExit, "more than 40 bytes"):
            self.phone(40)


if __name__ == "__main__":
    unittest.main()
