"""Reads the files of the ramdisks in an Android vendor_boot image.

`ramdisk_files(f, suffix)` yields (path, bytes) of each regular file whose name ends in
`suffix` in every ramdisk of a vendor_boot image of header version 3 or 4, opened for reading
in binary. A ramdisk is an LZ4 stream of the legacy format holding cpio "newc" archives. Every size the
image gives is checked against it, and a ramdisk inflates to at most MAX_RAMDISK, or raises
ValueError. The format is AOSP's system/tools/mkbootimg.
"""
import ctypes, re, stat, struct

from erofs import LZ4

MAX_RAMDISK = 1 << 30
LZ4_LEGACY, LZ4_LEGACY_BLOCK = 0x184C2102, 8 << 20


def lz4_legacy(data):
    """The bytes of an LZ4 stream of the legacy format, which `lz4 -l` writes."""
    if data[:4] != struct.pack("<I", LZ4_LEGACY):
        raise ValueError(f"a ramdisk that is no LZ4 legacy stream: {data[:4].hex()}")
    out, pos = bytearray(), 4
    dst = ctypes.create_string_buffer(LZ4_LEGACY_BLOCK)
    while pos + 4 <= len(data):
        size, = struct.unpack_from("<I", data, pos)
        pos += 4
        if size == LZ4_LEGACY:
            continue  # the next of concatenated streams
        if size == 0 or pos + size > len(data):
            raise ValueError(f"an LZ4 block of {size} bytes at {pos}")
        n = LZ4.LZ4_decompress_safe(data[pos:pos + size], dst, size, LZ4_LEGACY_BLOCK)
        if n < 0:
            raise ValueError(f"the LZ4 block at {pos} does not decode")
        out += dst.raw[:n]
        if len(out) > MAX_RAMDISK:
            raise ValueError("a ramdisk inflates past its cap")
        pos += size
    return bytes(out)


def cpio(data):
    """Yields (path, mode, bytes) of each entry of concatenated cpio "newc" archives."""
    pos = 0
    while pos + 110 <= len(data):
        if data[pos:pos + 6] not in (b"070701", b"070702"):
            if data[pos:].strip(b"\0"):
                raise ValueError(f"no cpio header at {pos}")
            return
        # int(x, 16) alone would take a sign, spaces or `_`, and a negative size loops.
        if not re.fullmatch(rb"[0-9a-fA-F]{104}", data[pos + 6:pos + 110]):
            raise ValueError(f"a cpio header at {pos} with a field of other than eight hex digits")
        fields = [int(data[pos + 6 + 8 * k:pos + 14 + 8 * k], 16) for k in range(13)]
        mode, filesize, namesize = fields[1], fields[6], fields[11]
        name_at = pos + 110
        data_at = (name_at + namesize + 3) & ~3
        end = data_at + filesize
        if namesize == 0 or end > len(data):
            raise ValueError(f"a cpio entry at {pos} runs past its archive")
        name = data[name_at:name_at + namesize - 1].decode()
        pos = (end + 3) & ~3
        if name == "TRAILER!!!":
            continue
        yield name, mode, data[data_at:end]


def ramdisk_files(f, suffix=""):
    f.seek(0, 2)
    length = f.tell()

    def read(offset, n):
        if offset + n > length:
            raise ValueError(f"{n} bytes at {offset} run past the image")
        f.seek(offset)
        return f.read(n)

    h = read(0, 2128)
    magic, version, page = struct.unpack_from("<8sII", h, 0)
    if magic != b"VNDRBOOT" or version not in (3, 4) or page not in (2048, 4096, 8192, 16384):
        raise ValueError(f"not a vendor_boot image of version 3 or 4: {magic} {version} {page}")
    ramdisk_size, = struct.unpack_from("<I", h, 24)
    header_size, = struct.unpack_from("<I", h, 2096)
    start = -(-header_size // page) * page
    section = read(start, ramdisk_size)
    if version == 3:
        ramdisks = [(0, ramdisk_size)]
    else:
        dtb_size, = struct.unpack_from("<I", h, 2100)
        table_size, entries, entry_size = struct.unpack_from("<III", h, 2112)
        if entry_size < 12 or entries * entry_size > table_size:
            raise ValueError(f"a ramdisk table of {entries} entries of {entry_size} bytes")
        table_at = start + -(-ramdisk_size // page) * page + -(-dtb_size // page) * page
        table = read(table_at, table_size)
        ramdisks = []
        for k in range(entries):
            size, offset = struct.unpack_from("<II", table, k * entry_size)
            if offset + size > ramdisk_size:
                raise ValueError(f"ramdisk {k} runs past the ramdisk section")
            ramdisks.append((offset, size))
    # Entries may overlap, so each ramdisk is cut from the section only when it is read.
    for offset, size in ramdisks:
        for path, mode, data in cpio(lz4_legacy(section[offset:offset + size])):
            if stat.S_ISREG(mode) and path.endswith(suffix):
                yield path, data
