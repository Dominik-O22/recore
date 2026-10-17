#!/usr/bin/env python3
"""Copies the binaries the speed comparison runs on into <corpora>/corpus-openwrt/bin, where
ghidra/run-reference.sh and ghidra/speed.py read a corpus: nine daemons and libraries from three
releases on each of the three architectures, named <image>__<file>.

Usage: python3 -I bench/firmware/pick.py
"""
import shutil, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "corpus"))
from store import CORPORA  # noqa: E402

FLEET = CORPORA / "corpus-openwrt"
RELEASES = ["19.07.10", "22.03.7", "24.10.8"]
ARCHES = ["x86_64", "aarch64", "armv7"]
FILES = ["usr/sbin/dnsmasq", "usr/sbin/dropbear", "bin/busybox", "usr/sbin/uhttpd", "usr/sbin/odhcpd",
         "sbin/netifd", "sbin/procd", "lib/libc.so", "lib/libubox.so*"]

out = FLEET / "bin"
out.mkdir(exist_ok=True)
for release in RELEASES:
    for arch in ARCHES:
        rootfs = FLEET / "images" / f"{release}-{arch}" / "rootfs"
        for pattern in FILES:
            # The library's file name carries its ABI date; the real file, not its symlinks.
            path = next(p for p in sorted(rootfs.glob(pattern)) if not p.is_symlink())
            shutil.copyfile(path, out / f"{release}-{arch}__{path.name}")
print(f"{len(list(out.iterdir()))} binaries in {out}")
