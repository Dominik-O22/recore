#!/usr/bin/env python3
"""Fetches the OpenWrt release fleet: one root filesystem per release and architecture, unpacked.

Usage: python3 -I corpus/fetch_openwrt.py [pin]
  pin   rewrites corpus/openwrt-images.tsv from OpenWrt's release listing and each target's
        sha256sums, reading only those text files.
  (no argument) downloads every image the manifest pins, checks its sha256 and unpacks it to
        <corpora>/corpus-openwrt/images/<id>/rootfs, where corpus/store.py names <corpora>.
        A download lands in its own new directory, dl/<id>/. An image already unpacked is skipped.

Each release ships its root filesystem as a tarball beside the disk images, so nothing here needs
a firmware unpacker. Nothing downloaded is executed: the tarballs are only read, through Python's
tarfile with its data filter, and absolute symbolic links are rewritten to stay inside the rootfs.
"""
import hashlib, os, re, shutil, sys, tarfile, urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from store import CORPORA  # noqa: E402

RELEASES = "https://downloads.openwrt.org/releases"
MANIFEST = Path(__file__).resolve().parent / "openwrt-images.tsv"
OUT = CORPORA / "corpus-openwrt"
# The virtual-machine targets, which build the same packages as the routers of their architecture.
# armvirt split into 32 and 64 in 18.06 and became armsr in 23.05.
TARGETS = {
    "x86/64": "x86_64",
    "armvirt/64": "aarch64",
    "armsr/armv8": "aarch64",
    "armvirt/generic": "armv7",
    "armvirt/32": "armv7",
    "armsr/armv7": "armv7",
}


def text(url: str) -> str | None:
    try:
        return urllib.request.urlopen(url, timeout=60).read().decode()
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None
        raise


def rootfs(release: str, target: str) -> tuple[str, str] | None:
    """The rootfs tarball of a target and its sha256, from the target's sha256sums."""
    sums = text(f"{RELEASES}/{release}/targets/{target}/sha256sums")
    if sums is None:
        return None
    # One per target, under three names over the years; 24.10 on also has a "-targz-" copy.
    found = [(name.lstrip("*"), digest) for digest, name in (line.split() for line in sums.splitlines() if line.strip())
             if name.endswith("rootfs.tar.gz") and "-targz-" not in name]
    assert len(found) == 1, (release, target, found)
    return found[0]


def pin() -> None:
    releases = sorted(set(re.findall(r'href="(\d+\.\d+\.\d+)/"', text(f"{RELEASES}/"))), key=lambda r: tuple(map(int, r.split("."))))
    jobs = [(release, target) for release in releases for target in TARGETS]
    with ThreadPoolExecutor(12) as pool:
        found = list(pool.map(lambda job: (*job, rootfs(*job)), jobs))
    rows = [f"{release}-{TARGETS[target]}\t{RELEASES}/{release}/targets/{target}/{name}\t{digest}"
            for release, target, hit in found if hit for name, digest in [hit]]
    MANIFEST.write_text("id\turl\tsha256\n" + "\n".join(rows) + "\n")
    print(f"{len(rows)} images pinned in {MANIFEST}")


def inside(member: tarfile.TarInfo, path: str) -> tarfile.TarInfo | None:
    """Keeps files, directories and links, with an absolute link made relative to the rootfs."""
    if not (member.isfile() or member.isdir() or member.issym() or member.islnk()):
        return None
    if member.issym() and member.linkname.startswith("/"):
        here = os.path.dirname(os.path.normpath("/" + member.name))
        member = member.replace(linkname=os.path.relpath(member.linkname, here), deep=False)
    return tarfile.data_filter(member, path)


def fetch(row: tuple[str, str, str]) -> str:
    id, url, digest = row
    image = OUT / "images" / id
    if (image / "rootfs").is_dir():
        return f"{id}: already unpacked"
    dl = OUT / "dl" / id
    dl.mkdir(parents=True, exist_ok=True)
    archive = dl / url.rsplit("/", 1)[1]
    if not archive.exists():
        part = archive.with_suffix(".part")
        urllib.request.urlretrieve(url, part)
        part.rename(archive)
    if hashlib.sha256(archive.read_bytes()).hexdigest() != digest:
        raise SystemExit(f"{archive}: sha256 is not the pinned {digest}")
    partial = image / "rootfs.part"
    shutil.rmtree(partial, ignore_errors=True)
    partial.mkdir(parents=True)
    with tarfile.open(archive) as tar:
        tar.extractall(partial, filter=inside)
    partial.rename(image / "rootfs")
    return f"{id}: unpacked"


def main() -> None:
    if sys.argv[1:] == ["pin"]:
        return pin()
    rows = [tuple(line.split("\t")) for line in MANIFEST.read_text().splitlines()[1:]]
    with ThreadPoolExecutor(6) as pool:
        for line in pool.map(fetch, rows):
            print(line)


if __name__ == "__main__":
    main()
