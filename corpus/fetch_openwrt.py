#!/usr/bin/env python3
"""Fetches the OpenWrt release fleet: one root filesystem per release and architecture, unpacked.

Usage: python3 -I corpus/fetch_openwrt.py [pin]
  pin   rewrites corpus/openwrt-images.tsv from OpenWrt's release listing and each target's
        sha256sums, and corpus/openwrt-variants.tsv from the package indexes of the releases the
        variants start from, reading only those text files.
  (no argument) downloads every image the manifest pins, checks its sha256 and unpacks it to
        <corpora>/corpus-openwrt/images/<id>/rootfs, where corpus/store.py names <corpora>.
        A download lands in its own new directory, dl/<id>/. An image already unpacked is skipped.
        Then it builds each variant: a copy of a release image with packages from that release's
        own feed installed over it, as opkg would, with the package database updated to match.

Each release ships its root filesystem as a tarball beside the disk images, so nothing here needs
a firmware unpacker. Nothing downloaded is executed: the tarballs are only read, through Python's
tarfile with its data filter, and absolute symbolic links are rewritten to stay inside the rootfs.
"""
import gzip, hashlib, io, os, re, shutil, sys, tarfile, urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from store import CORPORA  # noqa: E402

RELEASES = "https://downloads.openwrt.org/releases"
MANIFEST = Path(__file__).resolve().parent / "openwrt-images.tsv"
VARIANTS = Path(__file__).resolve().parent / "openwrt-variants.tsv"
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


# Each variant: its release image, the package it replaces and the package from the release's
# feed that replaces it. dnsmasq-full is built with DHCPv6 and DNSSEC, which stock dnsmasq leaves
# out, so the advisories in that code have cells to label.
SWAPS = {
    "18.06.9-armv7-full": ("18.06.9-armv7", "dnsmasq", "dnsmasq-full"),
    "19.07.10-aarch64-full": ("19.07.10-aarch64", "dnsmasq", "dnsmasq-full"),
    "21.02.0-x86_64-full": ("21.02.0-x86_64", "dnsmasq", "dnsmasq-full"),
    "21.02.7-armv7-full": ("21.02.7-armv7", "dnsmasq", "dnsmasq-full"),
    "22.03.2-aarch64-full": ("22.03.2-aarch64", "dnsmasq", "dnsmasq-full"),
    "22.03.7-x86_64-full": ("22.03.7-x86_64", "dnsmasq", "dnsmasq-full"),
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


def feeds(rootfs: Path) -> list[str]:
    """The release's package feeds, as the image itself lists them."""
    conf = (rootfs / "etc/opkg/distfeeds.conf").read_text()
    return [url.replace("http://", "https://", 1) for url in re.findall(r"^src/gz \S+ (\S+)$", conf, re.M)]


def stanzas(index: str) -> dict[str, dict[str, str]]:
    out = {}
    for stanza in index.split("\n\n"):
        fields = dict(re.findall(r"^([\w-]+): (.*)$", stanza, re.M))
        if "Package" in fields:
            out[fields["Package"]] = fields
    return out


def pin_variants() -> None:
    """Pins each swap's package and the libraries it needs that the image lacks, from the feed."""
    rows = []
    for id, (base, old, new) in SWAPS.items():
        rootfs = OUT / "images" / base / "rootfs"
        have = stanzas((rootfs / "usr/lib/opkg/status").read_text())
        index = {}
        for feed in feeds(rootfs):
            packages = gzip.decompress(urllib.request.urlopen(f"{feed}/Packages.gz", timeout=120).read()).decode()
            index |= {name: fields | {"feed": feed} for name, fields in stanzas(packages).items()}
        todo, chosen = [new], []
        while todo:
            name = todo.pop()
            if name in have or name in chosen or name == "libc":
                continue
            chosen.append(name)
            todo += [dep.split()[0] for dep in index[name].get("Depends", "").split(", ") if dep]
        for name in chosen:
            fields = index[name]
            rows.append(f"{id}\t{base}\t{old if name == new else ''}\t{fields['feed']}/{fields['Filename']}\t{fields['SHA256sum']}")
    VARIANTS.write_text("id\tbase\treplaces\turl\tsha256\n" + "\n".join(rows) + "\n")
    print(f"{len(SWAPS)} variants, {len(rows)} packages pinned in {VARIANTS}")


def ipk(path: Path) -> dict[str, bytes]:
    """The members of an .ipk: a gzipped tar or, in later releases, an ar archive."""
    data = path.read_bytes()
    if data[:8] == b"!<arch>\n":
        members, at = {}, 8
        while at < len(data):
            header = data[at : at + 60]
            size = int(header[48:58])
            members[header[:16].decode().strip().rstrip("/").removeprefix("./")] = data[at + 60 : at + 60 + size]
            at += 60 + size + size % 2
        return members
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        return {m.name.removeprefix("./"): tar.extractfile(m).read() for m in tar if m.isfile()}


def install(rootfs: Path, package: Path, replaces: str) -> None:
    """Installs one package over the rootfs and records it in opkg's database."""
    info = rootfs / "usr/lib/opkg/info"
    status = rootfs / "usr/lib/opkg/status"
    entries = status.read_text().split("\n\n")
    if replaces:
        for file in (info / f"{replaces}.list").read_text().split():
            (rootfs / file.lstrip("/")).unlink(missing_ok=True)
        for file in info.glob(f"{replaces}.*"):
            file.unlink()
        entries = [e for e in entries if not re.match(rf"Package: {re.escape(replaces)}$", e, re.M)]
    members = ipk(package)
    with tarfile.open(fileobj=io.BytesIO(members["data.tar.gz"])) as tar:
        files = [m.name.removeprefix(".") for m in tar if not m.isdir()]
        tar.extractall(rootfs, filter=inside)
    with tarfile.open(fileobj=io.BytesIO(members["control.tar.gz"])) as tar:
        control = tar.extractfile("./control").read().decode()
    name = re.search(r"^Package: (.+)$", control, re.M).group(1)
    (info / f"{name}.control").write_text(control)
    (info / f"{name}.list").write_text("".join(f"{f}\n" for f in files))
    kept = "\n".join(line for line in control.strip().splitlines() if re.match(r"(Package|Version|Depends|Architecture):", line))
    entries.insert(-1 if entries and not entries[-1].strip() else len(entries), f"{kept}\nStatus: install user installed")
    status.write_text("\n\n".join(entries))


def variant(id: str, rows: list[tuple[str, ...]]) -> str:
    image = OUT / "images" / id
    if (image / "rootfs").is_dir():
        return f"{id}: already built"
    partial = image / "rootfs.part"
    shutil.rmtree(partial, ignore_errors=True)
    image.mkdir(parents=True, exist_ok=True)
    shutil.copytree(OUT / "images" / rows[0][1] / "rootfs", partial, symlinks=True)
    for _, _, replaces, url, digest in rows:
        install(partial, download(OUT / "dl" / id, url, digest), replaces)
    partial.rename(image / "rootfs")
    return f"{id}: built from {rows[0][1]}"


def download(dl: Path, url: str, digest: str) -> Path:
    dl.mkdir(parents=True, exist_ok=True)
    archive = dl / url.rsplit("/", 1)[1]
    if not archive.exists():
        part = archive.with_suffix(".part")
        urllib.request.urlretrieve(url, part)
        part.rename(archive)
    if hashlib.sha256(archive.read_bytes()).hexdigest() != digest:
        raise SystemExit(f"{archive}: sha256 is not the pinned {digest}")
    return archive


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
    archive = download(OUT / "dl" / id, url, digest)
    partial = image / "rootfs.part"
    shutil.rmtree(partial, ignore_errors=True)
    partial.mkdir(parents=True)
    with tarfile.open(archive) as tar:
        tar.extractall(partial, filter=inside)
    partial.rename(image / "rootfs")
    return f"{id}: unpacked"


def main() -> None:
    if sys.argv[1:] == ["pin"]:
        pin()
        return pin_variants()
    rows = [tuple(line.split("\t")) for line in MANIFEST.read_text().splitlines()[1:]]
    with ThreadPoolExecutor(6) as pool:
        for line in pool.map(fetch, rows):
            print(line)
    variants = {}
    for row in (tuple(line.split("\t")) for line in VARIANTS.read_text().splitlines()[1:]):
        variants.setdefault(row[0], []).append(row)
    for id, rows in variants.items():
        print(variant(id, rows))


if __name__ == "__main__":
    main()
