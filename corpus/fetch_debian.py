#!/usr/bin/env python3
"""Adds Debian builds to a corpus: stripped executables plus their -dbgsym debug files.

Usage: fetch_debian.py <arch> <corpus-dir>      e.g. amd64 corpus, arm64 corpus-arm64, armhf corpus-armhf
                                                or armel corpus-armel
Writes <corpus-dir>/bin/deb__<pkg>__<name> and <corpus-dir>/debug/deb__<pkg>__<name>.debug.
Debian builds differ from Arch's: calls go through a PLT, and flags and compiler versions differ.
"""
import lzma, re, subprocess, sys, urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

MIRROR = "https://deb.debian.org"
SUITE = "trixie"
MAX_PER_PACKAGE = 8
PACKAGES = """coreutils bash grep sed gawk findutils tar gzip xz-utils zstd curl openssh-client git sqlite3
make diffutils less nano tmux htop jq lua5.4 zsh binutils-common openssl rsync wget file ninja-build cmake re2c
gperf fish ripgrep fd-find bat eza hyperfine""".split()


def index(url):
    """Maps package name to its pool path from a Packages.xz index."""
    text = lzma.decompress(urllib.request.urlopen(url, timeout=180).read()).decode()
    out = {}
    for stanza in text.split("\n\n"):
        name = re.search(r"^Package: (.+)$", stanza, re.M)
        path = re.search(r"^Filename: (.+)$", stanza, re.M)
        if name and path:
            out[name.group(1)] = path.group(1)
    return out


def fetch(base, path, dest_dir):
    dest = dest_dir / Path(path).name
    if not dest.exists():
        tmp = dest.with_suffix(".part")
        urllib.request.urlretrieve(f"{MIRROR}/{base}/{path}", tmp)
        tmp.rename(dest)
    return dest


def unpack(deb, dest):
    """Extracts a .deb's data archive, whatever its compression."""
    dest.mkdir(parents=True, exist_ok=True)
    members = subprocess.run(["ar", "t", deb], capture_output=True, text=True).stdout.split()
    member = next(m for m in members if m.startswith("data.tar"))
    tarball = dest / member
    tarball.write_bytes(subprocess.run(["ar", "p", deb, member], capture_output=True).stdout)
    subprocess.run(["tar", "-xf", tarball, "-C", dest], check=False, stderr=subprocess.DEVNULL)
    tarball.unlink()


def build_id(path):
    out = subprocess.run(["readelf", "-n", path], capture_output=True, text=True).stdout
    m = re.search(r"Build ID: (\w+)", out)
    return m.group(1) if m else None


def process(pkg, arch, corpus, binaries, debugs):
    if pkg not in binaries or f"{pkg}-dbgsym" not in debugs:
        return pkg, "no package or no dbgsym", 0
    pkgs = corpus / "pkgs" / f"deb-{arch}"
    pkgs.mkdir(parents=True, exist_ok=True)
    work = pkgs / "x" / pkg
    unpack(fetch("debian", binaries[pkg], pkgs), work)
    unpack(fetch("debian-debug", debugs[f"{pkg}-dbgsym"], pkgs), work)
    candidates = []
    for directory in ("usr/bin", "usr/sbin", "usr/lib/git-core"):
        for f in sorted((work / directory).glob("*")):
            if f.is_symlink() or not f.is_file() or not re.fullmatch(r"[\w.+-]+", f.name) or f.read_bytes()[:4] != b"\x7fELF":
                continue
            bid = build_id(f)
            debug = work / "usr/lib/debug/.build-id" / bid[:2] / f"{bid[2:]}.debug" if bid else None
            if debug and debug.exists():
                candidates.append((f.stat().st_size, f, debug))
    candidates.sort()
    step = max(1, len(candidates) // MAX_PER_PACKAGE)
    kept = candidates[::step][-MAX_PER_PACKAGE:] if len(candidates) > MAX_PER_PACKAGE else candidates
    for _, f, debug in kept:
        name = f"deb__{pkg}__{f.name}"
        (corpus / "bin" / name).write_bytes(f.read_bytes())
        (corpus / "debug" / f"{name}.debug").write_bytes(debug.read_bytes())
    return pkg, "ok", len(kept)


def main():
    arch, corpus = sys.argv[1], Path(sys.argv[2])
    for d in ("bin", "debug"):
        (corpus / d).mkdir(parents=True, exist_ok=True)
    binaries = index(f"{MIRROR}/debian/dists/{SUITE}/main/binary-{arch}/Packages.xz")
    debugs = index(f"{MIRROR}/debian-debug/dists/{SUITE}-debug/main/binary-{arch}/Packages.xz")
    with ThreadPoolExecutor(6) as pool:
        for pkg, status, n in pool.map(lambda p: process(p, arch, corpus, binaries, debugs), PACKAGES):
            print(f"{pkg:18} {status:24} {n} binaries")
    made = [f for f in (corpus / "bin").iterdir() if f.name.startswith("deb__")]
    print(f"total: {len(made)} Debian binaries, {sum(f.stat().st_size for f in made) / 1e6:.0f} MB")


if __name__ == "__main__":
    main()
