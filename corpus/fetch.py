#!/usr/bin/env python3
"""Builds the corpus from Arch packages: stripped executables plus their separate debug files.

For each package in packages.txt, downloads the package and its matching -debug package from an
Arch mirror, extracts ELF executables from usr/bin, and pairs each with its debug file by build ID.
Writes corpus/bin/<pkg>__<name> and corpus/debug/<pkg>__<name>.debug.
"""
import io, os, re, subprocess, sys, tarfile, urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

MIRROR = "https://geo.mirror.pkgbuild.com"
from store import CORPORA

HERE = Path(__file__).parent
PKGS, BIN, DEBUG = (CORPORA / "corpus" / d for d in ("pkgs", "bin", "debug"))
MAX_PER_PACKAGE = 12  # coreutils alone ships ~100 near-identical small tools


def repo_index(repo):
    """Maps package name to (version, filename) from a repo's sync database."""
    data = urllib.request.urlopen(f"{MIRROR}/{repo}/os/x86_64/{repo}.db", timeout=120).read()
    index = {}
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        for member in tar:
            if member.name.endswith("/desc"):
                fields = tar.extractfile(member).read().decode().split("\n\n")
                desc = {f.split("\n", 1)[0]: f.split("\n", 1)[1] for f in fields if "\n" in f}
                index[desc["%NAME%"]] = (desc["%VERSION%"], desc["%FILENAME%"])
    return index


def download(repo, filename):
    dest = PKGS / filename
    if not dest.exists():
        tmp = dest.with_suffix(".part")
        urllib.request.urlretrieve(f"{MIRROR}/{repo}/os/x86_64/{filename}", tmp)
        tmp.rename(dest)
    return dest


def extract(archive, dest, prefix):
    dest.mkdir(parents=True, exist_ok=True)
    subprocess.run(["tar", "--zstd", "-xf", archive, "-C", dest, "--wildcards", prefix], check=False,
                   stderr=subprocess.DEVNULL)


def build_id(path):
    out = subprocess.run(["readelf", "-n", path], capture_output=True, text=True).stdout
    m = re.search(r"Build ID: (\w+)", out)
    return m.group(1) if m else None


def process(pkg, repos):
    for repo in ("core", "extra"):
        if pkg in repos[repo]:
            break
    else:
        return pkg, "not in core/extra", 0
    version, filename = repos[repo][pkg]
    dbg = repos[f"{repo}-debug"].get(f"{pkg}-debug")
    if not dbg or dbg[0] != version:
        return pkg, f"no matching debug package for {version}", 0
    work = PKGS / "x" / pkg
    extract(download(repo, filename), work, "usr/bin/*")
    extract(download(f"{repo}-debug", dbg[1]), work, "usr/lib/debug/*")
    candidates = []
    for f in sorted((work / "usr/bin").glob("*")):
        # Names like "[" break shell tooling downstream.
        if not re.fullmatch(r"[\w.+-]+", f.name):
            continue
        if f.is_symlink() or not f.is_file() or f.read_bytes()[:4] != b"\x7fELF":
            continue
        bid = build_id(f)
        debug = work / "usr/lib/debug/.build-id" / bid[:2] / f"{bid[2:]}.debug" if bid else None
        if debug and debug.exists():
            candidates.append((f.stat().st_size, f, debug.resolve()))
    # Keep a spread of sizes rather than the first N alphabetically.
    candidates.sort()
    step = max(1, len(candidates) // MAX_PER_PACKAGE)
    kept = candidates[::step][-MAX_PER_PACKAGE:] if len(candidates) > MAX_PER_PACKAGE else candidates
    for _, f, debug in kept:
        name = f"{pkg}__{f.name}"
        (BIN / name).write_bytes(f.read_bytes())
        (DEBUG / f"{name}.debug").write_bytes(debug.read_bytes())
    return pkg, version, len(kept)


def main():
    for d in (PKGS, BIN, DEBUG):
        d.mkdir(exist_ok=True)
    names = [l.strip() for l in (HERE / "packages.txt").read_text().splitlines() if l.strip() and not l.startswith("#")]
    repos = {r: repo_index(r) for r in ("core", "extra", "core-debug", "extra-debug")}
    with ThreadPoolExecutor(8) as pool:
        for pkg, status, n in pool.map(lambda p: process(p, repos), names):
            print(f"{pkg:12} {status:28} {n} binaries")
    print(f"total: {len(list(BIN.iterdir()))} binaries, {sum(f.stat().st_size for f in BIN.iterdir()) / 1e6:.0f} MB")


if __name__ == "__main__":
    main()
