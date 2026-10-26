#!/usr/bin/env python3
"""Downloads the source of the game the agent tasks are built from, Brogue CE, by pinned URL and
sha256, and writes its game logic into a directory without running anything from it.

Usage: fetch.py <dir>. The archive is kept in <dir>/pkgs, so a second run downloads nothing, and
the C files and headers of src/brogue, src/variants and src/platform go to <dir>/src.
"""
import hashlib, io, sys, tarfile, urllib.request
from pathlib import Path, PurePosixPath

BROGUE = "https://github.com/tmewett/BrogueCE/archive/refs/tags/v1.15.1.tar.gz"
SHA256 = "2abc186c5327342cb9ad7e45d41096ab10797d5ba76dcac843824ac2a0bfb3ac"
ROOT = PurePosixPath("BrogueCE-1.15.1/src")
DIRS = ("brogue", "variants", "platform")


def archive(pkgs: Path) -> bytes:
    path = pkgs / "BrogueCE-1.15.1.tar.gz"
    if not path.exists():
        print(f"downloading {BROGUE}", file=sys.stderr)
        with urllib.request.urlopen(BROGUE) as response:
            path.write_bytes(response.read())
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != SHA256:
        sys.exit(f"{path}: sha256 is not the pinned {SHA256}")
    return data


def main() -> None:
    out = Path(sys.argv[1])
    pkgs, src = out / "pkgs", out / "src"
    pkgs.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(archive(pkgs))) as tar:
        for entry in tar:
            name = PurePosixPath(entry.name)
            # Only regular .c and .h files directly in the three directories, so no member can
            # name a path outside <dir>/src.
            if not entry.isfile() or name.parent.parent != ROOT or name.parent.name not in DIRS:
                continue
            if name.suffix not in (".c", ".h"):
                continue
            target = src / name.parent.name / name.name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(tar.extractfile(entry).read())


if __name__ == "__main__":
    main()
