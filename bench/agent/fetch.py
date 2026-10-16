#!/usr/bin/env python3
"""Downloads the targets of the agent tasks into a directory, each from a release pinned by
URL and sha256, and checks each target against its own sha256.

Usage: fetch.py <dir>. Packages are kept in <dir>/pkgs, so a second run downloads nothing.
"""
import hashlib, io, sys, tarfile, urllib.request, zipfile
from pathlib import Path

GIT = "https://github.com/git-for-windows/git/releases/download/v2.56.0.windows.2/MinGit-2.56.0.2-64-bit.zip"
PYTHON = "https://www.python.org/ftp/python/3.13.7/python-3.13.7-embed-amd64.zip"
EXPAT = "https://snapshot.debian.org/archive/debian/20221027T213940Z/pool/main/e/expat/libexpat1_2.5.0-1_amd64.deb"
EXPAT_FIXED = "https://snapshot.debian.org/archive/debian-security/20240917T203947Z/pool/updates/main/e/expat/libexpat1_2.5.0-1+deb12u1_amd64.deb"

PACKAGES = {
    GIT: "da35e72aa21c005a5a0d298cfbae110bc1609a815730ea0dde84b01a1b3cd3be",
    PYTHON: "f6cca216a359be84797cabb54149ce5e062afb16cc7567eb7fc51cacb2d86b65",
    EXPAT: "fe36a7f35361fc40d0057ef447a7302fd41d51740d51c98fb3870bbed5b96e56",
    EXPAT_FIXED: "c2bd305125bcece5816b2521f293a99499d674cd2dd744416caa4952158ad99d",
}

# Each target: the package, the file in it, and the target's sha256.
TARGETS = {
    "git.exe": (GIT, "ucrt64/bin/git.exe", "b824434dfe3b5f9cf648af6c9cc8cb1f6a982cc6e13b6c6ebbe6533c7e51cc2e"),
    "python313.dll": (PYTHON, "python313.dll", "41ec4fc4e5bc8b207258590238f7f050b13fdfee84c4a7b1ecff6e945d031a10"),
    "libx-before.so": (EXPAT, "./lib/x86_64-linux-gnu/libexpat.so.1.8.10", "a60b748760fea6f1a27baab72ea5149d1aa41be28f9cfac9e37ce40bf5fb7ca7"),
    "libx-after.so": (EXPAT_FIXED, "./lib/x86_64-linux-gnu/libexpat.so.1.8.10", "5284992cab1e026b8fc254576c89e7fcc37bcf43d5b6dc66a9fb1fb1cd400f88"),
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def package(pkgs: Path, url: str) -> bytes:
    path = pkgs / url.rsplit("/", 1)[1]
    if not path.exists():
        print(f"downloading {url}", file=sys.stderr)
        with urllib.request.urlopen(url) as response:
            path.write_bytes(response.read())
    data = path.read_bytes()
    if sha256(data) != PACKAGES[url]:
        sys.exit(f"{path}: sha256 is not the pinned {PACKAGES[url]}")
    return data


def member(data: bytes, url: str, name: str) -> bytes:
    if url.endswith(".zip"):
        return zipfile.ZipFile(io.BytesIO(data)).read(name)
    # A .deb is an ar archive of 60-byte headers, each followed by its member, padded to even.
    at = 8
    while at < len(data):
        header = data[at : at + 60]
        size = int(header[48:58])
        if header[:16].strip().startswith(b"data.tar"):
            return tarfile.open(fileobj=io.BytesIO(data[at + 60 : at + 60 + size])).extractfile(name).read()
        at += 60 + size + size % 2
    sys.exit(f"{url}: no data.tar")


def main() -> None:
    out = Path(sys.argv[1])
    pkgs = out / "pkgs"
    pkgs.mkdir(parents=True, exist_ok=True)
    for target, (url, name, digest) in TARGETS.items():
        data = member(package(pkgs, url), url, name)
        if sha256(data) != digest:
            sys.exit(f"{target}: sha256 is not the pinned {digest}")
        (out / target).write_bytes(data)


if __name__ == "__main__":
    main()
