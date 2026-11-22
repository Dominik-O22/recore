#!/usr/bin/env python3
"""Downloads the two Android kernel builds the agent tasks are on, by pinned URL and sha256, and
lays out what a session gets apart from what only the key may read: the kernel of GKI build
16924931 of android13-5.15, and modules of GKI build 16958505 of android14-6.1.

Usage: python3 -I fetch.py <dir>. Each download is kept in a directory of its own in <dir>/pkgs, so
a second run downloads nothing. <dir>/task gets the session's inputs: the raw Image, and each of
MODULES as shipped and then `llvm-strip --strip-unneeded`, which leaves only the symbols its
relocations and exports need. <dir>/key gets what the key was derived from: the kernel's vmlinux
and System.map, and each module unstripped with its DWARF decompressed, as <module>.ko.debug.
No corpus holds either build: the corpora hold GKI builds 17002073 and 16969351. The kernel comes
from 5.15 because recore does not find the symbol table in the 6.1 build's Image, whose
kallsyms_seqs_of_names lies between the markers and the token table, and the modules from 6.1
because the 5.15 build publishes none with DWARF.
"""
import hashlib, os, shutil, subprocess, sys, tarfile, urllib.request
from pathlib import Path, PurePosixPath

CI = "https://ci.android.com/builds/submitted/{build}/kernel_aarch64/latest/raw/{file}"
KERNEL_BUILD, MODULE_BUILD = "16924931", "16958505"
PINS = {
    (KERNEL_BUILD, "Image"): "390daeb809eef887503a27946c60835abf1d4091ae3c7ab14a6b998e28b56d0c",
    (KERNEL_BUILD, "System.map"): "a3e4a596d4c22785ea078698e01c92c8a0804b0af2a3df76531515109f31e1d4",
    (KERNEL_BUILD, "vmlinux"): "682beb50440cc624825681a22aed3867f3cd9b63ede93aead070798746f6f348",
    (MODULE_BUILD, "system_dlkm_staging_archive.tar.gz"): "ce294ddf893b97e22fec721cd68429ca722d9ceeefd9c7c7a6ad58383cafa9a6",
    (MODULE_BUILD, "unstripped_modules.tar.gz"): "33d37007578a23163a3c62d64b58070573fba3d690efad632fe8a2b862d7bc5a",
}
MODULES = ("gzvm", "zram", "rfkill")


def download(pkgs: Path, build: str, file: str) -> Path:
    path = pkgs / f"{build}-{file}" / file
    if not path.exists():
        print(f"downloading {file} of build {build}", file=sys.stderr)
        path.parent.mkdir(parents=True, exist_ok=True)
        part = path.with_name(file + ".part")
        with urllib.request.urlopen(CI.format(build=build, file=file), timeout=600) as response, open(part, "wb") as out:
            shutil.copyfileobj(response, out)
        # A download that is not the pinned file gets no name, so the next run fetches it again.
        check(part, build, file)
        part.rename(path)
    check(path, build, file)
    return path


def check(path: Path, build: str, file: str) -> None:
    digest = hashlib.sha256()
    with open(path, "rb") as data:
        while chunk := data.read(1 << 20):
            digest.update(chunk)
    if digest.hexdigest() != PINS[build, file]:
        sys.exit(f"{path}: sha256 is not the pinned {PINS[build, file]}")


def place(source: Path, target: Path) -> None:
    """Links `target` to a download, which nothing writes to."""
    target.unlink(missing_ok=True)
    os.link(source, target)


def modules(archive: Path, directory: str) -> dict[str, bytes]:
    """The bytes of each of MODULES directly in `directory` of a tar archive. Only regular files
    are read, and their names come from MODULES, so no member can write outside <dir>."""
    with tarfile.open(archive) as tar:
        found = {
            path.stem: tar.extractfile(member).read()
            for member in tar
            if member.isfile() and (path := PurePosixPath(member.name)).suffix == ".ko" and str(path.parent) == directory and path.stem in MODULES
        }
    if missing := set(MODULES) - found.keys():
        sys.exit(f"{archive}: no {', '.join(sorted(missing))} in {directory}")
    return found


def main() -> None:
    out = Path(sys.argv[1])
    pkgs, task, key, work = out / "pkgs", out / "task", out / "key", out / "work"
    for directory in (task, key, work):
        directory.mkdir(parents=True, exist_ok=True)
    place(download(pkgs, KERNEL_BUILD, "Image"), task / "Image")
    place(download(pkgs, KERNEL_BUILD, "System.map"), key / "System.map")
    place(download(pkgs, KERNEL_BUILD, "vmlinux"), key / "vmlinux")
    shipped = modules(download(pkgs, MODULE_BUILD, "system_dlkm_staging_archive.tar.gz"), "flatten/lib/modules")
    unstripped = modules(download(pkgs, MODULE_BUILD, "unstripped_modules.tar.gz"), "unstripped")
    for module in MODULES:
        (work / f"{module}.ko").write_bytes(shipped[module])
        subprocess.run(["llvm-strip", "--strip-unneeded", work / f"{module}.ko", "-o", task / f"{module}.ko"], check=True)
        (work / f"{module}.unstripped.ko").write_bytes(unstripped[module])
        # Android compresses DWARF with zstd, which recore's DWARF reader does not read.
        subprocess.run(["llvm-objcopy", "--decompress-debug-sections", work / f"{module}.unstripped.ko", key / f"{module}.ko.debug"], check=True)


if __name__ == "__main__":
    main()
