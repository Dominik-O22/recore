#!/usr/bin/env python3
"""Adds Android kernel modules to a corpus: the GKI modules of one Android build, or the vendor
modules of one Pixel release.

Usage: fetch_android_kmod.py <corpus>   corpus-kmod-android or corpus-kmod-android-vendor, or either
                                        with -holdout; the name picks the build and the half
GKI, build 17002073 of android16-6.12: <corpus>/bin/kmod__<module>.ko is the module as shipped,
and <corpus>/debug/kmod__<module>.ko.debug the unstripped one with its DWARF decompressed, which
the build compresses with zstd and recore reads only uncompressed.
Vendor, the Pixel 9's modules of 25Q1: the shipped modules keep every function symbol and have
no DWARF, so each is its own debug file.
A module is held out when the CRC-32 of its name is 0 modulo 3, the same rule for both builds.
The downloads are kept in the tuned corpus's pkgs/, and the corpus's truth/ is written last, so
that check.sh never takes a corpus half made. A corpus that has truth/ is left as it is.
"""
import os, shutil, subprocess, sys, tarfile, urllib.request, zlib
from pathlib import Path, PurePosixPath

from store import CORPORA

GKI = "https://ci.android.com/builds/submitted/17002073/kernel_aarch64/latest/raw"
# Gitiles makes this archive when asked, so its bytes differ between downloads and cannot be
# pinned by a checksum. The tag pins the modules in it.
PIXEL = "https://android.googlesource.com/device/google/caimito-kernels/6.1/+archive/refs/heads/main/25Q1-12919773.tar.gz"


def held_out(module):
    return zlib.crc32(module.encode()) % 3 == 0


def download(url, pkgs, name):
    """Downloads `url` once, into a directory of its own in `pkgs`."""
    dest = pkgs / name / Path(url).name
    if not dest.exists():
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_suffix(".part")
        urllib.request.urlretrieve(url, tmp)
        tmp.rename(dest)
    return dest


def modules(archive, directory):
    """Maps module name to the bytes of each .ko file directly in `directory` of a tar archive."""
    with tarfile.open(archive) as tar:
        return {
            path.stem: tar.extractfile(member).read()
            for member in tar
            if member.isfile() and (path := PurePosixPath(member.name)).suffix == ".ko" and str(path.parent) == directory
        }


def gki(pkgs, work):
    """Yields (module, shipped, debug) for every GKI module."""
    shipped = modules(download(f"{GKI}/system_dlkm_staging_archive.tar.gz", pkgs, "gki-17002073-staging"), "flatten/lib/modules")
    unstripped = modules(download(f"{GKI}/unstripped_modules.tar.gz", pkgs, "gki-17002073-unstripped"), "unstripped")
    if shipped.keys() != unstripped.keys():
        sys.exit(f"the two archives hold different modules: {sorted(shipped.keys() ^ unstripped.keys())}")
    for module, data in shipped.items():
        compressed, plain = work / "compressed.ko", work / "plain.ko"
        compressed.write_bytes(unstripped[module])
        subprocess.run(["llvm-objcopy", "--decompress-debug-sections", compressed, plain], check=True)
        yield module, data, plain.read_bytes()


def vendor(pkgs, work):
    """Yields (module, shipped, debug) for every Pixel 9 vendor module. Only the top level of the
    archive is the shipping build: its subdirectories are 16K-page, KASAN and debug variants."""
    for module, data in modules(download(PIXEL, pkgs, "pixel9-25Q1"), ".").items():
        yield module, data, data


def main():
    corpus = CORPORA / sys.argv[1]
    tuned = corpus.name.removesuffix("-holdout")
    builds = {"corpus-kmod-android": gki, "corpus-kmod-android-vendor": vendor}
    if tuned not in builds:
        sys.exit(f"no Android build for {corpus.name}: name one of {', '.join(builds)}, or either with -holdout")
    if (corpus / "truth").exists():
        print(f"{corpus} has truth/ already, so it is left as it is")
        return

    work = corpus / "work"
    for d in ("bin", "debug", "work"):
        shutil.rmtree(corpus / d, ignore_errors=True)
        (corpus / d).mkdir(parents=True)
    kept = 0
    for module, shipped, debug in builds[tuned](CORPORA / tuned / "pkgs", work):
        if held_out(module) != corpus.name.endswith("-holdout"):
            continue
        name = f"kmod__{module}.ko"
        (corpus / "bin" / name).write_bytes(shipped)
        (corpus / "debug" / f"{name}.debug").write_bytes(debug)
        kept += 1

    # recore-corpus writes <corpus>/truth as it goes, so it writes beside it and the whole
    # directory is renamed into place.
    for d in ("bin", "debug"):
        os.symlink(Path("..") / d, work / d)
    repository = Path(__file__).resolve().parent.parent
    subprocess.run(["cargo", "run", "--profile", "ci", "-q", "-p", "recore-corpus", "--", "--corpus", work.resolve(), "truth"], cwd=repository, check=True)
    (work / "truth").rename(corpus / "truth")
    shutil.rmtree(work)
    print(f"total: {kept} modules, {len(list((corpus / 'truth').iterdir()))} with truth")


if __name__ == "__main__":
    main()
