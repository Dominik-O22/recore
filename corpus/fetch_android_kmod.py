#!/usr/bin/env python3
"""Adds Android kernel modules to a corpus: the GKI modules of one Android build, or the vendor
modules of one Pixel release.

Usage: python3 -I fetch_android_kmod.py <corpus>
       corpus-kmod-android, corpus-kmod-android-vendor, or corpus-kmod-android-<set> or
       corpus-kmod-android-<set>-stripped for a set of OLDER, each with -holdout or without; the
       name picks the build and the half
GKI, build 17002073 of android16-6.12: <corpus>/bin/kmod__<module>.ko is the module as shipped,
and <corpus>/debug/kmod__<module>.ko.debug the unstripped one with its DWARF decompressed, which
the build compresses with zstd and recore reads only uncompressed.
Vendor, the Pixel 9's modules of 25Q1: the shipped modules keep every function symbol and have
no DWARF, so each is its own debug file.
OLDER, the vendor modules of older Pixels: the shipped modules keep every function symbol, and
the debug file is the module with any DWARF it has decompressed. The -stripped corpus has each
module as `llvm-strip --strip-unneeded` leaves it, with the symbols its relocations and exports
need and the `$x` and `$d` mapping symbols, so that recore finds the rest itself.
A module is held out when the CRC-32 of its name is 0 modulo 3, the same rule for every build.
The downloads are kept in the tuned corpus's pkgs/, and the corpus's truth/ is written last, so
that check.sh never takes a corpus half made. A corpus that has truth/ is left as it is.
"""
import functools, os, shutil, subprocess, sys, tarfile, urllib.request, zlib
from pathlib import Path, PurePosixPath

# `-I` leaves the script's directory off the path.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from store import CORPORA  # noqa: E402

GKI = "https://ci.android.com/builds/submitted/17002073/kernel_aarch64/latest/raw"
# Gitiles makes this archive when asked, so its bytes differ between downloads and cannot be
# pinned by a checksum. The tag pins the modules in it.
GITILES = "https://android.googlesource.com/device/google"
PIXEL = f"{GITILES}/caimito-kernels/6.1/+archive/refs/heads/main/25Q1-12919773.tar.gz"
# Pinned by commit. They are older than kCFI: where they have CFI, it is LLVM's, which gives each
# module a `__cfi_check` and jump tables.
OLDER = {
    # Pixel 5, Linux 4.19, clang 12, Qualcomm: LTO, CFI.
    "redbull": f"{GITILES}/redbull-kernel/+archive/50b543afe3f9bff69b2841061343fdca4aeab13d.tar.gz",
    # Pixel 7, Linux 5.10, clang 14, Tensor G2: CFI, BTI and pointer authentication.
    "pantah": f"{GITILES}/pantah-kernel/+archive/ca2a5a30cf74625555df758277661ad4e75e330d.tar.gz",
    # Pixel 2, Linux 4.4, clang 11, and the same phone's modules of Android 8.1 built by GCC 4.9:
    # the large code model, without CFI.
    "wahoo": f"{GITILES}/wahoo-kernel/+archive/d62ab4e163ee054b67cc6dd9ab6f194fefb941af.tar.gz",
    "wahoo-gcc": f"{GITILES}/wahoo-kernel/+archive/ff3ad8367361fc9f69b4b2947f14b44a2fdaf74c/gcc.tar.gz",
}


def held_out(module):
    return zlib.crc32(module.encode()) % 3 == 0


def download(url, pkgs, name):
    """Downloads `url` once, into a directory of its own in `pkgs`. Gitiles sends no length, so
    a download of an archive cut short shows only when it is read to its end, which happens
    before the file gets its name."""
    dest = pkgs / name / Path(url).name
    if not dest.exists():
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_suffix(".part")
        with urllib.request.urlopen(url, timeout=180) as response, open(tmp, "wb") as out:
            shutil.copyfileobj(response, out)
        if dest.name.endswith(".tar.gz"):
            with tarfile.open(tmp) as tar:
                tar.getmembers()
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


def decompressed(data, work):
    """The bytes of an ELF file with its compressed DWARF decompressed, which recore reads only
    so; the same bytes where nothing is compressed."""
    compressed, plain = work / "compressed.ko", work / "plain.ko"
    compressed.write_bytes(data)
    subprocess.run(["llvm-objcopy", "--decompress-debug-sections", compressed, plain], check=True)
    return plain.read_bytes()


def gki(pkgs, work):
    """Yields (module, shipped, debug) for every GKI module."""
    shipped = modules(download(f"{GKI}/system_dlkm_staging_archive.tar.gz", pkgs, "gki-17002073-staging"), "flatten/lib/modules")
    unstripped = modules(download(f"{GKI}/unstripped_modules.tar.gz", pkgs, "gki-17002073-unstripped"), "unstripped")
    if shipped.keys() != unstripped.keys():
        sys.exit(f"the two archives hold different modules: {sorted(shipped.keys() ^ unstripped.keys())}")
    for module, data in shipped.items():
        yield module, data, decompressed(unstripped[module], work)


def vendor(pkgs, work):
    """Yields (module, shipped, debug) for every Pixel 9 vendor module. Only the top level of the
    archive is the shipping build: its subdirectories are 16K-page, KASAN and debug variants."""
    for module, data in modules(download(PIXEL, pkgs, "pixel9-25Q1"), ".").items():
        yield module, data, data


def older(name, strip, pkgs, work):
    """Yields (module, shipped, debug) for each module at the top of the archive of the set
    `name` of OLDER, as shipped or stripped."""
    for module, data in modules(download(OLDER[name], pkgs, name), ".").items():
        shipped = data
        if strip:
            (work / "shipped.ko").write_bytes(data)
            subprocess.run(["llvm-strip", "--strip-unneeded", work / "shipped.ko", "-o", work / "stripped.ko"], check=True)
            shipped = (work / "stripped.ko").read_bytes()
        yield module, shipped, decompressed(data, work)


def write_truth(corpus):
    """Writes <corpus>/truth from bin/ and debug/. recore-corpus writes truth/ as it goes, so it
    writes beside the corpus, and the whole directory is renamed into place."""
    work = corpus / "work"
    for d in ("bin", "debug"):
        os.symlink(Path("..") / d, work / d)
    repository = Path(__file__).resolve().parent.parent
    subprocess.run(["cargo", "run", "--profile", "ci", "-q", "-p", "recore-corpus", "--", "--corpus", work.resolve(), "truth"], cwd=repository, check=True)
    (work / "truth").rename(corpus / "truth")
    shutil.rmtree(work)


def fresh(corpus, *directories):
    """Empties `directories` of `corpus` and its work/, unless the corpus has truth/ already, and
    says whether it had not."""
    if (corpus / "truth").exists():
        shutil.rmtree(corpus / "work", ignore_errors=True)
        print(f"{corpus} has truth/ already, so it is left as it is")
        return False
    for d in (*directories, "work"):
        shutil.rmtree(corpus / d, ignore_errors=True)
        (corpus / d).mkdir(parents=True)
    return True


def main():
    corpus = CORPORA / sys.argv[1]
    tuned = corpus.name.removesuffix("-holdout")
    builds = {"corpus-kmod-android": gki, "corpus-kmod-android-vendor": vendor}
    for name in OLDER:
        builds[f"corpus-kmod-android-{name}"] = functools.partial(older, name, False)
        builds[f"corpus-kmod-android-{name}-stripped"] = functools.partial(older, name, True)
    if tuned not in builds:
        sys.exit(f"no Android build for {corpus.name}: name one of {', '.join(builds)}, or any with -holdout")
    if not fresh(corpus, "bin", "debug"):
        return

    kept = 0
    # A set's stripped corpora read the downloads of its shipped one.
    for module, shipped, debug in builds[tuned](CORPORA / tuned.removesuffix("-stripped") / "pkgs", corpus / "work"):
        if held_out(module) != corpus.name.endswith("-holdout"):
            continue
        name = f"kmod__{module}.ko"
        (corpus / "bin" / name).write_bytes(shipped)
        (corpus / "debug" / f"{name}.debug").write_bytes(debug)
        kept += 1

    write_truth(corpus)
    print(f"total: {kept} modules, {len(list((corpus / 'truth').iterdir()))} with truth")


if __name__ == "__main__":
    main()
