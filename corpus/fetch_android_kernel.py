#!/usr/bin/env python3
"""Adds an Android kernel to a corpus: the vmlinux of a GKI build as built, stripped, or as the
raw Image a boot partition holds.

Usage: python3 -I fetch_android_kernel.py <corpus>
       corpus-kernel-android, corpus-kernel-android-stripped or corpus-kernel-android-image, or
       any with -holdout
The tuned corpora hold GKI build 17002073 of android16-6.12, whose modules fetch_android_kmod.py
takes. A kernel cannot be split as a set of modules is, so the held-out corpora hold another one,
GKI build 16969351 of android15-6.6.
<corpus>/bin/vmlinux is the kernel as built, with its symbols and DWARF, and in -stripped the same
after `llvm-strip --strip-all`. In -image, bin/Image.toml is the layout of image/Image, which is
vmlinux's loaded bytes as `objcopy -O binary` writes them: a region for each segment it loads.
The debug file is vmlinux with its DWARF decompressed, which recore reads only so. The Image
holds vmlinux's bytes at vmlinux's addresses, so vmlinux is its debug file too.
The downloads are kept in the pkgs/ of corpus-kernel-android, and the held-out kernel's in that
of corpus-kernel-android-holdout, so that no tuned corpus holds the held-out kernel. The large files
are hard links to them, and the corpus's truth/ is written last. A corpus that has truth/ is left as it is.
"""
import os, struct, subprocess, sys
from pathlib import Path

# `-I` leaves the script's directory off the path.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from fetch_android_kmod import download, fresh, write_truth  # noqa: E402
from store import CORPORA  # noqa: E402

CI = "https://ci.android.com/builds/submitted/{build}/kernel_aarch64/latest/raw/{file}"
# The build of the tuned corpora, and the one of the held out.
BUILDS = {False: "17002073", True: "16969351"}
PT_LOAD, PF_X, PF_W = 1, 1, 2


def layout(vmlinux):
    """The layout of the Image cut from `vmlinux`, as TOML. `objcopy -O binary` puts each loaded
    segment at its physical address less the lowest one, and the kernel's are its addresses."""
    data = vmlinux.read_bytes()
    entry, phoff = struct.unpack_from("<QQ", data, 0x18)
    phentsize, phnum = struct.unpack_from("<HH", data, 0x36)
    segments = []
    for index in range(phnum):
        kind, flags, _, address, physical, size = struct.unpack_from("<IIQQQQ", data, phoff + index * phentsize)
        if kind == PT_LOAD and size:
            segments.append((address, physical, size, flags))
    base = min(physical for _, physical, _, _ in segments)
    lines = ['machine = "aarch64"', f"entry = [{entry:#x}]"]
    for address, physical, size, flags in segments:
        lines += ["", "[[region]]", 'file = "../image/Image"', f"offset = {physical - base:#x}", f"length = {size:#x}", f"address = {address:#x}"]
        lines += ["executable = true"] * bool(flags & PF_X) + ["writable = true"] * bool(flags & PF_W)
    return "\n".join(lines) + "\n"


def main():
    corpus = CORPORA / sys.argv[1]
    held_out = corpus.name.endswith("-holdout")
    form = corpus.name.removesuffix("-holdout").removeprefix("corpus-kernel-android")
    if form not in ("", "-stripped", "-image"):
        sys.exit(f"no Android kernel for {corpus.name}: name corpus-kernel-android, its -stripped or its -image, or any with -holdout")
    if not fresh(corpus, "bin", "debug", *["image"] * (form == "-image")):
        return

    build = BUILDS[held_out]
    pkgs = CORPORA / ("corpus-kernel-android-holdout" if held_out else "corpus-kernel-android") / "pkgs"
    vmlinux = download(CI.format(build=build, file="vmlinux"), pkgs, f"gki-{build}-vmlinux")
    debug = pkgs / f"gki-{build}-debug" / "vmlinux.debug"
    if not debug.exists():
        debug.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["llvm-objcopy", "--decompress-debug-sections", vmlinux, debug.with_suffix(".part")], check=True)
        debug.with_suffix(".part").rename(debug)

    name = "vmlinux"
    if form == "":
        os.link(vmlinux, corpus / "bin" / name)
    elif form == "-stripped":
        subprocess.run(["llvm-strip", "--strip-all", vmlinux, "-o", corpus / "bin" / name], check=True)
    else:
        name = "Image"
        image = download(CI.format(build=build, file="Image"), pkgs, f"gki-{build}-Image")
        # The layout and the truth hold only for an Image that is what the kernel's build makes
        # of this vmlinux.
        cut = corpus / "work" / "Image"
        subprocess.run(["llvm-objcopy", "-O", "binary", "-R", ".note", "-R", ".note.gnu.build-id", "-R", ".comment", "-S", vmlinux, cut], check=True)
        if cut.read_bytes() != image.read_bytes():
            sys.exit(f"{image} is not vmlinux's loaded bytes")
        os.link(image, corpus / "image" / name)
        (corpus / "bin" / f"{name}.toml").write_text(layout(vmlinux))
    os.link(debug, corpus / "debug" / f"{name}.debug")

    write_truth(corpus)
    print(f"{corpus.name}: build {build}, {len(list((corpus / 'truth').iterdir()))} with truth")


if __name__ == "__main__":
    main()
