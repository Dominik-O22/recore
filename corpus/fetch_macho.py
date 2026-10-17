#!/usr/bin/env python3
"""Builds a Mach-O corpus from Homebrew bottles: stripped executables plus the originals.

Usage: fetch_macho.py <arch> <corpus>      e.g. arm64 corpus-macho, or x86_64 corpus-macho-x86
Writes, in the corpora's directory that corpus/store.py names, <corpus>/bin/brew__<formula>__<name>, stripped the way applications ship, and
<corpus>/debug/brew__<formula>__<name>.debug, the file as Homebrew built it. Homebrew does not
strip, so the original's symbol table names every function; that is the truth to score against.

Also writes <corpus>/nostarts/<same name>: the stripped file with its LC_FUNCTION_STARTS load
command made unreadable. Function starts are most of the truth, so an analysis that reads them
scores against its own input; this copy leaves an analyzer the unwind tables to go on, and
`recore corpus --no-frames` takes those away too.

Nothing downloaded is run. Needs llvm-strip and, for universal files, llvm-lipo.
"""
import hashlib, json, re, struct, subprocess, sys, tarfile, urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from store import CORPORA

API = "https://formulae.brew.sh/api/formula"
# The macOS releases whose bottles are taken, per architecture, most wanted first. Not every
# formula is built for every release.
TAGS = {"arm64": ["arm64_sequoia", "arm64_sonoma", "arm64_tahoe"], "x86_64": ["sequoia", "sonoma", "tahoe", "ventura"]}
MAX_PER_FORMULA = 6
FORMULAE = """jq lua sqlite zstd xz tmux htop curl git tree pcre2 nano less make gawk grep gnu-sed coreutils wget
rsync ninja cmake re2c openssl@3 ripgrep fd bat eza hyperfine
blueutil pngpaste switchaudio-osx terminal-notifier cliclick duti trash macvim reattach-to-user-namespace
sleepwatcher mas swiftformat""".split()

MH_MAGIC_64, FAT_MAGIC, MH_EXECUTE = 0xFEEDFACF, 0xCAFEBABE, 2
LC_FUNCTION_STARTS = 0x26
# A load command number no loader knows. Without the high bit, unknown commands are skipped.
LC_IGNORED = 0x7F000026


def without_function_starts(data):
    """The thin image `data` with its function starts hidden from whoever reads it."""
    data = bytearray(data)
    count = struct.unpack_from("<I", data, 16)[0]
    offset = 32
    for _ in range(count):
        command, size = struct.unpack_from("<II", data, offset)
        if command == LC_FUNCTION_STARTS:
            struct.pack_into("<I", data, offset, LC_IGNORED)
        offset += size
    return bytes(data)


def is_executable(head):
    """Whether a file starting with `head` is a Mach-O program, thin or universal."""
    if len(head) < 16:
        return False
    if struct.unpack(">I", head[:4])[0] == FAT_MAGIC:
        # Java class files share the magic; a universal file lists only a handful of slices.
        return struct.unpack(">I", head[4:8])[0] < 8
    return struct.unpack("<I", head[:4])[0] == MH_MAGIC_64 and struct.unpack("<I", head[12:16])[0] == MH_EXECUTE


def bottle(formula, arch, pkgs):
    """Downloads the formula's bottle for `arch`, checked against the hash Homebrew publishes."""
    info = json.load(urllib.request.urlopen(f"{API}/{formula}.json", timeout=60))
    files = info["bottle"]["stable"]["files"]
    entry = next((files[tag] for tag in TAGS[arch] if tag in files), None)
    if entry is None:
        return None
    dest = pkgs / f"{formula}-{entry['sha256'][:12]}.tar.gz"
    if not dest.exists():
        request = urllib.request.Request(entry["url"], headers={"Authorization": "Bearer QQ=="})
        data = urllib.request.urlopen(request, timeout=600).read()
        if hashlib.sha256(data).hexdigest() != entry["sha256"]:
            raise ValueError("bottle does not match its published hash")
        tmp = dest.with_suffix(".part")
        tmp.write_bytes(data)
        tmp.rename(dest)
    return dest


def process(formula, arch, corpus):
    try:
        archive = bottle(formula, arch, corpus / "pkgs")
    except Exception as error:
        return formula, f"failed: {error}", 0
    if archive is None:
        return formula, f"no {arch} bottle", 0
    candidates = []
    with tarfile.open(archive) as tar:
        for member in tar:
            name = Path(member.name).name
            if not member.isfile() or member.size < 4096 or not re.fullmatch(r"[\w.+-]+", name):
                continue
            data = tar.extractfile(member).read()
            if is_executable(data[:16]):
                candidates.append((member.size, name, data))
    candidates.sort(key=lambda c: c[:2])
    step = max(1, len(candidates) // MAX_PER_FORMULA)
    kept = candidates[::step][-MAX_PER_FORMULA:] if len(candidates) > MAX_PER_FORMULA else candidates
    written = 0
    for _, name, data in kept:
        name = f"brew__{formula}__{name}"
        original = corpus / "debug" / f"{name}.debug"
        original.write_bytes(data)
        if struct.unpack(">I", data[:4])[0] == FAT_MAGIC:
            thinned = subprocess.run(["llvm-lipo", original, "-thin", arch, "-output", original], capture_output=True)
            if thinned.returncode != 0:
                original.unlink()
                continue
        stripped = corpus / "bin" / name
        if subprocess.run(["llvm-strip", "-o", stripped, original], capture_output=True).returncode != 0:
            original.unlink()
            continue
        stripped.chmod(0o644)
        (corpus / "nostarts" / name).write_bytes(without_function_starts(stripped.read_bytes()))
        written += 1
    return formula, "ok", written


def main():
    arch, corpus = sys.argv[1], CORPORA / sys.argv[2]
    for d in ("bin", "debug", "nostarts", "pkgs"):
        (corpus / d).mkdir(parents=True, exist_ok=True)
    with ThreadPoolExecutor(6) as pool:
        for formula, status, n in pool.map(lambda f: process(f, arch, corpus), FORMULAE):
            print(f"{formula:28} {status:24} {n} binaries")
    made = [f for f in (corpus / "bin").iterdir() if f.name.startswith("brew__")]
    print(f"total: {len(made)} Homebrew binaries, {sum(f.stat().st_size for f in made) / 1e6:.0f} MB")


if __name__ == "__main__":
    main()
