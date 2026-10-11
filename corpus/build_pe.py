#!/usr/bin/env python3
"""Builds Windows programs for the PE corpora with llvm-mingw, so compiler and flags are known.

The programs are the ones corpus/jt/build.py builds for ELF, from the same pinned tarballs,
compiled at -O2 by clang for x86_64-w64-mingw32 (into corpus-pe) and i686-w64-mingw32 (into
corpus-pe32) and linked by lld with a PDB. The toolchain is a pinned llvm-mingw release, unpacked
into corpus-pe/toolchain.

For each program this writes <corpus>/bin/mingw__<name>.exe, <corpus>/debug/mingw__<name>.exe.pdb
and <corpus>/debug/mingw__<name>.exe.jumptables. The last holds the `.llvm_jump_table_sizes`
section that `-mllvm -emit-jump-table-sizes-section` makes clang emit for COFF too: one (table
address, entry count) pair of pointer-sized integers per jump table. The section and the mingw
runtime's DWARF are stripped from the shipped binary. `recore-corpus jumptables` turns the pairs
into <corpus>/jumptables/mingw__<name>.exe.json.

Usage: build_pe.py [--force] [name...]
"""
import hashlib, shutil, subprocess, sys, tarfile, urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "jt"))
import build as elf  # noqa: E402  the ELF recipes: pinned URLs, hashes and the download cache

ROOT = Path(__file__).resolve().parent.parent
TOOLCHAIN = ROOT / "corpus-pe" / "toolchain"
TOOLCHAIN_URL = ("https://github.com/mstorsjo/llvm-mingw/releases/download/20261006/"
                 "llvm-mingw-20261006-ucrt-ubuntu-22.04-x86_64.tar.xz")
TOOLCHAIN_SHA256 = "5f9c6ed95b2d4bdb2869a488c5fd5857fbdabcf288a0aa3eb1da43f6a08d8ab4"
TARGETS = {"x86_64-w64-mingw32": ROOT / "corpus-pe", "i686-w64-mingw32": ROOT / "corpus-pe32"}
JOBS = 4
CFLAGS = ["-O2", "-g", "-gcodeview", "-mllvm", "-emit-jump-table-sizes-section"]
META_SECTION = ".llvm_jump_table_sizes"


@dataclass
class Program:
    # Globs of translation units relative to the source root, minus `exclude` globs.
    sources: list[str]
    exclude: list[str] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)
    libs: list[str] = field(default_factory=list)
    # Files to create in the source root before compiling, as name to content.
    files: dict[str, str] = field(default_factory=dict)
    # Extra flags per target triple.
    target_flags: dict[str, list[str]] = field(default_factory=dict)


# Windows recipes. Sources and versions come from the ELF recipe of the same name.
PROGRAMS = {
    "sqlite3": Program(["sqlite3.c", "shell.c"]),
    "lua": Program(["src/*.c"], exclude=["src/luac.c"], flags=["-DLUA_USE_JUMPTABLE=0"]),
    "minigzip": Program(["*.c", "test/minigzip.c"], flags=["-I."]),
    "zstd": Program(
        ["lib/common/*.c", "lib/compress/*.c", "lib/decompress/*.c", "lib/dictBuilder/*.c", "programs/*.c"],
        flags=["-Ilib", "-Ilib/common", "-Ilib/compress", "-Ilib/dictBuilder", "-DZSTD_DISABLE_ASM",
               "-DZSTD_MULTITHREAD"]),
    "bzip2": Program(["blocksort.c", "huffman.c", "crctable.c", "randtable.c", "compress.c", "decompress.c",
                      "bzlib.c", "bzip2.c"]),
    "duk": Program(["src/duktape.c", "examples/cmdline/duk_cmdline.c"], flags=["-Isrc"]),
    "mujs": Program(["one.c", "main.c"]),
    "lz4": Program(["lib/*.c", "programs/*.c"], flags=["-Ilib"]),
    # C++ with exceptions, against the toolchain's libc++.dll and libunwind.dll.
    "ninja": Program(
        ["src/*.cc", "src/getopt.c"],
        exclude=["src/*_test.cc", "src/*_perftest.cc", "src/*-posix.cc", "src/*.in.cc", "src/browse.cc",
                 "src/test.cc", "src/hash_collision_bench.cc", "src/*-win32-msvc.cc", "src/minidump-win32.cc"],
        flags=["-DNOMINMAX", "-D_WIN32_WINNT=0x0601", "-D__USE_MINGW_ANSI_STDIO=1"]),
    "tcc": Program(
        ["tcc.c"], flags=["-DONE_SOURCE=1", "-DTCC_TARGET_PE"], files={"config.h": '#define TCC_VERSION "0.9.27"\n'},
        target_flags={"x86_64-w64-mingw32": ["-DTCC_TARGET_X86_64"], "i686-w64-mingw32": ["-DTCC_TARGET_I386"]}),
}


def run(argv, **kwargs):
    result = subprocess.run(argv, capture_output=True, text=True, **kwargs)
    if result.returncode != 0:
        raise RuntimeError(f"{' '.join(map(str, argv))}\n{result.stderr[-3000:]}")


def toolchain():
    """Downloads and unpacks the pinned llvm-mingw release once; returns its bin directory."""
    if not (TOOLCHAIN / "bin").exists():
        archive = ROOT / "corpus-pe" / "pkgs" / TOOLCHAIN_URL.rsplit("/", 1)[1]
        if not archive.exists():
            archive.parent.mkdir(parents=True, exist_ok=True)
            urllib.request.urlretrieve(TOOLCHAIN_URL, archive)
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        if digest != TOOLCHAIN_SHA256:
            raise RuntimeError(f"{archive.name}: sha256 {digest}, expected {TOOLCHAIN_SHA256}")
        tmp = TOOLCHAIN.with_name("toolchain.part")
        shutil.rmtree(tmp, ignore_errors=True)
        tmp.mkdir(parents=True)
        with tarfile.open(archive) as tar:
            tar.extractall(tmp, filter="tar")
        (root,) = tmp.iterdir()
        root.rename(TOOLCHAIN)
        tmp.rmdir()
    return TOOLCHAIN / "bin"


def unpack(archive, dest):
    """Extracts a fresh copy of the archive and returns its single top-level directory."""
    shutil.rmtree(dest, ignore_errors=True)
    dest.mkdir(parents=True)
    shutil.unpack_archive(archive, dest, filter="data") if archive.suffix != ".zip" else shutil.unpack_archive(archive, dest)
    (root,) = dest.iterdir()
    return root


def build(name, program, target, corpus, tools):
    root = unpack(elf.fetch(elf.PROGRAMS[name]), corpus / "src" / "x" / name)
    for file, content in program.files.items():
        (root / file).write_text(content)
    excluded = {p for pattern in program.exclude for p in root.glob(pattern)}
    sources = sorted(p for pattern in program.sources for p in root.glob(pattern) if p not in excluded)
    obj_dir = corpus / "src" / "obj" / name
    shutil.rmtree(obj_dir, ignore_errors=True)
    obj_dir.mkdir(parents=True)
    flags = [*CFLAGS, f"-ffile-prefix-map={root}=.", *program.flags, *program.target_flags.get(target, [])]

    def compile_unit(source):
        obj = obj_dir / (source.relative_to(root).as_posix().replace("/", "_") + ".o")
        compiler = tools / f"{target}-{'clang' if source.suffix == '.c' else 'clang++'}"
        try:
            run([compiler, *flags, "-c", source, "-o", obj], cwd=root)
        except RuntimeError as error:
            # clang 23 cannot attach the metadata to some i386 COMDAT functions. Such a unit is
            # built without it, which leaves its jump tables out of the truth rather than wrong.
            if "cannot make section" not in str(error):
                raise
            run([compiler, *(f for f in flags if f not in CFLAGS[3:]), "-c", source, "-o", obj], cwd=root)
        return obj

    with ThreadPoolExecutor(JOBS) as pool:
        objects = list(pool.map(compile_unit, sources))
    out = f"mingw__{name}.exe"
    linked = obj_dir / out
    linker = tools / f"{target}-{'clang' if all(s.suffix == '.c' for s in sources) else 'clang++'}"
    run([linker, *objects, *program.libs, "-o", linked, f"-Wl,--pdb={corpus / 'debug' / (out + '.pdb')}"])
    run([tools / "llvm-objcopy", "--dump-section", f"{META_SECTION}={corpus / 'debug' / (out + '.jumptables')}",
         "--strip-all", f"--remove-section={META_SECTION}", linked, corpus / "bin" / out])
    return (corpus / "bin" / out).stat().st_size


def main():
    args = sys.argv[1:]
    force = "--force" in args
    names = [a for a in args if a != "--force"] or list(PROGRAMS)
    tools = toolchain()
    failed = 0
    for target, corpus in TARGETS.items():
        for d in ("bin", "debug"):
            (corpus / d).mkdir(parents=True, exist_ok=True)
        for name in names:
            label = f"{corpus.name:12} {name:10}"
            if not force and (corpus / "bin" / f"mingw__{name}.exe").exists():
                print(f"{label} already built")
                continue
            try:
                print(f"{label} {build(name, PROGRAMS[name], target, corpus, tools) / 1e3:.0f} kB")
            except Exception as error:
                failed += 1
                print(f"{label} FAILED: {error}")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
