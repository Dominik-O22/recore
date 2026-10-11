#!/usr/bin/env python3
"""Builds the jump-table corpus: programs compiled with clang so every jump table is recorded.

clang's `-mllvm -emit-jump-table-sizes-section` writes a `.llvm_jump_table_sizes` section holding
one (table address, entry count) pair per jump table. For each program below this downloads a
pinned source tarball into corpus/jt/src, builds it with distro-like flags, and writes
corpus/bin/jt__<name> (stripped, metadata section removed) and corpus/debug/jt__<name>.debug
(symbol table, DWARF and the metadata section). `recore-corpus jumptables` turns those into
corpus/jumptables/jt__<name>.json.

Usage: build.py [--force] [name...]
"""
import hashlib, os, shutil, subprocess, sys, tarfile, urllib.request, zipfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
CORPUS = HERE.parent
SRC = HERE / "src"
JOBS = 4
CFLAGS = ["-O2", "-g", "-fPIE", "-fno-plt", "-fstack-protector-strong", "-fcf-protection",
          "-mllvm", "-emit-jump-table-sizes-section"]
LDFLAGS = ["-pie", "-Wl,-z,relro,-z,now"]
META_SECTION = ".llvm_jump_table_sizes"


@dataclass
class Program:
    url: str
    sha256: str
    # Globs of translation units relative to the source root, minus `exclude` globs.
    sources: list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)
    libs: list[str] = field(default_factory=list)
    # Shell commands run in the source root first, with CC, CXX and CFLAGS exported.
    prepare: list[str] = field(default_factory=list)
    # Executable left behind by `prepare`, for programs built by their own build system.
    exe: str | None = None


PROGRAMS = {
    "sqlite3": Program(
        "https://www.sqlite.org/2025/sqlite-amalgamation-3500400.zip",
        "1d3049dd0f830a025a53105fc79fd2ab9431aea99e137809d064d8ee8356b032",
        sources=["sqlite3.c", "shell.c"], libs=["-lm"]),
    # LUA_USE_JUMPTABLE=0 makes the interpreter loop a switch instead of computed goto.
    "lua": Program(
        "https://www.lua.org/ftp/lua-5.4.8.tar.gz",
        "4f18ddae154e793e46eeab727c59ef1c0c0c2b744e7b94219710d76f530629ae",
        sources=["src/*.c"], exclude=["src/luac.c"],
        flags=["-DLUA_USE_LINUX", "-DLUA_USE_JUMPTABLE=0"], libs=["-lm", "-ldl"]),
    "minigzip": Program(
        "https://zlib.net/fossils/zlib-1.3.1.tar.gz",
        "9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23",
        sources=["*.c", "test/minigzip.c"], flags=["-I.", "-DHAVE_UNISTD_H"]),
    "zstd": Program(
        "https://github.com/facebook/zstd/releases/download/v1.5.7/zstd-1.5.7.tar.gz",
        "eb33e51f49a15e023950cd7825ca74a4a2b43db8354825ac24fc1b7ee09e6fa3",
        sources=["lib/common/*.c", "lib/compress/*.c", "lib/decompress/*.c", "lib/dictBuilder/*.c", "programs/*.c"],
        flags=["-Ilib", "-Ilib/common", "-Ilib/compress", "-Ilib/dictBuilder", "-DZSTD_DISABLE_ASM",
               "-DZSTD_MULTITHREAD", "-pthread"],
        libs=["-pthread"]),
    "bzip2": Program(
        "https://sourceware.org/pub/bzip2/bzip2-1.0.8.tar.gz",
        "ab5a03176ee106d3f0fa90e381da478ddae405918153cca248e682cd0c4a2269",
        sources=["blocksort.c", "huffman.c", "crctable.c", "randtable.c", "compress.c", "decompress.c", "bzlib.c",
                 "bzip2.c"],
        flags=["-D_FILE_OFFSET_BITS=64"]),
    "xz": Program(
        "https://github.com/tukaani-project/xz/releases/download/v5.8.1/xz-5.8.1.tar.gz",
        "507825b599356c10dca1cd720c9d0d0c9d5400b9de300af00e4d1ea150795543",
        prepare=["./configure --quiet --disable-shared --disable-nls --disable-doc", f"make -s -j{JOBS}"],
        exe="src/xz/xz"),
    "duk": Program(
        "https://duktape.org/duktape-2.7.0.tar.xz",
        "90f8d2fa8b5567c6899830ddef2c03f3c27960b11aca222fa17aa7ac613c2890",
        sources=["src/duktape.c", "examples/cmdline/duk_cmdline.c"], flags=["-Isrc"], libs=["-lm"]),
    "mujs": Program(
        "https://mujs.com/downloads/mujs-1.3.6.tar.gz",
        "7cf3a5e622cff41903efff0334518fc94af063256752c38ba4618a5191e44f18",
        sources=["one.c", "main.c"], libs=["-lm"]),
    "lz4": Program(
        "https://github.com/lz4/lz4/releases/download/v1.10.0/lz4-1.10.0.tar.gz",
        "537512904744b35e232912055ccf8ec66d768639ff3abe5788d90d792ec5f48b",
        sources=["lib/*.c", "programs/*.c"], flags=["-Ilib"]),
    "ninja": Program(
        "https://github.com/ninja-build/ninja/archive/refs/tags/v1.13.1.tar.gz",
        "f0055ad0369bf2e372955ba55128d000cfcc21777057806015b45e4accbebf23",
        sources=["src/*.cc"],
        exclude=["src/*_test.cc", "src/*_perftest.cc", "src/*-win32.cc", "src/*.in.cc", "src/browse.cc",
                 "src/test.cc", "src/hash_collision_bench.cc"],
        flags=["-std=c++14", "-fno-rtti", "-DNINJA_PYTHON=\"python3\"", "-DUSE_PPOLL"]),
    "tcc": Program(
        "https://download.savannah.gnu.org/releases/tinycc/tcc-0.9.27.tar.bz2",
        "de23af78fca90ce32dff2dd45b3432b2334740bb9bb7b05bf60fdbfc396ceb9c",
        prepare=["./configure"], sources=["tcc.c"], flags=["-DONE_SOURCE=1"], libs=["-lm", "-ldl"]),
}


def run(argv, **kwargs):
    result = subprocess.run(argv, capture_output=True, text=True, **kwargs)
    if result.returncode != 0:
        raise RuntimeError(f"{argv if isinstance(argv, str) else ' '.join(map(str, argv))}\n{result.stderr[-3000:]}")


def fetch(program):
    """Downloads the tarball into the cache and checks it against its pinned hash."""
    dest = SRC / "dl" / program.url.rsplit("/", 1)[1]
    if not dest.exists():
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_suffix(".part")
        urllib.request.urlretrieve(program.url, tmp)
        tmp.rename(dest)
    digest = hashlib.sha256(dest.read_bytes()).hexdigest()
    if digest != program.sha256:
        raise RuntimeError(f"{dest.name}: sha256 {digest}, expected {program.sha256}")
    return dest


def unpack(archive, name):
    """Extracts a fresh copy of the archive and returns its single top-level directory."""
    dest = SRC / "x" / name
    shutil.rmtree(dest, ignore_errors=True)
    dest.mkdir(parents=True)
    if archive.suffix == ".zip":
        with zipfile.ZipFile(archive) as z:
            z.extractall(dest)
    else:
        with tarfile.open(archive) as tar:
            tar.extractall(dest, filter="data")
    (root,) = dest.iterdir()
    return root


def build(name, program):
    root = unpack(fetch(program), name)
    cflags = CFLAGS + [f"-ffile-prefix-map={root}=."]
    env = os.environ | {"CC": "clang", "CXX": "clang++", "CFLAGS": " ".join(cflags), "CXXFLAGS": " ".join(cflags),
                        "LDFLAGS": " ".join(LDFLAGS)}
    for command in program.prepare:
        run(command, shell=True, cwd=root, env=env)
    if program.exe:
        exe = root / program.exe
    else:
        excluded = {p for pattern in program.exclude for p in root.glob(pattern)}
        sources = sorted(p for pattern in program.sources for p in root.glob(pattern) if p not in excluded)
        obj_dir = SRC / "obj" / name
        shutil.rmtree(obj_dir, ignore_errors=True)
        obj_dir.mkdir(parents=True)

        def compile_unit(source):
            obj = obj_dir / (source.relative_to(root).as_posix().replace("/", "_") + ".o")
            compiler = "clang" if source.suffix == ".c" else "clang++"
            run([compiler, *cflags, *program.flags, "-c", source, "-o", obj], cwd=root)
            return obj

        with ThreadPoolExecutor(JOBS) as pool:
            objects = list(pool.map(compile_unit, sources))
        exe = obj_dir / name
        linker = "clang" if all(s.suffix == ".c" for s in sources) else "clang++"
        run([linker, *LDFLAGS, *objects, *program.libs, "-o", exe])

    stripped = CORPUS / "bin" / f"jt__{name}"
    run(["objcopy", "--only-keep-debug", exe, CORPUS / "debug" / f"jt__{name}.debug"])
    run(["strip", "--strip-all", f"--remove-section={META_SECTION}", "-o", stripped, exe])
    return stripped.stat().st_size


def main():
    args = sys.argv[1:]
    force = "--force" in args
    names = [a for a in args if a != "--force"] or list(PROGRAMS)
    for d in ("bin", "debug"):
        (CORPUS / d).mkdir(exist_ok=True)
    failed = 0
    for name in names:
        if not force and (CORPUS / "bin" / f"jt__{name}").exists():
            print(f"{name:10} already built")
            continue
        try:
            print(f"{name:10} {build(name, PROGRAMS[name]) / 1e3:.0f} kB")
        except Exception as error:
            failed += 1
            print(f"{name:10} FAILED: {error}")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
