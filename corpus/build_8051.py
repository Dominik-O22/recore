#!/usr/bin/env python3
"""Builds 8051 programs for corpus-8051 with SDCC, so every function's address is known.

Each program is open source C from a pinned archive, unpacked into corpus-8051/pkgs/<project>,
compiled by `sdcc -mmcs51 --debug` and linked into Intel hex. The modules the linker takes from
SDCC's library are then compiled from the library's sources with the program's own flags and
linked in their place, so that library functions have debug records too. What a project leaves
to its user, such as `main`, `putchar` or a port, is in corpus/8051.

For each program this writes
  corpus-8051/bin/<name>.toml     the layout recore loads, naming the image
  corpus-8051/image/<name>.bin    the code memory, banks one after another
  corpus-8051/debug/<name>.cdb    the linker's debug records: where each function starts and ends
  corpus-8051/debug/<name>.map    the linker's map, for the routines written in assembly
  corpus-8051/debug/<name>.rst    the listings of all modules at their final addresses

A banked program places translation units in the segments BANK1, BANK2 and so on, which the
linker puts at 0x8000 of each bank. Code reaches a `__banked` function through
`__sdcc_banked_call`, and with `--model-huge` every function is one.

Usage: build_8051.py [--force] [name...]
"""
import hashlib, re, shutil, subprocess, sys, tarfile, urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "corpus-8051"
GLUE = Path(__file__).resolve().parent / "8051"
LIBRARY = Path("/usr/share/sdcc/lib/src")
JOBS = 8
# Where a bank's code starts, and so where the code every bank shares ends.
BANK_START = 0x8000
# The call of a banked function, which loads its address and bank into R0 to R2, and the whole
# of `__sdcc_banked_call`, which pushes the address, selects the bank and returns into it.
BANKED_CALL = "78 ll 79 hh 7a bb 12 ss ss"
BANKED_CALL_STUB = "c0 b1 c8 c0 e0 e9 c0 e0 ea 54 0f 53 b1 f0 42 b1 c8 22"


@dataclass
class Project:
    url: str
    sha256: str


@dataclass
class Program:
    project: str
    # Globs of translation units relative to the project's root, minus `exclude` globs.
    sources: list[str]
    exclude: list[str] = field(default_factory=list)
    # Globs of the units that are the project's own library: linked only where something
    # refers to them, as the project's build does with an archive.
    library: list[str] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)
    # Directories for the include path, relative to the project's root.
    include: list[str] = field(default_factory=list)
    # Flags for each translation unit of the project, with `{stem}` standing for its name.
    unit_flags: list[str] = field(default_factory=list)
    # Directories under corpus/8051 with what the project leaves to its user, such as `main`,
    # `putchar` and a configuration header. Their `.c` files are compiled and they are on the
    # include path.
    glue: list[str] = field(default_factory=list)
    # Bank number to globs of the translation units placed in it, relative to the project's
    # root or to a glue directory. The rest is common to all banks, as is SDCC's library, whose
    # helpers the compiler calls without switching banks.
    banks: dict[int, list[str]] = field(default_factory=dict)
    # Addresses the hardware enters besides the reset and the interrupt vectors.
    entries: list[int] = field(default_factory=list)


def github(repository, commit, sha256):
    return Project(f"https://github.com/{repository}/archive/{commit}.tar.gz", sha256)


PROJECTS = {
    "tiny-AES-c": github("kokke/tiny-AES-c", "23856752fbd139da0b8ca6e471a13d5bcc99a08d",
                         "b91c219c4ff2dd4f24750130c27045e264b52d763d3b5b2cd24230334176f820"),
    "crypto-algorithms": github("B-Con/crypto-algorithms", "cfbde48414baacf51fc7c74f275190881f037d32",
                                "525d7b38eb549e52b21f6fc5e21362b912d66912aa458a5e4819f9427fc8f477"),
    "jsmn": github("zserge/jsmn", "25647e692c7906b96ffd2b05ca54c097948e879c",
                   "02ac62537ea34ee33b55efa41a832b78086548715298a454b6f304e29a7c9d43"),
    "heatshrink": github("atomicobject/heatshrink", "7d419e1fa4830d0b919b9b6a91fe2fb786cf3280",
                         "b18a1b7ad6f51eac7ac1a81ca072703bd21d6d8727c05cd505843643705af65d"),
    "printf": github("mpaland/printf", "d3b984684bb8a8bdc48cc7a1abecb93ce59bbe3e",
                     "4b5a9be01deea0af6452844d9d6ec5d60509f33ed8a73e1a9fba54155137043f"),
    "uip": github("adamdunkels/uip", "a49def743f6e5c7d0c0f2d724f0b8e0c563a4a37",
                  "a6325363533ae30f971bb1d214529d6466df18699fd71d876dd6bebe58e8c29c"),
    "uzlib": github("pfalcon/uzlib", "6d60d651a4499a64f2e5b21b4cc08d98cb84b5c1",
                    "b3e71434ee1ad26cf715f459e730245ca045a0833b6d92dbe719e1932970994d"),
    "ch554_sdcc": github("Blinkinlabs/ch554_sdcc", "6d7aa8f351877eb709484b30cac5af3f7a375b2d",
                         "d9865613f9ba3efa5aa6eae2de52616bf047562b0bec3c688bcf7202adee7f14"),
    "fx2lib": github("djmuhlestein/fx2lib", "3f9434a90c04ae3f7294f62038621ef885bcd8d0",
                     "47a55c6be4980a38cdac52d6060ec34b200abdda5bbc341be9f6b1072e8bff9f"),
    "fatfs": github("abbrev/fatfs", "ab992fcf2926b8a1ee3f0a8f9cefb6584174100d",
                    "90ae59d7a9a500eadd81fda05fb40ce5868b75a38445ec3d6cb5837d604c1dc4"),
    "coremark": github("eembc/coremark", "1f483d5b8316753a742cbf5590caf5bd0a4e4777",
                       "4067e7f260218df13f2875d8f821a8ff32a84153c6e0759d7c89f96c0a8bf987"),
    "micro-ecc": github("kmackay/micro-ecc", "541b3a78026420a3e369c4c9281c396b5e531113",
                        "48b36c6ae7401dd27f5b478764cad8e42ca601e4e81f9984d07ec1c7f1251329"),
    "libcrc": github("lammertb/libcrc", "7719e2112a9a960b1bba130d02bebdf58e8701f1",
                     "7132970cbf93b36b80b465d9b65d3a780ab508b2fed1144aefa5d1ca8d40eece"),
}

CH554 = {"flags": ["--model-small", "--xram-size", "0x0300", "--xram-loc", "0x0100", "-DFREQ_SYS=24000000"],
         "include": ["include"]}

# The Cypress FX2's library, with the descriptors and the interrupt jump table where the chip
# looks for them. The chip enters the table itself: it overwrites the low byte of the address
# in two interrupt vectors with four times the number of what interrupted.
FX2 = {"library": ["lib/*.c", "lib/interrupts/*.c", "lib/usbav.a51"], "include": ["include"],
       "flags": ["--model-small", "--code-size", "0x3c00", "--xram-size", "0x0200", "--xram-loc", "0x3c00",
                 "-Wl-bDSCR_AREA=0x3e00", "-Wl-bINT2JT=0x3f00"],
       "entries": list(range(0x3F00, 0x3FB8, 4))}

PROGRAMS = {
    "aes": Program("tiny-AES-c", ["aes.c", "test.c"], flags=["--model-large"], glue=["console"]),
    # Each test of the suite has a `main` of its own, which the glue calls in turn.
    "crypto": Program("crypto-algorithms", ["*.c"], exclude=["base64_test.c", "aes*.c"],
                      flags=["--model-large", "--stack-auto", "--opt-code-size"],
                      unit_flags=["-Dmain=main_{stem}", "-DIP=des_IP"], glue=["console", "crypto", "crypto_include"]),
    "jsmn": Program("jsmn", ["example/simple.c"],
                    flags=["--model-medium", "--stack-auto", "-DEXIT_SUCCESS=0", "-DEXIT_FAILURE=1"],
                    glue=["console"]),
    "heatshrink": Program("heatshrink", ["heatshrink_encoder.c", "heatshrink_decoder.c"],
                          flags=["--model-large", "--stack-auto"], glue=["console", "heatshrink"]),
    "uzlib": Program("uzlib", ["src/*.c"], include=["src"], flags=["--model-large", "--stack-auto", "--opt-code-size"],
                     glue=["console", "uzlib"]),
    "ecc": Program("micro-ecc", ["uECC.c"], flags=["--model-large", "--stack-auto", "-DuECC_PLATFORM=0"],
                   glue=["console", "ecc"]),
    # The 32- and 64-bit sums read tables that the project generates by running a program.
    "crc": Program("libcrc", ["src/*.c"], exclude=["src/crc32.c", "src/crc64.c", "src/nmea-chk.c"], include=["include"],
                   flags=["--model-large", "--opt-code-speed"],
                   glue=["console", "crc"]),
    "printf": Program("printf", ["printf.c"], flags=["--model-large", "--stack-auto"], glue=["printf"]),
    "fatfs": Program("fatfs", ["source/ff.c", "source/ffunicode.c"], include=["source"],
                     flags=["--model-large", "--stack-auto"],
                     glue=["console", "fatfs"]),
    "uip": Program("uip", ["uip/psock.c", "uip/timer.c", "uip/uip.c", "uip/uip_arp.c", "uip/uiplib.c", "lib/memb.c",
                           "apps/webserver/http-strings.c", "apps/webserver/httpd*.c", "unix/main.c"],
                   exclude=["apps/webserver/httpd-fsdata.c"], include=["uip", "lib", "apps/webserver", "unix"],
                   flags=["--model-large", "--stack-auto"], glue=["console", "uip"]),
    # With a port of its own, since the project's assume a hosted C library.
    "coremark": Program("coremark", ["core_list_join.c", "core_main.c", "core_matrix.c", "core_state.c",
                                     "core_util.c"],
                        flags=["--model-large", "--stack-auto", "-DITERATIONS=1", "-DTOTAL_DATA_SIZE=600",
                               "-DFLAGS_STR=\"--model-large\""],
                        glue=["console", "coremark"]),
    # SDCC's own library, which the glue calls most of. Without `--stack-auto` the library's
    # temporaries do not all fit the internal memory of one program: text and floating point
    # are one each, and the long integers are left to the last.
    "libtext": Program("tiny-AES-c", [], flags=["--model-large", "-DWITH_TEXT"], glue=["console", "libtest"]),
    "libfloat": Program("tiny-AES-c", [], flags=["--model-large", "-DWITH_FLOAT"], glue=["console", "libtest"]),
    "libtest_auto": Program("tiny-AES-c", [],
                            flags=["--model-large", "--stack-auto", "--opt-code-speed", "-DWITH_TEXT",
                                   "-DWITH_NUMBERS", "-DWITH_FLOAT"],
                            glue=["console", "libtest"]),
    # Banked. With `--model-huge` every function is called through the bank switch.
    "coremark_banked": Program("coremark", ["core_list_join.c", "core_main.c", "core_matrix.c", "core_state.c",
                                            "core_util.c"],
                               flags=["--model-huge", "--stack-auto", "-DITERATIONS=1", "-DTOTAL_DATA_SIZE=600",
                                      "-DFLAGS_STR=\"--model-huge\""],
                               glue=["console", "coremark", "banked"],
                               banks={1: ["core_list_join.c"], 2: ["core_matrix.c"],
                                      3: ["core_state.c", "core_util.c"]}),
    "uip_banked": Program("uip", ["uip/psock.c", "uip/timer.c", "uip/uip.c", "uip/uip_arp.c", "uip/uiplib.c",
                                  "lib/memb.c", "apps/webserver/http-strings.c", "apps/webserver/httpd*.c",
                                  "unix/main.c"],
                          exclude=["apps/webserver/httpd-fsdata.c"], include=["uip", "lib", "apps/webserver", "unix"],
                          flags=["--model-huge", "--stack-auto", "--opt-code-size"],
                          glue=["console", "uip", "banked"],
                          banks={1: ["uip/uip.c", "uip/uip_arp.c"], 2: ["uip/psock.c", "lib/memb.c"],
                                 3: ["apps/webserver/*.c"]}),
    # Banked by hand: each bank holds some algorithms with their tests and exports one
    # `__banked` function, and everything else is an ordinary call within the bank.
    "crypto_banked": Program("crypto-algorithms", ["*.c"], exclude=["base64_test.c", "aes*.c"],
                             flags=["--model-large", "--stack-auto"],
                             unit_flags=["-Dmain=main_{stem}", "-DIP=des_IP"],
                             glue=["console", "crypto_banked", "crypto_include", "banked"],
                             banks={1: ["md*.c", "sha*.c", "base64.c"], 2: ["arcfour*.c", "blowfish*.c", "des*.c", "rot-13*.c"]}),
    "fx2_bulkloop": Program("fx2lib", ["examples/bulkloop/bulkloop.c", "examples/bulkloop/dscr.a51"], **FX2),
    "fx2_debugdev": Program("fx2lib", ["examples/debugdevice/debugdev.c", "examples/debugdevice/dscr.a51"], **FX2),
    "ch554_cdc_i2c": Program("ch554_sdcc", ["examples/usb_device_cdc_i2c/firmware/*.c", "include/debug.c"],
                             **CH554),
    "ch554_cdcx2": Program("ch554_sdcc", ["examples/usb_device_cdcx2/main.c", "include/debug.c"], **CH554),
    "ch554_flash": Program("ch554_sdcc", ["examples/usb_spi_flash/*.c", "include/debug.c", "include/spi.c"],
                           **CH554),
    "ch554_midi": Program("ch554_sdcc", ["examples/usb_device_midi/main.c", "include/debug.c"], **CH554),
    "ch554_oled": Program("ch554_sdcc", ["examples/oled_ssd1306/main.c", "include/debug.c", "include/i2c.c"],
                          **CH554),
}

def run(argv, **kwargs):
    # SDCC can take very long over one function. A unit that does is one to leave out.
    result = subprocess.run(argv, capture_output=True, text=True, timeout=300, **kwargs)
    if result.returncode != 0:
        errors = [line for line in (result.stdout + result.stderr).splitlines() if "warning" not in line]
        raise RuntimeError(f"{' '.join(map(str, argv[-3:]))}\n" + "\n".join(errors[:6]))


def fetch(name):
    """Downloads and unpacks a project once into a directory of its own; returns its root."""
    project, home = PROJECTS[name], CORPUS / "pkgs" / name
    if not (home / "src").exists():
        archive = home / "archive.tar.gz"
        if not archive.exists():
            shutil.rmtree(home, ignore_errors=True)
            home.mkdir(parents=True)
            urllib.request.urlretrieve(project.url, archive)
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        if digest != project.sha256:
            raise RuntimeError(f"{name}: sha256 {digest}, expected {project.sha256}")
        tmp = home / "src.part"
        shutil.rmtree(tmp, ignore_errors=True)
        with tarfile.open(archive) as tar:
            tar.extractall(tmp, filter="data")
        tmp.rename(home / "src")
    (root,) = (home / "src").iterdir()
    return root


def read_hex(path):
    """The bytes of an Intel hex file by address."""
    memory, upper = {}, 0
    for line in path.read_text().split():
        record = bytes.fromhex(line[1:])
        count, address, kind, data = record[0], int.from_bytes(record[1:3]), record[3], record[4:-1]
        if kind == 0:
            memory.update((upper + address + i, byte) for i, byte in enumerate(data[:count]))
        elif kind == 4:
            upper = int.from_bytes(data) << 16
    return memory


def library_modules(map_file):
    """Names of the modules the linker took from a library, as the map lists them."""
    linked = map_file.read_text().split("Libraries Linked", 1)
    return set(re.findall(r"\[ (\S+)\.rel \]", linked[1])) if len(linked) == 2 else set()


def write_layout(name, memory, entries, banked):
    """Writes the image and the layout that loads it."""
    # The linker lets a segment run on past the end of its bank, into addresses that the next
    # bank's number and the common code's addresses name.
    if any(address >> 16 and address & 0xFFFF < BANK_START for address in memory):
        raise RuntimeError("a bank's code does not fit it")
    # Unprogrammed memory reads as 0xFF.
    regions, image = [], bytearray()
    for bank in sorted({address >> 16 for address in memory}):
        used = [address for address in memory if address >> 16 == bank]
        start, end = min(used), max(used) + 1
        regions.append((len(image), end - start, start))
        image += bytes(memory.get(address, 0xFF) for address in range(start, end))
    (CORPUS / "image" / f"{name}.bin").write_bytes(image)
    # Reset. recore reads the interrupt vectors from their slots.
    layout = f'machine = "8051"\nentry = [{", ".join(f"{entry:#06x}" for entry in [0, *entries])}]\n'
    for offset, length, address in regions:
        layout += (f'\n[[region]]\nfile = "../image/{name}.bin"\noffset = {offset:#x}\nlength = {length:#x}\n'
                   f"address = {address:#08x}\nexecutable = true\n")
    if banked:
        layout += (f"\n[banking]\ncommon = [[0x0000, {BANK_START:#06x}]]\n\n[[banking.trampoline]]\n"
                   f'call = "{BANKED_CALL}"\nstub = "{BANKED_CALL_STUB}"\n')
    (CORPUS / "bin" / f"{name}.toml").write_text(layout)
    return len(image)


def build(name, program):
    root = fetch(program.project)
    work = CORPUS / "obj" / name
    shutil.rmtree(work, ignore_errors=True)
    (work / "lib").mkdir(parents=True)
    roots = [root, *(GLUE / glue for glue in program.glue)]
    excluded = {p for pattern in program.exclude for p in root.glob(pattern)}
    sources = sorted(p for pattern in program.sources for p in root.glob(pattern) if p not in excluded)
    sources += sorted(p for glue in roots[1:] for p in glue.glob("*.c"))
    include = [f"-I{glue}" for glue in roots[1:]]
    # Older C than SDCC's default, in which `f()` declares a function of any arguments.
    flags = ["-mmcs51", "--debug", *program.flags]
    project_flags = ["--std-c11", *(f"-I{root / directory}" for directory in [".", *program.include])]
    bank_of = {p: bank for bank, patterns in program.banks.items() for pattern in patterns
               for directory in roots for p in directory.glob(pattern)}

    def compile_unit(source, out_dir=work, bank=None):
        obj = out_dir / (source.stem + ".rel")
        if obj.exists():
            raise RuntimeError(f"two translation units are named {source.stem}")
        if source.suffix != ".c":
            run(["sdas8051", "-plosgff", obj, source], cwd=work)
            return obj
        bank = bank_of.get(source, bank)
        segment = ["--codeseg", f"BANK{bank}"] if bank is not None else []
        unit = [flag.format(stem=source.stem.replace("-", "_")) for flag in program.unit_flags] if root in source.parents else []
        unit += ["--std-c23"] if LIBRARY in source.parents else project_flags
        run(["sdcc", *flags, *include, *unit, *segment, f"-I{source.parent}", "-c", source, "-o", obj], cwd=work)
        return obj

    members = sorted(p for pattern in program.library for p in root.glob(pattern))
    with ThreadPoolExecutor(JOBS) as pool:
        objects = list(pool.map(compile_unit, sources))
        archived = list(pool.map(lambda source: compile_unit(source, work / "lib"), members))
    if archived:
        run(["sdar", "-rc", work / "lib" / "project.lib", *archived])
    banks = sorted(set(bank_of.values()))
    link = ["sdcc", *flags, *(["-L", work / "lib", "-lproject"] if archived else []), "-lliblonglong",
            *(f"-Wl-bBANK{bank}={bank << 16 | BANK_START:#x}" for bank in banks)]
    if banks:
        link.append("-Wl-r")
    # Link, name what came from a library as a unit of its own, and link again until nothing
    # new comes from one: the linker lists only the units it is given by name. Of SDCC's library
    # that means compiling the module from its source. What remains is the startup code and the
    # other routines that library has only in assembly.
    while True:
        run([*link, *objects, "-o", work / f"{name}.ihx"], cwd=work)
        named = {obj.stem for obj in objects}
        taken = library_modules(work / f"{name}.map") - named
        own = [obj for obj in archived if obj.stem in taken]
        wanted = sorted(LIBRARY / f"{module}.c" for module in taken - {obj.stem for obj in own})
        wanted = [source for source in wanted if source.exists()]
        if not own and not wanted:
            break
        with ThreadPoolExecutor(JOBS) as pool:
            objects += own + list(pool.map(lambda source: compile_unit(source, work / "lib"), wanted))

    for suffix in ("cdb", "map"):
        shutil.copy(work / f"{name}.{suffix}", CORPUS / "debug" / f"{name}.{suffix}")
    (CORPUS / "debug" / f"{name}.rst").write_text("".join(obj.with_suffix(".rst").read_text() for obj in objects))
    return write_layout(name, read_hex(work / f"{name}.ihx"), program.entries, bool(banks))


def main():
    args = sys.argv[1:]
    force = "--force" in args
    names = [a for a in args if a != "--force"] or list(PROGRAMS)
    for d in ("bin", "image", "debug"):
        (CORPUS / d).mkdir(parents=True, exist_ok=True)
    failed = 0
    for name in names:
        if not force and (CORPUS / "bin" / f"{name}.toml").exists():
            print(f"{name:20} already built", flush=True)
            continue
        try:
            print(f"{name:20} {build(name, PROGRAMS[name]) / 1e3:.1f} kB", flush=True)
        except Exception as error:
            failed += 1
            print(f"{name:20} FAILED: {error}", flush=True)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
