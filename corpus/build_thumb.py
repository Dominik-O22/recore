#!/usr/bin/env python3
"""Builds Cortex-M programs for corpus-thumb with clang, so every function's address is known.

Each program is open source C from a pinned archive, unpacked into corpus-thumb/pkgs/<project>,
compiled by clang for one Cortex-M core at one optimisation level and linked by rust-lld into an
ELF image that runs from flash. What a project leaves to its user, such as `main`, a port or a
configuration header, is in corpus/thumb or shared with the 8051 corpus in corpus/8051. Every
program has the same small runtime from corpus/thumb/runtime: the vector table and reset handler,
a serial console, and the few C library functions the projects call. `printf` is the printf
project's. The compiler's helpers (division, soft floating point, `memcpy`) come from the
`compiler_builtins` that Rust ships for each Cortex-M target, which `rustup target add` installs.

For each program this writes
  corpus-thumb/bin/<name>.toml     the layout recore loads, naming the image
  corpus-thumb/image/<name>.bin    the flash, as `llvm-objcopy -O binary` cuts it from the ELF
  corpus-thumb/debug/<name>.debug  the ELF, with its symbols, mapping symbols and DWARF

Usage: build_thumb.py [--force] [name...]
"""
import hashlib, shutil, subprocess, sys, tarfile, urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, replace
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "corpus-thumb"
GLUE = Path(__file__).resolve().parent
RUNTIME = GLUE / "thumb" / "runtime"
JOBS = 8
RAM = 0x20000000


@dataclass
class Project:
    url: str
    sha256: str


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
    "fatfs": github("abbrev/fatfs", "ab992fcf2926b8a1ee3f0a8f9cefb6584174100d",
                    "90ae59d7a9a500eadd81fda05fb40ce5868b75a38445ec3d6cb5837d604c1dc4"),
    "coremark": github("eembc/coremark", "1f483d5b8316753a742cbf5590caf5bd0a4e4777",
                       "4067e7f260218df13f2875d8f821a8ff32a84153c6e0759d7c89f96c0a8bf987"),
    "micro-ecc": github("kmackay/micro-ecc", "541b3a78026420a3e369c4c9281c396b5e531113",
                        "48b36c6ae7401dd27f5b478764cad8e42ca601e4e81f9984d07ec1c7f1251329"),
    "libcrc": github("lammertb/libcrc", "7719e2112a9a960b1bba130d02bebdf58e8701f1",
                     "7132970cbf93b36b80b465d9b65d3a780ab508b2fed1144aefa5d1ca8d40eece"),
    # V11.3.1
    "FreeRTOS-Kernel": github("FreeRTOS/FreeRTOS-Kernel", "3a22924e0a9ddbbc8b0758881c33b3422a5cc20d",
                              "e7d25915c043f4695eb066117cc60a42e7c58e421d971ebaf6fe2ec97208d658"),
    # v2.11.3
    "littlefs": github("littlefs-project/littlefs", "6cb4e86540eca0d9ba62500a298385c9d863c8be",
                       "4803faf6db6c60093558a315a10c50926d2cfa5668a3f03fa2523fd09b10b747"),
    # v1.18.0, and the CMSIS headers it needs from v6.4.0
    "CMSIS-DSP": github("ARM-software/CMSIS-DSP", "4b6f26593e9d3b24a9bc93b3646a3a859238eae2",
                        "1deb39cb13d88f868ade15e6a9a86a0dbb465e82eec21113f572d9f1627d9d6a"),
    "CMSIS_6": github("ARM-software/CMSIS_6", "af1b110e46a1720349f6f125e386e126767699bd",
                      "8c01ea5b9c79d2766ef134194259cd7b97c0419f2d0a55356d44c8bf9aad1d1f"),
    "minmea": github("kosma/minmea", "c43c9e7c5ed788122a9d8a5445679e1594f8a030",
                     "0f1480384b71181a84e39d3bd62ed3e1747643a33de9637fec8ac9d50abdfff0"),
}


@dataclass
class Core:
    """A Cortex-M core: how clang targets it, the Rust target whose compiler helpers it links,
    and where its flash starts."""
    flags: list[str]
    rust_target: str
    flash: int


CORES = {
    # Thumb-1 only (ARMv6-M), with flash at 0 as on an nRF51 or an LPC11xx.
    "m0": Core(["--target=thumbv6m-none-eabi", "-mcpu=cortex-m0", "-mfloat-abi=soft"], "thumbv6m-none-eabi", 0x00000000),
    # Thumb-2 (ARMv7-M), with flash where an STM32 has it.
    "m3": Core(["--target=thumbv7m-none-eabi", "-mcpu=cortex-m3", "-mfloat-abi=soft"], "thumbv7m-none-eabi", 0x08000000),
    "m4": Core(["--target=thumbv7em-none-eabi", "-mcpu=cortex-m4", "-mfloat-abi=soft"], "thumbv7em-none-eabi", 0x08000000),
    # With its floating-point unit, so the code has VFP instructions.
    "m4f": Core(["--target=thumbv7em-none-eabihf", "-mcpu=cortex-m4", "-mfpu=fpv4-sp-d16", "-mfloat-abi=hard"],
                "thumbv7em-none-eabihf", 0x08000000),
}


@dataclass
class Program:
    project: str
    core: str
    opt: str
    # Globs of translation units relative to the project's root, minus `exclude` globs.
    sources: list[str]
    exclude: list[str] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)
    # Directories for the include path, relative to the project's root.
    include: list[str] = field(default_factory=list)
    # Flags for each translation unit of the project, with `{stem}` standing for its name.
    unit_flags: list[str] = field(default_factory=list)
    # Directories under corpus/ with what the project leaves to its user. Their `.c` files are
    # compiled and they are on the include path.
    glue: list[str] = field(default_factory=list)
    # Other projects whose files the program compiles or includes, as project to globs of
    # translation units; their roots are on the include path after `extra_include`.
    extra: dict[str, list[str]] = field(default_factory=dict)
    extra_include: list[str] = field(default_factory=list)
    # Laid out as GNU ld lays out a vendor's build without -ffunction-sections: one section of
    # code per translation unit, so a function ending in a call that never returns runs into the
    # next, and zeros, not lld's traps, in the gaps between the units.
    gnu_layout: bool = False


FREERTOS = {"sources": ["tasks.c", "queue.c", "list.c", "timers.c", "event_groups.c", "portable/MemMang/heap_4.c"],
            "include": ["include"], "glue": ["thumb/freertos"]}
LITTLEFS = {"sources": ["lfs.c", "lfs_util.c"], "glue": ["thumb/littlefs"], "flags": ["-DLFS_NO_MALLOC", "-DLFS_NO_DEBUG", "-DLFS_NO_WARN", "-DLFS_NO_ERROR", "-DLFS_NO_ASSERT"]}
COREMARK = {"sources": ["core_list_join.c", "core_main.c", "core_matrix.c", "core_state.c", "core_util.c"],
            "flags": ["-DITERATIONS=1", "-DTOTAL_DATA_SIZE=2000", "-DPERFORMANCE_RUN=1"], "glue": ["thumb/coremark"]}
DSP_INCLUDE = ["Include", "PrivateInclude"]
UIP = {"sources": ["uip/psock.c", "uip/timer.c", "uip/uip.c", "uip/uip_arp.c", "uip/uiplib.c", "lib/memb.c",
                   "apps/webserver/http-strings.c", "apps/webserver/httpd*.c", "unix/main.c"],
       "exclude": ["apps/webserver/httpd-fsdata.c"], "include": ["uip", "lib", "apps/webserver", "unix"],
       "glue": ["thumb/uip"]}

PROGRAMS = {
    "aes_m0_Os": Program("tiny-AES-c", "m0", "Os", ["aes.c", "test.c"]),
    "aes_m4_O2": Program("tiny-AES-c", "m4", "O2", ["aes.c", "test.c"]),
    "crypto_m3_O2": Program("crypto-algorithms", "m3", "O2", ["*.c"], exclude=["base64_test.c", "aes*.c"],
                            unit_flags=["-Dmain=main_{stem}", "-DIP=des_IP"], glue=["8051/crypto", "8051/crypto_include"]),
    "crypto_m0_O0": Program("crypto-algorithms", "m0", "O0", ["*.c"], exclude=["base64_test.c", "aes*.c"],
                            unit_flags=["-Dmain=main_{stem}", "-DIP=des_IP"], glue=["8051/crypto", "8051/crypto_include"]),
    "jsmn_m3_Os": Program("jsmn", "m3", "Os", ["example/simple.c"]),
    "heatshrink_m0_O2": Program("heatshrink", "m0", "O2", ["heatshrink_encoder.c", "heatshrink_decoder.c"], glue=["8051/heatshrink"]),
    "heatshrink_m4_O0": Program("heatshrink", "m4", "O0", ["heatshrink_encoder.c", "heatshrink_decoder.c"], glue=["8051/heatshrink"]),
    "uzlib_m3_Os": Program("uzlib", "m3", "Os", ["src/*.c"], include=["src"], glue=["8051/uzlib"]),
    "ecc_m4_O2": Program("micro-ecc", "m4", "O2", ["uECC.c"], flags=["-DuECC_PLATFORM=0"], glue=["8051/ecc"]),
    # With the project's assembly for Thumb-2, which it picks for the core itself. Above the first
    # level of optimisation clang runs out of registers for it.
    "ecc_m3_Os": Program("micro-ecc", "m3", "Os", ["uECC.c"], flags=["-DuECC_OPTIMIZATION_LEVEL=1"], glue=["8051/ecc"]),
    # The 32- and 64-bit sums read tables that the project generates by running a program.
    "crc_m0_O0": Program("libcrc", "m0", "O0", ["src/*.c"], exclude=["src/crc32.c", "src/crc64.c", "src/nmea-chk.c"],
                         include=["include"], glue=["8051/crc"]),
    "printf_m3_O2": Program("printf", "m3", "O2", [], glue=["thumb/printf"]),
    "printf_m0_Os": Program("printf", "m0", "Os", [], glue=["thumb/printf"]),
    "fatfs_m4_Os": Program("fatfs", "m4", "Os", ["source/ff.c", "source/ffunicode.c"], include=["source"],
                           glue=["8051/fatfs"]),
    "fatfs_m0_O2": Program("fatfs", "m0", "O2", ["source/ff.c", "source/ffunicode.c"], include=["source"],
                           glue=["8051/fatfs"]),
    "uip_m3_Os": Program("uip", "m3", "Os", **UIP),
    "coremark_m0_O2": Program("coremark", "m0", "O2", **COREMARK),
    "coremark_m3_O0": Program("coremark", "m3", "O0", **COREMARK),
    "coremark_m4_O2": Program("coremark", "m4", "O2", **COREMARK),
    "freertos_m3_O2": Program("FreeRTOS-Kernel", "m3", "O2", **FREERTOS, extra={"FreeRTOS-Kernel": ["portable/GCC/ARM_CM3/port.c"]},
                              extra_include=["portable/GCC/ARM_CM3"]),
    "freertos_m0_Os": Program("FreeRTOS-Kernel", "m0", "Os", **FREERTOS, extra={"FreeRTOS-Kernel": ["portable/GCC/ARM_CM0/port.c", "portable/GCC/ARM_CM0/portasm.c"]},
                              extra_include=["portable/GCC/ARM_CM0"]),
    "freertos_m4f_O2": Program("FreeRTOS-Kernel", "m4f", "O2", **FREERTOS, extra={"FreeRTOS-Kernel": ["portable/GCC/ARM_CM4F/port.c"]},
                               extra_include=["portable/GCC/ARM_CM4F"]),
    "littlefs_m3_Os": Program("littlefs", "m3", "Os", **LITTLEFS),
    "littlefs_m0_O2": Program("littlefs", "m0", "O2", **LITTLEFS),
    "dsp_m4f_O2": Program("CMSIS-DSP", "m4f", "O2", [], include=DSP_INCLUDE, glue=["thumb/dsp"],
                          extra={"CMSIS-DSP": ["Source/BasicMathFunctions/BasicMathFunctions.c",
                                               "Source/FilteringFunctions/arm_fir_init_f32.c", "Source/FilteringFunctions/arm_fir_f32.c",
                                               "Source/FilteringFunctions/arm_biquad_cascade_df1_init_f32.c",
                                               "Source/FilteringFunctions/arm_biquad_cascade_df1_f32.c",
                                               "Source/MatrixFunctions/MatrixFunctions.c", "Source/StatisticsFunctions/arm_mean_f32.c", "Source/StatisticsFunctions/arm_rms_f32.c", "Source/StatisticsFunctions/arm_std_f32.c", "Source/StatisticsFunctions/arm_var_f32.c", "Source/StatisticsFunctions/arm_max_f32.c",
                                               "Source/SupportFunctions/SupportFunctions.c", "Source/ComplexMathFunctions/ComplexMathFunctions.c"],
                                 "CMSIS_6": []},
                          extra_include=["CMSIS/Core/Include"]),
    "dsp_m0_Os": Program("CMSIS-DSP", "m0", "Os", [], include=DSP_INCLUDE, glue=["thumb/dsp"],
                         extra={"CMSIS-DSP": ["Source/BasicMathFunctions/BasicMathFunctions.c",
                                              "Source/FilteringFunctions/arm_fir_init_q15.c", "Source/FilteringFunctions/arm_fir_q15.c",
                                              "Source/FilteringFunctions/arm_fir_init_f32.c", "Source/FilteringFunctions/arm_fir_f32.c",
                                              "Source/FilteringFunctions/arm_biquad_cascade_df1_init_f32.c",
                                              "Source/FilteringFunctions/arm_biquad_cascade_df1_f32.c",
                                              "Source/MatrixFunctions/MatrixFunctions.c", "Source/StatisticsFunctions/arm_mean_f32.c", "Source/StatisticsFunctions/arm_rms_f32.c", "Source/StatisticsFunctions/arm_std_f32.c", "Source/StatisticsFunctions/arm_var_f32.c", "Source/StatisticsFunctions/arm_max_f32.c",
                                              "Source/SupportFunctions/SupportFunctions.c", "Source/ComplexMathFunctions/ComplexMathFunctions.c"],
                                "CMSIS_6": []},
                         extra_include=["CMSIS/Core/Include"]),
    "minmea_m3_O2": Program("minmea", "m3", "O2", ["minmea.c", "example.c"], glue=["thumb/minmea"]),
}
# The same projects laid out as a vendor's build is, for Thumb-1 and Thumb-2.
GNU_LAYOUT = {
    "freertos_m0_Os_gnu": ("freertos_m0_Os", "m0", "Os"), "freertos_m3_O2_gnu": ("freertos_m3_O2", "m3", "O2"),
    "coremark_m0_O2_gnu": ("coremark_m0_O2", "m0", "O2"), "coremark_m3_Os_gnu": ("coremark_m3_O0", "m3", "Os"),
    "fatfs_m0_O2_gnu": ("fatfs_m0_O2", "m0", "O2"), "fatfs_m3_Os_gnu": ("fatfs_m4_Os", "m3", "Os"),
    "littlefs_m0_O2_gnu": ("littlefs_m0_O2", "m0", "O2"), "littlefs_m3_Os_gnu": ("littlefs_m3_Os", "m3", "Os"),
    "uip_m0_Os_gnu": ("uip_m3_Os", "m0", "Os"), "uip_m3_O2_gnu": ("uip_m3_Os", "m3", "O2"),
    "printf_m0_Os_gnu": ("printf_m0_Os", "m0", "Os"), "minmea_m3_O2_gnu": ("minmea_m3_O2", "m3", "O2"),
}
for name, (like, core, opt) in GNU_LAYOUT.items():
    PROGRAMS[name] = replace(PROGRAMS[like], core=core, opt=opt, gnu_layout=True)


def run(argv, **kwargs):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=300, **kwargs)
    if result.returncode != 0:
        errors = [line for line in (result.stdout + result.stderr).splitlines() if "warning" not in line]
        raise RuntimeError(f"{' '.join(map(str, argv[-3:]))}\n" + "\n".join(errors[:8]))
    return result.stdout


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


def sysroot():
    return Path(run(["rustc", "--print", "sysroot"]).strip())


def linker():
    host = run(["rustc", "-vV"]).split("host: ", 1)[1].split()[0]
    return sysroot() / "lib" / "rustlib" / host / "bin" / "rust-lld"


def builtins(core):
    """An archive of the compiler helpers Rust ships for the core's target, made once from the
    objects of its `compiler_builtins` rlib, whose metadata member the linker would not take."""
    target = CORES[core].rust_target
    archive = CORPUS / "obj" / "builtins" / f"{target}.a"
    if not archive.exists():
        (rlib,) = (sysroot() / "lib" / "rustlib" / target / "lib").glob("libcompiler_builtins-*.rlib")
        work = archive.parent / target
        shutil.rmtree(work, ignore_errors=True)
        work.mkdir(parents=True)
        run(["llvm-ar", "x", rlib], cwd=work)
        run(["llvm-ar", "rcs", archive, *sorted(work.glob("*.o"))])
    return archive


LINKER_SCRIPT = """\
MEMORY {{
  FLASH (rx) : ORIGIN = {flash:#x}, LENGTH = 512K
  RAM (rwx) : ORIGIN = {ram:#x}, LENGTH = 128K
}}
ENTRY(Reset_Handler)
_estack = ORIGIN(RAM) + LENGTH(RAM);
SECTIONS {{
  .isr_vector : {{ KEEP(*(.isr_vector)) }} > FLASH
  .text : {{ *(.text .text.*) }} > FLASH {fill}
  .rodata : {{ *(.rodata .rodata.*) . = ALIGN(4); }} > FLASH
  .data : {{ _sdata = .; *(.data .data.*) . = ALIGN(4); _edata = .; }} > RAM AT > FLASH
  _sidata = LOADADDR(.data);
  .bss (NOLOAD) : {{ _sbss = .; *(.bss .bss.* COMMON) . = ALIGN(4); _ebss = .; }} > RAM
  /DISCARD/ : {{ *(.ARM.exidx*) *(.ARM.extab*) }}
}}
"""


def build(name, program):
    core = CORES[program.core]
    root = fetch(program.project)
    work = CORPUS / "obj" / name
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)
    glue = [GLUE / directory for directory in program.glue]
    excluded = {p for pattern in program.exclude for p in root.glob(pattern)}
    sources = sorted(p for pattern in program.sources for p in root.glob(pattern) if p not in excluded)
    extra_roots = {project: fetch(project) for project in program.extra}
    sources += [extra_roots[project] / pattern for project, patterns in program.extra.items() for pattern in patterns]
    printf = fetch("printf")
    sources += [printf / "printf.c", *sorted(RUNTIME.glob("*.c")), *sorted(p for directory in glue for p in directory.glob("*.c"))]
    include = [*(f"-I{directory}" for directory in glue), f"-I{RUNTIME}", f"-I{printf}",
               *(f"-I{root / directory}" for directory in [".", *program.include]),
               *(f"-I{extra / directory}" for extra in extra_roots.values() for directory in [".", *program.extra_include]),
               "-isystem", str(RUNTIME / "include")]
    sections = [] if program.gnu_layout else ["-ffunction-sections", "-fdata-sections"]
    flags = [*core.flags, f"-{program.opt}", "-g", "-ffreestanding", *sections,
             "-fno-common", "-fno-unwind-tables", "-fno-asynchronous-unwind-tables", "-w", *program.flags]

    def compile_unit(source):
        obj = work / (source.stem + ".o")
        if obj.exists():
            raise RuntimeError(f"two translation units are named {source.stem}")
        unit = [flag.format(stem=source.stem.replace("-", "_")) for flag in program.unit_flags] if root in source.parents else []
        run(["clang", *flags, *include, *unit, f"-I{source.parent}", "-c", source, "-o", obj])
        return obj

    with ThreadPoolExecutor(JOBS) as pool:
        objects = list(pool.map(compile_unit, sources))
    script = work / "link.ld"
    script.write_text(LINKER_SCRIPT.format(flash=core.flash, ram=RAM, fill="=0" if program.gnu_layout else ""))
    elf = work / f"{name}.elf"
    run([linker(), "-flavor", "gnu", "-T", script, "--gc-sections", "-o", elf, *objects, builtins(program.core)])
    image = CORPUS / "image" / f"{name}.bin"
    run(["llvm-objcopy", "-O", "binary", elf, image])
    shutil.copy(elf, CORPUS / "debug" / f"{name}.debug")
    size = image.stat().st_size
    (CORPUS / "bin" / f"{name}.toml").write_text(
        f'machine = "cortex-m"\n\n[[region]]\nfile = "../image/{name}.bin"\noffset = 0x0\nlength = {size:#x}\n'
        f"address = {core.flash:#010x}\nexecutable = true\n")
    return size


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
