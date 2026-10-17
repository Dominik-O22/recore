# recore

Binary analysis built for AI agents. recore gets a compiled program ready to query more than 1,000 times faster than Ghidra, and serves it over the Model Context Protocol with no JVM, no GUI and no project database.

| 328 binaries, ELF and Windows PE | Time to analyze all of them |
|---|---|
| Ghidra 12.1.4, headless, 4 cores each | 5 hours 34 minutes |
| recore, 16 cores | 8.0 seconds |

That is 2,500 times faster overall, 1,089 times for the median binary, and up to 25,700 times for `eza`, which takes Ghidra 830 s and recore 32 ms. The Ghidra figure is its own reported analysis time, without JVM startup or import, which add 2 to 6 s a binary. The recore figure is a whole new process, from launch to answer. Pinned to a single core while Ghidra keeps its four, recore still takes 22 seconds for all of them, 900 times faster.

Most of Ghidra's time goes to two jobs: 44% to recovering jump tables, for which it runs its decompiler on every function that has one, and 16% to finding the functions that never return. recore settles both during its one pass over the code.

| Binary | Ghidra | recore |
|---|---|---|
| `git.exe`, 64-bit, 7,672 functions | 433 s | 0.08 s |
| `obs-browser.dll`, 64-bit | 20 s | 0.02 s |
| `bzip2.exe`, 64-bit | 6 s | 0.004 s |
| coconutBattery, Swift and Objective-C, macOS | 76 s at best, 40 minute timeout by default | 0.028 s |

The last row is from [an issue on the REA project](https://github.com/morluto/rea/issues/1783), where Ghidra's Objective-C analyzer stalls. Those Ghidra times are from the reporter's machine. recore resolves the selector of 4,293 of that program's 4,294 message sends in the same 28 ms.

## Built for agents

An agent asks many small questions and cannot click through a GUI. recore is shaped around that:

- **One process, stdio, plain text.** `recore-mcp` is an MCP server. Every answer is text sized for a context window, with addresses the next call accepts as they are.
- **Nothing to wait for.** A binary is analyzed in milliseconds on first touch and kept. Functions are decompiled when asked for.
- **Findings stick.** Names, comments, C structs and function prototypes are saved per binary and change every later answer, the decompiled C included.
- **A bad function costs one function.** The decompiler runs in a child process with a time limit. A crash or a hang is reported for that function and the session carries on.
- **The same tools from a shell.** `recore-mcp <tool> <binary>` runs one tool and prints the answer.

```
recore-mcp summary program.exe
recore-mcp strings program.exe 'license|serial'
recore-mcp decompile program.exe 0x401260
recore-mcp trace program.exe 0x401260 --param 1
recore-mcp rename program.exe 0x401260 check_license
recore-mcp rename program.exe check_license param_1 serial
```

| | Tools |
|---|---|
| Look around | `summary`, `functions`, `strings`, `imports`, `symbols`, `classes`, `addr`, `bytes` |
| Read code | `function`, `xrefs`, `disassemble`, `decompile`, `pcode`, `trace`, `structs` |
| Compare builds | `diff` |
| Record findings | `rename`, `comment`, `declare`, `type` |

[crates/mcp/README.md](crates/mcp/README.md) describes each one.

## Agents on real tasks

Three tasks on public binaries, each with one answer. List what `git version --build-options` prints, from Git for Windows' `git.exe`. Find `chr()` in `python313.dll` and say what it rejects. Explain Debian's security update of libexpat from its two builds. A fresh Claude session gets the binaries, one tool and no hints, and its report is scored against a 17-item key. Ghidra 12.1.4 runs as an MCP server, [pyghidra-mcp](https://github.com/clearbluejar/pyghidra-mcp), over binaries it analyzed before the session started, with [ghidriff](https://github.com/clearbluejar/ghidriff) to compare the builds and headless scripting allowed.

| Model | Tool | Score of 17 | Session | Analysis first | Tokens read | Cost |
|---|---|---|---|---|---|---|
| Haiku 5.5 | recore | 16.8 | 288 s | none | 1.68 M | $0.08 |
| Haiku 5.5 | Ghidra | 13 | 284 s | 513 s | 3.85 M | $0.26 |
| Sonnet 5.5 | recore | 16.0 | 118 s | none | 0.43 M | $0.26 |
| Sonnet 5.5 | Ghidra | 15 | 541 s | 513 s | 3.11 M | $1.10 |

recore's rows are the mean of four sessions and Ghidra's are one session each, so the table is an illustration and not a benchmark. Ghidra analyzes the four binaries before the session starts. pyghidra-mcp then spends another 906 s decompiling every function to index it for search, which the table leaves out. recore analyzes a binary on every command-line call, in 10 to 100 ms here from a new process to its answer, and once as an MCP server. Tokens read is the context of every response, summed.

Both tools get the answers for git and Python. They part on the libexpat update. Both Ghidra sessions missed two of the five functions that set the parser's hash salt, a field at offset `0x398`: they store it through expressions such as `param_1[0x73]`, which a search of the decompiled C for `0x398` does not find. recore's `xrefs --offset 0x398` lists every instruction that writes the field. Haiku with Ghidra also worked from ghidriff's report, which lists 43 functions deleted and 38 added where neither build lost or gained one, and left the modified functions it had not reached "not verified". With recore, each session started from `diff`:

```
$ recore-mcp diff libx-before.so --to libx-after.so
295 functions before, 295 after: 275 the same, 20 changed, 0 removed, 0 added
...
0x88f0(XML_ParseBuffer) 476 -> 0x8780(XML_ParseBuffer) 470  (same name)
    no longer calls 0x6350 (after: 0x60f0)
    no longer uses "xml=http://www.w3.org/XML/1998/namespace"
    + if (param_2 < 0) {
    + *(undefined4 *)(param_1 + 0x218) = 0x29;
    + }
...
changed in numbers only, 17: the same instructions with other constants or offsets, ...
0x4930 -> 0x48e0  0x1e7b -> 0x1e94
0x50e0 -> 0x5090  0x1df2 -> 0x1e0b
0x91e0(XML_GetParsingStatus) -> 0x9040(XML_GetParsingStatus)  0x8c3 -> 0x8c9
```

Those numbers are source line numbers that assertions and accounting report, moved by the lines the update added.

Opus 5.5 is left out: in three sessions its safeguards stopped the response after `recore-mcp --help`, before the first task.

[`bench/agent`](bench/agent) fetches the binaries, runs a session with either tool and scores it.

## How

The analysis is written from scratch in Rust: loading, function discovery, calls that never return, jump tables, strings, references, library function names by fingerprint, and C++, Objective-C and Swift classes with their methods. The C comes from Ghidra's decompiler engine, compiled into recore and fed recore's analysis instead of Ghidra's.

It reads ELF, Windows PE and Mach-O for x86, x86-64 and AArch64, ELF for 32-bit ARM, A32 and Thumb-2 side by side, and raw firmware that a layout file describes: 8051 and ARM Cortex-M.

## Fast is not sloppy

Scored against debug information, on the same binaries as Ghidra. Mach-O binaries have none, so their truth is the symbol table of the unstripped original plus the linker's list of function starts.

| Corpus | | Functions found | Precision | Jump tables exact |
|---|---|---|---|---|
| Linux x86-64 | recore | 100.0% | 100.0% | 535 of 535 |
| | Ghidra | 99.7% | 97.1% | 487 of 535 |
| Linux AArch64 | recore | 100.0% | 99.9% | |
| | Ghidra | 100.0% | 99.9% | |
| Linux 32-bit ARM, armhf | recore | 99.1% | 99.6% | 5,090 of 5,161 |
| | Ghidra | 64.3% | 99.8% | 4,123 of 5,161 |
| Linux 32-bit ARM, armel | recore | 99.0% | 99.6% | 5,252 of 5,323 |
| | Ghidra | 55.1% | 99.7% | 3,821 of 5,323 |
| Windows x86 | recore | 99.3% | 98.8% | 6,244 of 6,277 |
| | Ghidra | 83.1% | 98.5% | 5,834 of 6,277 |
| Windows x86-64 | recore | 99.8% | 98.2% | 3,151 of 3,159 |
| | Ghidra | 91.0% | 97.9% | 2,972 of 3,159 |
| AArch64 Mach-O | recore | 100.0% | 100.0% | |
| | Ghidra | 100.0% | 99.7% | |
| AArch64 Mach-O, function starts hidden | recore | 99.8% | 99.9% | |
| | Ghidra | 75.5% | 99.2% | |
| x86-64 Mach-O | recore | 100.0% | 100.0% | |
| | Ghidra | 99.9% | 99.1% | |
| x86-64 Mach-O, function starts hidden | recore | 99.2% | 99.2% | |
| | Ghidra | 72.0% | 98.2% | |

The two 32-bit ARM corpora are the Debian builds of the same packages as the others. armhf is Thumb-2, with A32 in the PLT, in the C runtime and in all the Rust code. armel is A32 throughout. Their truth is the symbol table of each debug file, where `$a`, `$t` and `$d` symbols say what each byte is, and their jump tables are the ones GCC and clang dispatch to in five ways, each kept only where every case is an instruction of its function. A stripped binary has no such symbols, and recore tells A32 from Thumb by the bit ARM sets on every pointer to Thumb code: it puts 99.96% of armhf functions and every armel one in the right instruction set. Ghidra took 96 minutes of analysis over the 152 binaries, with 4 cores each, and recore 7 seconds on one core. Of the functions Ghidra misses, recore first finds a third through a pointer in data, a quarter through `.ARM.exidx`, a fifth in the gaps between functions, where Debian's builds keep library code nothing calls, and a tenth through an address the code computes.

The Linux AArch64 and Mach-O corpora have no jump table truth. A stripped Mach-O binary keeps the linker's list of function starts and both tools read it, so the rows with it hidden show what each finds on its own.

Three of Ghidra's exports give a jump table target as a negative number, which the scorer rejects along with the whole binary. They were scored with those targets written as unsigned.

Decompiled function signatures against PDB records, 8 binaries per corpus:

| Corpus | | Functions decompiled | Parameters exact | Returns a value or not |
|---|---|---|---|---|
| Windows x86-64 | recore | 99.7% | 89.8% | 93.2% |
| | Ghidra | 91.9% | 82.6% | 92.7% |
| Windows x86 | recore | 98.8% | 85.8% | 91.0% |
| | Ghidra | 85.4% | 86.1% | 90.5% |

Each tool's percentages are over the functions it decompiled, and recore decompiles more of them. On the 8,523 32-bit functions both decompiled, recore gets the parameters of 86.5% right and Ghidra 86.1%.

Against DWARF, on six programs of each Linux ARM corpus, recore gets the parameter count right for 72.4% of armhf functions and 72.8% of armel ones, and for 75.8% of arm64 ones on the same programs. In C code that is 85.4%, 85.0% and 92.7%. A 64-bit argument takes two registers on 32-bit ARM, which is part of the gap.

References from code to data have no ground truth, so they are scored against Ghidra's own, on 11 binaries: recore finds 96.6% of them on Linux x86-64, 91.8% on Windows x86, 96.0% on Windows x86-64 and 85.2% on Linux AArch64. Most of the rest are a later element or field of an object recore refers to the start of, which Ghidra reaches by following a loop or a constant index.

With unwind tables hidden, recore finds 99.8% of functions on Linux x86-64 and 99.2% on Linux AArch64. 32-bit ARM C code has no unwind table to hide, and its C++ and Rust code has `.ARM.exidx`. With that hidden, recore finds 98.6% on armhf and 98.3% on armel, and takes many landing pads of the C++ and Rust code for functions, at 95.0% and 78.4% precision. A binary with landing pads keeps the table, since unwinding needs it. It finds every C++ class that has type information in the Linux and macOS corpora, 13,952 of them, at the right vtable address.

## Firmware

A firmware image has no header that says where its bytes load or where execution starts. A layout file beside the image says so, and recore takes the layout wherever it takes an executable:

```toml
machine = "8051"
compiler = "keil"
entry = [0x0000]

[[region]]
file = "image.bin"
offset = 0x10000
length = 0x10000
address = 0x010000
executable = true

[banking]
common = [[0x0000, 0x4000]]

[[banking.trampoline]]
entry = "90 hh ll 02 ss ss"
stub = "e5 2a c0 e0 02 31 .."
```

An 8051 addresses 64 KB of code, and larger programs switch banks. recore gives each bank its own range of addresses, loads the code the banks share once, and reads a call through a bank-switching trampoline as a call of the function it reaches. The trampolines are byte patterns in the layout, so a compiler's scheme is data and not code.

What is not yet known can be left open. `recore sweep` then finds which bank each region is, which ranges the banks share and which trampoline scheme the image uses, and writes the completed layout. It ranks candidates by a score that needs no ground truth, which counts where jumps and calls between regions land. On three banked programs of the corpus below and on a 1.1 MB monitor firmware built with Keil C51, with the answers withheld, it places every bank correctly: 3 banks in about 10 ms and 17 banks in 205 ms. Against 122 deliberately wrong layouts of the corpus programs, the right one scores higher in all 111 that change the analysis. The sweep knows two trampoline schemes: SDCC's, and Keil's in every configuration of its bank switch whose table uses `LJMP`. It does not search for a region's load address.

Scored against the debug records of 24 open source programs built with SDCC, 21 of which Ghidra can load as one flat image. Both tools start from the same entry points.

| 21 programs, 8051 | Functions found | Precision | Jump tables exact |
|---|---|---|---|
| recore | 99.6% | 99.4% | 16 of 16 |
| Ghidra | 84.8% | 65.9% | 8 of 16 |

Most of Ghidra's wrong starts are inside SDCC's `printf`, which it cuts into about 50 functions. Over all 24 programs, the three banked ones included, recore finds 99.7% at 99.3% precision and reads 19 of 19 jump tables. Two of the truth rules were written after seeing misses and both concern the two Cypress FX2 programs: their interrupt jump table counts as code, and the layout lists its 46 entries, because the chip indexes that table itself and no code refers to it.

The monitor firmware, 17 banks of Keil C51 code, analyzes in 40 ms: 10,537 functions, 529 jump tables and 1,561 trampolines. An emulator that ran 40% of its instructions executed no byte that recore had not listed as code and called no address that recore had not found as a function. Every function decompiles, in 1.4 ms on average.

The decompiler names the compiler's library routines by a hash of their code, so a call of Keil's 32-bit divide reads as a division. It takes its calling convention from the layout's `compiler`. Against SDCC's debug records it gets the parameters of 54.2% of functions right and whether they return a value for 83.8%. That is well short of the Windows figures above. Two-byte values that the code builds from single bytes still print as `CONCAT11(high,low)` in half of SDCC's functions and a fifth of Keil's.

A `names` file gives the hardware's registers and bits their names, the standard 8051 ones are built in, and `recore-mcp unnamed` lists the addresses the code uses most that have none. Text is found where it is stored as ASCII. A firmware that stores its menu as indices into its own font, as the monitor's does, shows none of that text.

A Cortex-M layout needs only `machine = "cortex-m"` and its flash region. recore reads the reset handler and every interrupt handler from the vector table, which it takes to start the lowest executable region unless the layout says `vectors = <address>`, or `vectors = "none"` with the entry points in `entry`. It is scored against the ELF each image was cut from, with Ghidra seeded from the same vector table. 27 programs are built by clang for Cortex-M0, M3 and M4 at `-O0`, `-Os` and `-O2`, each function in its own section. 12 more are laid out as a vendor build usually is, with no per-function sections, so unused library functions stay in the image between the used ones.

| Cortex-M | | Functions found | Precision | Jump tables exact |
|---|---|---|---|---|
| 27 programs | recore | 99.9% | 100.0% | 119 of 119 |
| | Ghidra | 91.5% | 98.6% | 112 of 119 |
| 12 vendor-style builds | recore | 99.3% | 99.9% | 57 of 59 |
| | Ghidra | 66.8% | 98.6% | 49 of 59 |

recore analyzes all 39 in 55 ms, none taking more than 3 ms. Most of the functions Ghidra misses are reached only by a tail call, by an address the code builds with `MOVW` and `MOVT`, or, in the vendor-style builds, by nothing at all. recore finds those by dividing the unreached code between functions into whole functions. Every function decompiles, in 3 ms on average, and against DWARF the number of parameters is right for 86.7% of the C functions. The System Control Space registers, such as `SYST_RVR` and the NVIC's, are named without a names file. The corpus has no GCC-built code, because no ARM GCC was at hand. GCC's Thumb-1 switch helpers are recognised, and tested only on hand-assembled code.

## What Ghidra does that recore does not

- **Processors.** Ghidra covers dozens. recore covers six.
- **Types.** Ghidra ships struct layouts for the common libraries and lets a user edit types in a GUI. recore knows the types a caller declares, the prototypes of Windows, C library and macOS functions, classes from MSVC and Itanium type information and Objective-C metadata, and, when a binary has DWARF or a PDB, the structs, prototypes and globals in it. Without debug info, recore gives each pointer parameter a function reads fields through a struct of those fields, so the C reads `param_1->field_0x28`. Ghidra prints `*(long *)(param_1 + 0x28)` until a user creates the struct. `rename` names a recovered struct and its fields and saves them, and giving two functions' structs one name makes them one type.
- **A GUI**, a debugger, scripting, and a database of everything it found.

Other limits: a Swift method that is only in a vtable is named by its kind and place, as `Type.getter_2`, because the image holds no name for it; `trace` does not follow a value through memory; a name goes on a function, on data or on a variable of a function, not on an address inside a function; arm64e Mach-O loads but is untested.

## Installing

Each [release](https://github.com/Dominik-O22/recore/releases) has `recore-mcp` for Linux on x86-64 and arm64 and for macOS on Apple silicon, as one self-contained binary. With [mise](https://mise.jdx.dev), which checks the release's signature before it installs:

```
mise use -g packslip:github.com/Dominik-O22/recore
```

## Building

A Rust toolchain, a C++ compiler and cmake. The C++ compiler builds the decompiler engine, vendored under `third_party/`, and cmake builds the Swift demangler.

```
cargo build --release
```

With [mise](https://mise.jdx.dev), `mise install` fetches the Rust toolchain and cmake, and `mise run build`, `mise run test` and `mise run dist` do the rest. `dist` packs `recore-mcp` for the machine it runs on, as a release does. The binary is self-contained: the decompiler's language files are part of it.

For Claude Code, in `.mcp.json`:

```json
{
  "mcpServers": {
    "recore": { "command": "/path/to/recore/target/release/recore-mcp" }
  }
}
```

## Reproducing the numbers

The corpora are not in the repository. `corpus/fetch*.py` download them, except the monitor firmware, a vendor's image that is not ours to share, `corpus/build_8051.py` builds the 8051 programs with SDCC, `corpus/build_thumb.py` the Cortex-M ones with clang, `ghidra/run-reference.sh` runs Ghidra over them and records its times, and `check.sh` analyzes and scores them with recore. Ghidra refuses a project path that has a part starting with a dot. `ghidra/run-refs.sh` and `recore-corpus score-references` produce the reference comparison. `recore-bench run analysis --save <name>` and `--compare <name>` hold a change against an earlier build. Next to the times they report the processor instructions executed, which stay the same to a few hundredths of a percent whatever else the machine is doing.

The speed table compares Ghidra's `Total Time` per binary with the wall time of `recore-mcp summary`, fastest of three runs, and `ghidra/speed.py` measures it. Both ran on the same Ryzen 7 9850X3D. Ghidra analyzed several binaries at a time with 4 cores each, and recore one at a time, with all cores or pinned to one with `taskset`.

| Directory | Contents |
|---|---|
| `crates/core` | Loading and analysis |
| `crates/decomp` | Ghidra's decompiler engine as a library |
| `crates/mcp` | The MCP server and command line |
| `crates/corpus`, `crates/bench` | Scorers, timings and a profiler |
| `third_party/ghidra-decompiler` | The vendored engine, with its own licence notes |

## Licence

Apache 2.0. The vendored decompiler engine is Apache 2.0 from the Ghidra project, with zlib under its own licence. The prototypes in `crates/decomp/data/*.protos` come from Ghidra's type archives, under the same licence.
