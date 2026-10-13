# recore

Binary analysis built for AI agents. recore gets a compiled program ready to query more than 1,000 times faster than Ghidra, and serves it over the Model Context Protocol with no JVM, no GUI and no project database.

| 252 binaries, ELF and Windows PE | Time to analyze all of them |
|---|---|
| Ghidra 12.1.4, headless, 4 cores each | 4 hours 30 minutes |
| recore, one thread | 12.1 seconds |
| recore, 16 cores | 8.0 seconds |

That is 1,338 times faster overall, and 881 times for the median binary. The Ghidra figure is its own reported analysis time, without JVM startup or import. The recore figure is a whole new process, from launch to answer.

Most of Ghidra's time goes to two jobs: 44% to recovering jump tables, for which it runs its decompiler on every function that has one, and 16% to finding the functions that never return. recore settles both during its one pass over the code.

| Binary | Ghidra | recore |
|---|---|---|
| `git.exe`, 64-bit, 7,672 functions | 433 s | 0.19 s |
| `obs-browser.dll`, 64-bit | 21 s | 0.036 s |
| `bzip2.exe`, 64-bit | 7 s | 0.005 s |
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
| Read code | `function`, `xrefs`, `disassemble`, `decompile`, `pcode`, `trace` |
| Compare builds | `diff` |
| Record findings | `rename`, `comment`, `declare`, `type` |

[crates/mcp/README.md](crates/mcp/README.md) describes each one.

## One session

A stripped program that checks a licence key, and two stripped builds of Lua 5.4.8 that differ by a small patch. A fresh agent got one tool and no hints: find a key the program accepts, then say what the patch changed. The same two tasks went to Claude Haiku once with `recore-mcp` and once with Ghidra 12.1.4 headless. Both found the key and described every change correctly.

| | recore | Ghidra |
|---|---|---|
| Find the key | 54 s, 10 calls | 101 s, 4 runs |
| Explain the patch | 182 s, 22 calls | 445 s, 9 runs |
| Scripts the agent had to write | none | 5 |
| Tokens used | 104,000 | 164,000 |

That is one run each, so the times are an illustration and not a benchmark. With Ghidra the agent wrote Java scripts to list strings, decompile and compare, rewrote its comparison twice because addresses inside the decompiled text made unchanged functions look changed, and ended with five functions to rule out by hand. With recore it called `diff`:

```
$ recore-mcp diff lua-before lua-after
786 functions before, 787 after: 782 the same, 4 changed, 0 removed, 1 added

changed, as before -> after with bytes of code
0xa5f0 78 -> 0xa630 94  (same place among its neighbours, listed as "rawlen")
    now calls 0x5bb0
0x19b10 100 -> 0x19b50 116  (same place among its neighbours, listed as "abs")
0x22ad0 185 -> 0x22b10 185  (same place among its neighbours, listed as "reverse")
0x283f0 289 -> 0x28430 337  (same place among its neighbours, listed as "insert")
    now uses "too many arguments"

removed: none

added
0x5bb0 71
```

The key took six calls that mattered: `summary`, `strings`, `imports`, `functions`, one `decompile` of three functions, and `bytes` for the two tables the check reads. The run above is from before `diff` printed the calls, strings and table names of each change, which that run's report asked for.

## How

The analysis is written from scratch in Rust: loading, function discovery, calls that never return, jump tables, strings, references, library function names by fingerprint, and C++, Objective-C and Swift classes with their methods. The C comes from Ghidra's decompiler engine, compiled into recore and fed recore's analysis instead of Ghidra's.

It reads ELF, Windows PE and Mach-O for x86, x86-64 and AArch64, and raw 8051 firmware that a layout file describes.

## Fast is not sloppy

Scored against debug information, on the same binaries as Ghidra. Mach-O binaries have none, so their truth is the symbol table of the unstripped original plus the linker's list of function starts.

| Corpus | | Functions found | Precision | Jump tables exact |
|---|---|---|---|---|
| Linux x86-64 | recore | 100.0% | 100.0% | 535 of 535 |
| | Ghidra | 99.7% | 97.1% | 487 of 535 |
| Linux AArch64 | recore | 100.0% | 99.9% | |
| | Ghidra | 100.0% | 99.9% | |
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

References from code to data have no ground truth, so they are scored against Ghidra's own, on 11 binaries: recore finds 96.6% of them on Linux x86-64, 91.8% on Windows x86, 96.0% on Windows x86-64 and 85.2% on Linux AArch64. Most of the rest are a later element or field of an object recore refers to the start of, which Ghidra reaches by following a loop or a constant index.

With unwind tables hidden, recore finds 99.8% of functions on Linux x86-64 and 99.2% on Linux AArch64. It finds every C++ class that has type information in the Linux and macOS corpora, 13,952 of them, at the right vtable address.

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
stub = "e5 49 c0 e0 02 46 .."
```

An 8051 addresses 64 KB of code, and larger programs switch banks. recore gives each bank its own range of addresses, loads the code the banks share once, and reads a call through a bank-switching trampoline as a call of the function it reaches. The trampolines are byte patterns in the layout, so a compiler's scheme is data and not code.

What is not yet known can be left open. `recore sweep` then finds which bank each region is, which ranges the banks share and which trampoline scheme the image uses, and writes the completed layout. It ranks candidates by a score that needs no ground truth, which counts where jumps and calls between regions land. On three banked programs of the corpus below and on a 1.1 MB monitor firmware built with Keil C51, with the answers withheld, it places every bank correctly: 3 banks in under 45 ms and 17 banks in 250 ms. Against 124 deliberately wrong layouts of the corpus programs, the right one scores higher in all 113 that change the analysis. The sweep knows two trampoline schemes, Keil's and SDCC's, and does not search for a region's load address.

Scored against the debug records of 24 open source programs built with SDCC, 21 of which Ghidra can load as one flat image. Both tools start from the same entry points.

| 21 programs, 8051 | Functions found | Precision | Jump tables exact |
|---|---|---|---|
| recore | 99.6% | 99.4% | 16 of 16 |
| Ghidra | 84.8% | 65.9% | 8 of 16 |

Most of Ghidra's wrong starts are inside SDCC's `printf`, which it cuts into about 50 functions. Over all 24 programs, the three banked ones included, recore finds 99.7% at 99.3% precision and reads 19 of 19 jump tables. Two of the truth rules were written after seeing misses and both concern the two Cypress FX2 programs: their interrupt jump table counts as code, and the layout lists its 46 entries, because the chip indexes that table itself and no code refers to it.

The monitor firmware, 17 banks of Keil C51 code, analyzes in 40 ms: 10,537 functions, 529 jump tables and 1,561 trampolines. An emulator that ran 40% of its instructions executed no byte that recore had not listed as code and called no address that recore had not found as a function. Every function decompiles, in 1.4 ms on average.

The decompiler names the compiler's library routines by a hash of their code, so a call of Keil's 32-bit divide reads as a division. It takes its calling convention from the layout's `compiler`. Against SDCC's debug records it gets the parameters of 54.3% of functions right and whether they return a value for 86.6%. That is well short of the Windows figures above. Two-byte values that the code builds from single bytes still print as `CONCAT11(high,low)` in half of SDCC's functions and a fifth of Keil's.

A `names` file gives the hardware's registers their names, the standard 8051 ones are built in, and `recore-mcp unnamed` lists the addresses the code uses most that have none. Text is found where it is stored as ASCII. A firmware that stores its menu as indices into its own font, as the monitor's does, shows none of that text.

## What Ghidra does that recore does not

- **Processors.** Ghidra covers dozens. recore covers four.
- **Types.** Ghidra ships struct layouts for the common libraries and lets a user edit types in a GUI. recore knows the types a caller declares, the prototypes of Windows, C library and macOS functions, classes from MSVC and Itanium type information and Objective-C metadata, and, when a binary has DWARF or a PDB, the structs, prototypes and globals in it.
- **A GUI**, a debugger, scripting, and a database of everything it found.

Other limits: a Swift method that is only in a vtable is named by its kind and place, as `Type.getter_2`, because the image holds no name for it; `trace` does not follow a value through memory; a name goes on a function, on data or on a variable of a function, not on an address inside a function; arm64e Mach-O loads but is untested.

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

The corpora are not in the repository. `corpus/fetch*.py` download them, `corpus/build_8051.py` builds the 8051 programs with SDCC, `ghidra/run-reference.sh` runs Ghidra over them and records its times, and `check.sh` analyzes and scores them with recore. `ghidra/run-refs.sh` and `recore-corpus score-references` produce the reference comparison. `recore-bench run analysis --save <name>` and `--compare <name>` hold a change against an earlier build. Next to the times they report the processor instructions executed, which stay the same to a few hundredths of a percent whatever else the machine is doing.

The speed table compares Ghidra's `Total Time` per binary with the wall time of `recore-mcp summary`, fastest of three runs. Both ran on the same Ryzen 7 9850X3D. Ghidra analyzed several binaries at a time with 4 cores each, and recore one at a time.

| Directory | Contents |
|---|---|
| `crates/core` | Loading and analysis |
| `crates/decomp` | Ghidra's decompiler engine as a library |
| `crates/mcp` | The MCP server and command line |
| `crates/corpus`, `crates/bench` | Scorers, timings and a profiler |
| `third_party/ghidra-decompiler` | The vendored engine, with its own licence notes |

## Licence

Apache 2.0. The vendored decompiler engine is Apache 2.0 from the Ghidra project, with zlib under its own licence.
