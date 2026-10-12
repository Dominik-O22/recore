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
```

| | Tools |
|---|---|
| Look around | `summary`, `functions`, `strings`, `imports`, `symbols`, `classes`, `addr`, `bytes` |
| Read code | `function`, `xrefs`, `disassemble`, `decompile`, `pcode`, `trace` |
| Record findings | `rename`, `comment`, `declare`, `type` |

[crates/mcp/README.md](crates/mcp/README.md) describes each one.

## How

The analysis is written from scratch in Rust: loading, function discovery, calls that never return, jump tables, strings, references, C++ and Objective-C classes. The C comes from Ghidra's decompiler engine, compiled into recore and fed recore's analysis instead of Ghidra's.

It reads ELF, Windows PE and Mach-O for x86, x86-64 and AArch64.

## Fast is not sloppy

Scored against debug information, on the same binaries as Ghidra.

| Corpus | | Functions found | Precision | Jump tables exact |
|---|---|---|---|---|
| Linux x86-64 | recore | 100.0% | 100.0% | 535 of 535 |
| | Ghidra | 99.9% | 96.8% | 487 of 535 |
| Windows x86 | recore | 99.3% | 98.8% | 6,244 of 6,277 |
| | Ghidra | 83.1% | 98.5% | 5,834 of 6,277 |
| Windows x86-64 | recore | 99.8% | 98.2% | 3,137 of 3,159 |
| | Ghidra | 91.0% | 97.9% | 2,972 of 3,159 |

Ghidra's Linux run covers 110 of that corpus's 184 binaries, so those two rows are not over the same set.

Decompiled function signatures against PDB records, 8 binaries per corpus:

| Corpus | | Functions decompiled | Parameters exact | Returns a value or not |
|---|---|---|---|---|
| Windows x86-64 | recore | 99.7% | 88.5% | 93.3% |
| | Ghidra | 91.9% | 82.6% | 92.7% |
| Windows x86 | recore | 98.8% | 85.8% | 91.0% |
| | Ghidra | 85.4% | 86.1% | 90.5% |

Each tool's percentages are over the functions it decompiled, and recore decompiles more of them. On the 8,523 32-bit functions both decompiled, recore gets the parameters of 86.5% right and Ghidra 86.1%.

References from code to data have no ground truth, so they are scored against Ghidra's own, on 11 binaries: recore finds 96.3% of them on Linux x86-64, 88.2% on Windows x86, 93.2% on Windows x86-64 and 85.1% on Linux AArch64.

There is no Ghidra run for function recovery on the Linux AArch64 and Mach-O corpora. With unwind tables hidden, recore finds 99.2% of functions on Linux AArch64. With the linker's list of function starts hidden, it finds 98.6% on AArch64 Mach-O and 99.2% on x86-64 Mach-O.

## What Ghidra does that recore does not

- **Processors.** Ghidra covers dozens. recore covers three.
- **Types.** Ghidra propagates data types and imports them from PDB and DWARF. recore knows the types a caller declares, Windows API prototypes, and classes from MSVC type information and Objective-C metadata.
- **A GUI**, a debugger, scripting, and a database of everything it found.

Other limits: a Swift method that is only in a vtable is named by its kind and place, as `Type.getter_2`, because the image holds no name for it; `trace` does not follow a value through memory; a name goes on a function or on data, not on a place inside a function; arm64e Mach-O loads but is untested.

## Building

A Rust toolchain, a C++ compiler and cmake. The C++ compiler builds the decompiler engine, vendored under `third_party/`, and cmake builds the Swift demangler.

```
cargo build --release
```

For Claude Code, in `.mcp.json`:

```json
{
  "mcpServers": {
    "recore": { "command": "/path/to/recore/target/release/recore-mcp" }
  }
}
```

## Reproducing the numbers

The corpora are not in the repository. `corpus/fetch*.py` download them, `ghidra/run-reference.sh` runs Ghidra over them and records its times, and `check.sh` analyzes and scores them with recore. `ghidra/run-refs.sh` and `recore-corpus score-references` produce the reference comparison. `recore-bench run analysis --save <name>` and `--compare <name>` hold a change against an earlier build. Next to the times they report the processor instructions executed, which stay the same to a few hundredths of a percent whatever else the machine is doing.

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
