# recore

recore analyzes a compiled program and hands the result to an AI agent: where its functions are, what they call, what they refer to, and what they look like as C. It reads ELF, Windows PE and Mach-O files for x86, x86-64 and AArch64.

The analysis is written from scratch in Rust and takes milliseconds. The C comes from Ghidra's decompiler engine, built into recore and fed recore's analysis instead of Ghidra's. There is no Ghidra install, no JVM and no project database.

## What an agent gets

`recore-mcp` is a Model Context Protocol server over stdio. The same program runs any one tool from a shell. [crates/mcp/README.md](crates/mcp/README.md) describes every tool.

| | Tools |
|---|---|
| Look around | `summary`, `functions`, `strings`, `imports`, `symbols`, `classes`, `addr`, `bytes` |
| Read code | `function`, `xrefs`, `disassemble`, `decompile`, `pcode`, `trace` |
| Record findings | `rename`, `comment`, `declare`, `type` |

Names, comments, C types and function prototypes are saved per binary and change every later answer, the decompiled C included.

```
recore-mcp summary program.exe
recore-mcp strings program.exe 'license|serial'
recore-mcp decompile program.exe 0x401260
recore-mcp trace program.exe 0x401260 --param 1
recore-mcp rename program.exe 0x401260 check_license
```

## How it compares with Ghidra

Every number here comes from the corpora and scorers in this repository, against ground truth from debug information. Ghidra is 12.1.4, run headless with its default analyzers.

### Finding functions

| Corpus | | Function recall | Precision | Never-returning calls found | Jump tables exact |
|---|---|---|---|---|---|
| Linux x86-64, 184 binaries | recore | 100.0% | 100.0% | 100.0% | 535 of 535 |
| | Ghidra, 110 of them | 99.9% | 96.8% | 72.7% | 487 of 535 |
| Windows x86, 65 binaries | recore | 99.3% | 98.8% | 98.2% | 6,244 of 6,277 |
| | Ghidra | 83.1% | 98.5% | 83.4% | 5,834 of 6,277 |
| Windows x86-64, 71 binaries | recore | 99.8% | 98.2% | 99.1% | 3,137 of 3,159 |
| | Ghidra | 91.0% | 97.9% | 86.4% | 2,972 of 3,159 |

The Ghidra run on the Linux corpus covers 110 of its 184 binaries, so those two rows are not over the same set. There is no Ghidra run for the two remaining corpora. On 74 Linux AArch64 binaries recore scores 100.0% recall. On 88 Mach-O binaries the linker's list of function starts is most of the ground truth, so the fair runs hide it from recore: 98.6% recall on AArch64 and 99.2% on x86-64.

With the unwind tables hidden as well, recall is 99.8% on Linux x86-64, 99.2% on Linux AArch64, 98.5% on Windows x86-64, 96.5% on AArch64 Mach-O and 98.1% on x86-64 Mach-O.

### Decompiled signatures

Parameter counts and whether a function returns a value, against PDB records, on the 8 binaries per corpus that both tools ran on.

| Corpus | | Functions decompiled | Parameters exact | Returns a value or not |
|---|---|---|---|---|
| Windows x86-64, 9,572 functions | recore | 99.7% | 87.9% | 91.4% |
| | Ghidra | 91.9% | 82.6% | 92.7% |
| Windows x86, 10,030 functions | recore | 98.8% | 85.7% | 90.1% |
| | Ghidra | 85.4% | 86.1% | 90.5% |

Ghidra is ahead on the return column in both corpora and on parameters for 32-bit code.

### Speed

Analysis runs at about 100 ns per instruction on one machine (Ryzen 7 9850X3D): 240 ms for a 2.6 million instruction binary, 4 ms from a new process to a summary of a small one.

One outside data point: [an issue on the REA project](https://github.com/morluto/rea/issues/1783) reports Ghidra's analysis of a 1.85 MB Swift and Objective-C program timing out after 40 minutes by default, and taking 76 seconds with one analyzer turned off. recore analyzes the same file in 28 ms and resolves the selector of 4,293 of its 4,294 Objective-C message sends. The Ghidra times are from the reporter's machine, not from ours.

## What is missing

- **Processors and formats.** Only x86, x86-64 and AArch64, in ELF, PE and Mach-O. Ghidra covers dozens of processors.
- **Type recovery.** Structs come from what the caller declares. Nothing infers them from code, and there is no import of PDB or DWARF types.
- **C++ classes on Linux and macOS.** Classes are read from MSVC type information and from Objective-C metadata only.
- **Swift.** Names are demangled, but Swift's own metadata is not read, which costs function recall on Swift programs without symbols.
- **Edits.** A name goes on a function or on data, not on a place inside a function. Each edit restarts the decompiler process.
- **`trace`.** It does not follow a value through memory.
- **arm64e** Mach-O files load but are untested.

## Building

A Rust toolchain, a C++ compiler and cmake. The C++ compiler builds Ghidra's decompiler engine, which is vendored under `third_party/`, and cmake builds the Swift demangler.

```
cargo build --release
cargo test --release --workspace
```

To use it from Claude Code, put this in `.mcp.json`:

```json
{
  "mcpServers": {
    "recore": { "command": "/path/to/recore/target/release/recore-mcp" }
  }
}
```

## Layout

| Directory | Contents |
|---|---|
| `crates/core` | Loading, function discovery, jump tables, strings, classes, Objective-C metadata |
| `crates/decomp` | Ghidra's decompiler engine as a library, in a child process per binary so that a crash costs one function |
| `crates/mcp` | The MCP server and command line |
| `crates/corpus` | Ground truth from debug information, and the scorers |
| `crates/bench` | Timings and a sampling profiler |
| `corpus/`, `ghidra/` | Scripts that fetch the corpora and run Ghidra for the reference results |
| `third_party/ghidra-decompiler` | The vendored engine, with its own licence notes |

The corpora themselves are not in the repository. `corpus/fetch*.py` download them, and `check.sh` analyzes and scores them.

## Licence

Apache 2.0. The vendored decompiler engine is Apache 2.0 from the Ghidra project, with zlib under its own licence; see [third_party/ghidra-decompiler/README.md](third_party/ghidra-decompiler/README.md).
