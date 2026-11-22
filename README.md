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
| Run code | `run` |
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

The analysis is written from scratch in Rust: loading, function discovery, calls that never return, jump tables, strings, references, library function names by fingerprint, and C++, Objective-C and Swift classes with their methods. The C comes from Ghidra's decompiler engine, compiled into recore and fed recore's analysis instead of Ghidra's. `run` interprets the p-code of the same engine's processor specifications, and computes the x87's 80-bit floats in software. Its arithmetic rounds as the processor's does, and its transcendental instructions come within a unit in the last place of the processor's. It can start from a snapshot of a live process's memory instead of the file's, so a function runs on the state a program had. [`snapshot.rs`](crates/mcp/src/emulate/snapshot.rs) gives the format.

It reads ELF, Windows PE and Mach-O for x86, x86-64 and AArch64, ELF for 32-bit ARM, A32 and Thumb-2 side by side, Linux kernel modules for x86-64 and AArch64, and raw firmware that a layout file describes: 8051 and ARM Cortex-M.

## Fast is not sloppy

Scored against debug information, on the same binaries as Ghidra. Mach-O binaries have none, so their truth is the symbol table of the unstripped original plus the linker's list of function starts.

| Corpus | | Functions found | Precision | Jump tables exact |
|---|---|---|---|---|
| Linux x86-64 | recore | 100.0% | 100.0% | 535 of 535 |
| | Ghidra | 99.7% | 97.1% | 487 of 535 |
| Linux AArch64 | recore | 100.0% | 99.9% | |
| | Ghidra | 100.0% | 99.9% | |
| Linux 32-bit ARM, armhf | recore | 99.1% | 99.7% | 5,090 of 5,158 |
| | Ghidra | 64.3% | 99.8% | 4,123 of 5,158 |
| Linux 32-bit ARM, armel | recore | 99.0% | 99.6% | 5,252 of 5,323 |
| | Ghidra | 55.1% | 99.7% | 3,821 of 5,323 |
| Windows x86 | recore | 99.3% | 98.8% | 6,244 of 6,277 |
| | Ghidra | 83.1% | 98.5% | 5,834 of 6,277 |
| Windows x86, relocations stripped | recore | 99.1% | 98.3% | 6,232 of 6,277 |
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

The two 32-bit ARM corpora are the Debian builds of the same packages as the others. armhf is Thumb-2, with A32 in the PLT, in the C runtime and in all the Rust code. armel is A32 throughout. Their truth is the symbol table of each debug file, where `$a`, `$t` and `$d` symbols say what each byte is, and their jump tables are the ones GCC and clang dispatch to in five ways, each kept only where every case is an instruction of its function. A dispatch that runs only for an index in range, as GCC's `ADDLS PC, PC, Rm, LSL #2`, falls through to its default, and both the truth and recore count the instruction after it as a case. A stripped binary has no such symbols, and recore tells A32 from Thumb by the bit ARM sets on every pointer to Thumb code: it puts 99.96% of armhf functions and every armel one in the right instruction set. Ghidra took 96 minutes of analysis over the 152 binaries, with 4 cores each, and recore 7 seconds on one core. The rules that find them were worked out on these binaries. On 58 more, from 14 packages a router or an IoT device carries (BusyBox, Dropbear, dnsmasq, hostapd, wpa_supplicant, iptables, OpenVPN, lighttpd, Mosquitto and others), scored once, recore finds 99.1% of armhf functions at 99.7% precision and 98.7% of armel ones at 99.4%, with 1,081 of 1,091 and 1,079 of 1,104 jump tables exact. Of the functions Ghidra misses, recore first finds a third through a pointer in data, a quarter through `.ARM.exidx`, a fifth in the gaps between functions, where Debian's builds keep library code nothing calls, and a tenth through an address the code computes.

A 32-bit Windows program linked with `/FIXED`, as many older games and tools are, carries no base relocations, so nothing in the file says which of its numbers are addresses. The row with them stripped scores the same binaries with the relocation directory removed. recore then reads every aligned word of data that lands in the image as a possible pointer, and treats a function found only through one as a guess that code running on into it overrules. Ghidra was not run on it.

The Linux AArch64 and Mach-O corpora have no jump table truth. A stripped Mach-O binary keeps the linker's list of function starts and both tools read it, so the rows with it hidden show what each finds on its own.

The rules were worked out on the binaries above. Each corpus but Linux AArch64 also has a held-out sibling of programs none of them is, scored once with the same build as the tuned corpus beside it. That build is newer than the one behind the table above, so a few tuned numbers differ by a tenth or two. Linux x86-64 holds the Debian builds of the 14 packages of the 32-bit ARM holdout. Windows holds Firefox 140 ESR (clang-cl, with Rust), the .NET 9 runtime and Wireshark (MSVC), with PDBs from Mozilla's and Microsoft's symbol servers and Wireshark's own. Mach-O holds 35 Homebrew formulae on AArch64 and the 19 of them with an x86-64 bottle, including Zig, Swift and Haskell programs.

| Corpus | Tuned: found | Precision | Held out: found | Precision | Held-out binaries |
|---|---|---|---|---|---|
| Linux x86-64 | 100.0% | 100.0% | 99.7% | 100.0% | 28 |
| Linux x86-64, unwind info hidden | 99.8% | 99.6% | 99.4% | 100.0% | |
| Windows x86-64 | 99.8% | 98.3% | 99.9% | 99.6% | 29 |
| Windows x86-64, unwind info hidden | 98.5% | 97.1% | 96.7% | 98.8% | |
| Windows x86 | 99.4% | 99.0% | 98.3% | 97.4% | 31 |
| Windows x86, relocations stripped | 99.2% | 99.0% | 98.8% | 98.1% | |
| AArch64 Mach-O | 100.0% | 100.0% | 100.0% | 100.0% | 56 |
| AArch64 Mach-O, function starts hidden | 99.8% | 99.9% | 99.6% | 45.8% | |
| x86-64 Mach-O | 100.0% | 100.0% | 97.7% | 100.0% | 26 |
| x86-64 Mach-O, function starts hidden | 99.3% | 99.7% | 77.3% | 85.6% | |
| Linux kernel modules, x86-64 | 100.0% | 99.4% | 100.0% | 99.8% | 24 |
| Linux kernel modules, AArch64 | 100.0% | 97.5% | 100.0% | 98.9% | 26 |
| Android kernel modules, GKI | 100.0% | 100.0% | 100.0% | 99.9% | 30 |
| Android kernel modules, Pixel 9 | 100.0% | 100.0% | 100.0% | 99.9% | 103 |
| Android kernel modules, Pixel 5 | 100.0% | 100.0% | 100.0% | 100.0% | 111 |
| Android kernel modules, Pixel 5, stripped | 99.2% | 83.3% | 98.9% | 61.1% | |
| Android kernel modules, Pixel 7 | 100.0% | 100.0% | 100.0% | 100.0% | 84 |
| Android kernel modules, Pixel 7, stripped | 93.7% | 98.5% | 94.3% | 97.5% | |
| Android kernel modules, Pixel 2, clang | 100.0% | 100.0% | 100.0% | 100.0% | 2 |
| Android kernel modules, Pixel 2, clang, stripped | 95.9% | 94.9% | 88.0% | 91.7% | |
| Android kernel modules, Pixel 2, GCC | 100.0% | 100.0% | 100.0% | 100.0% | 2 |
| Android kernel modules, Pixel 2, GCC, stripped | 89.7% | 94.6% | 88.0% | 93.2% | |
| Android kernel, vmlinux | 100.0% | 99.0% | 100.0% | 98.9% | 1 |
| Android kernel, vmlinux stripped | 100.0% | 98.9% | 100.0% | 98.8% | |
| Android kernel, vmlinux stripped, unwind info hidden | 87.8% | 92.3% | 91.3% | 94.6% | |
| Android kernel, Image | 55.0% | 88.3% | 57.7% | 91.8% | |

A kernel module is a relocatable file whose sections have no addresses until the kernel loads it. recore places it where Linux puts modules and applies its relocations, so its calls into the kernel read as imports and DWARF names the same addresses. The x86-64 corpus is 40 drivers, file systems and network modules from Debian's kernel, and 25 more held out, 24 of them scored. The AArch64 corpus is 50 modules from Debian's arm64 kernel: the drivers a phone's or a board's system on a chip needs, such as touchscreens, Wi-Fi, display, MMC and sound codecs, and the USB and file system modules both kernels build. 30 more are held out, 26 of them scored. Each module has every symbol it does not need stripped, so that recore finds its static functions itself. A function symbol it keeps gives the function's size, and recore starts no function inside one at an address no symbol names. On x86-64 the kernel's own list of the functions it can trace, `__mcount_loc`, gives most of them; on AArch64 that list is `__patchable_function_entries`. The precision lost is code that only a jump label reaches, which the kernel patches in at run time, and on AArch64 also the `_THIS_IP_` labels whose address the kernel takes for its debug and lock records.

The Android corpora are modules that clang built for Android phones. GKI is Google's generic kernel, android16-6.12 build 17002073: 70 modules, the 49 with DWARF scored, and 42 more held out, 30 of them scored. Pixel 9 is the vendor modules of that phone's 25Q1 release. They ship without DWARF, so their own function symbols are the truth: 212 modules, 153 of them scored, and 125 more held out, 103 of them scored. Both keep every function symbol, so recore finds every function, and only precision varies. Before each function clang's kCFI puts a hash of its type, a word of data that a `$d` mapping symbol marks. recore decodes none of it, nor any AArch64 word at an address off a word. Before it read those marks, a hash that reads as `adr` or `bl` started a function wherever it pointed, and precision was 97.4% on GKI and 71.4% on the Pixel modules. Now that recore reads each symbol's size too, nothing starts inside a function. Precision went from 99.0% to 100.0% on GKI and from 95.8% to 100.0% on the Pixel modules. The false starts it lost were `_THIS_IP_` labels, code that only a jump label reaches, and jumps inside a function read as tail calls.

The older Android corpora hold what recore was measured to do worst on. Each set of modules is a Pixel's vendor modules as shipped, with every function symbol, and with `llvm-strip --strip-unneeded`, split by the same CRC-32 rule: the Pixel 5 (Linux 4.19, clang 12), the Pixel 7 (5.10, clang 14) and the Pixel 2 (4.4, clang 11, and GCC 4.9 for Android 8.1). The Pixel 5's and 7's CFI is LLVM's, from before kCFI. Each module has a real `__cfi_check` and `__cfi_check_fail`, and an indirect call goes through a jump table after the module's functions, an entry a `b` to the function, after a `bti c` on the Pixel 7. The truth takes each entry as a thunk, which no score asks recore for or counts against it. The kernel corpora are GKI build 17002073 itself: its vmlinux as built, with every symbol and its DWARF, the same with `llvm-strip --strip-all`, and the raw `Image` a boot partition holds, through a layout read from vmlinux's program headers. The Image is vmlinux's loaded bytes at vmlinux's addresses, so it takes vmlinux's truth. A kernel cannot be split, so the held-out kernel is another one, android15-6.6 build 16969351. clang leaves the `.cold` piece of a kernel function without a type, and the truth takes it as a fragment of its function. DWARF does not say that the kernel's `__stack_chk_fail` never returns, though it ends in a call to `panic`, so the truth takes that from objtool's list, which flags no other function of vmlinux that DWARF does not. recore does worst on the stripped Pixel 5 modules, at 83.3% precision, and on the Image, where it finds 55.0% of the functions. Of the modules' calls into the kernel, 13.8% have no prototype on the Pixel 5, 4.6% on the Pixel 7, and 3.5% and 3.8% on the Pixel 2's clang and GCC builds.

A module's calls into the kernel take their prototypes from `crates/decomp/data/kernel.protos`, which `crates/decomp/data/kernel_protos.py` makes from the BTF of the GKI 6.12, the Pixel 9's 6.1 and the Pixel 7's 5.10 kernel. It holds the prototypes of the functions those kernels export to modules, the newest kernel's where they differ. Kernels before 5.2 carry no BTF, so a few functions that only the Pixel 5's 4.19 and the Pixel 2's 4.4 export, and the kernel's assembly, such as `__arch_copy_from_user`, which no BTF describes, are written by hand from those kernels' headers in `crates/decomp/data/kernel_headers.txt`. Of the calls to imports, those without a prototype went from 88.9% to 6.6% on GKI's modules and from 90.1% to 4.2% on the Pixel 9's. Most of the rest call other modules' exports.

recore reads the hashes too. Each is the low 32 bits of xxHash64 of the Itanium mangling of the function's type, so it cannot be reversed, but it can be looked up. `crates/decomp/data/kcfi.protos` holds the hash of every function type the GKI 6.12 and the Pixel's 6.1 kernel define, every `FUNC_PROTO` of their BTF, and `crates/decomp/data/kernel_protos.py --kcfi` makes it. A function whose hash is there takes that prototype in the decompiler, with the kernel's struct names on its pointers, as a function with DWARF takes DWARF's. GKI hashes integers by width, as a kernel built with `CONFIG_CFI_ICALL_NORMALIZE_INTEGERS` does, and the Pixel's 6.1 by their C names, so recore reads each module in the spelling that finds more of its hashes. That gives 1,567 of GKI's 3,596 functions a prototype and 8,830 of the Pixel's 19,899, which `recore-decompile kcfi <dir>` counts. What misses mostly takes a pointer to a struct of the module's own, which no kernel type names, and a type that passes a struct by value is left out of the table. On GKI's sample, of the functions decompiled before and after, the parameter counts right went from 1,985 to 2,119, whether a function returns a value from 2,079 to 2,174, parameter types from 2,580 to 3,139 and return types from 449 to 813. Held out, 1,070 of GKI's 2,717 functions and 4,193 of the Pixel's 10,761 get a prototype, and the parameter counts right went from 1,285 to 1,372 of 1,477. A struct the kernel names has no layout here. The decompiler recovers one for that parameter from the function's own reads and writes, as for any pointer parameter, and prints it under the kernel's name, so `platform_device *param_1` reads `param_1->field_0xd8`. Each function gets a struct of its own, so the fields it shows do not depend on what was decompiled before it. `structs` says which name each such struct prints as, `type platform_device` lists them, and `rename platform_device.field_0xd8` names a field where one struct prints under that name. On GKI, 951 of the 1,763 parameters that take a kernel struct's name print fields this way, and where the decompiler recovers none, bytes past the pointer print with a cast, as past a `void *`.

A call that never returns ends the function that makes it, so recore has to know which do. In a kernel module the callee is most often a function of the kernel, such as `panic` or `__fortify_panic`, and recore takes objtool's list of them, `tools/objtool/noreturns.h`. The truth takes them from DWARF where a module has it, and from the same list where it does not, as on the Pixel modules. On every tuned module with DWARF the two agree. On the Pixel modules the truth and recore read the same list, so that number says recore finds the calls, not that it knows which functions never return. recore finds every such call in `.text` of the tuned modules: 1,068 on x86-64, 1,404 on AArch64, 1,275 on GKI and 5,199 on Pixel 9. It also takes 1, 49, 2 and 5 calls as never returning that the truth does not, each to a function of the module itself. GKI's 2 end their function, so the compiler treated that callee as never returning too. Held out, it finds 546 of 546, 315 of 315, 802 of 802 and 2,784 of 2,788.

Jump tables hold up: 765 of 765 exact on Windows x86-64 and 1,248 of 1,252 on x86. The Linux x86-64 loss is all BusyBox where unwind info is read. With it hidden, BusyBox is half and tcpdump most of the rest. On Windows x86, Wireshark 3.6's command line tools lose about 39 functions each, the 32-bit .NET runtime finds 94.9% of `coreclr.dll`, and Firefox's Rust `crashhelper.exe` comes in at 76.8% precision. Without function starts, ShellCheck, a Haskell program, is most of the Mach-O loss: without it, recore finds 98.6% at 99.8% on AArch64 and 96.5% at 99.8% on x86-64. On AArch64 recore decodes the tables GHC puts before each function as code. On x86-64 the truth is at fault too: ShellCheck's symbol table names 23,803 of those tables (`*_info_dsp`), the truth counts each as a function, and they are every one of the misses in the 97.7% row. The x86-64 Mach-O rows therefore understate what recore finds and say nothing sure about its precision on that program.

Three of Ghidra's exports give a jump table target as a negative number, which the scorer rejects along with the whole binary. They were scored with those targets written as unsigned.

Decompiled function signatures against PDB records, 8 binaries per corpus:

| Corpus | | Functions decompiled | Parameters exact | Returns a value or not |
|---|---|---|---|---|
| Windows x86-64 | recore | 99.7% | 89.8% | 93.3% |
| | Ghidra | 91.9% | 82.6% | 92.7% |
| Windows x86 | recore | 98.8% | 86.3% | 91.0% |
| | Ghidra | 85.4% | 86.1% | 90.5% |

Each tool's percentages are over the functions it decompiled, and recore decompiles more of them. On the 8,523 32-bit functions both decompiled, recore gets the parameters of 87.1% right and Ghidra 86.1%.

Against DWARF, on six programs of each Linux ARM corpus, recore gets the parameter count right for 73.4% of armhf functions and 73.0% of armel ones, and for 76.1% of arm64 ones on the same programs. In C code that is 86.5%, 85.0% and 92.5%. Most of the gap is in C++. A function that returns a class in memory takes the address to write it to as a hidden argument, which on 32-bit ARM looks the same as a constructor's `this`, and many functions never read a parameter they declare, such as `this` in a virtual function that returns a constant.

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

A Cortex-M layout needs only `machine = "cortex-m"` and its flash region. recore reads the reset handler and every interrupt handler from the vector table, which it takes to start the lowest executable region unless the layout says `vectors = <address>`, or `vectors = "none"` with the entry points in `entry`. It is scored against the ELF each image was cut from, with Ghidra seeded from the same vector table. 27 programs are built for Cortex-M0, M3 and M4 at `-O0`, `-Os` and `-O2`, each function in its own section. 12 more are laid out as a vendor build usually is, with no per-function sections, so unused library functions stay in the image between the used ones. clang builds each of the 39 and so does GCC, and GNU ld links them all with libgcc and newlib-nano from the Arm GNU Toolchain.

| Cortex-M | | Functions found | Precision | Jump tables exact |
|---|---|---|---|---|
| 27 programs, clang | recore | 98.7% | 98.9% | 119 of 119 |
| | Ghidra | 86.2% | 96.9% | 112 of 119 |
| 27 programs, GCC | recore | 99.0% | 98.9% | 41 of 41 |
| | Ghidra | 87.5% | 98.1% | 36 of 41 |
| 12 vendor-style builds, clang | recore | 98.3% | 98.9% | 57 of 57 |
| | Ghidra | 69.3% | 97.7% | 49 of 57 |
| 12 vendor-style builds, GCC | recore | 99.2% | 98.9% | 27 of 28 |
| | Ghidra | 63.8% | 98.0% | 15 of 28 |

recore analyzes all 78 in 107 ms, none taking more than 3 ms. Most of the functions Ghidra misses are reached only by a tail call, by an address the code builds with `MOVW` and `MOVT`, or, in the vendor-style builds, by nothing at all. recore finds those by dividing the unreached code between functions into whole functions. libgcc's hand-written floating point shares code between routines. `__aeabi_ddiv` jumps into the end of `__aeabi_dmul`, and both reach their special cases with `BLEQ`. recore gives such code to the routine whose stack frame it pops. Of the 79 starts it still puts inside a function, 64 are a `BX LR` that Thumb-1 division leaves after its last branch, which looks the same as an empty function. GCC's Thumb-1 switches call libgcc's `__gnu_thumb1_case_*` helpers with the table after the call, and recore reads all 15 of those tables.

All but one of the 7,481 functions recore finds decompile, in 3.8 ms on average, and that one is data it took for code. Against DWARF the number of parameters is right for 85.9% of the C functions clang built and 84.7% of those GCC built. The System Control Space registers, such as `SYST_RVR` and the NVIC's, are named without a names file.

## What Ghidra does that recore does not

- **Processors.** Ghidra covers dozens. recore covers six.
- **Types.** Ghidra ships struct layouts for the common libraries and lets a user edit types in a GUI. recore knows the types a caller declares, the prototypes of Windows, C library and macOS functions and of the functions the Linux kernel exports to its modules, classes from MSVC and Itanium type information and Objective-C metadata, and, when a binary has DWARF or a PDB, the structs, prototypes and globals in it, and the prototypes an Android kernel module's kCFI hashes name. Without debug info, recore gives each pointer parameter a function reads fields through a struct of those fields, so the C reads `param_1->field_0x28`. Ghidra prints `*(long *)(param_1 + 0x28)` until a user creates the struct. Against DWARF on 259 x86-64 and arm64 binaries that struct recovery was not tuned on, 97.9% of the recovered fields start where a member starts, and 98.7% of the structs are no larger than the true type. `rename` names a recovered struct and its fields and saves them, and giving two functions' structs one name makes them one type.
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

The corpora are not in the repository. They live in one directory that every checkout shares, `~/recore-corpora` unless `RECORE_CORPORA` names another, and `check.sh` writes recore's output for them to `target/corpus`. `corpus/fetch*.py` download them, except the monitor firmware, a vendor's image that is not ours to share, `corpus/build_8051.py` builds the 8051 programs with SDCC, `corpus/build_thumb.py` the Cortex-M ones with clang and GCC, and `MISE_ENV=corpus mise run corpus` runs both after `MISE_ENV=corpus mise install` has fetched the tools `mise.corpus.toml` names. `corpus/strip_relocs.py` writes `corpus-pe32/norelocs`, the same images with their base relocations stripped, which `check.sh` scores against the same truth. `ghidra/run-reference.sh` runs Ghidra over them and records its times, and `check.sh` analyzes and scores them with recore. Ghidra refuses a project path that has a part starting with a dot. `ghidra/run-refs.sh` and `recore-corpus score-references` produce the reference comparison. `recore-decompile structs <corpus>... --tuning bench/set.txt` scores recovered structs against DWARF, the binaries of the benchmark set apart from the rest. `recore-bench run analysis --save <name>` and `--compare <name>` hold a change against an earlier build. Next to the times they report the processor instructions executed, which stay the same to a few hundredths of a percent whatever else the machine is doing.

Only the tests under `crates/*/tests` may name a program whose binary they need. The test `crates/core/tests/general_naming.rs` fails when one of its words appears anywhere else in the repository. CI runs it with the other tests, and `check.sh` runs it before the corpora.

The speed table compares Ghidra's `Total Time` per binary with the wall time of `recore-mcp summary`, fastest of three runs, and `ghidra/speed.py` measures it. Both ran on the same Ryzen 7 9850X3D. Ghidra analyzed several binaries at a time with 4 cores each, and recore one at a time, with all cores or pinned to one with `taskset`.

| Directory | Contents |
|---|---|
| `crates/core` | Loading and analysis |
| `crates/decomp` | Ghidra's decompiler engine as a library |
| `crates/mcp` | The MCP server and command line |
| `crates/lift` | The lifter behind `recore-mcp lift`: a 32-bit x86 program as Rust on `crates/machine`, for `player/`. Its p-code reader is the one `run` uses |
| `crates/corpus`, `crates/bench` | Scorers, timings and a profiler |
| `third_party/ghidra-decompiler` | The vendored engine, with its own licence notes |

## Licence

Apache 2.0. The vendored decompiler engine is Apache 2.0 from the Ghidra project, with zlib under its own licence. The prototypes in `crates/decomp/data/win32.protos`, `clib.protos` and `macos.protos` come from Ghidra's type archives, under the same licence. `crates/decomp/data/kernel.protos` holds function prototypes and `kcfi.protos` function types, both taken from Linux kernels' BTF, and `kernel.protos` also from their headers, and Linux is licensed under the GPL-2.0.
