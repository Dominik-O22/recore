# recore-mcp

A Model Context Protocol server that gives an agent recore's analysis of an ELF, Windows PE or Mach-O binary, and Ghidra's decompiler on top of it, over stdio. It analyzes each binary once and keeps it, so a query after the first takes about a millisecond.

## Tools

Every tool takes `path`, the binary to analyze, and answers with text. Addresses are hex, with or without `0x`.

| Tool | Arguments | Answer |
|---|---|---|
| `summary` | | Format, machine, image base, entry, sections, counts of functions, imports, strings and jump tables, analysis time. |
| `strings` | `pattern`?, `limit`? (100) | Each string with its address and the functions that use it. Strings in the data sections that nothing found refers to are listed too, with `used by: none`. `pattern` is a regular expression matched anywhere, ignoring case, and also matches the text as written, so `chr() arg` finds "chr() arg". |
| `imports` | `pattern`? | Each imported function with its slot and the functions that call it. |
| `functions` | `pattern`?, `limit`? (100), `sort`? (`address` or `size`) | Address, size in bytes, number of calling functions, name. `pattern` matches names. |
| `function` | `addr` or `name` | Extent, callers, calls made (imports by name, Objective-C message sends by selector), strings and globals referred to. `addr` is any address inside the function. |
| `xrefs` | `addr`, or `offset` with `function`? and `limit`? | Call sites if it is a function or import slot, and the message sends only it implements if it is an Objective-C method. For data, the instructions that read or write it or take its address, and the pointers in data that hold it. |
| `decompile` | `functions` (list), `addresses`?, `around`?, `timeout`? | C for each function. With `addresses`, each line of C follows the address of the instruction it came from. With `around`, only the lines near that address are shown. |
| `bytes` | `addr`, `len`? (256, at most 4096) | Hex dump of the bytes mapped at the address. |
| `classes` | `pattern`? | C++ classes from MSVC and Itanium (GCC, Clang) type information: base classes, vtable address, virtual functions in vtable order. Objective-C classes and categories from a Mach-O image's metadata: superclasses, instance methods, then class methods. |
| `addr` | `addr` or `offset` | What is at the address: a string, a function, a name, or data told by its first slots, each pointer followed to the string, function or record it reaches, two deep. Also the offset in the file of the same byte. |
| `disassemble` | `function` or `addr`, `count`?, `pcode`? | Instructions as Ghidra's listing prints them, in basic blocks with each block's successors. Each line has the bytes and what the analysis knows: call target, string or data referred to, switch targets, comment. `pcode` adds each instruction's raw p-code. |
| `pcode` | `function`, `limit`? (400), `timeout`? | The function's data flow after the decompiler has simplified it: blocks, and operations over values assigned once each. |
| `trace` | `function`, then `param`, `returns`, or `call` with `arg`; `depth`? (2), `timeout`? | One value followed through the code and across calls: a parameter forward, or a returned value or call argument back to where it comes from. |
| `run` | `function`, `args`?, `set`?, `read`?, `dump`?, `bits`?, `steps`? (10,000,000) | Runs a function as its processor would and answers what it did: the value returned, each buffer passed in as it was left, and the memory written. With `coverage`, lists what a run would stop on instead, and `function` may be left out. See below. |
| `unnamed` | `space`?, `limit`? (100) | The data addresses the code reads or writes that have no name, most accessed first, with read and write counts and the functions that touch each. `space` keeps one memory of an 8051: `sfr`, `xdata` or `idata`. |
| `symbols` | `pattern`?, `limit`? (100) | Every named address: functions, import slots, vtables, exported data, and names given with `rename`. |
| `diff` | `to`, `function`?, `limit`? (100), `timeout`? | Compares the build at `path` with a later one at `to`: the functions that changed, with their size before and after, the calls and strings each gained or lost and the name a table of the program lists it under, and the functions removed and added. Functions whose instructions are the same over other constants are listed apart, each with the constants that differ, such as an assertion's line number. With `function`, the lines of that function's C that the later build dropped and added. |
| `rename` | `addr` and `name`, `var`?, or `names` (list of these) | Names a function entry or a data address. With `var`, names a parameter or local variable of the function at `addr`, given as `decompile` spells it now. An empty name removes it. `addr` may also be a struct, `S_401a20_RDI` as `decompile` prints a recovered one, or `Struct.field_0x10` for one of its fields. |
| `comment` | `addr`, `text` | Attaches a note to an address. `function`, `disassemble` and `decompile` show it. Empty text removes it. |
| `declare` | `code`, or `addr` and `type` | `code` is C: `struct`, `union`, `enum`, `typedef`, and `extern` prototypes that set a named function's parameters and return type. `addr` with `type` says what the data at an address is. |
| `type` | `name`? | Size, alignment and fields with offsets of a struct or union, or the values of an enum. A struct kept with `rename` also lists the functions passed a pointer to it. Without `name`, what `declare` and `rename` have recorded. |
| `structs` | `function`, `refused`?, `timeout`? | The structs a function's pointer parameters got, and the pointers their fields hold. With `refused`, also each pointer read through that got none, and why. |

The decompiler prints unnamed functions as `func_0x10001000`. Every address argument accepts that form.

From a universal Mach-O file the arm64 slice is analyzed, or the x86-64 one if there is no other. A message send to an object shows as `calls -[? selector]`, since the class of the receiver is only known when the program runs; when the binary implements the selector exactly once, that method is named too, and counts the send among its callers. A send to a class loaded right before it shows as `calls +[NSString stringWithFormat:]`.

In decompiled C a send through one of the linker's selector stubs reads `objc_msgSend$addSubview:(view, child)`, with the receiver and one argument per colon. Selector and class references print as `sel_init` and `class_NSString`. Swift names are demangled with Swift's own demangler.

`xrefs` on a data address that holds pointers, such as a vtable, also lists what each entry points to. `bytes` and `summary` give file offsets next to addresses.

## Edits

`rename`, `comment` and `declare` change what every later answer says, the decompiler's C included. They are saved in one JSON file per binary under `$XDG_DATA_HOME/recore/edits` (or `~/.local/share/recore/edits`), named after the file and a hash of its contents. They survive a restart and a move of the binary, and do not apply to a file whose bytes have changed. `RECORE_EDITS_DIR` names another directory. `summary` prints the path.

The decompiler process takes renames, comments and named structs as it runs and keeps the parameters it has found for the functions it decompiled. A declaration, a type, a name taken away, or a named struct that grows replaces it with one that starts from the new edits, so the first decompilation after one waits for that process to load the binary again.

## Structs

A function that reads fields through a pointer parameter shows it as a struct of those fields: `S_401a20_RDI *param_1` and `param_1->field_0x28`. The name says where the struct came from: the function, the register or stack slot the pointer is passed in (`stack4` for 4 bytes above the return address), and the offsets of the pointer fields followed to reach a nested one (`S_401a20_RDI_10`). Each function has its own struct, which covers the bytes that function touches. `structs` lists a function's structs, and with `refused` the pointers that got none and why: a pointer used as a number, one that points into the middle of something, or one stepped through by elements of different sizes.

`rename S_401a20_RDI Connection` keeps the struct under that name, with the structs it points to under their own names until they are renamed too, and remembers that the function is passed a `Connection` in `RDI`. That function shows `Connection *param_1` from then on, and so does a caller that passes its pointer on, once the function is decompiled for its parameters. `rename Connection.field_0x28 timeout` names a field. Renaming a second function's struct to `Connection` says the two are one type: the fields of both make up the struct, or the rename is refused with the offsets where a field of one crosses a field of the other. A named struct goes only on a pointer the code uses inside it; where it does not fit, the function keeps a struct of its own and a warning at the top of its C says why.

A name goes on a function entry, on data, or on a variable of a function. A variable is remembered by where it is stored, so its name holds when other edits change how the function decompiles, and is dropped only if the variable itself is gone. An address inside a function takes a comment, not a name.

## Debug information

When a binary has debug information, the decompiler uses it: functions take their prototypes and parameter names, globals their types, and fields print by name. It is read from DWARF in the binary itself, from a `.debug` file, or from the `.pdb` of a Windows binary, looked for next to the binary under the binary's name (`tool.debug`, `tool.exe.pdb`, `tool.pdb`) or the name the binary records, and in a `.debug` directory there. `RECORE_DEBUG` names more directories to look in, separated by colons; `RECORE_DEBUG=off` turns it off. `type` and `declare` know the types by name. Only the decompiler reads debug information: `summary`, `functions` and the other tools that do not decompile are as fast with it as without, and do not show its names.

## Data flow

`diff` pairs the functions of two builds by name, then by code that is the same but for the addresses in it, then by their place among the callers and callees already paired, and last by their order between paired neighbours. A paired function counts as changed when its code differs. That suits a patch or a point release built with the same compiler; two builds by different compilers have little code in common and come out as mostly changed. In 32-bit ARM code a number the code loads from a literal pool or builds with `movw` and `movt` counts as an address when it points into the image, or does once the code adds the PC to it, so a change to a constant that looks like an address goes unseen. In position-independent ARM code it holds for any number that points into the image once added to the address of the global offset table, since such code reaches its data by offsets from the table. 8051 code is paired but not compared, and the answer counts those pairs as not compared.

`xrefs` with `offset` answers who sets or uses a field: it lists the functions that reach memory at that offset from a register, whatever structure the register points to, so a large offset is telling and a small one is not. `function` and `decompile` say which function names a function's assertions carry, which is its own name unless the assertion came in with an inlined function.

A call that passes a printf or scanf format is shown with the arguments the format asks for. The decompiler by itself judges from the registers around the call, and leaves out a value the caller also looked at. This holds for the C library's functions and for a program's own that hand their arguments on to one, such as a logging function built on `vsnprintf`; a function that merely takes a variable number of arguments is left alone, since a string with a `%` in it need not be a format.

An answer that leaves something out says so where it does: how many of how many it shows, and the argument that shows the rest.

`pcode` and `trace` read the decompiler's own intermediate form, the one its C is printed from. Stack bookkeeping and dead code are gone, every value has one definition, and a call lists its arguments in order. `trace` follows a value through at most 16 functions and does not follow it through memory: a value stored to a global or the heap and read back elsewhere is reported at the store and no further.

`run` interprets the p-code of the decompiler's processor specifications, so one interpreter serves x86, x86-64, AArch64, Cortex-M and the 8051. Arguments follow the platform's calling convention for integers and pointers: a number (decimal, or hex as `0x1f`), `hex:4142` for bytes put in memory and passed by address, `str:text` for a string with its end, `buf:16` for 16 zero bytes. `set` takes `RDX=5` for a register, and `0x20000000=hex:0011` or `EXTMEM:0x100=hex:09` for bytes of memory, the second form for a memory other than the one the code is in. `read` shows more registers after the run, `dump` shows `ADDRESS:LENGTH` of memory, which is how to read what a returned pointer reaches, and `bits` cuts the result to the width of the function's return type. `f32:1.5` and `f64:1.5` pass a float where the platform passes one: on the stack on x86-32, in the XMM registers on x86-64, and in `d0` to `d7` on AArch64. `set` takes them too, as `XMM0=f64:2.5` or `ST0=f64:2.5`. A float function returns in `XMM0` on x86-64, in `d0` on AArch64, and in `ST0` on x86-32, as does a `long double` on x86-64. `read` shows an x87 register as the extended float it holds, in hex and to 21 significant digits, enough to tell any two apart. `XMM0:f64` or `ST0:f32` shows a float of that size, from the register's low bytes, or from an x87 register rounded as a store of it would be.

The x87's floats are computed in software as the processor computes them, in 80 bits, each result rounded once to the precision and in the direction the control word sets. The control word starts as the system sets it for a new thread. Windows sets 0x27f, which rounds to 53 bits as a double has, and Linux and macOS set 0x37f, which rounds to 64. `--set FPUControlWord=0x37f` changes it, and a run that did x87 arithmetic says which it began with. Against this machine's own x87, sums, differences, products, quotients, square roots, rounding to an integer, and stores to integers and narrower floats come out the same in every bit under all 16 settings of precision and rounding, and so do comparisons and loads of floats and integers of each size, which the control word does not change. Startup code can set another word, as a C runtime may: give that one with `set`.

The instructions the specification leaves opaque or approximate run whole. `F2XM1`, `FYL2X`, `FYL2XP1`, `FSIN`, `FCOS`, `FSINCOS`, `FPTAN` and `FPATAN` give the exact result rounded once, to 64 bits whatever the precision control, in the direction the control word sets. `FSIN`, `FCOS`, `FSINCOS` and `FPTAN` reduce their argument by the processor's 66-bit pi, as Intel's and AMD's processors do, so the sine of a large argument is the one the processor gives and not the true one. An argument of 2^63 or more is left as it is with C2 set. `FLDPI`, `FLDL2E`, `FLDL2T`, `FLDLG2` and `FLDLN2` load the true constant rounded as the control word says. `FSCALE`, `FXTRACT`, `FXAM`, `FPREM`, `FPREM1` and the constants come out the same as this machine's in every bit. The remainders are exact and set C2 when they are partial and the low bits of the quotient in C0, C3 and C1 when not, so a loop on C2, as `fmod` has, stops where the processor's does.

It runs the function and what it calls, not the program. Imports such as `memcpy`, `strlen` and `malloc` run as stand-ins, a call to any other import ends the run and names it, and so does a processor operation or an instruction the specifications give no semantics. A run stops after `steps` instructions, with the bytes a stand-in moves counted as well, and after 30 seconds.

Most MMX, SSE, SSSE3 and SSE4.1 integer instructions that the x86 specification leaves as named operations run as the processor runs them, among them `PSHUFLW`, `PMADDWD`, `PAVGB`, `PSHUFB` and `PMOVZXBW`: the same as this machine's in every bit over generated inputs, in a unit test and in the oracle. A run still stops at the string compares (`PCMPISTRI` and its kin), `PALIGNR` on XMM registers, `MASKMOVQ` and `MASKMOVDQU`, the packed floats the specification leaves named, AVX and 3DNow!.

With `coverage`, `run` runs nothing and lists what a run of `function` and every function it calls would stop on, or a run anywhere in the binary without `function`: the instructions above, those the specifications give no semantics, and the calls to imports with no stand-in, each with how many there are and where the first is. It lifts each instruction once, which takes about 20 seconds for a binary of two million instructions. A path that never reaches what it lists still runs, calls through pointers are not followed, and `skip`, `ticks` and `args` are not read. It reads x86 and x86-64 code only.

What a run does not tell you:
- Memory that nothing wrote and the file does not hold reads as zeros. The answer counts those reads and says where the first were, labelled with the region on a Cortex-M. On a chip that memory is the peripherals and the globals the startup code sets, so a result that depends on it needs those given with `set`.
- A write past the end of a buffer or of a block `malloc` gave is listed with the memory it landed in. The stack is not listed.
- A register that is read before anything sets it reads as zero without a word. Only memory is counted.
- Dividing by zero stops an x86 run and gives zero on ARM, as the hardware does. A signed quotient too large for its register, as `INT_MIN / -1`, does not trap on x86 here, because the specification divides in a wider register and cuts the result.
- The processor's transcendental instructions are not rounded correctly, and the run's are, so the two can be a unit in the last place of the 64-bit significand apart. Against this machine's x87, an AMD Ryzen 7 9850X3D, over 32,000 inputs to each instruction across all 16 control words, with huge arguments to `FSIN`, `FYL2X` near 1 and `F2XM1` across its domain among them, they never differ by more. They differ by one in 0.5% of results for `FSIN` and `FCOS`, 1.3% for `FPATAN`, 1.4% for `FYL2X`, 2.2% for `F2XM1`, 2.5% for `FYL2XP1` and 9% for `FPTAN`. Intel bounds its own error in a directed rounding at under 1.5 units, so an Intel processor can be 2 apart there. A C library's `sin` or `log` that returns the instruction's result as it is differs as often. Its `pow` and `exp`, which round further, agreed with this machine in every bit in the oracle's test.
- Where the processor leaves a result undefined, the run does what this machine does. `F2XM1` of a finite operand outside -1 to 1 leaves it as it is. `FYL2XP1` with x at -1 or below gives y negated when y is a zero or an infinity, and x otherwise. A partial remainder takes off 32 bits of quotient and as many more as the exponents' difference has above a multiple of 32. An Intel processor may do these otherwise. The remainder a loop of `FPREM` ends with is the same on any of them.
- `FBLD`, `FBSTP`, `FFREE`, `FFREEP`, `FXSAVE` and `FXRSTOR` are processor operations the specification gives no semantics, so a run stops at one and names it.
- The x87 has no tag word here, the top-of-stack field of the status word reads as 0, and its exception flags are never set. A ninth push loses the oldest value instead of giving the processor's not-a-number, an unmasked exception does not trap, and `FXAM` never finds a register empty. C1 does not say whether a result was rounded up.
- A 64-bit integer argument on x86-32 takes two slots of the stack. Pass its low and high halves as two arguments. An `f64:` argument takes its two slots by itself.
- On an 8051 the arguments go in with `set`, because where they are depends on the compiler. The result is `DPL` for SDCC and `R7` for Keil, and the registers that hold the rest of a wider result are shown after it. `R0` to `R7` are bytes of internal memory, in the bank that `RS1` and `RS0` select, so a bank switch, a direct address and `@R0` all reach the same bytes, and a function that expects the caller to have picked its bank is run with `--set RS0=1`. The first bank's bytes are not listed among the writes. The internal stack starts at the `SP` the startup code sets, if the reset vector reaches a `MOV SP,#n`, else at 0x40; the answer says which. `SP` set by the caller wins. Banks of code memory are not modelled.

To check the oracle itself after a change to the interpreter, the shim or a processor specification, run `cargo test --profile tests -p recore-mcp --test oracle -- --ignored`. It builds C functions for x86-64, AArch64, x86-32, the x87, Thumb and the 8051, and compares the oracle with this machine and with µCsim on thousands of generated cases. The x87 functions run on this machine as a 32-bit program, and the oracle has to leave the same 80 bits in ST0. Among them are functions that call `pow`, `exp`, `log`, `log1p`, `sin`, `tan`, `atan2`, `fmod` and `remainder`, which gcc builds from the x87's own instructions, except `pow`, which is glibc's x87 one taken from its 32-bit `libm.a`. Those may be a unit in the last place apart, as above. It needs gcc with 32-bit libraries, clang, sdcc and `s51`.

## From a shell

With a tool name and a binary as arguments, the same binary runs that one tool and prints the answer:

```
recore-mcp strings firmware.dll password --limit 20
recore-mcp function firmware.dll 0x10001260
recore-mcp xrefs firmware.dll 0x1002abd0
recore-mcp decompile firmware.dll 0x10001260 0x10014750
recore-mcp bytes firmware.dll 0x1002abd0 64
recore-mcp addr firmware.dll --offset 0x280cc
recore-mcp disassemble firmware.dll 0x10001260 --count 40 --pcode
recore-mcp trace firmware.dll 0x10001260 --param 1
recore-mcp run firmware.dll 0x10001260 5 hex:41424344 --bits 32
recore-mcp diff firmware-1.0.dll firmware-1.1.dll
recore-mcp rename firmware.dll 0x10001260 parse_header
recore-mcp rename firmware.dll parse_header param_1 header
recore-mcp rename firmware.dll 0x10001260 parse_header 0x10001300 read_block
recore-mcp declare firmware.dll 'struct Header { uint4 magic; uint2 version; };'
recore-mcp declare firmware.dll 0x1002abd0 Header
```

`recore-mcp <tool> --help` describes one tool and each of its options. Plain arguments are what the tool looks up; the other arguments in the table are options, `--limit 20`. `recore-mcp --help` lists the tools. Each run analyzes the binary again, so a long session is faster through the server.

## Decompiler isolation

Ghidra's decompiler can crash or loop on a function. It runs in a child process per binary, started when the binary is first loaded and kept for later calls. If a function crashes the child or runs past `timeout`, the server reports that for the one function, kills the child and starts another.

## Registering with Claude Code

Build with `cargo build --release`, then put this in `.mcp.json` at the root of the project, with the path to your checkout:

```json
{
  "mcpServers": {
    "recore": {
      "command": "/path/to/recore/target/release/recore-mcp"
    }
  }
}
```
