# recore-mcp

A Model Context Protocol server that gives an agent recore's analysis of an ELF, Windows PE or Mach-O binary, and Ghidra's decompiler on top of it, over stdio. It analyzes each binary once and keeps it, so a query after the first takes about a millisecond.

## Tools

Every tool takes `path`, the binary to analyze, and answers with text. Addresses are hex, with or without `0x`.

| Tool | Arguments | Answer |
|---|---|---|
| `summary` | | Format, machine, image base, entry, sections, counts of functions, imports, strings and jump tables, analysis time. |
| `strings` | `pattern`?, `limit`? (100) | Each string with its address and the functions that use it. Strings in the data sections that nothing found refers to are listed too, with `used by: none`. `pattern` is a regular expression matched anywhere, ignoring case; text that is not a valid expression is matched as written. |
| `imports` | `pattern`? | Each imported function with its slot and the functions that call it. |
| `functions` | `pattern`?, `limit`? (100), `sort`? (`address` or `size`) | Address, size in bytes, number of calling functions, name. `pattern` matches names. |
| `function` | `addr` or `name` | Extent, callers, calls made (imports by name, Objective-C message sends by selector), strings and globals referred to. `addr` is any address inside the function. |
| `xrefs` | `addr`, or `offset` with `function`? and `limit`? | Call sites if it is a function or import slot, and the message sends only it implements if it is an Objective-C method. For data, the instructions that read or write it or take its address, and the pointers in data that hold it. |
| `decompile` | `functions` (list), `addresses`?, `around`?, `timeout`? | C for each function. With `addresses`, each line of C follows the address of the instruction it came from. With `around`, only the lines near that address are shown. |
| `bytes` | `addr`, `len`? (256, at most 4096) | Hex dump of the bytes mapped at the address. |
| `classes` | `pattern`? | C++ classes from MSVC and Itanium (GCC, Clang) type information: base classes, vtable address, virtual functions in vtable order. Objective-C classes and categories from a Mach-O image's metadata: superclasses, instance methods, then class methods. |
| `addr` | `addr` or `offset` | The address in the image and the offset in the file of the same byte, and what is there. |
| `disassemble` | `function` or `addr`, `count`?, `pcode`? | Instructions as Ghidra's listing prints them, in basic blocks with each block's successors. Each line has the bytes and what the analysis knows: call target, string or data referred to, switch targets, comment. `pcode` adds each instruction's raw p-code. |
| `pcode` | `function`, `limit`? (400), `timeout`? | The function's data flow after the decompiler has simplified it: blocks, and operations over values assigned once each. |
| `trace` | `function`, then `param`, `returns`, or `call` with `arg`; `depth`? (2), `timeout`? | One value followed through the code and across calls: a parameter forward, or a returned value or call argument back to where it comes from. |
| `symbols` | `pattern`?, `limit`? (100) | Every named address: functions, import slots, vtables, exported data, and names given with `rename`. |
| `diff` | `to`, `function`?, `limit`? (100), `timeout`? | Compares the build at `path` with a later one at `to`: the functions that changed, with their size before and after, the calls and strings each gained or lost and the name a table of the program lists it under, and the functions removed and added. Functions whose instructions are the same over other constants are listed apart. With `function`, the lines of that function's C that the later build dropped and added. |
| `rename` | `addr` and `name`, `var`?, or `names` (list of these) | Names a function entry or a data address. With `var`, names a parameter or local variable of the function at `addr`, given as `decompile` spells it now. An empty name removes it. |
| `comment` | `addr`, `text` | Attaches a note to an address. `function`, `disassemble` and `decompile` show it. Empty text removes it. |
| `declare` | `code`, or `addr` and `type` | `code` is C: `struct`, `union`, `enum`, `typedef`, and `extern` prototypes that set a named function's parameters and return type. `addr` with `type` says what the data at an address is. |
| `type` | `name`? | Size, alignment and fields with offsets of a struct or union, or the values of an enum. Without `name`, what `declare` has recorded. |

The decompiler prints unnamed functions as `func_0x10001000`. Every address argument accepts that form.

From a universal Mach-O file the arm64 slice is analyzed, or the x86-64 one if there is no other. A message send to an object shows as `calls -[? selector]`, since the class of the receiver is only known when the program runs; when the binary implements the selector exactly once, that method is named too, and counts the send among its callers. A send to a class loaded right before it shows as `calls +[NSString stringWithFormat:]`.

In decompiled C a send through one of the linker's selector stubs reads `objc_msgSend$addSubview:(view, child)`, with the receiver and one argument per colon. Selector and class references print as `sel_init` and `class_NSString`. Swift names are demangled with Swift's own demangler.

`xrefs` on a data address that holds pointers, such as a vtable, also lists what each entry points to. `bytes` and `summary` give file offsets next to addresses.

## Edits

`rename`, `comment` and `declare` change what every later answer says, the decompiler's C included. They are saved in one JSON file per binary under `$XDG_DATA_HOME/recore/edits` (or `~/.local/share/recore/edits`), named after the file and a hash of its contents. They survive a restart and a move of the binary, and do not apply to a file whose bytes have changed. `RECORE_EDITS_DIR` names another directory. `summary` prints the path.

An edit replaces the decompiler process with one that starts from the new edits, so the first decompilation after an edit waits for that process to load the binary again. Several renames in one `names` list cost one restart.

A name goes on a function entry, on data, or on a variable of a function. A variable is remembered by where it is stored, so its name holds when other edits change how the function decompiles, and is dropped only if the variable itself is gone. An address inside a function takes a comment, not a name.

## Debug information

When a binary has debug information, the decompiler uses it: functions take their prototypes and parameter names, globals their types, and fields print by name. It is read from DWARF in the binary itself, from a `.debug` file, or from the `.pdb` of a Windows binary, looked for next to the binary under the binary's name (`tool.debug`, `tool.exe.pdb`, `tool.pdb`) or the name the binary records, and in a `.debug` directory there. `RECORE_DEBUG` names more directories to look in, separated by colons; `RECORE_DEBUG=off` turns it off. `type` and `declare` know the types by name. Only the decompiler reads debug information: `summary`, `functions` and the other tools that do not decompile are as fast with it as without, and do not show its names.

## Data flow

`diff` pairs the functions of two builds by name, then by code that is the same but for the addresses in it, then by their place among the callers and callees already paired, and last by their order between paired neighbours. A paired function counts as changed when its code differs. That suits a patch or a point release built with the same compiler; two builds by different compilers have little code in common and come out as mostly changed.

`xrefs` with `offset` answers who sets or uses a field: it lists the functions that reach memory at that offset from a register, whatever structure the register points to, so a large offset is telling and a small one is not. `function` and `decompile` say which function names a function's assertions carry, which is its own name unless the assertion came in with an inlined function.

A call that passes a printf or scanf format is shown with the arguments the format asks for. The decompiler by itself judges from the registers around the call, and leaves out a value the caller also looked at. This holds for the C library's functions and for a program's own that hand their arguments on to one, such as a logging function built on `vsnprintf`; a function that merely takes a variable number of arguments is left alone, since a string with a `%` in it need not be a format.

An answer that leaves something out says so where it does: how many of how many it shows, and the argument that shows the rest.

`pcode` and `trace` read the decompiler's own intermediate form, the one its C is printed from. Stack bookkeeping and dead code are gone, every value has one definition, and a call lists its arguments in order. `trace` follows a value through at most 16 functions and does not follow it through memory: a value stored to a global or the heap and read back elsewhere is reported at the store and no further.

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
