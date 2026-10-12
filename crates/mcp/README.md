# recore-mcp

A Model Context Protocol server that gives an agent recore's analysis of an ELF or Windows PE binary, and Ghidra's decompiler on top of it, over stdio. It analyzes each binary once and keeps it, so a query after the first takes about a millisecond.

## Tools

Every tool takes `path`, the binary to analyze, and answers with text. Addresses are hex, with or without `0x`.

| Tool | Arguments | Answer |
|---|---|---|
| `summary` | | Format, machine, image base, entry, sections, counts of functions, imports, strings and jump tables, analysis time. |
| `strings` | `pattern`?, `limit`? (100) | Each string with its address and the functions that use it. `pattern` is a case-insensitive substring. |
| `imports` | `pattern`? | Each imported function with its slot and the functions that call it. |
| `functions` | `pattern`?, `limit`? (100), `sort`? (`address` or `size`) | Address, size in bytes, number of calling functions, name. `pattern` matches names. |
| `function` | `addr` or `name` | Extent, callers, calls made (imports by name), strings and globals referred to. `addr` is any address inside the function. |
| `xrefs` | `addr` | Call sites if it is a function or import slot. For data, the instructions that read or write it or take its address, and the pointers in data that hold it. |
| `decompile` | `functions` (list of addresses or names), `timeout`? (seconds per function, 30) | C for each function. |
| `bytes` | `addr`, `len`? (256, at most 4096) | Hex dump of the bytes mapped at the address. |
| `classes` | `pattern`? | C++ classes from MSVC type information: base classes, vtable address, virtual functions in vtable order. |
| `addr` | `addr` or `offset` | The address in the image and the offset in the file of the same byte, and what is there. |

The decompiler prints unnamed functions as `func_0x10001000`. Every address argument accepts that form.

`xrefs` on a data address that holds pointers, such as a vtable, also lists what each entry points to. `bytes` and `summary` give file offsets next to addresses.

## From a shell

With a tool name and a binary as arguments, the same binary runs that one tool and prints the answer:

```
recore-mcp strings firmware.dll password --limit 20
recore-mcp function firmware.dll 0x10001260
recore-mcp xrefs firmware.dll 0x1002abd0
recore-mcp decompile firmware.dll 0x10001260 0x10014750
recore-mcp bytes firmware.dll 0x1002abd0 64
recore-mcp addr firmware.dll --offset 0x280cc
```

Plain arguments are what the tool looks up; the other arguments in the table are options, `--limit 20`. `recore-mcp --help` lists the tools. Each run analyzes the binary again, so a long session is faster through the server.

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
