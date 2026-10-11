# Ghidra decompiler engine (vendored)

The C++ decompiler from Ghidra, built as a static library by `build.rs` and used by
`crates/decomp`. Nothing here is modified.

Source: `Ghidra/Features/Decompiler/src/decompile/` of the Ghidra repository at commit
`918d44ebc2` (12.3 DEV), copied from `~/Work/tries/ghidra-profile/master`.

| Directory | Contents |
|---|---|
| `cpp/` | The `CORE`, `DECCORE` and `SLEIGH` groups of the upstream `Makefile`, plus `sleigh_arch` and `inject_sleigh`, and every header they include. The bison outputs (`xml.cc`, `grammar.cc`, `pcodeparse.cc`) are checked in upstream and copied as they are, next to their `.y` sources. |
| `zlib/` | Ghidra's subset of zlib 1.3.1, used to read `.sla` files. Built with `NO_GZIP`, like Ghidra's own build. |
| `languages/` | `x86.ldefs`, `x86-64.pspec`, `x86-64-gcc.cspec` from `Ghidra/Processors/x86/data/languages/`, and `x86-64.sla`, which is build output: the SLEIGH compiler's result for `x86-64.slaspec`, taken from the built distribution `dist-master/ghidra_12.3_DEV`. |

Left out: the console (`consolemain`, `ifacedecomp`, `interface`), the Ghidra client protocol
(`*_ghidra`, `ghidra_process`), the BFD and XML image loaders, the SLEIGH compiler, and the tests.

To update, copy the same file set from a newer checkout and rebuild `x86-64.sla` with the matching
SLEIGH compiler. The `.sla` format version must match the engine.

## Licences

- `cpp/`: Apache License 2.0 (`LICENSE`, `NOTICE`). Every file carries the Apache header. The three bison-generated parsers also carry the GPLv3 bison skeleton notice
  with its special exception, which permits distributing the generated parser under other terms.
- `languages/`: the files carry no header. Upstream's `Ghidra/Processors/x86/certification.manifest`
  lists them as `GHIDRA`, its tag for Apache 2.0.
- `zlib/`: zlib licence (`zlib/LICENSE`).
