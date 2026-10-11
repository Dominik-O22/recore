# Ghidra decompiler engine (vendored)

The C++ decompiler from Ghidra, built as a static library by `build.rs` and used by
`crates/decomp`. One file is modified, see below.

Source: `Ghidra/Features/Decompiler/src/decompile/` of the Ghidra repository at commit
`918d44ebc2` (12.3 DEV), copied from `~/Work/tries/ghidra-profile/master`.

| Directory | Contents |
|---|---|
| `cpp/` | The `CORE`, `DECCORE` and `SLEIGH` groups of the upstream `Makefile`, plus `sleigh_arch` and `inject_sleigh`, and every header they include. The bison outputs (`xml.cc`, `grammar.cc`, `pcodeparse.cc`) are checked in upstream and copied as they are, next to their `.y` sources. |
| `zlib/` | Ghidra's subset of zlib 1.3.1, used to read `.sla` files. Built with `NO_GZIP`, like Ghidra's own build. |
| `languages/` | From `Ghidra/Processors/{x86,AARCH64}/data/languages/`: the `.ldefs` language lists, the processor specs (`x86.pspec`, `x86-64.pspec`, `AARCH64.pspec`) and the compiler specs for the targets `crates/decomp` supports (`x86win`, `x86gcc`, `x86-64-win`, `x86-64-gcc`, `AARCH64`). The `.sla` files (`x86.sla`, `x86-64.sla`, `AARCH64.sla`) are build output: the SLEIGH compiler's result for the matching `.slaspec`, taken from the built distribution `dist-master/ghidra_12.3_DEV`. |

Left out: the console (`consolemain`, `ifacedecomp`, `interface`), the Ghidra client protocol
(`*_ghidra`, `ghidra_process`), the BFD and XML image loaders, the SLEIGH compiler, and the tests.

To update, copy the same file set from a newer checkout and rebuild the `.sla` files with the matching
SLEIGH compiler. The `.sla` format version must match the engine.

## Local changes

- `cpp/funcdata_block.cc`, `Funcdata::switchOverJumpTables`: drops jump-table overrides whose
  indirect jump the flow never reached, or that the engine rejected. Upstream dereferences a null
  pointer or reads past an empty vector for those. The
  change is marked with a `recore:` comment.

## Licences

- `cpp/`: Apache License 2.0 (`LICENSE`, `NOTICE`). Every file carries the Apache header. The three bison-generated parsers also carry the GPLv3 bison skeleton notice
  with its special exception, which permits distributing the generated parser under other terms.
- `languages/`: the files carry no header. Upstream's `Ghidra/Processors/x86/certification.manifest`
  lists them as `GHIDRA`, its tag for Apache 2.0, and so does the one for `AARCH64`.
- `zlib/`: zlib licence (`zlib/LICENSE`).
