# Ghidra decompiler engine (vendored)

The C++ decompiler from Ghidra, built as a static library by `build.rs` and used by
`crates/decomp`. Five source files and two language files are modified, see below.

Source: `Ghidra/Features/Decompiler/src/decompile/` of the Ghidra repository at commit
`918d44ebc2` (12.3 DEV), copied from `~/Work/tries/ghidra-profile/master`.

| Directory | Contents |
|---|---|
| `cpp/` | The `CORE`, `DECCORE` and `SLEIGH` groups of the upstream `Makefile`, plus `sleigh_arch` and `inject_sleigh`, and every header they include. The bison outputs (`xml.cc`, `grammar.cc`, `pcodeparse.cc`) are checked in upstream and copied as they are, next to their `.y` sources. |
| `zlib/` | Ghidra's subset of zlib 1.3.1, used to read `.sla` files. Built with `NO_GZIP`, like Ghidra's own build. |
| `languages/` | From `Ghidra/Processors/{x86,AARCH64,8051}/data/languages/`: the `.ldefs` language lists, the processor specs (`x86.pspec`, `x86-64.pspec`, `AARCH64.pspec`, `cip-51.pspec`) and the compiler specs for the targets `crates/decomp` supports (`x86win`, `x86gcc`, `x86-64-win`, `x86-64-gcc`, `AARCH64`, `keil-cx51`). The `.sla` files (`x86.sla`, `x86-64.sla`, `AARCH64.sla`) are build output: the SLEIGH compiler's result for the matching `.slaspec`, taken from the built distribution `dist-master/ghidra_12.3_DEV`. `cip-51.sla` is built here, and two of the 8051 files are modified, see below. |

Left out: the console (`consolemain`, `ifacedecomp`, `interface`), the Ghidra client protocol
(`*_ghidra`, `ghidra_process`), the BFD and XML image loaders, the SLEIGH compiler, and the tests.

To update, copy the same file set from a newer checkout and rebuild the `.sla` files with the matching
SLEIGH compiler. The `.sla` format version must match the engine.

## Local changes

- `cpp/funcdata_block.cc`, `Funcdata::switchOverJumpTables`: drops jump-table overrides whose
  indirect jump the flow never reached, or that the engine rejected. Upstream dereferences a null
  pointer or reads past an empty vector for those. The
  change is marked with a `recore:` comment.

- `cpp/sleigh_arch.cc`, `SleighArchitecture::buildTypegrp`: the untyped core types are named
  `undefined1` to `undefined8`, as Ghidra's interface names them, where upstream's standalone
  default is `xunknown1` to `xunknown8`. Marked with a `recore:` comment.

- `cpp/unionresolve.cc`: two guards for unions, which programs with debug information for C++
  library types reach. `ResolvedUnion::ResolvedUnion` takes a field number that the data-type it
  comes with does not have to mean the data-type as a whole, where upstream reads past the end
  of the field list. The two `ScoreUnionFields` constructors for truncations resolve to an
  untyped value when no data-type covers the piece of the chosen field, where upstream stores a
  null pointer and dereferences it later. Marked with `recore:` comments.

- `cpp/prettyprint.hh` and `cpp/printlanguage.hh`, `setLowLevel` of `EmitPrettyPrint` and of
  `PrintLanguage`: replaces the emitter the pretty printer
  writes through, which upstream only swaps between its own two. `crates/decomp` uses it to
  print each line of C with the address of the instruction it came from. Marked with a
  `recore:` comment.

- `languages/cip-51.sla`: built from upstream's unmodified `cip-51.slaspec` with `PTRSIZE`
  defined as 3, which `8051_main.sinc` provides for. The distribution's own `cip-51.sla` has a
  16-bit code space, though `8051.ldefs` lists the language as 24 bits wide. With 24 bits a
  code address is `bank << 16 | address`, and `LJMP`, `LCALL`, `AJMP` and `ACALL` stay in the
  bank of their instruction. To rebuild, in a copy of the 8051 language directory:
  `support/sleigh -DPTRSIZE=3 cip-51.slaspec cip-51.sla`.

- `languages/cip-51.pspec`: of the special function registers and their bits, only those
  every 8051 has are named, `SCON` and `SBUF` under their usual names. Upstream names the
  registers of the Silicon Labs parts. Marked with a `recore:` comment.

- `languages/keil-cx51.cspec`: the stack is in `INTMEM`, where the language's pushes and calls
  keep it, with the stack change of a call and a range for locals to match. Upstream names
  `RAM`, which leaves every pushed return address in the C. Marked with `recore:` comments.

## Licences

- `cpp/`: Apache License 2.0 (`LICENSE`, `NOTICE`). Every file carries the Apache header. The three bison-generated parsers also carry the GPLv3 bison skeleton notice
  with its special exception, which permits distributing the generated parser under other terms.
- `languages/`: the files carry no header. Upstream's `Ghidra/Processors/x86/certification.manifest`
  lists them as `GHIDRA`, its tag for Apache 2.0, and so do the ones for `AARCH64` and `8051`.
- `zlib/`: zlib licence (`zlib/LICENSE`).
