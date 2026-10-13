# Ghidra decompiler engine (vendored)

The C++ decompiler from Ghidra, built as a static library by `build.rs` and used by
`crates/decomp`. Seven source files, two language files and the SLEIGH sources of the 8051 language are modified, and one compiler spec is added, see below.

Source: `Ghidra/Features/Decompiler/src/decompile/` of the Ghidra repository at commit
`918d44ebc2` (12.3 DEV), copied from `~/Work/tries/ghidra-profile/master`.

| Directory | Contents |
|---|---|
| `cpp/` | The `CORE`, `DECCORE` and `SLEIGH` groups of the upstream `Makefile`, plus `sleigh_arch` and `inject_sleigh`, and every header they include. The bison outputs (`xml.cc`, `grammar.cc`, `pcodeparse.cc`) are checked in upstream and copied as they are, next to their `.y` sources. |
| `slaspec/` | The SLEIGH sources of the 8051 language, from `Ghidra/Processors/8051/data/languages/`, modified: see below. Not built by `build.rs`. |
| `zlib/` | Ghidra's subset of zlib 1.3.1, used to read `.sla` files. Built with `NO_GZIP`, like Ghidra's own build. |
| `languages/` | From `Ghidra/Processors/{x86,AARCH64,8051}/data/languages/`: the `.ldefs` language lists, the processor specs (`x86.pspec`, `x86-64.pspec`, `AARCH64.pspec`, `cip-51.pspec`) and the compiler specs for the targets `crates/decomp` supports (`x86win`, `x86gcc`, `x86-64-win`, `x86-64-gcc`, `AARCH64`, `keil-cx51`), and `sdcc-mcs51.cspec`, which is recore's own. The `.sla` files (`x86.sla`, `x86-64.sla`, `AARCH64.sla`) are build output: the SLEIGH compiler's result for the matching `.slaspec`, taken from the built distribution `dist-master/ghidra_12.3_DEV`. `cip-51.sla` is built from `slaspec/`, and two of the 8051 files are modified, see below. |

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

- `cpp/funcdata_varnode.cc`, `Funcdata::calcNZMask`: the low byte of the incoming stack
  pointer is taken as zero only if the pointer is wider than a byte. Upstream clears it for
  any, so the 8051's stack pointer was the constant 0 wherever code kept it in memory, as
  SDCC does for a frame pointer. Marked with a `recore:` comment.

- `cpp/fspec.hh`, `ProtoModel::addEffect`: adds a side-effect of a call to the ones the
  compiler spec lists. `crates/decomp` uses it for the byte of memory SDCC keeps its frame
  pointer in, which differs from program to program. Marked with a `recore:` comment.

- `languages/cip-51.sla`: built from `slaspec/`, upstream's `cip-51.slaspec` and
  `8051_main.sinc` with five changes, each marked with a `recore:` comment. To rebuild, run
  `support/sleigh cip-51.slaspec cip-51.sla` of the distribution in a copy of `slaspec/`.
  - `PTRSIZE` is 3. The distribution's own `cip-51.sla` has a 16-bit code space, though
    `8051.ldefs` lists the language as 24 bits wide. With 24 bits a code address is
    `bank << 16 | address`, and `LJMP`, `LCALL`, `AJMP` and `ACALL` stay in the bank of their
    instruction.
  - `@A+DPTR` is an address in the bank of its instruction too, where upstream has bank 0: a
    table read with `MOVC` lies in the bank of the code that reads it.
  - The direct addresses 0 to 7 are the registers `R0` to `R7`. Upstream has them as internal
    memory, apart from the registers, so a value that C51 moves from one register to another
    by its address was lost.
  - Each flag is a register of its own, `CY`, `AC`, `F0`, `RS1`, `RS0`, `OV` and `F1`, as in the
    x86 and AArch64 languages. Upstream keeps them as bits of one register `PSW`, so a test of
    the carry flag is a shift and a mask in the C. The status word is put together where code
    reads it whole and taken apart where code writes it; a bit address in it is its flag, and
    `P` is the parity of `A`. Three things upstream has wrong went with the rewrite: `ADDC`
    and `SUBB` lost the carry out when operand plus carry wrapped, `ADD`, `ADDC` and `SUBB`
    left the overflow flag alone, and `ADD` and `ANL` wrote a sign and a zero flag into `F0`
    and `F1`. `AC` is still set by no instruction. `crates/decomp/tests/i8051_flags.rs` runs
    the p-code of every instruction that touches a flag against the processor's rules. The
    other variants `8051_main.sinc` serves upstream are not kept working.
  - The direct address 0x81 is the register `SP` that `PUSH`, `POP` and calls use. Upstream
    has a special function register there that they do not touch, so a frame that code sets
    up with `MOV A, SP` and `MOV SP, A` was no part of the stack.

- `languages/cip-51.pspec`: of the special function registers and their bits, only those
  every 8051 has are named, `SCON` and `SBUF` under their usual names. Upstream names the
  registers of the Silicon Labs parts. The bits of internal memory have no names, where
  upstream's, such as `20.0`, read as numbers in C. The bytes 8 to 0x1f have no names either:
  upstream names them as the registers of banks 1 to 3, where most programs keep variables.
  Marked with `recore:` comments.

- `languages/keil-cx51.cspec`, each change marked with a `recore:` comment:
  - The stack is in `INTMEM`, where the language's pushes and calls keep it, with the stack
    change of a call and a range for locals to match. Upstream names `RAM`, which leaves every
    pushed return address in the C.
  - `EXTMEM` is global. Upstream leaves it out, and every store to external memory is dropped.
  - Parameters are in `R6R7`, `R4R5` and `R2R3`, of one or two bytes, and the result is in
    `R6R7` or `R4R5R6R7`, as in upstream's `mx51.cspec` for the same compiler. Upstream lists
    single registers, `R4` and `R5` first.
  - `CY`, `AC`, `OV`, `ACC`, `B`, `DPTR` and `R0` to `R7` are killed by a call, and the register
    bank and the user's flags are unaffected. Upstream has all of `PSW` unaffected, so a test
    of the carry flag after a call tests the flag from before it.

- `languages/sdcc-mcs51.cspec`: not from upstream. The 8051 as SDCC compiles for it, the
  `sdcc` compiler of the language in `8051.ldefs`: the first argument and the result in
  `DPL`, `DPH`, `B` and `A` by size, further arguments on the stack, no register kept
  across a call.

## Licences

- `cpp/`: Apache License 2.0 (`LICENSE`, `NOTICE`). Every file carries the Apache header. The three bison-generated parsers also carry the GPLv3 bison skeleton notice
  with its special exception, which permits distributing the generated parser under other terms.
- `languages/` and `slaspec/`: the files carry no header, and `sdcc-mcs51.cspec` is recore's. Upstream's `Ghidra/Processors/x86/certification.manifest`
  lists them as `GHIDRA`, its tag for Apache 2.0, and so do the ones for `AARCH64` and `8051`.
- `zlib/`: zlib licence (`zlib/LICENSE`).
