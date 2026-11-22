//! Linux kernel modules, and other relocatable x86-64 and AArch64 ELF files, read as if they were
//! linked.
//!
//! In a relocatable file every section sits at address 0 until a loader places it and applies
//! its relocations, as the kernel does when it loads a `.ko`. [`link`] does the same and writes
//! the file back in the shape of a linked shared library, so every reader of ELF files takes it
//! as it is:
//! - each allocated section gets an address, in the order of the file, and every relocation is
//!   applied, in the debug sections too, so that DWARF names the same addresses;
//! - each undefined symbol a call or a jump names gets a `.plt` stub and a `.got` slot that a
//!   `.rela.dyn` relocation binds to it, which makes it an import; every other undefined symbol,
//!   such as `jiffies`, gets 8 bytes of `.extern`, a section without bytes in the file;
//! - each 64-bit pointer to the module itself gets a relative relocation in `.rela.dyn`, and so
//!   does the start of each function the kernel can trace: on x86-64 from `__mcount_loc`, on
//!   AArch64 from `__patchable_function_entries`;
//! - `.dynsym` names the functions and objects of `.symtab`, but for the padding the kernel puts
//!   before each function (`__pfx_`, `__cfi_`), and the symbols in `.extern`;
//! - the entry is `init_module`, the function the kernel calls first;
//! - on x86-64, calls and jumps to the kernel's thunks are rewritten to what the kernel patches them to
//!   when it loads a module: `jmp __x86_return_thunk` to `ret`, `call __x86_indirect_thunk_rax`
//!   to `call rax`, and `call __fentry__` to a no-op.

use std::collections::{BTreeSet, HashMap};

use object::elf::{self, SHN_LORESERVE};

const ET_REL: u16 = elf::ET_REL.0;
const ET_DYN: u16 = elf::ET_DYN.0;
const EM_X86_64: u16 = elf::EM_X86_64.0;
const EM_AARCH64: u16 = elf::EM_AARCH64.0;

const SHT_PROGBITS: u32 = elf::SHT_PROGBITS.0;
const SHT_SYMTAB: u32 = elf::SHT_SYMTAB.0;
const SHT_STRTAB: u32 = elf::SHT_STRTAB.0;
const SHT_RELA: u32 = elf::SHT_RELA.0;
const SHT_NOBITS: u32 = elf::SHT_NOBITS.0;
const SHT_DYNSYM: u32 = elf::SHT_DYNSYM.0;
const SHF_WRITE: u64 = elf::SHF_WRITE.0;
const SHF_ALLOC: u64 = elf::SHF_ALLOC.0;
const SHF_EXECINSTR: u64 = elf::SHF_EXECINSTR.0;
const SHF_COMPRESSED: u64 = elf::SHF_COMPRESSED.0;
const SHN_UNDEF: u16 = elf::SHN_UNDEF.0;
const SHN_ABS: u16 = elf::SHN_ABS.0;
const STB_GLOBAL: u8 = elf::STB_GLOBAL.0;
const STT_NOTYPE: u8 = elf::STT_NOTYPE.0;
const STT_OBJECT: u8 = elf::STT_OBJECT.0;
const STT_FUNC: u8 = elf::STT_FUNC.0;

const R_X86_64_64: u32 = elf::R_X86_64_64.0;
const R_X86_64_PC32: u32 = elf::R_X86_64_PC32.0;
const R_X86_64_PLT32: u32 = elf::R_X86_64_PLT32.0;
const R_X86_64_JUMP_SLOT: u32 = elf::R_X86_64_JUMP_SLOT.0;
const R_X86_64_RELATIVE: u32 = elf::R_X86_64_RELATIVE.0;
const R_X86_64_32: u32 = elf::R_X86_64_32.0;
const R_X86_64_32S: u32 = elf::R_X86_64_32S.0;
const R_X86_64_PC64: u32 = elf::R_X86_64_PC64.0;

const R_AARCH64_ABS64: u32 = elf::R_AARCH64_ABS64.0;
const R_AARCH64_ABS32: u32 = elf::R_AARCH64_ABS32.0;
const R_AARCH64_PREL64: u32 = elf::R_AARCH64_PREL64.0;
const R_AARCH64_PREL32: u32 = elf::R_AARCH64_PREL32.0;
const R_AARCH64_MOVW_UABS_G0: u32 = elf::R_AARCH64_MOVW_UABS_G0.0;
const R_AARCH64_MOVW_UABS_G3: u32 = elf::R_AARCH64_MOVW_UABS_G3.0;
const R_AARCH64_LD_PREL_LO19: u32 = elf::R_AARCH64_LD_PREL_LO19.0;
const R_AARCH64_ADR_PREL_LO21: u32 = elf::R_AARCH64_ADR_PREL_LO21.0;
const R_AARCH64_ADR_PREL_PG_HI21: u32 = elf::R_AARCH64_ADR_PREL_PG_HI21.0;
const R_AARCH64_ADR_PREL_PG_HI21_NC: u32 = elf::R_AARCH64_ADR_PREL_PG_HI21_NC.0;
const R_AARCH64_ADD_ABS_LO12_NC: u32 = elf::R_AARCH64_ADD_ABS_LO12_NC.0;
const R_AARCH64_LDST8_ABS_LO12_NC: u32 = elf::R_AARCH64_LDST8_ABS_LO12_NC.0;
const R_AARCH64_TSTBR14: u32 = elf::R_AARCH64_TSTBR14.0;
const R_AARCH64_CONDBR19: u32 = elf::R_AARCH64_CONDBR19.0;
const R_AARCH64_JUMP26: u32 = elf::R_AARCH64_JUMP26.0;
const R_AARCH64_CALL26: u32 = elf::R_AARCH64_CALL26.0;
const R_AARCH64_LDST16_ABS_LO12_NC: u32 = elf::R_AARCH64_LDST16_ABS_LO12_NC.0;
const R_AARCH64_LDST32_ABS_LO12_NC: u32 = elf::R_AARCH64_LDST32_ABS_LO12_NC.0;
const R_AARCH64_LDST64_ABS_LO12_NC: u32 = elf::R_AARCH64_LDST64_ABS_LO12_NC.0;
const R_AARCH64_LDST128_ABS_LO12_NC: u32 = elf::R_AARCH64_LDST128_ABS_LO12_NC.0;
const R_AARCH64_JUMP_SLOT: u32 = elf::R_AARCH64_JUMP_SLOT.0;
const R_AARCH64_RELATIVE: u32 = elf::R_AARCH64_RELATIVE.0;

/// The kernel's list of the `call __fentry__` that starts each function it can trace, after the
/// function's `endbr64` when it has one.
const MCOUNT_LOC: &[u8] = b"__mcount_loc";
/// The kernel's list of the padding before each function, which it patches in at run time.
const PATCHABLE_FUNCTION_ENTRIES: &[u8] = b"__patchable_function_entries";
const ENDBR64: [u8; 4] = [0xf3, 0x0f, 0x1e, 0xfa];
const AARCH64_NOP: u32 = 0xd503_201f;
const BTI_C: u32 = 0xd503_245f;

/// The size of a `.plt` stub: x86-64's `jmp [rip+slot]` padded to 16 bytes as ELF linkers pad
/// theirs, or AArch64's four instructions.
const STUB: u64 = 16;

/// The machines [`link`] places code for.
#[derive(Clone, Copy, PartialEq)]
enum Machine {
    X86_64,
    Aarch64,
}

impl Machine {
    /// Where the first section goes: where Linux loads its modules. On x86-64, code built for the
    /// kernel takes addresses there as sign-extended 32-bit immediates, which no other code uses.
    fn base(self) -> u64 {
        match self {
            Machine::X86_64 => 0xffff_ffff_c000_0000,
            Machine::Aarch64 => 0xffff_8000_0000_0000,
        }
    }

    /// Whether a relocation of `kind` is a call or a jump, which makes an undefined symbol an import.
    fn calls(self, kind: u32) -> bool {
        match self {
            Machine::X86_64 => kind == R_X86_64_PLT32,
            Machine::Aarch64 => matches!(kind, R_AARCH64_CALL26 | R_AARCH64_JUMP26),
        }
    }

    /// Whether a relocation of `kind` stores a 64-bit pointer, which a loader would relocate again.
    fn stores_pointer(self, kind: u32) -> bool {
        kind == self.relocation(R_X86_64_64, R_AARCH64_ABS64)
    }

    fn relocation(self, x86_64: u32, aarch64: u32) -> u32 {
        match self {
            Machine::X86_64 => x86_64,
            Machine::Aarch64 => aarch64,
        }
    }

    /// The bytes a relocation of `kind` writes at `place` to refer to `value`, given the `old`
    /// bytes there, or `None` for a kind it does not apply.
    fn apply(self, kind: u32, place: u64, value: u64, old: &[u8]) -> Option<Vec<u8>> {
        let relative = value.wrapping_sub(place);
        let little = |word: u64, width: usize| word.to_le_bytes()[..width].to_vec();
        if self == Machine::X86_64 {
            return match kind {
                R_X86_64_64 => Some(little(value, 8)),
                R_X86_64_PC64 => Some(little(relative, 8)),
                R_X86_64_PC32 | R_X86_64_PLT32 => Some(little(relative, 4)),
                R_X86_64_32 | R_X86_64_32S => Some(little(value, 4)),
                _ => None,
            };
        }
        let data = |width: usize| (old.len() >= width).then_some(width);
        match kind {
            R_AARCH64_ABS64 => return data(8).map(|w| little(value, w)),
            R_AARCH64_PREL64 => return data(8).map(|w| little(relative, w)),
            R_AARCH64_ABS32 => return data(4).map(|w| little(value, w)),
            R_AARCH64_PREL32 => return data(4).map(|w| little(relative, w)),
            _ => {}
        }
        let insn = u32::from_le_bytes(old.get(..4)?.try_into().ok()?);
        // `field(bits, shift, imm)` puts the low `bits` of `imm` at bit `shift` of the instruction.
        let field = |bits: u32, shift: u32, imm: u64| {
            let mask = ((1u32 << bits) - 1) << shift;
            insn & !mask | (imm as u32) << shift & mask
        };
        let adr = |imm: u64| field(2, 29, imm) & !(0x7ffff << 5) | ((imm >> 2) as u32 & 0x7ffff) << 5;
        let lo12 = value & 0xfff;
        let insn = match kind {
            R_AARCH64_CALL26 | R_AARCH64_JUMP26 => field(26, 0, relative >> 2),
            R_AARCH64_CONDBR19 | R_AARCH64_LD_PREL_LO19 => field(19, 5, relative >> 2),
            R_AARCH64_TSTBR14 => field(14, 5, relative >> 2),
            R_AARCH64_ADR_PREL_LO21 => adr(relative),
            R_AARCH64_ADR_PREL_PG_HI21 | R_AARCH64_ADR_PREL_PG_HI21_NC => adr((value & !0xfff).wrapping_sub(place & !0xfff) >> 12),
            R_AARCH64_ADD_ABS_LO12_NC | R_AARCH64_LDST8_ABS_LO12_NC => field(12, 10, lo12),
            R_AARCH64_LDST16_ABS_LO12_NC => field(12, 10, lo12 >> 1),
            R_AARCH64_LDST32_ABS_LO12_NC => field(12, 10, lo12 >> 2),
            R_AARCH64_LDST64_ABS_LO12_NC => field(12, 10, lo12 >> 3),
            R_AARCH64_LDST128_ABS_LO12_NC => field(12, 10, lo12 >> 4),
            R_AARCH64_MOVW_UABS_G0..=R_AARCH64_MOVW_UABS_G3 => field(16, 5, value >> (16 * ((kind - R_AARCH64_MOVW_UABS_G0) / 2))),
            _ => return None,
        };
        Some(insn.to_le_bytes().to_vec())
    }

    /// The `.plt` stub at `stub` that jumps through the `.got` slot at `slot`.
    fn stub(self, stub: u64, slot: u64) -> Vec<u8> {
        match self {
            Machine::X86_64 => {
                let mut bytes = vec![0xff, 0x25];
                bytes.extend_from_slice(&(slot.wrapping_sub(stub + 6) as u32).to_le_bytes());
                bytes.resize(STUB as usize, 0xcc);
                bytes
            }
            // `adrp x16, slot; ldr x17, [x16, #slot]; add x16, x16, #slot; br x17`, as GNU ld writes it.
            Machine::Aarch64 => {
                let page = (slot & !0xfff).wrapping_sub(stub & !0xfff) >> 12;
                let lo12 = (slot & 0xfff) as u32;
                let adrp = 0x9000_0010 | (page as u32 & 3) << 29 | ((page >> 2) as u32 & 0x7ffff) << 5;
                [adrp, 0xf940_0211 | (lo12 >> 3) << 10, 0x9100_0210 | lo12 << 10, 0xd61f_0220].iter().flat_map(|i| i.to_le_bytes()).collect()
            }
        }
    }
}

/// `data` as a linked image when it is a relocatable x86-64 or AArch64 ELF file, and unchanged
/// otherwise.
pub fn link(data: Vec<u8>) -> Vec<u8> {
    try_link(&data).unwrap_or(data)
}

fn try_link(data: &[u8]) -> Option<Vec<u8>> {
    if data.get(..6)? != b"\x7fELF\x02\x01" || u16_at(data, 16)? != ET_REL {
        return None;
    }
    let machine = match u16_at(data, 18)? {
        EM_X86_64 => Machine::X86_64,
        EM_AARCH64 => Machine::Aarch64,
        _ => return None,
    };
    let (shoff, shnum, shstrndx) = (u64_at(data, 0x28)?, u16_at(data, 0x3c)?, usize::from(u16_at(data, 0x3e)?));
    let mut sections: Vec<Section> = (0..u64::from(shnum)).map(|index| Section::read(data, shoff.checked_add(index * 64)?)).collect::<Option<_>>()?;
    let symtab_index = sections.iter().position(|s| s.kind == SHT_SYMTAB)?;
    let symtab = sections[symtab_index];
    let strings = sections.get(symtab.link as usize)?.contents(data)?;
    let symbols: Vec<Symbol> = symtab.contents(data)?.as_chunks::<24>().0.iter().map(Symbol::read).collect();
    let name = |symbol: &Symbol| cstr(strings, symbol.name);

    let mut next = machine.base();
    for section in sections.iter_mut().filter(|s| s.flags & SHF_ALLOC != 0) {
        section.addr = next.checked_next_multiple_of(section.align.max(1))?;
        next = section.addr.checked_add(section.size)?;
    }

    let relocations: Vec<Relocation> = sections
        .iter()
        .filter(|s| s.kind == SHT_RELA && s.link as usize == symtab_index)
        .filter(|s| sections.get(s.info as usize).is_some_and(|target| target.kind != SHT_NOBITS && target.flags & SHF_COMPRESSED == 0))
        .filter_map(|s| Some(s.contents(data)?.as_chunks::<24>().0.iter().map(|entry| Relocation::read(s.info as usize, entry))))
        .flatten()
        .filter(|r| r.symbol != 0 && r.symbol < symbols.len())
        .collect();

    // What each relocation to an undefined symbol becomes: a patch over a call to a thunk, a
    // call to an import, or a reference to memory outside the module.
    let mut patches: Vec<Option<(u64, Vec<u8>)>> = Vec::with_capacity(relocations.len());
    let (mut called, mut referenced) = (BTreeSet::new(), BTreeSet::new());
    for r in &relocations {
        let symbol = &symbols[r.symbol];
        let target = &sections[r.section];
        let patch = (machine == Machine::X86_64 && symbol.shndx == SHN_UNDEF && r.kind == R_X86_64_PLT32)
            .then(|| thunk(name(symbol), target.contents(data)?, usize::try_from(r.offset).ok()?))
            .flatten();
        if patch.is_none() && symbol.shndx == SHN_UNDEF {
            if machine.calls(r.kind) {
                called.insert(name(symbol))
            } else {
                referenced.insert(name(symbol))
            };
        }
        patches.push(patch);
    }
    let imports: Vec<&[u8]> = called.iter().copied().collect();
    let externs: Vec<&[u8]> = referenced.difference(&called).copied().collect();

    let plt = next.checked_next_multiple_of(STUB)?;
    let got = plt.checked_add(STUB * imports.len() as u64)?;
    let extern_start = got.checked_add(8 * imports.len() as u64)?;
    extern_start.checked_add(8 * externs.len() as u64)?;
    let undefined: HashMap<&[u8], u64> = imports
        .iter()
        .enumerate()
        .map(|(index, &name)| (name, plt + STUB * index as u64))
        .chain(externs.iter().enumerate().map(|(index, &name)| (name, extern_start + 8 * index as u64)))
        .collect();
    let address = |symbol: &Symbol| match symbol.shndx {
        SHN_UNDEF => undefined.get(name(symbol)).copied(),
        SHN_ABS => Some(symbol.value),
        index if index < SHN_LORESERVE => Some(sections.get(usize::from(index))?.addr.wrapping_add(symbol.value)),
        _ => None,
    };
    let in_module = |symbol: &Symbol| {
        symbol.shndx != SHN_UNDEF && symbol.shndx < SHN_LORESERVE && sections.get(usize::from(symbol.shndx)).is_some_and(|s| s.flags & SHF_ALLOC != 0)
    };

    let old_names = sections.get(shstrndx)?.contents(data)?;
    let mut out = data.to_vec();
    let mut dynamic_relocations: Vec<Relocation> = Vec::new();
    for (r, patch) in relocations.iter().zip(patches) {
        let target = &sections[r.section];
        if let Some((start, bytes)) = patch {
            put(&mut out, target.offset.wrapping_add(start), &bytes);
            continue;
        }
        let symbol = &symbols[r.symbol];
        let Some(value) = address(symbol).map(|s| s.wrapping_add_signed(r.addend)) else { continue };
        let place = target.addr.wrapping_add(r.offset);
        let Some(old) = target.contents(data).and_then(|bytes| bytes.get(usize::try_from(r.offset).ok()?..)) else { continue };
        let Some(bytes) = machine.apply(r.kind, place, value, old).filter(|bytes| bytes.len() <= old.len()) else { continue };
        put(&mut out, target.offset.wrapping_add(r.offset), &bytes);
        if machine.stores_pointer(r.kind) && target.flags & SHF_ALLOC != 0 && in_module(symbol) {
            // The kernel's patch lists point into functions. Moved back over the `endbr64`, an
            // entry of `__mcount_loc` points at a function's start; on x86-64 one of the padding
            // before a function points at none.
            let pointer = match cstr(old_names, target.name) {
                PATCHABLE_FUNCTION_ENTRIES if machine == Machine::Aarch64 => Some(ftrace_start(&sections, data, value)),
                PATCHABLE_FUNCTION_ENTRIES => None,
                MCOUNT_LOC => Some(value.wrapping_sub(4 * u64::from(code_at(&sections, data, value.wrapping_sub(4), 4) == Some(&ENDBR64[..])))),
                _ => Some(value),
            };
            if let Some(pointer) = pointer {
                let kind = machine.relocation(R_X86_64_RELATIVE, R_AARCH64_RELATIVE);
                dynamic_relocations.push(Relocation { section: 0, offset: place, kind, symbol: 0, addend: pointer as i64 });
            }
        }
    }

    // The new sections follow the file's own: `.plt`, `.got`, `.extern`, `.dynsym`, `.dynstr`.
    let (extern_index, dynsym_index, dynstr_index) = (sections.len() + 2, sections.len() + 3, sections.len() + 4);

    // `.symtab` at the addresses just given, with each symbol of `.extern` defined there.
    let mut entry = 0;
    for (index, symbol) in symbols.iter().enumerate() {
        let mut symbol = *symbol;
        if in_module(&symbol) {
            symbol.value = address(&symbol)?;
        } else if symbol.shndx == SHN_UNDEF
            && index != 0
            && let Some(&slot) = undefined.get(name(&symbol)).filter(|&&slot| slot >= extern_start)
        {
            (symbol.shndx, symbol.value) = (extern_index as u16, slot);
            if symbol.kind() == STT_NOTYPE {
                symbol.info = symbol.info & 0xf0 | STT_OBJECT;
            }
        }
        if name(&symbol) == b"init_module" && in_module(&symbol) {
            entry = symbol.value;
        }
        put(&mut out, symtab.offset + 24 * index as u64, &symbol.bytes());
    }

    let mut dynstr = vec![0u8];
    let mut dynsym = vec![Symbol::default()];
    let mut add = |name: &[u8], kind: u8, shndx: u16, value: u64, size: u64| {
        let offset = dynstr.len() as u32;
        dynstr.extend_from_slice(name);
        dynstr.push(0);
        dynsym.push(Symbol { name: offset, info: STB_GLOBAL << 4 | kind, other: 0, shndx, value, size });
    };
    for (index, &import) in imports.iter().enumerate() {
        add(import, STT_FUNC, SHN_UNDEF, 0, 0);
        let slot = got + 8 * index as u64;
        let kind = machine.relocation(R_X86_64_JUMP_SLOT, R_AARCH64_JUMP_SLOT);
        dynamic_relocations.push(Relocation { section: 0, offset: slot, kind, symbol: index + 1, addend: 0 });
    }
    for symbol in symbols.iter().filter(|s| in_module(s) && matches!(s.kind(), STT_FUNC | STT_OBJECT) && !name(s).is_empty() && !is_padding(name(s))) {
        add(name(symbol), symbol.kind(), symbol.shndx, address(symbol)?, symbol.size);
    }
    for &name in &externs {
        add(name, STT_OBJECT, extern_index as u16, undefined[name], 8);
    }

    let stubs: Vec<u8> = (0..imports.len() as u64).flat_map(|index| machine.stub(plt + STUB * index, got + 8 * index)).collect();

    let mut names = old_names.to_vec();
    let mut new_section = |name: &str, kind: u32, flags: u64, addr: u64, size: u64, link: usize, entsize: u64, align: u64| {
        let section = Section { name: names.len() as u32, kind, flags, addr, offset: 0, size, link: link as u32, info: 0, align, entsize };
        names.extend_from_slice(name.as_bytes());
        names.push(0);
        section
    };
    let rela: Vec<u8> = dynamic_relocations.iter().flat_map(Relocation::bytes).collect();
    let dynsym: Vec<u8> = dynsym.iter().flat_map(Symbol::bytes).collect();
    let new = [
        (new_section(".plt", SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR, plt, stubs.len() as u64, 0, 0, STUB), stubs),
        (new_section(".got", SHT_PROGBITS, SHF_ALLOC | SHF_WRITE, got, 8 * imports.len() as u64, 0, 8, 8), vec![0; 8 * imports.len()]),
        (new_section(".extern", SHT_NOBITS, SHF_ALLOC | SHF_WRITE, extern_start, 8 * externs.len() as u64, 0, 0, 8), Vec::new()),
        (Section { info: 1, ..new_section(".dynsym", SHT_DYNSYM, 0, 0, dynsym.len() as u64, dynstr_index, 24, 8) }, dynsym),
        (new_section(".dynstr", SHT_STRTAB, 0, 0, dynstr.len() as u64, 0, 0, 1), dynstr),
        (new_section(".rela.dyn", SHT_RELA, 0, 0, rela.len() as u64, dynsym_index, 24, 8), rela),
    ];
    let shstrtab = new_section(".shstrtab", SHT_STRTAB, 0, 0, 0, 0, 0, 1);
    let new = new.into_iter().chain([(Section { size: names.len() as u64, ..shstrtab }, names)]);

    for (mut section, bytes) in new {
        out.resize(out.len().next_multiple_of(8), 0);
        section.offset = out.len() as u64;
        out.extend_from_slice(&bytes);
        sections.push(section);
    }
    out.resize(out.len().next_multiple_of(8), 0);
    let shoff = out.len() as u64;
    for section in &sections {
        out.extend_from_slice(&section.bytes());
    }
    put(&mut out, 16, &ET_DYN.to_le_bytes());
    put(&mut out, 0x18, &entry.to_le_bytes());
    put(&mut out, 0x28, &shoff.to_le_bytes());
    put(&mut out, 0x3c, &u16::try_from(sections.len()).ok().filter(|&n| n < SHN_LORESERVE)?.to_le_bytes());
    put(&mut out, 0x3e, &(sections.len() as u16 - 1).to_le_bytes());
    Some(out)
}

/// The start of the AArch64 function whose ftrace `nop`s start at `entry`, as the kernel's
/// `ftrace_call_adjust` finds it. Built with `-fpatchable-function-entry=4,2`, as for ftrace's
/// call ops, two of the four `nop`s come before the function, which may open with `bti c` before
/// the other two; built with `2,0`, as with clang's CFI, both follow the function's `bti c`.
fn ftrace_start(sections: &[Section], data: &[u8], entry: u64) -> u64 {
    let word = |at: u64| code_at(sections, data, at, 4).and_then(|bytes| u32_at(bytes, 0));
    let nops = |at: u64| word(at) == Some(AARCH64_NOP) && word(at + 4) == Some(AARCH64_NOP);
    if word(entry.wrapping_sub(4)) == Some(BTI_C) {
        entry - 4
    } else if nops(entry) && (nops(entry + 8) || word(entry + 8) == Some(BTI_C) && nops(entry + 12)) {
        entry + 8
    } else {
        entry
    }
}

/// Whether a function symbol names the padding the Linux kernel puts before each function, for
/// the code it patches in at run time, and not a function. LLVM's CFI of a 4.19 or 5.10 kernel
/// gives each module two real functions with the same prefix.
pub fn is_padding(name: &[u8]) -> bool {
    name.starts_with(b"__pfx_") || name.starts_with(b"__cfi_") && !matches!(name, b"__cfi_check" | b"__cfi_check_fail")
}

/// The bytes the kernel writes over the call or jump to `name` whose 32-bit displacement is at
/// `at` in `code`, as the offset they start at and the bytes, or `None` when `name` is not one
/// of its thunks.
fn thunk(name: &[u8], code: &[u8], at: usize) -> Option<(u64, Vec<u8>)> {
    const NOP: u8 = 0x90;
    const INT3: u8 = 0xcc;
    let opcode = *code.get(at.checked_sub(1)?)?;
    code.get(at..at.checked_add(4)?)?;
    let (start, mut bytes, fill) = match (name, opcode) {
        (b"__fentry__", 0xe8) => return Some(((at - 1) as u64, vec![0x0f, 0x1f, 0x44, 0x00, 0x00])),
        (b"__x86_return_thunk", 0xe9) => (at - 1, vec![0xc3], INT3),
        (_, 0xe8 | 0xe9) => {
            let register = indirect_thunk_register(name)?;
            // `-mindirect-branch-cs-prefix` puts a `cs` before each call and jump through r8 to
            // r15, to leave room for the extra byte of the instruction the kernel writes.
            let start = if register >= 8 && at >= 2 && code[at - 2] == 0x2e { at - 2 } else { at - 1 };
            let modrm = if opcode == 0xe8 { 0xd0 } else { 0xe0 } | (register & 7);
            let bytes = if register >= 8 { vec![0x41, 0xff, modrm] } else { vec![0xff, modrm] };
            (start, bytes, if opcode == 0xe8 { NOP } else { INT3 })
        }
        _ => return None,
    };
    bytes.resize(at + 4 - start, fill);
    Some((start as u64, bytes))
}

/// The register a retpoline thunk such as `__x86_indirect_thunk_rax` jumps through, numbered as
/// x86-64 encodes it.
fn indirect_thunk_register(name: &[u8]) -> Option<u8> {
    const REGISTERS: [&[u8]; 16] =
        [b"rax", b"rcx", b"rdx", b"rbx", b"rsp", b"rbp", b"rsi", b"rdi", b"r8", b"r9", b"r10", b"r11", b"r12", b"r13", b"r14", b"r15"];
    let register =
        [&b"__x86_indirect_thunk_"[..], b"__x86_indirect_call_thunk_", b"__x86_indirect_jump_thunk_"].iter().find_map(|prefix| name.strip_prefix(*prefix))?;
    REGISTERS.iter().position(|&r| r == register).map(|index| index as u8)
}

/// An ELF64 section header.
#[derive(Clone, Copy)]
struct Section {
    name: u32,
    kind: u32,
    flags: u64,
    addr: u64,
    offset: u64,
    size: u64,
    link: u32,
    info: u32,
    align: u64,
    entsize: u64,
}

impl Section {
    fn read(data: &[u8], at: u64) -> Option<Section> {
        let header = data.get(usize::try_from(at).ok()?..)?.get(..64)?;
        Some(Section {
            name: u32_at(header, 0)?,
            kind: u32_at(header, 4)?,
            flags: u64_at(header, 8)?,
            addr: u64_at(header, 16)?,
            offset: u64_at(header, 24)?,
            size: u64_at(header, 32)?,
            link: u32_at(header, 40)?,
            info: u32_at(header, 44)?,
            align: u64_at(header, 48)?,
            entsize: u64_at(header, 56)?,
        })
    }

    /// The section's bytes in the file.
    fn contents<'a>(&self, data: &'a [u8]) -> Option<&'a [u8]> {
        if self.kind == SHT_NOBITS {
            return None;
        }
        data.get(usize::try_from(self.offset).ok()?..)?.get(..usize::try_from(self.size).ok()?)
    }

    fn bytes(&self) -> Vec<u8> {
        [
            &self.name.to_le_bytes()[..],
            &self.kind.to_le_bytes(),
            &self.flags.to_le_bytes(),
            &self.addr.to_le_bytes(),
            &self.offset.to_le_bytes(),
            &self.size.to_le_bytes(),
            &self.link.to_le_bytes(),
            &self.info.to_le_bytes(),
            &self.align.to_le_bytes(),
            &self.entsize.to_le_bytes(),
        ]
        .concat()
    }
}

/// An ELF64 symbol.
#[derive(Clone, Copy, Default)]
struct Symbol {
    name: u32,
    info: u8,
    other: u8,
    shndx: u16,
    value: u64,
    size: u64,
}

impl Symbol {
    fn read(entry: &[u8; 24]) -> Symbol {
        let u64_in = |at| u64_at(entry, at).unwrap_or(0);
        Symbol {
            name: u32_at(entry, 0).unwrap_or(0),
            info: entry[4],
            other: entry[5],
            shndx: u16_at(entry, 6).unwrap_or(0),
            value: u64_in(8),
            size: u64_in(16),
        }
    }

    fn kind(&self) -> u8 {
        self.info & 0xf
    }

    fn bytes(&self) -> Vec<u8> {
        [&self.name.to_le_bytes()[..], &[self.info, self.other], &self.shndx.to_le_bytes(), &self.value.to_le_bytes(), &self.size.to_le_bytes()].concat()
    }
}

/// An ELF64 relocation with an addend, at `offset` in section `section`.
struct Relocation {
    section: usize,
    offset: u64,
    kind: u32,
    symbol: usize,
    addend: i64,
}

impl Relocation {
    fn read(section: usize, entry: &[u8; 24]) -> Relocation {
        let info = u64_at(entry, 8).unwrap_or(0);
        Relocation {
            section,
            offset: u64_at(entry, 0).unwrap_or(0),
            kind: info as u32,
            symbol: (info >> 32) as usize,
            addend: u64_at(entry, 16).unwrap_or(0) as i64,
        }
    }

    fn bytes(&self) -> Vec<u8> {
        let info = (self.symbol as u64) << 32 | u64::from(self.kind);
        [self.offset.to_le_bytes(), info.to_le_bytes(), self.addend.to_le_bytes()].concat()
    }
}

/// The `length` bytes at `addr` in the placed sections.
fn code_at<'a>(sections: &[Section], data: &'a [u8], addr: u64, length: usize) -> Option<&'a [u8]> {
    let section = sections.iter().find(|s| s.flags & SHF_ALLOC != 0 && addr >= s.addr && addr - s.addr < s.size)?;
    section.contents(data)?.get(usize::try_from(addr - section.addr).ok()?..)?.get(..length)
}

/// Writes `bytes` over `out` at `at`, when they fit.
fn put(out: &mut [u8], at: u64, bytes: &[u8]) {
    if let Some(slot) = usize::try_from(at).ok().and_then(|at| out.get_mut(at..at.checked_add(bytes.len())?)) {
        slot.copy_from_slice(bytes);
    }
}

/// The NUL-terminated string at `at` in a string table.
fn cstr(strings: &[u8], at: u32) -> &[u8] {
    let rest = strings.get(at as usize..).unwrap_or_default();
    &rest[..rest.iter().position(|&b| b == 0).unwrap_or(rest.len())]
}

fn u16_at(data: &[u8], at: u64) -> Option<u16> {
    Some(u16::from_le_bytes(data.get(usize::try_from(at).ok()?..)?.get(..2)?.try_into().ok()?))
}

fn u32_at(data: &[u8], at: u64) -> Option<u32> {
    Some(u32::from_le_bytes(data.get(usize::try_from(at).ok()?..)?.get(..4)?.try_into().ok()?))
}

fn u64_at(data: &[u8], at: u64) -> Option<u64> {
    Some(u64::from_le_bytes(data.get(usize::try_from(at).ok()?..)?.get(..8)?.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cs_prefix_is_overwritten_only_where_the_compiler_puts_one() {
        // `jne` with a displacement of 0x2e, then `jmp __x86_return_thunk`.
        assert_eq!(thunk(b"__x86_return_thunk", &[0x75, 0x2e, 0xe9, 0, 0, 0, 0], 3), Some((2, vec![0xc3, 0xcc, 0xcc, 0xcc, 0xcc])));
        // `cs call __x86_indirect_thunk_r11` is `call r11`.
        assert_eq!(thunk(b"__x86_indirect_thunk_r11", &[0x2e, 0xe8, 0, 0, 0, 0], 2), Some((0, vec![0x41, 0xff, 0xd3, 0x90, 0x90, 0x90])));
    }

    #[test]
    fn an_aarch64_relocation_writes_the_instruction_an_assembler_would() {
        const PLACE: u64 = 0xffff_8000_0001_2340;
        const WIDE: u64 = 0x1234_5678_9abc_def0;
        // The words are llvm-mc's encodings of each instruction with a zero operand and with the
        // operand that reaches `value` from `PLACE`, such as `bl #0` and `bl #-0x10000`.
        let rows: [(u32, u32, u64, Option<u32>); 22] = [
            (R_AARCH64_CALL26, 0x9400_0000, PLACE - 0x10000, Some(0x97ff_c000)),
            (R_AARCH64_JUMP26, 0x1400_0000, PLACE - 0x40, Some(0x17ff_fff0)),
            (R_AARCH64_CONDBR19, 0x5400_0001, PLACE - 0x40, Some(0x54ff_fe01)),
            (R_AARCH64_TSTBR14, 0x3628_0003, PLACE - 0x40, Some(0x362f_fe03)),
            (R_AARCH64_LD_PREL_LO19, 0x5800_0000, PLACE - 0x40, Some(0x58ff_fe00)),
            (R_AARCH64_ADR_PREL_LO21, 0x1000_0000, PLACE - 0x33, Some(0x30ff_fe60)),
            (R_AARCH64_ADR_PREL_PG_HI21, 0x9000_0000, 0xffff_8000_0000_1234, Some(0xf0ff_ff60)),
            (R_AARCH64_ADR_PREL_PG_HI21_NC, 0x9000_0001, 0xffff_8000_0123_4567, Some(0xd000_9101)),
            (R_AARCH64_ADD_ABS_LO12_NC, 0x9100_0020, 0xffff_8000_0000_59a0, Some(0x9126_8020)),
            (R_AARCH64_LDST8_ABS_LO12_NC, 0x3940_0020, 0xffff_8000_0000_59a0, Some(0x3966_8020)),
            (R_AARCH64_LDST16_ABS_LO12_NC, 0x7940_0020, 0xffff_8000_0000_59a0, Some(0x7953_4020)),
            (R_AARCH64_LDST32_ABS_LO12_NC, 0xb940_0020, 0xffff_8000_0000_59a0, Some(0xb949_a020)),
            (R_AARCH64_LDST64_ABS_LO12_NC, 0xf940_0020, 0xffff_8000_0000_59a0, Some(0xf944_d020)),
            (R_AARCH64_LDST128_ABS_LO12_NC, 0x3dc0_0020, 0xffff_8000_0000_59a0, Some(0x3dc2_6820)),
            (R_AARCH64_MOVW_UABS_G0, 0xd280_0000, WIDE, Some(0xd29b_de00)),
            (elf::R_AARCH64_MOVW_UABS_G0_NC.0, 0xf280_0000, WIDE, Some(0xf29b_de00)),
            (elf::R_AARCH64_MOVW_UABS_G1.0, 0xd2a0_0000, WIDE, Some(0xd2b3_5780)),
            (elf::R_AARCH64_MOVW_UABS_G1_NC.0, 0xf2a0_0000, WIDE, Some(0xf2b3_5780)),
            (elf::R_AARCH64_MOVW_UABS_G2.0, 0xd2c0_0000, WIDE, Some(0xd2ca_cf00)),
            (elf::R_AARCH64_MOVW_UABS_G2_NC.0, 0xf2c0_0000, WIDE, Some(0xf2ca_cf00)),
            (R_AARCH64_MOVW_UABS_G3, 0xf2e0_0000, WIDE, Some(0xf2e2_4680)),
            (elf::R_AARCH64_MOVW_SABS_G0.0, 0xd280_0000, WIDE, None),
        ];
        for (kind, old, value, new) in rows {
            let new = new.map(|word| word.to_le_bytes().to_vec());
            assert_eq!(Machine::Aarch64.apply(kind, PLACE, value, &old.to_le_bytes()), new, "relocation {kind}");
        }

        let data = [
            (R_AARCH64_ABS64, WIDE, WIDE.to_le_bytes().to_vec()),
            (R_AARCH64_ABS32, WIDE, WIDE.to_le_bytes()[..4].to_vec()),
            (R_AARCH64_PREL64, PLACE - 0x40, (-0x40i64).to_le_bytes().to_vec()),
            (R_AARCH64_PREL32, PLACE - 0x40, (-0x40i32).to_le_bytes().to_vec()),
        ];
        for (kind, value, new) in data {
            assert_eq!(Machine::Aarch64.apply(kind, PLACE, value, &[0; 8]), Some(new), "relocation {kind}");
        }
    }

    #[test]
    fn an_aarch64_function_starts_where_ftrace_call_adjust_puts_it() {
        const NOP: u32 = 0xd503_201f;
        const BTI_C: u32 = 0xd503_245f;
        const RET: u32 = 0xd65f_03c0;
        const BASE: u64 = 0xffff_8000_0000_0000;
        // The layouts the comment on the kernel's `ftrace_call_adjust` lists, each after a `ret`.
        let words = [
            RET, NOP, NOP, NOP, NOP, // `-fpatchable-function-entry=4,2`
            RET, NOP, NOP, BTI_C, NOP, NOP, // the same with `bti c`
            RET, NOP, NOP, // `-fpatchable-function-entry=2,0`
            RET, BTI_C, NOP, NOP, // the same with `bti c`
            RET,
        ];
        let data: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        let section = Section {
            name: 0,
            kind: SHT_PROGBITS,
            flags: SHF_ALLOC | SHF_EXECINSTR,
            addr: BASE,
            offset: 0,
            size: data.len() as u64,
            link: 0,
            info: 0,
            align: 4,
            entsize: 0,
        };
        // The word each `__patchable_function_entries` entry points at, and the function's start.
        for (entry, start) in [(1, 3), (6, 8), (12, 12), (16, 15)] {
            assert_eq!(ftrace_start(&[section], &data, BASE + 4 * entry), BASE + 4 * start, "entry at word {entry}");
        }
    }
}
