//! Linux kernel modules, and other relocatable x86-64 ELF files, read as if they were linked.
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
//!   does the start of each function `__mcount_loc` lists, the kernel's own list of them;
//! - `.dynsym` names the functions and objects of `.symtab`, but for the padding the kernel puts
//!   before each function (`__pfx_`, `__cfi_`), and the symbols in `.extern`;
//! - the entry is `init_module`, the function the kernel calls first;
//! - calls and jumps to the kernel's thunks are rewritten to what the kernel patches them to
//!   when it loads a module: `jmp __x86_return_thunk` to `ret`, `call __x86_indirect_thunk_rax`
//!   to `call rax`, and `call __fentry__` to a no-op.

use std::collections::{BTreeSet, HashMap};

const ET_REL: u16 = 1;
const ET_DYN: u16 = 3;
const EM_X86_64: u16 = 62;

const SHT_PROGBITS: u32 = 1;
const SHT_SYMTAB: u32 = 2;
const SHT_STRTAB: u32 = 3;
const SHT_RELA: u32 = 4;
const SHT_NOBITS: u32 = 8;
const SHT_DYNSYM: u32 = 11;
const SHF_WRITE: u64 = 1;
const SHF_ALLOC: u64 = 2;
const SHF_EXECINSTR: u64 = 4;
const SHF_COMPRESSED: u64 = 0x800;
const SHN_UNDEF: u16 = 0;
const SHN_LORESERVE: u16 = 0xff00;
const SHN_ABS: u16 = 0xfff1;
const STB_GLOBAL: u8 = 1;
const STT_NOTYPE: u8 = 0;
const STT_OBJECT: u8 = 1;
const STT_FUNC: u8 = 2;

const R_X86_64_64: u32 = 1;
const R_X86_64_PC32: u32 = 2;
const R_X86_64_PLT32: u32 = 4;
const R_X86_64_JUMP_SLOT: u32 = 7;
const R_X86_64_RELATIVE: u32 = 8;
const R_X86_64_32: u32 = 10;
const R_X86_64_32S: u32 = 11;
const R_X86_64_PC64: u32 = 24;

/// The kernel's list of the `call __fentry__` that starts each function it can trace, after the
/// function's `endbr64` when it has one.
const MCOUNT_LOC: &[u8] = b"__mcount_loc";
/// The kernel's list of the padding before each function, which it patches in at run time.
const PATCHABLE_FUNCTION_ENTRIES: &[u8] = b"__patchable_function_entries";
const ENDBR64: [u8; 4] = [0xf3, 0x0f, 0x1e, 0xfa];

/// Where the first section goes: where Linux loads its modules on x86-64. Code built for the
/// kernel takes addresses there as sign-extended 32-bit immediates, which no other code uses.
const BASE: u64 = 0xffff_ffff_c000_0000;
/// The size of a `.plt` stub: `jmp [rip+slot]`, padded to 16 bytes as ELF linkers pad theirs.
const STUB: u64 = 16;

/// `data` as a linked image when it is a relocatable x86-64 ELF file, and unchanged otherwise.
pub fn link(data: Vec<u8>) -> Vec<u8> {
    try_link(&data).unwrap_or(data)
}

fn try_link(data: &[u8]) -> Option<Vec<u8>> {
    if data.get(..6)? != b"\x7fELF\x02\x01" || u16_at(data, 16)? != ET_REL || u16_at(data, 18)? != EM_X86_64 {
        return None;
    }
    let (shoff, shnum, shstrndx) = (u64_at(data, 0x28)?, u16_at(data, 0x3c)?, usize::from(u16_at(data, 0x3e)?));
    let mut sections: Vec<Section> = (0..u64::from(shnum)).map(|index| Section::read(data, shoff.checked_add(index * 64)?)).collect::<Option<_>>()?;
    let symtab_index = sections.iter().position(|s| s.kind == SHT_SYMTAB)?;
    let symtab = sections[symtab_index];
    let strings = sections.get(symtab.link as usize)?.contents(data)?;
    let symbols: Vec<Symbol> = symtab.contents(data)?.as_chunks::<24>().0.iter().map(Symbol::read).collect();
    let name = |symbol: &Symbol| cstr(strings, symbol.name);

    let mut next = BASE;
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
        let patch = (symbol.shndx == SHN_UNDEF && r.kind == R_X86_64_PLT32)
            .then(|| thunk(name(symbol), target.contents(data)?, usize::try_from(r.offset).ok()?))
            .flatten();
        if patch.is_none() && symbol.shndx == SHN_UNDEF {
            if r.kind == R_X86_64_PLT32 {
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
        let (width, word) = match r.kind {
            R_X86_64_64 => (8, value),
            R_X86_64_PC64 => (8, value.wrapping_sub(place)),
            R_X86_64_PC32 | R_X86_64_PLT32 => (4, value.wrapping_sub(place)),
            R_X86_64_32 | R_X86_64_32S => (4, value),
            _ => continue,
        };
        if r.offset.checked_add(width).is_none_or(|end| end > target.size) {
            continue;
        }
        put(&mut out, target.offset.wrapping_add(r.offset), &word.to_le_bytes()[..width as usize]);
        if r.kind == R_X86_64_64 && target.flags & SHF_ALLOC != 0 && in_module(symbol) {
            // The kernel's patch lists point into functions. Moved back over the `endbr64`, an
            // entry of `__mcount_loc` points at a function's start; one of the padding before a
            // function points at none.
            let pointer = match cstr(old_names, target.name) {
                PATCHABLE_FUNCTION_ENTRIES => None,
                MCOUNT_LOC => Some(value.wrapping_sub(4 * u64::from(code_at(&sections, data, value.wrapping_sub(4), 4) == Some(&ENDBR64[..])))),
                _ => Some(value),
            };
            if let Some(pointer) = pointer {
                dynamic_relocations.push(Relocation { section: 0, offset: place, kind: R_X86_64_RELATIVE, symbol: 0, addend: pointer as i64 });
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
        dynamic_relocations.push(Relocation { section: 0, offset: slot, kind: R_X86_64_JUMP_SLOT, symbol: index + 1, addend: 0 });
    }
    for symbol in symbols.iter().filter(|s| in_module(s) && matches!(s.kind(), STT_FUNC | STT_OBJECT) && !name(s).is_empty() && !is_padding(name(s))) {
        add(name(symbol), symbol.kind(), symbol.shndx, address(symbol)?, symbol.size);
    }
    for &name in &externs {
        add(name, STT_OBJECT, extern_index as u16, undefined[name], 8);
    }

    let mut stubs = Vec::with_capacity(imports.len() * STUB as usize);
    for index in 0..imports.len() as u64 {
        let (stub, slot) = (plt + STUB * index, got + 8 * index);
        stubs.extend_from_slice(&[0xff, 0x25]);
        stubs.extend_from_slice(&(slot.wrapping_sub(stub + 6) as u32).to_le_bytes());
        stubs.resize(stubs.len() + STUB as usize - 6, 0xcc);
    }

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

/// Whether a function symbol names the padding the Linux kernel puts before each function, for
/// the code it patches in at run time, and not a function.
pub fn is_padding(name: &[u8]) -> bool {
    name.starts_with(b"__pfx_") || name.starts_with(b"__cfi_")
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
    use super::thunk;

    #[test]
    fn a_cs_prefix_is_overwritten_only_where_the_compiler_puts_one() {
        // `jne` with a displacement of 0x2e, then `jmp __x86_return_thunk`.
        assert_eq!(thunk(b"__x86_return_thunk", &[0x75, 0x2e, 0xe9, 0, 0, 0, 0], 3), Some((2, vec![0xc3, 0xcc, 0xcc, 0xcc, 0xcc])));
        // `cs call __x86_indirect_thunk_r11` is `call r11`.
        assert_eq!(thunk(b"__x86_indirect_thunk_r11", &[0x2e, 0xe8, 0, 0, 0, 0], 2), Some((0, vec![0x41, 0xff, 0xd3, 0x90, 0x90, 0x90])));
    }
}
