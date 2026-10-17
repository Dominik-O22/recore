//! ELF files whose section headers were removed, as OpenWrt's `sstrip` removes them from every
//! program it ships. The loader needs only the program headers, so such a file still runs, but
//! everything recore reads through sections is gone: the dynamic symbols, the relocations, the
//! unwind tables, and which bytes are code. [`restore`] writes the section headers back from what
//! the program headers and the dynamic table still say, so the file loads like any other.
//!
//! What it gives back, for each loaded segment:
//! - the tables the dynamic table points to, under their usual names: `.dynsym`, `.dynstr`, the
//!   relocations, `.dynamic`, and the unwind tables of `PT_GNU_EH_FRAME` and `PT_ARM_EXIDX`;
//! - in an executable segment, `.text` from the end of the tables before the first code to the
//!   end of `DT_FINI`, the last code the linker places, and `.rodata` for what follows; the
//!   PLT, which GNU ld places after `.init`, as `.plt`;
//! - in a read-only segment, `.rodata` for what no table covers, after the last of them;
//! - in a writable one, `.data.rel.ro` for the part `PT_GNU_RELRO` protects, `.data` for the
//!   rest, and `.bss` for the memory beyond the file's bytes.

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_GNU_EH_FRAME: u32 = 0x6474_e550;
const PT_GNU_RELRO: u32 = 0x6474_e552;
const PT_GNU_PROPERTY: u32 = 0x6474_e553;
const PT_ARM_EXIDX: u32 = 0x7000_0001;
const PF_X: u32 = 1;
const PF_W: u32 = 2;

const SHT_PROGBITS: u32 = 1;
const SHT_STRTAB: u32 = 3;
const SHT_RELA: u32 = 4;
const SHT_DYNAMIC: u32 = 6;
const SHT_NOTE: u32 = 7;
const SHT_NOBITS: u32 = 8;
const SHT_REL: u32 = 9;
const SHT_DYNSYM: u32 = 11;
const SHT_RELR: u32 = 19;
const SHT_ARM_EXIDX: u32 = 0x7000_0001;
const SHF_WRITE: u64 = 1;
const SHF_ALLOC: u64 = 2;
const SHF_EXECINSTR: u64 = 4;

const EM_386: u16 = 3;
const EM_ARM: u16 = 40;
const EM_X86_64: u16 = 62;
const EM_AARCH64: u16 = 183;

/// Whether `data` is a little-endian ELF file with program headers and no section headers.
pub fn is_sectionless(data: &[u8]) -> bool {
    Elf::parse(data).is_some_and(|elf| elf.shnum == 0 && !elf.segments.is_empty())
}

/// `data` with section headers written back, or `None` when it is not a sectionless ELF file
/// with a dynamic table to rebuild them from.
pub fn restore(data: &[u8]) -> Option<Vec<u8>> {
    let elf = Elf::parse(data)?;
    if elf.shnum != 0 {
        return None;
    }
    let sections = elf.sections()?;
    Some(elf.write(data, &sections))
}

#[derive(Clone, Copy)]
struct Segment {
    kind: u32,
    flags: u32,
    offset: u64,
    addr: u64,
    filesz: u64,
    memsz: u64,
}

/// A section to write: where it is, and what an ELF section header says about it.
struct Shdr {
    name: &'static str,
    kind: u32,
    flags: u64,
    addr: u64,
    size: u64,
    /// The name of the section `sh_link` names: the symbols a relocation table uses, the strings
    /// of a symbol table.
    link: Option<&'static str>,
    entsize: u64,
}

struct Elf<'a> {
    data: &'a [u8],
    wide: bool,
    machine: u16,
    shnum: u16,
    segments: Vec<Segment>,
}

impl<'a> Elf<'a> {
    fn parse(data: &'a [u8]) -> Option<Elf<'a>> {
        if data.get(..4)? != b"\x7fELF" || *data.get(5)? != 1 {
            return None;
        }
        let wide = match data.get(4)? {
            1 => false,
            2 => true,
            _ => return None,
        };
        let elf = Elf { data, wide, machine: u16_at(data, 18)?, shnum: 0, segments: Vec::new() };
        let (phoff, phentsize, phnum, shnum) = if wide {
            (elf.word(0x20)?, u16_at(data, 0x36)?, u16_at(data, 0x38)?, u16_at(data, 0x3C)?)
        } else {
            (elf.word(0x1C)?, u16_at(data, 0x2A)?, u16_at(data, 0x2C)?, u16_at(data, 0x30)?)
        };
        let segments = (0..u64::from(phnum))
            .map(|index| {
                let at = phoff + index * u64::from(phentsize);
                Some(if wide {
                    Segment {
                        kind: u32_at(data, at)?,
                        flags: u32_at(data, at + 4)?,
                        offset: u64_at(data, at + 8)?,
                        addr: u64_at(data, at + 16)?,
                        filesz: u64_at(data, at + 32)?,
                        memsz: u64_at(data, at + 40)?,
                    }
                } else {
                    Segment {
                        kind: u32_at(data, at)?,
                        offset: u32_at(data, at + 4)?.into(),
                        addr: u32_at(data, at + 8)?.into(),
                        filesz: u32_at(data, at + 16)?.into(),
                        memsz: u32_at(data, at + 20)?.into(),
                        flags: u32_at(data, at + 24)?,
                    }
                })
            })
            .collect::<Option<Vec<_>>>()?;
        Some(Elf { shnum, segments, ..elf })
    }

    /// The address-sized word at file offset `at`.
    fn word(&self, at: u64) -> Option<u64> {
        if self.wide { u64_at(self.data, at) } else { u32_at(self.data, at).map(u64::from) }
    }

    fn loads(&self) -> impl Iterator<Item = &Segment> {
        self.segments.iter().filter(|segment| segment.kind == PT_LOAD)
    }

    /// The file offset of address `addr`, in a loaded segment's bytes from the file.
    fn offset(&self, addr: u64) -> Option<u64> {
        self.loads().find(|s| addr >= s.addr && addr < s.addr + s.filesz).map(|s| s.offset + addr - s.addr)
    }

    fn u32_at_addr(&self, addr: u64) -> Option<u32> {
        u32_at(self.data, self.offset(addr)?)
    }

    fn dynamic(&self) -> Option<Vec<(u64, u64)>> {
        let segment = self.segments.iter().find(|s| s.kind == PT_DYNAMIC)?;
        let size = if self.wide { 16 } else { 8 };
        let entries = (0..segment.filesz / size)
            .map(|index| Some((self.word(segment.offset + index * size)?, self.word(segment.offset + index * size + size / 2)?)))
            .take_while(|entry| entry.is_some_and(|(tag, _)| tag != 0))
            .collect::<Option<Vec<_>>>()?;
        Some(entries)
    }

    /// How many entries the dynamic symbol table has. The ELF hash table says it outright; the
    /// GNU one says where each chain of symbols starts, and the last chain ends at the last. A
    /// GNU table with no chains, in a program that exports nothing, says nothing, and then the
    /// symbols run up to the next table the dynamic section points to.
    fn symbol_count(&self, tag: impl Fn(u64) -> Option<u64>, symbol_size: u64) -> Option<u64> {
        if let Some(hash) = tag(4) {
            return self.u32_at_addr(hash + 4).map(u64::from);
        }
        let symbols = tag(6)?;
        let chained = tag(0x6fff_fef5).and_then(|hash| {
            let (buckets, first, bloom) = (self.u32_at_addr(hash)?, self.u32_at_addr(hash + 4)?, self.u32_at_addr(hash + 8)?);
            let bucket_table = hash + 16 + u64::from(bloom) * if self.wide { 8 } else { 4 };
            let chains = bucket_table + 4 * u64::from(buckets);
            let last = (0..u64::from(buckets)).filter_map(|index| self.u32_at_addr(bucket_table + 4 * index)).max()?;
            if last < first {
                return None;
            }
            let mut index = u64::from(last);
            while self.u32_at_addr(chains + 4 * (index - u64::from(first)))? & 1 == 0 {
                index += 1;
            }
            Some(index + 1)
        });
        // The string table, the version tables, the hash table and the relocations.
        let next = [5, 0x6fff_fff0, 0x6fff_fffe, 0x6fff_fffc, 0x6fff_fef5, 7, 17, 23].into_iter().filter_map(&tag).filter(|&at| at > symbols).min();
        chained.or_else(|| next.map(|next| (next - symbols) / symbol_size))
    }

    /// The address of `.eh_frame`, from the pointer that opens `.eh_frame_hdr` at `hdr`.
    fn eh_frame(&self, hdr: u64) -> Option<u64> {
        let at = self.offset(hdr)?;
        let encoding = *self.data.get(at as usize + 1)?;
        let value = i64::from(u32_at(self.data, at + 4)? as i32);
        match encoding {
            // Signed 4 bytes, relative to the field itself or to the start of the header.
            0x1b => Some((hdr + 4).wrapping_add_signed(value)),
            0x3b => Some(hdr.wrapping_add_signed(value)),
            0x03 => Some(u64::from(u32_at(self.data, at + 4)?)),
            _ => None,
        }
    }

    /// Where the function at `addr` returns: the end of the first return instruction within a
    /// few dozen bytes. `.init` and `.fini` are a few instructions each.
    fn end_of_short_function(&self, addr: u64) -> Option<u64> {
        let at = self.offset(addr & !1)? as usize;
        let bytes = self.data.get(at..at + 64)?;
        let found = match self.machine {
            EM_X86_64 | EM_386 => bytes.iter().position(|&byte| byte == 0xC3).map(|end| end + 1),
            EM_AARCH64 => bytes.chunks_exact(4).position(|word| word == 0xd65f_03c0u32.to_le_bytes()).map(|end| 4 * end + 4),
            // Thumb: `bx lr` or a `pop` that takes the pc.
            EM_ARM if addr & 1 == 1 => bytes.chunks_exact(2).position(|half| half == [0x70, 0x47] || half[1] == 0xBD).map(|end| 2 * end + 2),
            // A32: `bx lr`, or a load of several registers from the stack that takes the pc.
            EM_ARM => bytes
                .chunks_exact(4)
                .map(|word| u32::from_le_bytes(word.try_into().unwrap()))
                .position(|word| word == 0xE12F_FF1E || word & 0xFFFF_8000 == 0xE8BD_8000)
                .map(|end| 4 * end + 4),
            _ => None,
        }?;
        Some((addr & !1) + found as u64)
    }

    /// Where the PLT is, with `count` stubs: GNU ld places it right after `.init`, and its first
    /// entry, which every stub jumps to, is the same few instructions in every program.
    fn plt(&self, init: u64, count: u64) -> Option<(u64, u64)> {
        let at = self.offset(init)? as usize;
        let window = self.data.get(at..(at + 8192).min(self.data.len()))?;
        let word = |offset: usize| window.get(offset..offset + 4).map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()));
        let found = |step: usize, matches: &dyn Fn(usize) -> bool| (0..window.len()).step_by(step).find(|&offset| matches(offset));
        let (start, size) = match self.machine {
            // `push {lr}; ldr lr, [pc, #4]`, 20 bytes in all; the stubs are walked below.
            EM_ARM => (found(4, &|o| word(o) == Some(0xE52D_E004) && word(o + 4) == Some(0xE59F_E004))?, 0),
            // `stp x16, x30, [sp, #-16]!`, then 32 bytes in all, and 16 for each stub.
            EM_AARCH64 => (found(4, &|o| word(o) == Some(0xA9BF_7BF0))?, 32 + 16 * count),
            // `push [rip+a]; jmp [rip+b]`, or `push [ebx+4]; jmp [ebx+8]` in 32-bit PIC: 16 bytes each.
            EM_X86_64 | EM_386 => {
                // The jump may carry a `bnd` prefix, 0xF2.
                let jumps = |b: &[u8], pattern: [u8; 2]| b[6..8] == pattern || b[6..9] == [0xF2, pattern[0], pattern[1]];
                let starts = |o: usize| window.get(o..o + 9).is_some_and(|b| b[..2] == [0xFF, 0x35] && jumps(b, [0xFF, 0x25]));
                let pic = |o: usize| window.get(o..o + 9).is_some_and(|b| b[..2] == [0xFF, 0xB3] && jumps(b, [0xFF, 0xA3]));
                (found(16, &|o| starts(o) || pic(o))?, 16 + 16 * count)
            }
            _ => return None,
        };
        if self.machine != EM_ARM {
            // With indirect branch tracking, each stub of the PLT pushes and jumps to the first
            // entry, and the stubs callers call, `endbr64; jmp [slot]`, follow in `.plt.sec`.
            let next = window.get(start + size as usize..).unwrap_or_default();
            let secondary = next.starts_with(&[0xF3, 0x0F, 0x1E, 0xFA, 0xFF, 0x25]) || next.starts_with(&[0xF3, 0x0F, 0x1E, 0xFA, 0xF2, 0xFF, 0x25]);
            let size = if secondary && matches!(self.machine, EM_X86_64 | EM_386) { size + 16 * count } else { size };
            return Some((init + start as u64, size));
        }
        // ARM stubs are `add ip, pc, #a; add ip, ip, #b; ldr pc, [ip, #c]!`, and one a Thumb
        // caller reaches has a four-byte `bx pc` and `nop` or `b .` before it, so walk them to
        // find the end.
        let is = |offset: usize, pattern: u32| word(offset).is_some_and(|w| w & 0xFFFF_F000 == pattern);
        let mut end = start + 20;
        loop {
            let stub = if word(end).is_some_and(|w| w & 0xFFFF == 0x4778) { end + 4 } else { end };
            if !(is(stub, 0xE28F_C000) && is(stub + 4, 0xE28C_C000) && is(stub + 8, 0xE5BC_F000)) {
                break;
            }
            end = stub + 12;
        }
        Some((init + start as u64, (end - start) as u64))
    }

    fn sections(&self) -> Option<Vec<Shdr>> {
        let dynamic = self.dynamic()?;
        let tag = |wanted: u64| dynamic.iter().find(|&&(tag, _)| tag == wanted).map(|&(_, value)| value);
        let word = if self.wide { 8 } else { 4 };
        let mut tables = Vec::new();
        let mut table = |name, kind, addr: Option<u64>, size: Option<u64>, link, entsize| {
            if let (Some(addr), Some(size)) = (addr, size)
                && size > 0
            {
                tables.push(Shdr { name, kind, flags: SHF_ALLOC, addr, size, link, entsize });
            }
        };
        let symbol_size = if self.wide { 24 } else { 16 };
        table(".dynsym", SHT_DYNSYM, tag(6), self.symbol_count(tag, symbol_size).map(|count| count * symbol_size), Some(".dynstr"), symbol_size);
        table(".dynstr", SHT_STRTAB, tag(5), tag(10), None, 0);
        let rela = if self.wide { 24 } else { 12 };
        table(".rela.dyn", SHT_RELA, tag(7), tag(8), Some(".dynsym"), rela);
        table(".rel.dyn", SHT_REL, tag(17), tag(18), Some(".dynsym"), 2 * word);
        let (plt_kind, plt_name, plt_entry) = if tag(20) == Some(7) { (SHT_RELA, ".rela.plt", rela) } else { (SHT_REL, ".rel.plt", 2 * word) };
        table(plt_name, plt_kind, tag(23), tag(2), Some(".dynsym"), plt_entry);
        table(".relr.dyn", SHT_RELR, tag(36), tag(35), None, word);
        for segment in &self.segments {
            match segment.kind {
                PT_DYNAMIC => table(".dynamic", SHT_DYNAMIC, Some(segment.addr), Some(segment.filesz), Some(".dynstr"), 2 * word),
                PT_ARM_EXIDX => table(".ARM.exidx", SHT_ARM_EXIDX, Some(segment.addr), Some(segment.filesz), None, 0),
                PT_GNU_PROPERTY => table(".note.gnu.property", SHT_NOTE, Some(segment.addr), Some(segment.filesz), None, 0),
                PT_GNU_EH_FRAME => {
                    table(".eh_frame_hdr", SHT_PROGBITS, Some(segment.addr), Some(segment.filesz), None, 0);
                    // `.eh_frame` runs to the next table or the end of its segment.
                    if let Some(frames) = self.eh_frame(segment.addr) {
                        let load = self.loads().find(|load| frames >= load.addr && frames < load.addr + load.filesz)?;
                        table(".eh_frame", SHT_PROGBITS, Some(frames), Some(load.addr + load.filesz - frames), None, 0);
                    }
                }
                _ => {}
            }
        }
        let relocation_size = if tag(20) == Some(7) { rela } else { 2 * word };
        if let Some((addr, size)) = tag(12).zip(tag(2)).and_then(|(init, size)| self.plt(init & !1, size / relocation_size)) {
            tables.push(Shdr { name: ".plt", kind: SHT_PROGBITS, flags: SHF_ALLOC | SHF_EXECINSTR, addr, size, link: None, entsize: 0 });
        }
        // Tables that overlap, such as `.dynamic` inside the writable segment, each keep their
        // bytes, and an `.eh_frame` taken to the end of its segment stops at the next table.
        tables.sort_by_key(|t| t.addr);
        for index in 1..tables.len() {
            let next = tables[index].addr;
            let previous = &mut tables[index - 1];
            if previous.addr + previous.size > next && previous.name == ".eh_frame" {
                previous.size = next - previous.addr;
            }
        }

        let relro = self.segments.iter().find(|s| s.kind == PT_GNU_RELRO).map(|s| (s.addr, s.addr + s.memsz));
        let mut out: Vec<Shdr> = Vec::new();
        for segment in self.loads() {
            let (start, end) = (segment.addr, segment.addr + segment.filesz);
            let inside: Vec<&Shdr> = tables.iter().filter(|t| t.addr >= start && t.addr < end).collect();
            let fill = |out: &mut Vec<Shdr>, name: &'static str, flags: u64, from: u64, to: u64| {
                // The gaps between the tables in `from..to` take `name`.
                let mut at = from;
                for t in inside.iter().filter(|t| t.addr + t.size > from && t.addr < to) {
                    if t.addr > at {
                        out.push(Shdr { name, kind: SHT_PROGBITS, flags, addr: at, size: t.addr - at, link: None, entsize: 0 });
                    }
                    at = at.max(t.addr + t.size);
                }
                if to > at {
                    out.push(Shdr { name, kind: SHT_PROGBITS, flags, addr: at, size: to - at, link: None, entsize: 0 });
                }
            };
            if segment.flags & PF_X != 0 {
                let fini = tag(13).filter(|&fini| (fini & !1) >= start && (fini & !1) < end);
                // Code starts after the last table before the first code the loader runs: GNU ld
                // puts `.init` there, and lld puts it after `.text`, before the entry point.
                let first = tag(12).map(|init| init & !1).into_iter().chain(self.word(0x18)).filter(|&at| at >= start && at < end).min().unwrap_or(start);
                let code = inside.iter().filter(|t| t.addr + t.size <= first).map(|t| t.addr + t.size).max().unwrap_or(start);
                // `.fini` is the last code the linker places, and read-only data may follow it.
                let code_end = fini
                    .and_then(|fini| self.end_of_short_function(fini))
                    .unwrap_or_else(|| inside.iter().filter(|t| t.addr >= code).map(|t| t.addr).min().unwrap_or(end));
                fill(&mut out, ".text", SHF_ALLOC | SHF_EXECINSTR, code, code_end);
                fill(&mut out, ".rodata", SHF_ALLOC, code_end, end);
            } else if segment.flags & PF_W != 0 {
                let (protected_start, protected_end) = relro.map_or((start, start), |(s, e)| (s.clamp(start, end), e.clamp(start, end)));
                fill(&mut out, ".data", SHF_ALLOC | SHF_WRITE, start, protected_start);
                fill(&mut out, ".data.rel.ro", SHF_ALLOC | SHF_WRITE, protected_start, protected_end);
                fill(&mut out, ".data", SHF_ALLOC | SHF_WRITE, protected_end, end);
                if segment.memsz > segment.filesz {
                    out.push(Shdr { name: ".bss", kind: SHT_NOBITS, flags: SHF_ALLOC | SHF_WRITE, addr: end, size: segment.memsz - segment.filesz, link: None, entsize: 0 });
                }
            } else {
                let linking = [SHT_DYNSYM, SHT_STRTAB, SHT_REL, SHT_RELA, SHT_RELR];
                let after = inside.iter().filter(|t| linking.contains(&t.kind)).map(|t| t.addr + t.size).max();
                // A read-only segment that holds the dynamic tables also holds the ELF header,
                // notes and version tables before them; only what follows the last is data.
                fill(&mut out, ".rodata", SHF_ALLOC, after.unwrap_or(start).min(end), end);
            }
        }
        out.extend(tables);
        out.sort_by_key(|s| s.addr);
        Some(out)
    }

    /// The file with a section name table and the section headers appended, and the ELF header
    /// pointing to them. Section 0 is the null section ELF requires.
    fn write(&self, data: &[u8], sections: &[Shdr]) -> Vec<u8> {
        let mut out = data.to_vec();
        let mut names = vec![0u8];
        let mut name_at = |name: &str| {
            let at = names.len() as u32;
            names.extend_from_slice(name.as_bytes());
            names.push(0);
            at
        };
        let named: Vec<u32> = sections.iter().map(|s| name_at(s.name)).collect();
        let shstrtab_name = name_at(".shstrtab");
        let names_offset = out.len() as u64;
        out.extend_from_slice(&names);
        while !out.len().is_multiple_of(8) {
            out.push(0);
        }
        let shoff = out.len() as u64;
        let index = |name: &str| sections.iter().position(|s| s.name == name).map_or(0, |i| i as u32 + 1);
        let header = |out: &mut Vec<u8>, name: u32, kind: u32, flags: u64, addr: u64, offset: u64, size: u64, link: u32, entsize: u64| {
            let align = if flags & SHF_EXECINSTR != 0 { 4 } else { 1 };
            if self.wide {
                for (value, width) in [(name.into(), 4), (kind.into(), 4), (flags, 8), (addr, 8), (offset, 8), (size, 8), (link.into(), 4), (0, 4), (align, 8), (entsize, 8)] {
                    out.extend_from_slice(&u64::to_le_bytes(value)[..width]);
                }
            } else {
                for value in [name.into(), kind.into(), flags, addr, offset, size, link.into(), 0, align, entsize] {
                    out.extend_from_slice(&(value as u32).to_le_bytes());
                }
            }
        };
        header(&mut out, 0, 0, 0, 0, 0, 0, 0, 0);
        for (section, &name) in sections.iter().zip(&named) {
            let offset = self.offset(section.addr).unwrap_or(0);
            let link = section.link.map_or(0, index);
            header(&mut out, name, section.kind, section.flags, section.addr, offset, section.size, link, section.entsize);
        }
        header(&mut out, shstrtab_name, SHT_STRTAB, 0, 0, names_offset, names.len() as u64, 0, 0);
        let (count, string_index) = (sections.len() as u16 + 2, sections.len() as u16 + 1);
        let entsize: u16 = if self.wide { 64 } else { 40 };
        let fields = if self.wide { (0x28, 0x3A) } else { (0x20, 0x2E) };
        if self.wide {
            out[fields.0..fields.0 + 8].copy_from_slice(&shoff.to_le_bytes());
        } else {
            out[fields.0..fields.0 + 4].copy_from_slice(&(shoff as u32).to_le_bytes());
        }
        for (at, value) in [(fields.1, entsize), (fields.1 + 2, count), (fields.1 + 4, string_index)] {
            out[at..at + 2].copy_from_slice(&value.to_le_bytes());
        }
        out
    }
}

fn u16_at(data: &[u8], at: u64) -> Option<u16> {
    Some(u16::from_le_bytes(data.get(at as usize..at as usize + 2)?.try_into().ok()?))
}

fn u32_at(data: &[u8], at: u64) -> Option<u32> {
    Some(u32::from_le_bytes(data.get(at as usize..at as usize + 4)?.try_into().ok()?))
}

fn u64_at(data: &[u8], at: u64) -> Option<u64> {
    Some(u64::from_le_bytes(data.get(at as usize..at as usize + 8)?.try_into().ok()?))
}
