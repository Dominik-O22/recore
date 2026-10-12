//! A loaded executable: its mapped bytes and the metadata that survives stripping.

use rustc_hash::FxHashMap;
use std::path::Path;

use anyhow::{Context, Result};
use object::{Object, ObjectSection, ObjectSymbol, ObjectSymbolTable, SectionKind, SymbolKind};

/// A section mapped at a virtual address.
pub struct Section {
    pub name: String,
    pub addr: u64,
    pub data: Vec<u8>,
    /// Where `data` starts in the file, for sections stored there as they are mapped.
    pub file_offset: Option<u64>,
    pub executable: bool,
    /// Whether the program can change the contents while running. Sections the loader makes
    /// read-only after relocation count as not writable.
    pub writable: bool,
}

impl Section {
    pub fn end(&self) -> u64 {
        self.addr + self.data.len() as u64
    }
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.addr && addr < self.end()
    }
    /// Whether the section holds the linker's stubs for reaching imports, not functions of the
    /// program: an ELF PLT, or Mach-O's `__stubs` and the like.
    pub fn is_stubs(&self) -> bool {
        let mach_o = ["__stubs", "__auth_stubs", "__objc_stubs", "__stub_helper"];
        self.executable && (self.name.starts_with(".plt") || self.name.rsplit_once(',').is_some_and(|(_, section)| mach_o.contains(&section)))
    }
}

/// The instruction set an image is built for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Machine {
    /// 32-bit x86.
    X86,
    X86_64,
    Aarch64,
}

/// The container an image came in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Elf,
    Pe,
    MachO,
}

pub struct Image {
    pub name: String,
    pub format: Format,
    pub machine: Machine,
    /// The address the image is linked to load at. PE images express many addresses as offsets
    /// from it. Zero for ELF and Mach-O, which use plain addresses.
    pub base: u64,
    /// The image is built with branch target identification (AArch64 BTI), so every address an
    /// indirect branch may reach starts with a marker instruction.
    pub branch_targets_marked: bool,
    pub entry: u64,
    /// Loaded sections, sorted by address.
    pub sections: Vec<Section>,
    /// Slot address (GOT entry) to the imported symbol its relocation binds.
    pub import_slots: FxHashMap<u64, String>,
    /// Exported function addresses from the dynamic symbol table. In a Mach-O image, also the
    /// methods its Objective-C metadata lists, which the runtime calls by name.
    pub exports: Vec<u64>,
    /// Names the image itself carries for addresses in it: exports, as written in the file.
    pub symbol_names: FxHashMap<u64, String>,
    /// `[start, end)` of every function the image describes: a frame description entry in
    /// `.eh_frame`, a PE `RUNTIME_FUNCTION`, or a Mach-O function start up to the next one.
    pub frames: Vec<(u64, u64)>,
    /// Pointers stored in data by relative relocations, as `(slot address, target)`. Targets in
    /// code are function pointers or, in computed-goto tables, labels.
    pub relative_targets: Vec<(u64, u64)>,
    /// Compilers for this format place jump tables and other data among the code, so bytes
    /// that control flow never reaches cannot be assumed to be instructions.
    pub data_in_code: bool,
}

impl Image {
    pub fn load(path: &Path) -> Result<Image> {
        let data = std::fs::read(path).with_context(|| format!("reading {path:?}"))?;
        if crate::macho::is_macho(&data) {
            return crate::macho::load(path.file_name().unwrap().to_string_lossy().into_owned(), &data);
        }
        let file = object::File::parse(&*data)?;

        let mut sections: Vec<Section> = file
            .sections()
            .filter(|s| s.address() != 0 && s.size() > 0)
            .filter(|s| !matches!(s.kind(), SectionKind::UninitializedData | SectionKind::UninitializedTls))
            .filter_map(|s| {
                Some(Section {
                    name: s.name().ok()?.to_string(),
                    addr: s.address(),
                    data: s.uncompressed_data().ok()?.into_owned(),
                    file_offset: s.file_range().map(|(offset, _)| offset),
                    executable: s.kind() == SectionKind::Text,
                    writable: s.kind() == SectionKind::Data && !is_relro(s.name().unwrap_or("")),
                })
            })
            .collect();
        sections.sort_by_key(|s| s.addr);

        let is_pe = file.format() == object::BinaryFormat::Pe;
        let (import_slots, relative_targets, exports, frames) = if is_pe {
            let pe = if file.is_64() {
                crate::pe::load::<object::pe::ImageNtHeaders64>(&data, &sections)?
            } else {
                crate::pe::load::<object::pe::ImageNtHeaders32>(&data, &sections)?
            };
            (pe.import_slots, pe.relative_targets, pe.exports, pe.frames)
        } else {
            elf_metadata(&file, &sections)
        };

        let machine = match file.architecture() {
            object::Architecture::I386 => Machine::X86,
            object::Architecture::X86_64 => Machine::X86_64,
            object::Architecture::Aarch64 => Machine::Aarch64,
            other => anyhow::bail!("unsupported architecture {other:?}"),
        };

        let branch_targets_marked = machine == Machine::Aarch64
            && file.section_by_name(".note.gnu.property").and_then(|s| s.uncompressed_data().ok()).is_some_and(|d| has_bti(&d));

        let symbol_names = file
            .exports()
            .map(|exports| {
                exports
                    .filter_map(|export| export.ok())
                    .filter_map(|export| match (export.target(), export.name()) {
                        (object::ExportTarget::Address { address }, object::NameOrOrdinal::Name(name)) => {
                            Some((address, String::from_utf8_lossy(name).into_owned()))
                        }
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default();

        Ok(Image {
            format: if is_pe { Format::Pe } else { Format::Elf },
            base: if is_pe { file.relative_address_base() } else { 0 },
            symbol_names,
            machine,
            branch_targets_marked,
            name: path.file_name().unwrap().to_string_lossy().into_owned(),
            entry: file.entry(),
            sections,
            import_slots,
            exports,
            frames,
            relative_targets,
            data_in_code: is_pe,
        })
    }

    pub fn section_at(&self, addr: u64) -> Option<&Section> {
        let index = self.sections.partition_point(|s| s.addr <= addr);
        self.sections[..index].last().filter(|s| s.contains(addr))
    }

    pub fn is_code(&self, addr: u64) -> bool {
        self.section_at(addr).is_some_and(|s| s.executable)
    }

    /// Bytes from `addr` to the end of its section.
    pub fn bytes_from(&self, addr: u64) -> Option<&[u8]> {
        let section = self.section_at(addr)?;
        Some(&section.data[(addr - section.addr) as usize..])
    }

    pub fn text(&self) -> Option<&Section> {
        self.sections.iter().find(|s| s.name == ".text" || s.name == "__TEXT,__text")
    }
}

/// Imports, relocated pointers, exports and unwind frames of an ELF image.
#[allow(clippy::type_complexity)]
fn elf_metadata(file: &object::File, sections: &[Section]) -> (FxHashMap<u64, String>, Vec<(u64, u64)>, Vec<u64>, Vec<(u64, u64)>) {
    let mut import_slots = FxHashMap::default();
    let mut relative_targets = Vec::new();
    if let Some(relocations) = file.dynamic_relocations() {
        let dynsyms = file.dynamic_symbol_table();
        for (addr, reloc) in relocations {
            match reloc.target() {
                object::RelocationTarget::Symbol(index) => {
                    let name = dynsyms.as_ref().and_then(|t| t.symbol_by_index(index).ok()).and_then(|s| s.name().ok());
                    if let Some(name) = name.filter(|n| !n.is_empty()) {
                        import_slots.insert(addr, name.to_string());
                    }
                }
                object::RelocationTarget::Absolute => relative_targets.push((addr, reloc.addend() as u64)),
                _ => {}
            }
        }
    }

    // Packed relative relocations store the target in the relocated word itself.
    if let Some(relr) = file.section_by_name(".relr.dyn").and_then(|s| s.uncompressed_data().ok()) {
        let read_word = |addr: u64| {
            let section = sections.iter().find(|s| s.contains(addr))?;
            let bytes = section.data.get((addr - section.addr) as usize..)?.get(..8)?;
            Some(u64::from_le_bytes(bytes.try_into().unwrap()))
        };
        relative_targets.extend(relr_slots(&relr).into_iter().filter_map(|slot| Some((slot, read_word(slot)?))));
    }

    let exports = file
        .dynamic_symbols()
        .filter(|s| s.kind() == SymbolKind::Text && s.address() != 0 && s.is_definition())
        .map(|s| s.address())
        .collect();

    let frames = file
        .section_by_name(".eh_frame")
        .and_then(|s| Some(parse_frames(&s.uncompressed_data().ok()?, s.address())))
        .unwrap_or_default();

    (import_slots, relative_targets, exports, frames)
}

/// Sections that are written only by the loader and protected afterwards (full RELRO).
fn is_relro(name: &str) -> bool {
    name.starts_with(".data.rel.ro") || matches!(name, ".got" | ".got.plt" | ".init_array" | ".fini_array" | ".dynamic")
}

/// Reads the `[start, end)` range of every FDE in an `.eh_frame` section loaded at `addr`.
/// Malformed entries are skipped.
pub(crate) fn parse_frames(data: &[u8], addr: u64) -> Vec<(u64, u64)> {
    use gimli::UnwindSection;
    let eh_frame = gimli::EhFrame::new(data, gimli::LittleEndian);
    let bases = gimli::BaseAddresses::default().set_eh_frame(addr);
    let mut frames = Vec::new();
    let mut entries = eh_frame.entries(&bases);
    let mut cies = FxHashMap::default();
    while let Ok(Some(entry)) = entries.next() {
        match entry {
            gimli::CieOrFde::Cie(_) => {}
            gimli::CieOrFde::Fde(partial) => {
                let fde = partial.parse(|_, bases, offset| {
                    if let Some(cie) = cies.get(&offset) {
                        return Ok(Clone::clone(cie));
                    }
                    let cie = eh_frame.cie_from_offset(bases, offset)?;
                    cies.insert(offset, cie.clone());
                    Ok(cie)
                });
                if let Ok(fde) = fde {
                    if fde.len() > 0 {
                        frames.push((fde.initial_address(), fde.initial_address() + fde.len()));
                    }
                }
            }
        }
    }
    frames.sort_unstable();
    frames.dedup();
    frames
}

/// Decodes a `.relr.dyn` section into the addresses it relocates. An even entry is an address;
/// an odd entry is a bitmap covering the 63 words after the previous one.
fn relr_slots(data: &[u8]) -> Vec<u64> {
    let mut slots = Vec::new();
    let mut next = 0u64;
    for entry in data.chunks_exact(8).map(|c| u64::from_le_bytes(c.try_into().unwrap())) {
        if entry & 1 == 0 {
            slots.push(entry);
            next = entry + 8;
        } else {
            slots.extend((0..63).filter(|bit| entry >> (bit + 1) & 1 == 1).map(|bit| next + 8 * bit));
            next += 8 * 63;
        }
    }
    slots
}

/// Whether a `.note.gnu.property` section declares AArch64 branch target identification.
fn has_bti(note: &[u8]) -> bool {
    const AARCH64_FEATURE_1_AND: u32 = 0xC000_0000;
    const FEATURE_1_BTI: u32 = 1;
    let word = |at: usize| note.get(at..at + 4).map(|b| u32::from_le_bytes(b.try_into().unwrap()));
    // Note header: name size, descriptor size, type, then the name padded to 4 bytes.
    let (Some(name_size), Some(desc_size)) = (word(0), word(4)) else { return false };
    let mut at = 12 + (name_size as usize).next_multiple_of(4);
    let end = (at + desc_size as usize).min(note.len());
    // The descriptor is a list of properties: type, data size, data padded to 8 bytes.
    while at + 8 <= end {
        let (Some(kind), Some(size)) = (word(at), word(at + 4)) else { return false };
        if kind == AARCH64_FEATURE_1_AND {
            return word(at + 8).is_some_and(|flags| flags & FEATURE_1_BTI != 0);
        }
        at += 8 + (size as usize).next_multiple_of(8);
    }
    false
}
