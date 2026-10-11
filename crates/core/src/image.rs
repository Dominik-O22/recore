//! A loaded executable: its mapped bytes and the metadata that survives stripping.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};
use object::{Object, ObjectSection, ObjectSymbol, ObjectSymbolTable, SectionKind, SymbolKind};

/// A section mapped at a virtual address.
pub struct Section {
    pub name: String,
    pub addr: u64,
    pub data: Vec<u8>,
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
}

/// The instruction set an image is built for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Machine {
    X86_64,
    Aarch64,
}

pub struct Image {
    pub name: String,
    pub machine: Machine,
    pub entry: u64,
    /// Loaded sections, sorted by address.
    pub sections: Vec<Section>,
    /// Slot address (GOT entry) to the imported symbol its relocation binds.
    pub import_slots: HashMap<u64, String>,
    /// Exported function addresses from the dynamic symbol table.
    pub exports: Vec<u64>,
    /// `[start, end)` of every frame description entry in `.eh_frame`.
    pub frames: Vec<(u64, u64)>,
    /// Pointers stored in data by relative relocations, as `(slot address, target)`. Targets in
    /// code are function pointers or, in computed-goto tables, labels.
    pub relative_targets: Vec<(u64, u64)>,
}

impl Image {
    pub fn load(path: &Path) -> Result<Image> {
        let data = std::fs::read(path).with_context(|| format!("reading {path:?}"))?;
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
                    executable: s.kind() == SectionKind::Text,
                    writable: s.kind() == SectionKind::Data && !is_relro(s.name().unwrap_or("")),
                })
            })
            .collect();
        sections.sort_by_key(|s| s.addr);

        let mut import_slots = HashMap::new();
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

        let frames = file.section_by_name(".eh_frame").map(|s| parse_frames(&s)).unwrap_or_default();

        let machine = match file.architecture() {
            object::Architecture::X86_64 => Machine::X86_64,
            object::Architecture::Aarch64 => Machine::Aarch64,
            other => anyhow::bail!("unsupported architecture {other:?}"),
        };

        Ok(Image {
            machine,
            name: path.file_name().unwrap().to_string_lossy().into_owned(),
            entry: file.entry(),
            sections,
            import_slots,
            exports,
            frames,
            relative_targets,
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
        self.sections.iter().find(|s| s.name == ".text")
    }
}

/// Sections that are written only by the loader and protected afterwards (full RELRO).
fn is_relro(name: &str) -> bool {
    name.starts_with(".data.rel.ro") || matches!(name, ".got" | ".got.plt" | ".init_array" | ".fini_array" | ".dynamic")
}

/// Reads the `[start, end)` range of every FDE. Malformed entries are skipped.
fn parse_frames(section: &object::Section) -> Vec<(u64, u64)> {
    use gimli::UnwindSection;
    let Ok(data) = section.uncompressed_data() else {
        return Vec::new();
    };
    let eh_frame = gimli::EhFrame::new(&data, gimli::LittleEndian);
    let bases = gimli::BaseAddresses::default().set_eh_frame(section.address());
    let mut frames = Vec::new();
    let mut entries = eh_frame.entries(&bases);
    let mut cies = HashMap::new();
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
