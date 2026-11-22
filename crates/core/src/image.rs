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

/// The instruction set an image is built for. A layout file names it as renamed here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Machine {
    /// 32-bit x86.
    #[serde(rename = "x86")]
    X86,
    #[serde(rename = "x86-64")]
    X86_64,
    #[serde(rename = "aarch64")]
    Aarch64,
    /// The 8051 and the many microcontrollers that keep its instruction set.
    #[serde(rename = "8051")]
    I8051,
    /// An ARM Cortex-M, which runs Thumb code only.
    #[serde(rename = "cortex-m")]
    Thumb,
    /// A 32-bit ARM application processor, which runs A32 and Thumb code side by side, as
    /// Linux on ARMv5 to ARMv7 does.
    #[serde(rename = "arm")]
    Arm,
}

/// What 32-bit ARM code at an address is: A32, four bytes an instruction, or Thumb.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstructionSet {
    A32,
    Thumb,
}

/// The compiler that built an image, where a layout file names it. It decides how functions
/// pass arguments and return values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Compiler {
    /// Keil's C51.
    Keil,
    Sdcc,
}

impl Machine {
    /// Bytes in a pointer, which is how wide a code or data address stored in the image is.
    pub fn pointer_size(self) -> u64 {
        match self {
            Machine::X86 | Machine::Thumb | Machine::Arm => 4,
            Machine::X86_64 | Machine::Aarch64 => 8,
            Machine::I8051 => 2,
        }
    }
}

/// The container an image came in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Elf,
    Pe,
    MachO,
    /// No container: bytes placed by a layout file, see [`crate::layout`].
    Raw,
}

/// How code that outgrew a 16-bit address space is laid out: several banks share the same
/// addresses and the hardware shows one of them at a time. A banked code address is written
/// `bank << 16 | address` here, so every bank has a range of its own. An image that is not banked
/// has no common ranges and no trampolines, and all its code is bank 0.
#[derive(Default)]
pub struct Banking {
    /// `[start, end)` of the 16-bit addresses that hold the same code whichever bank shows.
    /// That code is loaded once, as bank 0. Sorted.
    pub common: Vec<(u64, u64)>,
    /// The address of each trampoline entry, which is common code that switches banks on the
    /// way to a function, to the address of that function.
    pub trampolines: FxHashMap<u64, u64>,
    /// The address of each call that names a function and its bank and goes through a stub,
    /// which switches banks on the way, to the address of that function.
    pub calls: FxHashMap<u64, u64>,
    /// `[start, end)` of each run of trampoline entries that lie back to back, sorted. A run is
    /// one table: code, but no function for each entry.
    pub tables: Vec<(u64, u64)>,
}

impl Banking {
    /// Whether every bank holds the same code at the 16-bit address `target`.
    pub fn is_common(&self, target: u16) -> bool {
        self.common.iter().any(|&(start, end)| u64::from(target) >= start && u64::from(target) < end)
    }

    /// Where the 16-bit address `target` lies when `bank` shows.
    pub fn address(&self, bank: u64, target: u16) -> u64 {
        if self.is_common(target) { u64::from(target) } else { bank << 16 | u64::from(target) }
    }

    /// The address a jump or call at `from` to the 16-bit address `target` reaches: the function
    /// behind a trampoline entry, and otherwise the target in the bank of `from`. Nothing says
    /// which bank shows while common code runs, so a target it names outside the common ranges
    /// counts as bank 0, where the common code is loaded.
    pub fn reach(&self, from: u64, target: u16) -> u64 {
        let address = self.address(from >> 16, target);
        self.trampolines.get(&address).copied().unwrap_or(address)
    }
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
    /// `[start, end)` of memory the loader fills with zeros and the file holds no bytes for:
    /// uninitialized globals. Sorted by address.
    pub zero_filled: Vec<(u64, u64)>,
    /// Slot address (GOT entry) to the imported symbol its relocation binds.
    pub import_slots: FxHashMap<u64, String>,
    /// Exported function addresses from the dynamic symbol table. In a Mach-O image, also the
    /// methods its Objective-C metadata lists, which the runtime calls by name. In a raw image,
    /// the entry points its layout lists after the first, the interrupt vectors of an 8051,
    /// the functions its trampolines reach, and the stubs they go through.
    pub exports: Vec<u64>,
    /// Names the image itself carries for addresses in it: exports, as written in the file. In
    /// a raw image, what its layout says the trampoline tables and stubs are. In an IL2CPP
    /// build, also its methods and usage slots, as its metadata names them.
    pub symbol_names: FxHashMap<u64, String>,
    /// `[start, end)` of every function the image describes: a frame description entry in
    /// `.eh_frame`, a PE `RUNTIME_FUNCTION`, a Mach-O function start up to the next one, or an
    /// entry of ARM's `.ARM.exidx` up to the next one.
    pub frames: Vec<(u64, u64)>,
    /// Whether a frame may hold several functions: the linker merges the `.ARM.exidx` entries of
    /// functions next to each other that unwind alike. What calls or points into such a frame
    /// is a function all the same, and the frame ends a function only where no other starts.
    pub frames_merge: bool,
    /// `[start, end)` of every function of an ELF `.dynsym` with a size, in the order of that
    /// table: in a linked image its exports, in a kernel module, which recore links into a
    /// `.dynsym` of its own, the functions of `.symtab`. Ranges overlap where hand-written code
    /// names an entry inside a routine.
    pub symbol_extents: Vec<(u64, u64)>,
    /// Pointers stored in data by relative relocations, as `(slot address, target)`. Targets in
    /// code are function pointers or, in computed-goto tables, labels. Not those of a Linux
    /// kernel's jump labels, which point inside functions (see [`crate::kernel`]).
    pub relative_targets: Vec<(u64, u64)>,
    /// Whether a PE image that holds absolute addresses keeps no record of where: linked to
    /// load only at its base. `relative_targets` is then the words of its data that land in
    /// it, and any value in its code that lands in it may be an address.
    pub relocations_stripped: bool,
    /// The address and size of a PE image's version resource, a `VS_VERSIONINFO`.
    pub version_resource: Option<(u64, u64)>,
    /// Compilers for this format place jump tables and other data among the code, so bytes
    /// that control flow never reaches cannot be assumed to be instructions.
    pub data_in_code: bool,
    pub banking: Banking,
    /// What a layout says built the image. Without it the machine and the format decide.
    pub compiler: Option<Compiler>,
    /// A Linux kernel module, which has a `.modinfo` section: its imports are the kernel's
    /// functions, so a name such as `panic` is the kernel's and never returns.
    pub kernel_module: bool,
    /// An arm64 Linux kernel itself, as a `vmlinux` or a raw `Image`: its first code opens with
    /// the image header (see [`crate::kernel`]).
    pub kernel_image: bool,
    /// Where the code of a 32-bit ARM image changes instruction set, as `(address, set)` sorted
    /// by address: each holds up to the next. What comes before the first is in its set. Empty
    /// for every other machine.
    pub instruction_sets: Vec<(u64, InstructionSet)>,
    /// `[start, end)` of the data among the code that an AArch64 ELF file marks with `$d`
    /// mapping symbols, sorted: kCFI's type hash before each function, literal pools, tables.
    /// Without such marks, the kCFI hashes [`crate::kernel`] finds in the code.
    pub marked_data: Vec<(u64, u64)>,
    /// `[start, end)` of the code a Linux kernel's alternatives keep among its code to write over
    /// other code, which never runs where it lies, sorted (see [`crate::kernel`]).
    pub replacement_code: Vec<(u64, u64)>,
    /// The traps that execution goes on after, sorted: the `WARN()`s of a Linux kernel or
    /// module, which its `__bug_table` lists. Such a trap after a call does not say that the call
    /// never returns, as other traps do.
    pub resuming_traps: Vec<u64>,
    /// The managed program of a Unity IL2CPP build, read from the `global-metadata.dat` that
    /// ships with it.
    pub il2cpp: Option<std::sync::Arc<crate::il2cpp::Il2Cpp>>,
}

impl Image {
    /// An image of `sections` alone, entered at `entry`: no imports, exports, relocations,
    /// unwind information or names. Data sits among the code of a PE or raw image.
    pub fn bare(name: String, format: Format, machine: Machine, entry: u64, sections: Vec<Section>) -> Image {
        Image {
            name,
            format,
            machine,
            base: 0,
            branch_targets_marked: false,
            entry,
            sections,
            zero_filled: Vec::new(),
            import_slots: FxHashMap::default(),
            exports: Vec::new(),
            symbol_names: FxHashMap::default(),
            frames: Vec::new(),
            relative_targets: Vec::new(),
            relocations_stripped: false,
            version_resource: None,
            data_in_code: matches!(format, Format::Pe | Format::Raw),
            frames_merge: false,
            symbol_extents: Vec::new(),
            banking: Banking::default(),
            compiler: None,
            kernel_module: false,
            kernel_image: false,
            instruction_sets: Vec::new(),
            marked_data: Vec::new(),
            replacement_code: Vec::new(),
            resuming_traps: Vec::new(),
            il2cpp: None,
        }
    }

    /// Loads the executable at `path`, or the raw image the layout file at `path` describes.
    pub fn load(path: &Path) -> Result<Image> {
        if crate::layout::is_layout(path) {
            return crate::layout::load(path);
        }
        let data = std::fs::read(path).with_context(|| format!("reading {path:?}"))?;
        let mut image = Image::parse(path.file_name().unwrap().to_string_lossy().into_owned(), data)?;
        // IL2CPP metadata sits in a file beside an ELF or PE build.
        if image.format != Format::MachO {
            crate::il2cpp::attach(&mut image, path);
        }
        Ok(image)
    }

    /// Parses the ELF, PE or Mach-O executable in `data`, which needs no file around it: `load`
    /// reads one with this, and the fuzzer (fuzz/) feeds it bytes.
    pub fn parse(name: String, data: Vec<u8>) -> Result<Image> {
        if crate::macho::is_macho(&data) {
            return crate::macho::load(name, &data);
        }
        // OpenWrt and other firmware strip the section headers; read them back from the segments.
        let data = if crate::sectionless::is_sectionless(&data) { crate::sectionless::restore(&data).unwrap_or(data) } else { data };
        // A kernel module has no addresses until it is linked.
        let data = crate::relocatable::link(data);
        let file = object::File::parse(&*data)?;

        // The sections at an address, but for one whose end the file puts past 2^64.
        let mapped = || file.sections().filter(|s| s.address() != 0 && s.address().checked_add(s.size()).is_some());
        let mut sections: Vec<Section> = mapped()
            .filter(|s| s.size() > 0)
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
        // A section with no bytes in the file, or the tail of one that is larger in memory.
        let mut zero_filled: Vec<(u64, u64)> = mapped()
            .filter(|s| s.kind() != SectionKind::UninitializedTls)
            .filter_map(|s| {
                let stored = if s.kind() == SectionKind::UninitializedData { 0 } else { s.file_range().map_or(0, |(_, size)| size) };
                (s.size() > stored).then(|| (s.address() + stored, s.address() + s.size()))
            })
            .collect();
        zero_filled.sort_unstable();

        let is_pe = file.format() == object::BinaryFormat::Pe;
        let (import_slots, relative_targets, relocations_stripped, exports, symbol_extents, frames, version_resource) = if is_pe {
            let pe = if file.is_64() {
                crate::pe::load::<object::pe::ImageNtHeaders64>(&data, &sections)?
            } else {
                crate::pe::load::<object::pe::ImageNtHeaders32>(&data, &sections)?
            };
            (pe.import_slots, pe.relative_targets, pe.relocations_stripped, pe.exports, Vec::new(), pe.frames, pe.version_resource)
        } else {
            let (import_slots, relative_targets, exports, symbol_extents, frames) = elf_metadata(&file, &sections);
            (import_slots, relative_targets, false, exports, symbol_extents, frames, None)
        };

        let machine = match file.architecture() {
            object::Architecture::I386 => Machine::X86,
            object::Architecture::X86_64 => Machine::X86_64,
            object::Architecture::Aarch64 => Machine::Aarch64,
            object::Architecture::Arm if file.is_little_endian() && !file.is_64() => Machine::Arm,
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

        let mut image = Image {
            zero_filled,
            format: if is_pe { Format::Pe } else { Format::Elf },
            base: if is_pe { file.relative_address_base() } else { 0 },
            symbol_names,
            machine,
            branch_targets_marked,
            name,
            entry: file.entry(),
            kernel_module: file.section_by_name(".modinfo").is_some(),
            kernel_image: false,
            sections,
            import_slots,
            exports,
            frames,
            relative_targets,
            relocations_stripped,
            version_resource,
            // ARM code reads its constants from pools among it.
            data_in_code: is_pe || machine == Machine::Arm,
            frames_merge: false,
            symbol_extents,
            banking: Banking::default(),
            compiler: None,
            instruction_sets: Vec::new(),
            marked_data: Vec::new(),
            replacement_code: Vec::new(),
            resuming_traps: Vec::new(),
            il2cpp: None,
        };
        match machine {
            Machine::Arm => crate::arm::load(&file, &mut image),
            Machine::Aarch64 => image.marked_data = crate::arm64::marked_data(&file),
            _ => {}
        }
        if !is_pe {
            crate::kernel::read(&mut image);
        }
        Ok(image)
    }

    pub fn section_at(&self, addr: u64) -> Option<&Section> {
        let index = self.sections.partition_point(|s| s.addr <= addr);
        self.sections[..index].last().filter(|s| s.contains(addr))
    }

    /// Whether `addr` is an uninitialized global: memory the program has but the file does not.
    pub fn is_zero_filled(&self, addr: u64) -> bool {
        let index = self.zero_filled.partition_point(|&(start, _)| start <= addr);
        index > 0 && addr < self.zero_filled[index - 1].1
    }

    /// Whether the trap at `addr` is one that execution goes on after.
    pub fn resumes_after(&self, addr: u64) -> bool {
        self.resuming_traps.binary_search(&addr).is_ok()
    }

    pub fn is_code(&self, addr: u64) -> bool {
        self.section_at(addr).is_some_and(|s| s.executable)
    }

    /// Bytes from `addr` to the end of its section.
    pub fn bytes_from(&self, addr: u64) -> Option<&[u8]> {
        let section = self.section_at(addr)?;
        Some(&section.data[(addr - section.addr) as usize..])
    }

    /// The instruction set of the 32-bit ARM code at `addr`, and the addresses it holds over.
    pub fn instruction_set(&self, addr: u64) -> (InstructionSet, std::ops::Range<u64>) {
        let index = self.instruction_sets.partition_point(|&(start, _)| start <= addr);
        let (from, set) = match index {
            0 => (0, self.instruction_sets.first().map_or(InstructionSet::A32, |&(_, set)| set)),
            _ => self.instruction_sets[index - 1],
        };
        (set, from..self.instruction_sets.get(index).map_or(u64::MAX, |&(start, _)| start))
    }

    pub fn text(&self) -> Option<&Section> {
        self.sections.iter().find(|s| s.name == ".text" || s.name == "__TEXT,__text")
    }
}

/// Imports, relocated pointers, exports, the extents of sized exports and unwind frames of an ELF
/// image.
#[allow(clippy::type_complexity)]
fn elf_metadata(file: &object::File, sections: &[Section]) -> (FxHashMap<u64, String>, Vec<(u64, u64)>, Vec<u64>, Vec<(u64, u64)>, Vec<(u64, u64)>) {
    let sections = SectionFinder::new(sections);
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
                // A REL relocation keeps its addend in the word it relocates.
                object::RelocationTarget::Absolute if reloc.has_implicit_addend() => {
                    if let Some(word) = read_word(&sections, addr, if file.is_64() { 8 } else { 4 }) {
                        relative_targets.push((addr, word));
                    }
                }
                object::RelocationTarget::Absolute => relative_targets.push((addr, reloc.addend() as u64)),
                _ => {}
            }
        }
    }

    // Packed relative relocations store the target in the relocated word itself.
    if let Some(relr) = file.section_by_name(".relr.dyn").and_then(|s| s.uncompressed_data().ok()) {
        let word = if file.is_64() { 8 } else { 4 };
        relative_targets.extend(relr_slots(&relr, word).into_iter().filter_map(|slot| Some((slot, read_word(&sections, slot, word)?))));
    }

    let functions: Vec<(u64, u64)> = file
        .dynamic_symbols()
        .filter(|s| s.kind() == SymbolKind::Text && s.address() != 0 && s.is_definition())
        .map(|s| (s.address(), s.size()))
        .collect();
    let exports = functions.iter().map(|&(address, _)| address).collect();
    let symbol_extents = functions.iter().filter(|&&(_, size)| size > 0).map(|&(address, size)| (address, address.saturating_add(size))).collect();

    let frames = file
        .section_by_name(".eh_frame")
        .and_then(|s| Some(parse_frames(&s.uncompressed_data().ok()?, s.address())))
        .unwrap_or_default();

    (import_slots, relative_targets, exports, symbol_extents, frames)
}

/// Finds the section that holds each of a loader's addresses, of sections sorted by address.
/// An address mostly falls in the section of the one before, which is tried first. Others are
/// searched for, in time that grows with the log of the number of sections, which a damaged
/// image can make large. Of sections that overlap, as only a damaged image's do, it may find
/// either.
pub(crate) struct SectionFinder<'a> {
    sections: &'a [Section],
    last: std::cell::Cell<Option<&'a Section>>,
}

impl<'a> SectionFinder<'a> {
    pub(crate) fn new(sections: &'a [Section]) -> SectionFinder<'a> {
        SectionFinder { sections, last: std::cell::Cell::new(None) }
    }

    pub(crate) fn find(&self, addr: u64) -> Option<&'a Section> {
        if let Some(last) = self.last.get().filter(|s| s.contains(addr)) {
            return Some(last);
        }
        let index = self.sections.partition_point(|s| s.addr <= addr);
        let found = self.sections[..index].last().filter(|s| s.contains(addr))?;
        self.last.set(Some(found));
        Some(found)
    }
}

/// The little-endian word of `size` bytes at `addr`.
fn read_word(sections: &SectionFinder, addr: u64, size: usize) -> Option<u64> {
    let section = sections.find(addr)?;
    let bytes = section.data.get((addr - section.addr) as usize..)?.get(..size)?;
    Some(bytes.iter().rev().fold(0, |word, &byte| word << 8 | u64::from(byte)))
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
                if let Ok(fde) = fde
                    && fde.len() > 0
                    && let Some(end) = fde.initial_address().checked_add(fde.len())
                {
                    frames.push((fde.initial_address(), end));
                }
            }
        }
    }
    frames.sort_unstable();
    frames.dedup();
    frames
}

/// Decodes a `.relr.dyn` section of `word`-byte entries into the addresses it relocates. An even
/// entry is an address; an odd entry is a bitmap covering the words after the previous one, as
/// many as it has bits but one.
fn relr_slots(data: &[u8], word: usize) -> Vec<u64> {
    let (step, bits) = (word as u64, 8 * word as u64 - 1);
    let mut slots = Vec::new();
    let mut next = 0u64;
    for entry in data.chunks_exact(word).map(|c| c.iter().rev().fold(0u64, |entry, &byte| entry << 8 | u64::from(byte))) {
        // Slots past 2^64 are none a section holds, so the sums saturate.
        if entry & 1 == 0 {
            slots.push(entry);
            next = entry.saturating_add(step);
        } else {
            slots.extend((0..bits).filter(|bit| entry >> (bit + 1) & 1 == 1).map(|bit| next.saturating_add(step * bit)));
            next = next.saturating_add(step * bits);
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Whichever section held the address before, each address finds its own, and one in a
    /// gap or past the end finds none.
    #[test]
    fn the_section_finder_finds_each_address_in_any_order() {
        let section = |addr: u64| Section { name: String::new(), addr, data: vec![0; 0x100], file_offset: None, executable: false, writable: false };
        let sections: Vec<Section> = (1..=1000).map(|n| section(n * 0x1000)).collect();
        let finder = SectionFinder::new(&sections);
        for addr in [0x1000, 0x10ff, 0x5_0010, 0x2000, 0x3e_80ff, 0x1080] {
            assert_eq!(finder.find(addr).map(|s| s.addr), Some(addr & !0xfff));
        }
        for addr in [0, 0xfff, 0x1100, 0x5_0100, 0x3e_8100] {
            assert!(finder.find(addr).is_none());
        }
    }

    #[test]
    fn packed_relocations_count_words_of_the_image_s_own_size() {
        // An address, then a bitmap whose bits 1 and 3 after the marker name the first and the
        // third word past it.
        let entries = |words: &[u64], size: usize| words.iter().flat_map(|word| word.to_le_bytes()[..size].to_vec()).collect::<Vec<u8>>();
        assert_eq!(relr_slots(&entries(&[0x1000, 0b1011], 4), 4), [0x1000, 0x1004, 0x100C]);
        assert_eq!(relr_slots(&entries(&[0x1000, 0b1011], 8), 8), [0x1000, 0x1008, 0x1018]);
    }
}
