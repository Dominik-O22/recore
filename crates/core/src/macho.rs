//! Mach-O images, as macOS and iOS use: thin files and the slices of universal ones.
//!
//! Sections are named `segment,section`, as Apple's tools print them. What the loader would
//! write into the image is written here: a slot the linker chained into a fixup list holds its
//! target afterwards, pointer authentication bits stripped, so everything downstream reads
//! plain pointers.

use anyhow::{Context, Result, bail};
use object::macho;
use object::read::macho::{
    DyldChainedImport, FatArch, Fixup, LoadCommandVariant, MachOFatFile32, MachOFatFile64, MachOFile64, Nlist, Section as _, Segment as _,
};
use object::{Architecture, Endianness, FileKind, Object};
use rustc_hash::{FxHashMap, FxHashSet};

use crate::image::{Format, Image, Machine, Section, parse_frames};

/// Whether `file` is a Mach-O image or a universal file of them.
pub fn is_macho(file: &[u8]) -> bool {
    matches!(FileKind::parse(file), Ok(FileKind::MachO32 | FileKind::MachO64 | FileKind::MachOFat32 | FileKind::MachOFat64))
}

/// The image to analyze in `file`: the file itself when it is thin, and from a universal file
/// the arm64 slice, or failing that arm64e, or x86-64.
fn slice(file: &[u8]) -> Result<&[u8]> {
    fn arches<'a, Fat: FatArch>(file: &'a [u8], arches: &[Fat]) -> Result<Vec<(Architecture, macho::CpuSubtype, &'a [u8])>> {
        arches.iter().map(|arch| Ok((arch.architecture(), arch.cpusubtype(), arch.data(file)?))).collect()
    }
    let arches = match FileKind::parse(file)? {
        FileKind::MachOFat32 => arches(file, MachOFatFile32::parse(file)?.arches())?,
        FileKind::MachOFat64 => arches(file, MachOFatFile64::parse(file)?.arches())?,
        _ => return Ok(file),
    };
    let preference = |&(architecture, subtype, _): &(Architecture, macho::CpuSubtype, &[u8])| match architecture {
        Architecture::Aarch64 if subtype.id() != macho::CPU_SUBTYPE_ARM64E => Some(0),
        Architecture::Aarch64 => Some(1),
        Architecture::X86_64 => Some(2),
        _ => None,
    };
    let chosen = arches.iter().filter(|arch| preference(arch).is_some()).min_by_key(|arch| preference(arch));
    Ok(chosen.context("the universal file has no arm64 or x86-64 slice")?.2)
}

/// A name as source code spells it: a Swift name demangled, and otherwise the linker's leading
/// underscore removed.
fn plain_name(symbol: &[u8]) -> String {
    let name = String::from_utf8_lossy(symbol);
    crate::names::swift_name(&name).unwrap_or_else(|| name.strip_prefix('_').unwrap_or(&name).to_string())
}

/// The eight bytes of the loaded image at `slot`.
fn pointer_at(sections: &mut [Section], slot: u64) -> Option<&mut [u8]> {
    let index = sections.partition_point(|section| section.addr <= slot).checked_sub(1)?;
    let section = &mut sections[index];
    section.data.get_mut((slot.checked_sub(section.addr)?) as usize..)?.get_mut(..8)
}

/// Loads the Mach-O image in `file`, which [`is_macho`] accepted.
pub fn load(name: String, file: &[u8]) -> Result<Image> {
    let data = slice(file)?;
    let file = MachOFile64::<Endianness>::parse(data).context("only 64-bit Mach-O images are supported")?;
    let endian = file.endian();
    let machine = match file.architecture() {
        Architecture::Aarch64 => Machine::Aarch64,
        Architecture::X86_64 => Machine::X86_64,
        other => bail!("unsupported architecture {other:?}"),
    };

    // Each segment's address and file contents, in load command order: fixups name segments
    // by that index.
    let mut segments: Vec<(u64, &[u8])> = Vec::new();
    let mut sections = Vec::new();
    // `(address, size, first indirect symbol)` of each section of symbol pointers.
    let mut pointer_sections = Vec::new();
    let mut zero_filled: Vec<(u64, u64)> = Vec::new();
    let mut base = 0;
    let mut entry_offset = None;
    let (mut dysymtab, mut dyld_info, mut chained, mut function_starts, mut data_in_code) = (None, None, None, None, None);
    let mut commands = file.macho_load_commands()?;
    while let Some(command) = commands.next()? {
        match command.variant()? {
            LoadCommandVariant::Segment64(segment, section_data) => {
                segments.push((segment.vmaddr(endian), segment.data(endian, data).ok().context("a segment lies outside the file")?));
                if segment.name() == macho::SEG_TEXT.as_bytes() {
                    base = segment.vmaddr(endian);
                }
                // The loader makes `__DATA_CONST` read-only once it has bound the pointers in it.
                let writable = segment.initprot(endian).0 & macho::VM_PROT_WRITE.0 != 0
                    && segment.flags(endian).0 & macho::SG_READ_ONLY.0 == 0
                    && !segment.name().ends_with(b"_CONST");
                for section in segment.sections(endian, section_data)? {
                    let kind = section.section_type(endian);
                    if matches!(kind, macho::S_NON_LAZY_SYMBOL_POINTERS | macho::S_LAZY_SYMBOL_POINTERS) {
                        pointer_sections.push((section.addr(endian), section.size(endian), section.reserved1(endian)));
                    }
                    // Zero-filled sections have no bytes in the file.
                    let Some((offset, size)) = section.file_range(endian, section.offset(endian).into()).filter(|&(_, size)| size > 0) else {
                        if matches!(kind, macho::S_ZEROFILL | macho::S_GB_ZEROFILL) && section.size(endian) > 0 {
                            zero_filled.push((section.addr(endian), section.addr(endian) + section.size(endian)));
                        }
                        continue;
                    };
                    let instructions = macho::S_ATTR_PURE_INSTRUCTIONS.0 | macho::S_ATTR_SOME_INSTRUCTIONS.0;
                    sections.push(Section {
                        name: format!("{},{}", String::from_utf8_lossy(section.segment_name()), String::from_utf8_lossy(section.name())),
                        addr: section.addr(endian),
                        data: data.get(offset as usize..(offset + size) as usize).context("a section lies outside the file")?.to_vec(),
                        file_offset: Some(offset),
                        executable: section.flags(endian).0 & instructions != 0,
                        writable,
                    });
                }
            }
            LoadCommandVariant::Dysymtab(command) => dysymtab = Some(command),
            LoadCommandVariant::DyldInfo(command) => dyld_info = Some(command),
            LoadCommandVariant::EntryPoint(command) => entry_offset = Some(command.entryoff.get(endian)),
            LoadCommandVariant::LinkeditData(command) => match command.cmd.get(endian) {
                macho::LC_DYLD_CHAINED_FIXUPS => chained = Some(command),
                macho::LC_FUNCTION_STARTS => function_starts = Some(command),
                macho::LC_DATA_IN_CODE => data_in_code = Some(command),
                _ => {}
            },
            _ => {}
        }
    }
    sections.sort_by_key(|section| section.addr);

    let mut import_slots: FxHashMap<u64, String> = FxHashMap::default();
    let mut relative_targets = Vec::new();
    let segment = |index: usize| segments.get(index).copied().context("a fixup names a segment the image does not have");

    // Current linkers thread every pointer the loader must set into per-page chains: each slot
    // holds its target or the import it binds, and the distance to the next slot.
    if let Some(command) = chained {
        let fixups = command.chained_fixups(endian, data)?;
        let imports: Vec<DyldChainedImport> = fixups.imports(endian)?.collect::<object::Result<_>>()?;
        let mut starts = fixups.segments(endian)?;
        while let Some(chain) = starts.next()? {
            let (address, contents) = segment(chain.index() as usize)?;
            for fixup in chain.fixups(endian, base, contents) {
                let (offset, fixup) = fixup?;
                let slot = address + offset;
                let target = match fixup {
                    Fixup::Rebase(rebase) => base + rebase.target_offset,
                    Fixup::Bind(bind) => {
                        let import = imports.get(bind.ordinal as usize).context("a fixup binds an import the image does not list")?;
                        import_slots.insert(slot, plain_name(import.name));
                        0
                    }
                    _ => continue,
                };
                if let Some(pointer) = pointer_at(&mut sections, slot) {
                    pointer.copy_from_slice(&target.to_le_bytes());
                    if target != 0 {
                        relative_targets.push((slot, target));
                    }
                }
            }
        }
    }

    // Older linkers list the same in opcode streams, and leave each rebased slot holding its
    // target already.
    if let Some(command) = dyld_info {
        let mut rebases = command.rebases(endian, data, 8)?;
        while let Some(rebase) = rebases.next()? {
            let slot = segment(rebase.segment_index.into())?.0 + rebase.segment_offset;
            if let Some(pointer) = pointer_at(&mut sections, slot).filter(|_| rebase.kind == macho::REBASE_TYPE_POINTER) {
                relative_targets.push((slot, u64::from_le_bytes((&*pointer).try_into().expect("eight bytes"))));
            }
        }
        for mut binds in [command.binds(endian, data, 8)?, command.lazy_binds(endian, data, 8)?] {
            while let Some(bind) = binds.next()? {
                import_slots.insert(segment(bind.segment_index.into())?.0 + bind.segment_offset, plain_name(bind.symbol));
            }
        }
    }

    // Whatever binds them, the slots of the symbol pointer sections are named by the indirect
    // symbol table.
    let symbols = file.macho_symbol_table();
    if let Some(command) = dysymtab {
        let indirect = command.indirect_symbols(endian, data)?;
        for (address, size, first) in pointer_sections {
            for (index, entry) in indirect.iter().skip(first as usize).take((size / 8) as usize).enumerate() {
                let symbol = symbols.symbol(object::SymbolIndex(entry.get(endian).0 as usize)).ok().filter(|symbol| symbol.is_undefined());
                if let Some(name) = symbol.and_then(|symbol| symbol.name(endian, symbols.strings()).ok()) {
                    import_slots.entry(address + 8 * index as u64).or_insert_with(|| plain_name(name));
                }
            }
        }
    }
    // A lazily bound slot starts out pointing at the helper that binds it, which is not where
    // calls through it end up.
    relative_targets.retain(|(slot, _)| !import_slots.contains_key(slot));
    relative_targets.sort_unstable();

    let is_function = |addr: u64| sections.iter().any(|section| section.contains(addr) && section.executable && !section.is_stubs());
    let mut symbol_names: FxHashMap<u64, String> = FxHashMap::default();
    let mut exports = Vec::new();
    for export in file.exports()? {
        let export = export?;
        if let object::ExportTarget::Address { address } = export.target() {
            symbol_names.insert(address, plain_name(export.name().name().unwrap_or_default()));
            exports.extend(is_function(address).then_some(address));
        }
    }
    // Symbols that are not exported name functions too, in an image that was not stripped.
    for symbol in symbols.iter().filter(|symbol| symbol.is_definition() && !symbol.is_stab()) {
        if let Ok(name) = symbol.name(endian, symbols.strings()) {
            symbol_names.entry(symbol.n_value(endian)).or_insert_with(|| plain_name(name));
        }
    }
    symbol_names.retain(|&addr, _| is_function(addr));

    // The linker lists where every function starts, and where it left data such as jump tables
    // among the code. A function runs to the next start or to the data that follows it.
    let mut starts = Vec::new();
    if let Some(command) = function_starts {
        starts = command.function_starts(endian, data, base)?.collect::<object::Result<Vec<u64>>>()?;
        starts.sort_unstable();
        starts.dedup();
    }
    let mut data_starts: Vec<u64> = match data_in_code {
        Some(command) => command.data(endian, data)?.as_chunks::<8>().0.iter().map(|entry| base + u64::from(u32::from_le_bytes(entry[..4].try_into().unwrap()))).collect(),
        None => Vec::new(),
    };
    data_starts.sort_unstable();
    let section_of = |name: &str| sections.iter().find(|section| section.name == name);
    let mut frames: Vec<(u64, u64)> = starts
        .iter()
        .enumerate()
        .filter_map(|(index, &start)| {
            let section = sections.iter().find(|section| section.contains(start))?;
            let next = starts.get(index + 1).copied().unwrap_or(u64::MAX);
            let data = data_starts.get(data_starts.partition_point(|&data| data <= start)).copied().unwrap_or(u64::MAX);
            Some((start, next.min(data).min(section.end())))
        })
        .collect();
    // An image without that list still says where functions that can be unwound through lie.
    if starts.is_empty() {
        frames = section_of("__TEXT,__eh_frame").map(|section| parse_frames(&section.data, section.addr)).unwrap_or_default();
        exports.extend(section_of("__TEXT,__unwind_info").into_iter().flat_map(|section| unwind_starts(&section.data, base)).filter(|&addr| is_function(addr)));
    }

    // Slots bound to imports hold zero from here on, as do the encoded fixups the loader would
    // overwrite anyway.
    let bound: FxHashSet<u64> = import_slots.keys().copied().collect();
    for &slot in &bound {
        if let Some(pointer) = pointer_at(&mut sections, slot) {
            pointer.fill(0);
        }
    }

    zero_filled.sort_unstable();
    let mut image = Image {
        name,
        format: Format::MachO,
        machine,
        base: 0,
        branch_targets_marked: false,
        entry: entry_offset.map_or(0, |offset| base + offset),
        sections,
        zero_filled,
        import_slots,
        exports,
        symbol_names,
        frames,
        relative_targets,
        relocations_stripped: false,
        version_resource: None,
        data_in_code: false,
        frames_merge: false,
        banking: Default::default(),
        compiler: None,
        instruction_sets: Vec::new(),
    };
    // A method list of 32-bit offsets is no pointer the loader rebases, so nothing else says
    // that its methods are code.
    let methods = crate::objc::metadata(&image).map(|objc| objc.methods).unwrap_or_default();
    let is_function = |addr: u64| image.section_at(addr).is_some_and(|section| section.executable && !section.is_stubs());
    let methods: Vec<u64> = methods.iter().map(|method| method.0).filter(|&method| is_function(method)).collect();
    image.exports.extend(methods);
    // Swift's descriptors are all 32-bit offsets, to accessors, methods and witnesses.
    image.exports.extend(crate::swift::functions(&image));
    Ok(image)
}

/// Function entry points listed in a `__unwind_info` section, the compact unwind tables. The
/// linker folds neighbouring functions that unwind alike into one entry, so the list is not
/// complete, and it says nothing of where a function ends.
pub fn unwind_starts(section: &[u8], base: u64) -> Vec<u64> {
    const REGULAR: u32 = 2;
    const COMPRESSED: u32 = 3;
    let u32_at = |at: usize| section.get(at..at + 4).map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()));
    let u16_at = |at: usize| section.get(at..at + 2).map(|bytes| usize::from(u16::from_le_bytes(bytes.try_into().unwrap())));
    let mut starts: Vec<u32> = Vec::new();
    // The header ends with the offset and length of the first-level index, whose entries are
    // three words: a function offset, and the offsets of a second-level page and of its LSDAs.
    let (Some(index), Some(count)) = (u32_at(20), u32_at(24)) else { return Vec::new() };
    for entry in (0..count as usize).map(|i| index as usize + 12 * i) {
        let (Some(first), Some(page)) = (u32_at(entry), u32_at(entry + 4)) else { break };
        let page = page as usize;
        // The last index entry only marks where the covered code ends.
        if page == 0 {
            continue;
        }
        let (Some(kind), Some(entries), Some(count)) = (u32_at(page), u16_at(page + 4), u16_at(page + 6)) else { continue };
        starts.extend((0..count).filter_map(|i| match kind {
            // Function offset and encoding, a word each.
            REGULAR => u32_at(page + entries + 8 * i),
            // The low 24 bits are the function's offset from the page's first function.
            COMPRESSED => Some(first + (u32_at(page + entries + 4 * i)? & 0x00FF_FFFF)),
            _ => None,
        }));
    }
    starts.sort_unstable();
    starts.dedup();
    starts.into_iter().map(|offset| base + u64::from(offset)).collect()
}
