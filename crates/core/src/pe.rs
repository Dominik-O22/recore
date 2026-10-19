//! The parts of a Windows PE image that differ from ELF: the import address table, base
//! relocations, and the exception directory.

use rustc_hash::FxHashMap;

use anyhow::Result;
use object::read::pe::{ImageNtHeaders, Import, PeFile, ResourceDirectoryTable};
use object::{LittleEndian as LE, Object};

use crate::image::Section;

/// What a PE file contributes to an `Image` beyond its sections.
pub struct Metadata {
    /// Import address table slot to the name of the function the loader binds there.
    pub import_slots: FxHashMap<u64, String>,
    /// `(slot, value)` for every pointer the loader would rebase. Where the relocations are
    /// stripped, every aligned word of data whose value lands in the image.
    pub relative_targets: Vec<(u64, u64)>,
    /// Whether the image has no relocation directory, so loads only at its preferred base.
    pub relocations_stripped: bool,
    pub exports: Vec<u64>,
    /// `[start, end)` of every `RUNTIME_FUNCTION` in the exception directory.
    pub frames: Vec<(u64, u64)>,
    /// The address and size of the first version resource.
    pub version_resource: Option<(u64, u64)>,
}

/// Loads the metadata of a 32-bit (`ImageNtHeaders32`) or 64-bit (`ImageNtHeaders64`) image.
pub fn load<Pe: ImageNtHeaders>(data: &[u8], sections: &[Section]) -> Result<Metadata> {
    let pe = PeFile::<Pe>::parse(data)?;
    let base = pe.relative_address_base();
    let pointer_size = std::mem::size_of::<Pe::ImageThunkData>() as u64;

    let mut import_slots = FxHashMap::default();
    if let Some(table) = pe.import_table()? {
        let mut descriptors = table.descriptors()?;
        while let Some(descriptor) = descriptors.next()? {
            let slots = u64::from(descriptor.first_thunk.get(LE));
            // The lookup table names the imports; older linkers leave it out and the address
            // table doubles as it until the loader overwrites it.
            let lookup = match descriptor.original_first_thunk.get(LE) {
                0 => descriptor.first_thunk.get(LE),
                rva => rva,
            };
            let mut thunks = table.thunks(lookup)?;
            let mut index = 0u64;
            while let Some(thunk) = thunks.next::<Pe>()? {
                if let Ok(Import::Name(_, name)) = table.import::<Pe>(thunk) {
                    import_slots.insert(base + slots + pointer_size * index, String::from_utf8_lossy(name).into_owned());
                }
                index += 1;
            }
        }
    }

    let read_word = |bytes: &[u8]| {
        let mut raw = [0u8; 8];
        raw[..bytes.len()].copy_from_slice(bytes);
        u64::from_le_bytes(raw)
    };
    // The value at a relocated slot: a pointer of the image's own width.
    let read_pointer = |addr: u64, size: usize| {
        let section = sections.iter().find(|s| s.contains(addr))?;
        Some(read_word(section.data.get((addr - section.addr) as usize..)?.get(..size)?))
    };
    let mut relative_targets = Vec::new();
    let blocks = pe.data_directories().relocation_blocks(data, &pe.section_table())?;
    let relocations_stripped = blocks.is_none();
    if let Some(mut blocks) = blocks {
        while let Some(block) = blocks.next()? {
            for relocation in block {
                let size = match relocation.typ {
                    object::pe::IMAGE_REL_BASED_DIR64 => 8,
                    object::pe::IMAGE_REL_BASED_HIGHLOW => 4,
                    _ => continue,
                };
                let slot = base + u64::from(relocation.virtual_address);
                relative_targets.extend(read_pointer(slot, size).map(|value| (slot, value)));
            }
        }
    } else {
        // Nothing says which words are addresses, so each aligned word in data that lands in
        // the image may be one. What reads them still checks what each points at. Text is the
        // exception: in an image based at 0x400000, "ons\0" and the UTF-16 "s\0t\0" land in
        // its code, so a word that reads as text beside another that does is text. Resources
        // hold offsets, never addresses.
        let in_image = |value: u64| sections.iter().any(|s| s.contains(value));
        let is_text = |word: &[u8]| word.iter().all(|&byte| byte == 0 || byte == b' ' || byte.is_ascii_graphic()) && word.iter().any(|&byte| byte != 0);
        for section in sections.iter().filter(|s| !s.executable && s.name != ".rsrc") {
            let words: Vec<&[u8]> = section.data.chunks_exact(pointer_size as usize).collect();
            for (i, &word) in words.iter().enumerate() {
                let slot = section.addr + pointer_size * i as u64;
                let value = read_word(word);
                let text = is_text(word) && (i > 0 && is_text(words[i - 1]) || words.get(i + 1).is_some_and(|next| is_text(next)));
                if in_image(value) && !text && !import_slots.contains_key(&slot) {
                    relative_targets.push((slot, value));
                }
            }
        }
    }

    let exports = pe
        .exports()?
        .filter_map(|export| match export.ok()?.target() {
            object::ExportTarget::Address { address } => Some(address),
            _ => None,
        })
        .collect();

    let frames = sections.iter().find(|s| s.name == ".pdata").map(|pdata| function_frames(pdata, sections, base)).unwrap_or_default();

    let version_resource = version_resource(&pe, data).ok().flatten();

    Ok(Metadata { import_slots, relative_targets, relocations_stripped, exports, frames, version_resource })
}

/// The address and size of the first `RT_VERSION` resource: the first name and the first
/// language under the type.
fn version_resource<Pe: ImageNtHeaders>(pe: &PeFile<Pe>, data: &[u8]) -> Result<Option<(u64, u64)>> {
    const RT_VERSION: u16 = 16;
    let Some(directory) = pe.data_directories().resource_directory(data, &pe.section_table())? else { return Ok(None) };
    let first = |table: ResourceDirectoryTable| table.entries.first().map(|entry| entry.data(directory)).transpose();
    let Some(version) = directory.root()?.entries.iter().find(|entry| entry.name_or_id().id() == Some(RT_VERSION)) else { return Ok(None) };
    let Some(name) = version.data(directory)?.table() else { return Ok(None) };
    let Some(language) = first(name)?.and_then(|data| data.table()) else { return Ok(None) };
    let Some(entry) = first(language)?.and_then(|data| data.data()) else { return Ok(None) };
    Ok(Some((pe.relative_address_base() + u64::from(entry.offset_to_data.get(LE)), u64::from(entry.size.get(LE)))))
}

/// Function extents from the exception directory. Each entry is three RVAs: begin, end, and
/// unwind information.
///
/// One function can have several entries: the compiler gives a region its own entry, chained to
/// the function's main one, when it sets up more of the frame there. Chained entries are not
/// functions, so they are folded into the entry before them.
fn function_frames(pdata: &Section, sections: &[Section], base: u64) -> Vec<(u64, u64)> {
    /// `UNW_FLAG_CHAININFO`: this entry continues the function described by another.
    const CHAINED: u8 = 0x4;
    let rva = |bytes: &[u8]| u64::from(u32::from_le_bytes(bytes.try_into().unwrap()));
    let is_chained = |unwind: u64| {
        let section = sections.iter().find(|s| s.contains(unwind));
        // The first byte holds the version in its low three bits and the flags above them.
        section.and_then(|s| s.data.get((unwind - s.addr) as usize)).is_some_and(|&first| first >> 3 & CHAINED != 0)
    };

    let mut entries: Vec<(u64, u64, bool)> = pdata
        .data
        .chunks_exact(12)
        .map(|entry| (base + rva(&entry[0..4]), base + rva(&entry[4..8]), is_chained(base + rva(&entry[8..12]))))
        .filter(|&(start, end, _)| start != base && end > start)
        .collect();
    entries.sort_unstable();
    entries.dedup();

    let mut frames: Vec<(u64, u64)> = Vec::with_capacity(entries.len());
    for (start, end, chained) in entries {
        match frames.last_mut() {
            Some(last) if chained && start <= last.1 => last.1 = last.1.max(end),
            // A chained entry placed away from its function is a separate piece of code.
            _ => frames.push((start, end)),
        }
    }
    frames
}
