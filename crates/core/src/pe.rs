//! The parts of a Windows PE image that differ from ELF: the import address table, base
//! relocations, and the exception directory.

use std::collections::HashMap;

use anyhow::Result;
use object::read::pe::{Import, PeFile64};
use object::{LittleEndian as LE, Object};

use crate::image::Section;

/// What a PE file contributes to an `Image` beyond its sections.
pub struct Metadata {
    /// Import address table slot to the name of the function the loader binds there.
    pub import_slots: HashMap<u64, String>,
    /// `(slot, value)` for every 64-bit pointer the loader would rebase.
    pub relative_targets: Vec<(u64, u64)>,
    pub exports: Vec<u64>,
    /// `[start, end)` of every `RUNTIME_FUNCTION` in the exception directory.
    pub frames: Vec<(u64, u64)>,
}

pub fn load(data: &[u8], sections: &[Section]) -> Result<Metadata> {
    let pe = PeFile64::parse(data)?;
    let base = pe.relative_address_base();

    let mut import_slots = HashMap::new();
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
            while let Some(thunk) = thunks.next::<object::pe::ImageNtHeaders64>()? {
                if let Ok(Import::Name(_, name)) = table.import::<object::pe::ImageNtHeaders64>(thunk) {
                    import_slots.insert(base + slots + 8 * index, String::from_utf8_lossy(name).into_owned());
                }
                index += 1;
            }
        }
    }

    let read_word = |addr: u64| {
        let section = sections.iter().find(|s| s.contains(addr))?;
        let bytes = section.data.get((addr - section.addr) as usize..)?.get(..8)?;
        Some(u64::from_le_bytes(bytes.try_into().unwrap()))
    };
    let mut relative_targets = Vec::new();
    if let Some(mut blocks) = pe.data_directories().relocation_blocks(data, &pe.section_table())? {
        while let Some(block) = blocks.next()? {
            for relocation in block {
                if relocation.typ == object::pe::IMAGE_REL_BASED_DIR64 {
                    let slot = base + u64::from(relocation.virtual_address);
                    relative_targets.extend(read_word(slot).map(|value| (slot, value)));
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

    // Each entry is three RVAs: begin, end, unwind information.
    let frames = sections
        .iter()
        .find(|s| s.name == ".pdata")
        .map(|pdata| {
            let rva = |bytes: &[u8]| u64::from(u32::from_le_bytes(bytes.try_into().unwrap()));
            let mut frames: Vec<(u64, u64)> = pdata
                .data
                .chunks_exact(12)
                .map(|entry| (base + rva(&entry[0..4]), base + rva(&entry[4..8])))
                .filter(|&(start, end)| start != base && end > start)
                .collect();
            frames.sort_unstable();
            frames.dedup();
            frames
        })
        .unwrap_or_default();

    Ok(Metadata { import_slots, relative_targets, exports, frames })
}
