//! A raw image: bytes that come in no container, with a layout file that says where they load.
//!
//! The layout is a TOML file beside the bytes. It names the machine, the addresses execution
//! starts at, and each stretch of a file to load:
//!
//! ```toml
//! machine = "x86-64"
//! entry = [0x401000]
//!
//! [[region]]
//! file = "firmware.bin"
//! offset = 0x200
//! length = 0x8000
//! address = 0x401000
//! executable = true
//! ```
//!
//! [`Image::load`] takes a layout wherever it takes an executable.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use rustc_hash::FxHashMap;
use serde::Deserialize;

use crate::image::{Format, Image, Machine, Section};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Layout {
    machine: Machine,
    /// Where execution starts: the reset address first, then any other the hardware enters,
    /// such as interrupt vectors.
    entry: Vec<u64>,
    region: Vec<Region>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Region {
    /// Relative to the layout file.
    file: PathBuf,
    offset: u64,
    length: u64,
    address: u64,
    #[serde(default)]
    executable: bool,
    #[serde(default)]
    writable: bool,
    /// The section's name, which is the file's name and the offset when the layout gives none.
    name: Option<String>,
}

/// Whether `path` names a layout and not an executable.
pub fn is_layout(path: &Path) -> bool {
    path.extension().is_some_and(|extension| extension == "toml")
}

/// Loads the image the layout at `path` describes.
pub fn load(path: &Path) -> Result<Image> {
    let text = std::fs::read_to_string(path).with_context(|| format!("reading {path:?}"))?;
    let layout: Layout = toml::from_str(&text).with_context(|| format!("reading the layout {path:?}"))?;
    let (&entry, vectors) = layout.entry.split_first().context("the layout names no entry point")?;

    let mut files: FxHashMap<&Path, Vec<u8>> = FxHashMap::default();
    let mut sections = Vec::new();
    for region in &layout.region {
        if !files.contains_key(region.file.as_path()) {
            let file = path.with_file_name(&region.file);
            files.insert(&region.file, std::fs::read(&file).with_context(|| format!("reading {file:?}"))?);
        }
        let data = usize::try_from(region.offset)
            .ok()
            .zip(usize::try_from(region.length).ok())
            .and_then(|(offset, length)| files[region.file.as_path()].get(offset..offset.checked_add(length)?))
            .with_context(|| format!("{:?} has no {:#x} bytes at {:#x}", region.file, region.length, region.offset))?;
        sections.push(Section {
            name: region.name.clone().unwrap_or_else(|| format!("{}+{:#x}", region.file.display(), region.offset)),
            addr: region.address,
            data: data.to_vec(),
            file_offset: Some(region.offset),
            executable: region.executable,
            writable: region.writable,
        });
    }
    sections.sort_by_key(|section| section.addr);
    for pair in sections.windows(2) {
        ensure!(pair[0].end() <= pair[1].addr, "the regions `{}` and `{}` overlap", pair[0].name, pair[1].name);
    }

    Ok(Image {
        name: path.file_stem().unwrap_or_default().to_string_lossy().into_owned(),
        format: Format::Raw,
        machine: layout.machine,
        base: 0,
        branch_targets_marked: false,
        entry,
        sections,
        zero_filled: Vec::new(),
        import_slots: FxHashMap::default(),
        exports: vectors.to_vec(),
        symbol_names: FxHashMap::default(),
        frames: Vec::new(),
        relative_targets: Vec::new(),
        data_in_code: false,
    })
}
