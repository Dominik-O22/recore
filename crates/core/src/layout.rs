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
//! Banked code names the addresses every bank shares, and the byte patterns of the trampolines
//! that reach a function in another bank. A region of bank N loads at `N << 16 | address`:
//!
//! ```toml
//! [banking]
//! common = [[0x0000, 0x4900], [0xff00, 0x10000]]
//!
//! [[banking.trampoline]]
//! # Bytes in hex. `hh ll` is the target, `ss ss` the address of a stub, `..` any byte.
//! entry = "90 hh ll 02 ss ss"
//! stub = "e5 49 54 1f 23 23 c0 e0 74 46 c0 e0 c0 82 c0 83 02 46 .."
//! ```
//!
//! [`Image::load`] takes a layout wherever it takes an executable.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use rustc_hash::FxHashMap;
use serde::Deserialize;

use crate::image::{Banking, Format, Image, Machine, Section};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Layout {
    machine: Machine,
    /// Where execution starts: the reset address first, then any other the hardware enters,
    /// such as interrupt vectors.
    entry: Vec<u64>,
    region: Vec<Region>,
    banking: Option<BankingLayout>,
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BankingLayout {
    /// `[start, end)` of the 16-bit addresses that are the same in every bank.
    common: Vec<(u16, u32)>,
    #[serde(default)]
    trampoline: Vec<Trampoline>,
}

/// How code reaches a function in another bank: it jumps to or calls an entry, which names the
/// function and goes on to a stub, which switches to the function's bank. There is one stub per
/// bank, and in address order they select bank 0, bank 1 and so on.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Trampoline {
    entry: Pattern,
    stub: Pattern,
}

/// One byte of a pattern.
#[derive(Clone, Copy, PartialEq)]
enum Unit {
    Byte(u8),
    Any,
    /// The high and the low byte of the address of the function.
    TargetHigh,
    TargetLow,
    /// A byte of the address of the stub, high byte first.
    Stub,
}

/// A run of bytes with places in it that vary, written as hex bytes and the placeholders `..`,
/// `hh`, `ll` and `ss`.
#[derive(Deserialize)]
#[serde(try_from = "String")]
struct Pattern(Vec<Unit>);

impl TryFrom<String> for Pattern {
    type Error = anyhow::Error;

    fn try_from(text: String) -> Result<Pattern> {
        let unit = |word: &str| match word {
            ".." => Ok(Unit::Any),
            "hh" => Ok(Unit::TargetHigh),
            "ll" => Ok(Unit::TargetLow),
            "ss" => Ok(Unit::Stub),
            byte if byte.len() == 2 => u8::from_str_radix(byte, 16).map(Unit::Byte).with_context(|| format!("`{byte}` in the pattern `{text}` is not a byte")),
            other => anyhow::bail!("`{other}` in the pattern `{text}` is not a byte"),
        };
        Ok(Pattern(text.split_whitespace().map(unit).collect::<Result<_>>()?))
    }
}

/// What the placeholders of a pattern stand for where it matches.
#[derive(Default)]
struct Match {
    target: u16,
    stub: u16,
}

impl Pattern {
    fn count(&self, unit: Unit) -> usize {
        self.0.iter().filter(|&&other| other == unit).count()
    }

    /// Matches the pattern against the start of `bytes`.
    fn matches(&self, bytes: &[u8]) -> Option<Match> {
        let mut found = Match::default();
        for (&unit, &byte) in self.0.iter().zip(bytes.get(..self.0.len())?) {
            match unit {
                Unit::Byte(expected) if expected != byte => return None,
                Unit::Byte(_) | Unit::Any => {}
                Unit::TargetHigh => found.target |= u16::from(byte) << 8,
                Unit::TargetLow => found.target |= u16::from(byte),
                Unit::Stub => found.stub = found.stub << 8 | u16::from(byte),
            }
        }
        Some(found)
    }
}

impl BankingLayout {
    /// Finds the trampolines in the common code of `sections`, which are sorted by address.
    fn resolve(&self, sections: &[Section]) -> Result<Banking> {
        let mut banking = Banking { common: self.common.iter().map(|&(start, end)| (u64::from(start), u64::from(end))).collect(), ..Banking::default() };
        banking.common.sort_unstable();
        // Every place a pattern can match: each common address with the bytes from there on.
        let places = || {
            let common = sections.iter().flat_map(|section| banking.common.iter().map(move |&(start, end)| (section, start.max(section.addr), end.min(section.end()))));
            common.flat_map(|(section, start, end)| (start..end).map(move |addr| (addr, &section.data[(addr - section.addr) as usize..(end - section.addr) as usize])))
        };
        let mut trampolines = FxHashMap::default();
        for trampoline in &self.trampoline {
            let Trampoline { entry, stub } = trampoline;
            let placeholders = |pattern: &Pattern| [Unit::TargetHigh, Unit::TargetLow, Unit::Stub].map(|unit| pattern.count(unit));
            ensure!(placeholders(entry) == [1, 1, 2], "a trampoline entry names its target with `hh ll` and its stub with `ss ss`");
            ensure!(placeholders(stub) == [0, 0, 0] && !stub.0.is_empty(), "a trampoline stub is bytes and `..` only");
            let bank_of: FxHashMap<u64, u64> = places().filter(|(_, bytes)| stub.matches(bytes).is_some()).map(|(addr, _)| addr).zip(0..).collect();
            for (addr, bytes) in places() {
                if let Some(found) = entry.matches(bytes)
                    && let Some(&bank) = bank_of.get(&u64::from(found.stub))
                {
                    trampolines.insert(addr, banking.address(bank, found.target));
                }
            }
        }
        banking.trampolines = trampolines;
        Ok(banking)
    }
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

    let banking = layout.banking.map(|banking| banking.resolve(&sections)).transpose()?.unwrap_or_default();
    // A trampoline exists for each function that another bank calls.
    let mut exports = vectors.to_vec();
    exports.extend(banking.trampolines.values());
    exports.sort_unstable();
    exports.dedup();

    Ok(Image {
        name: path.file_stem().unwrap_or_default().to_string_lossy().into_owned(),
        format: Format::Raw,
        machine: layout.machine,
        base: 0,
        branch_targets_marked: false,
        entry,
        sections,
        zero_filled: if layout.machine == Machine::I8051 { crate::i8051::memory() } else { Vec::new() },
        import_slots: FxHashMap::default(),
        exports,
        symbol_names: FxHashMap::default(),
        frames: Vec::new(),
        relative_targets: Vec::new(),
        // An 8051 reads its constants and its switch tables from the code space.
        data_in_code: layout.machine == Machine::I8051,
        banking,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_entry_reaches_its_target_in_the_bank_its_stub_selects() {
        let layout: BankingLayout = toml::from_str(
            r#"
            common = [[0x0000, 0x0040]]
            [[trampoline]]
            entry = "90 hh ll 02 ss ss"
            stub = "e5 49 02 46 .."
            "#,
        )
        .unwrap();
        let mut code = Vec::new();
        // Stubs at 0x00 and 0x05, for bank 0 and bank 1.
        code.extend([0xE5, 0x49, 0x02, 0x46, 0x00, 0xE5, 0x49, 0x02, 0x46, 0x04]);
        // Entries at 0x0A, 0x10 and 0x16: to 0x8010 in bank 1, to 0x8010 in bank 0, and to the
        // common address 0x0020 by way of bank 1.
        code.extend([0x90, 0x80, 0x10, 0x02, 0x00, 0x05, 0x90, 0x80, 0x10, 0x02, 0x00, 0x00, 0x90, 0x00, 0x20, 0x02, 0x00, 0x05]);
        // The same bytes with a jump to something that is not a stub.
        code.extend([0x90, 0x80, 0x10, 0x02, 0x00, 0x06]);
        code.resize(0x9000, 0);
        // Outside the common range nothing is an entry.
        code[0x8000..0x8006].copy_from_slice(&[0x90, 0x80, 0x10, 0x02, 0x00, 0x05]);
        let section = Section { name: String::new(), addr: 0, data: code, file_offset: None, executable: true, writable: false };

        let banking = layout.resolve(&[section]).unwrap();
        let mut trampolines: Vec<(u64, u64)> = banking.trampolines.iter().map(|(&entry, &target)| (entry, target)).collect();
        trampolines.sort_unstable();
        assert_eq!(trampolines, [(0x0A, 0x1_8010), (0x10, 0x8010), (0x16, 0x0020)]);
        // From bank 2: a call to an entry, to common code, and to code of its own.
        assert_eq!([banking.reach(0x2_9000, 0x000A), banking.reach(0x2_9000, 0x0030), banking.reach(0x2_9000, 0x9100)], [0x1_8010, 0x0030, 0x2_9100]);
    }
}
