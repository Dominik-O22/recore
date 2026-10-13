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
//! That is a table of entries in the common code, one per function, each of which goes on to
//! the stub of the function's bank. The image names each stub `bank_switch_N` and each table
//! `bank_trampolines`. Where the caller itself names the bank and calls the one
//! stub there is, the pattern is that of the call, with `bb` for the bank:
//!
//! ```toml
//! [[banking.trampoline]]
//! call = "78 ll 79 hh 7a bb 12 ss ss"
//! stub = "c0 b1 c8 c0 e0 e9 c0 e0 ea 54 0f 53 b1 f0 42 b1 c8 22"
//! ```
//!
//! `names = "chip.toml"` beside `machine` names a file that says what the hardware's addresses
//! are called, see [`crate::hardware`].
//!
//! A layout can leave open what is not yet known of a banked image, for [`crate::sweep`] to
//! find: which bank a region is, written `bank = "?"` with the 16-bit address its bytes start
//! at as its `address`, the `common` ranges, and the trampolines.
//!
//! `compiler = "sdcc"` at the top says what built the code, where that decides how functions
//! are called. An 8051 image without it is taken as built by Keil's C51.
//!
//! [`Image::load`] takes a layout wherever it takes an executable.

use std::fmt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use rustc_hash::FxHashMap;
use serde::Deserialize;

use crate::image::{Banking, Compiler, Format, Image, Machine, Section};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Layout {
    pub(crate) machine: Machine,
    /// Where execution starts: the reset address first, then any other the hardware enters.
    /// The interrupt vectors of an 8051 need no listing where they follow one another from
    /// the first: see [`crate::i8051::interrupt_vectors`].
    pub(crate) entry: Vec<u64>,
    pub(crate) region: Vec<Region>,
    pub(crate) banking: Option<BankingLayout>,
    /// A file of names for the hardware's addresses, relative to the layout file: see
    /// [`crate::hardware`].
    pub(crate) names: Option<PathBuf>,
    /// What built the code, `"keil"` or `"sdcc"`, for a machine whose compilers disagree on
    /// how a function is called.
    pub(crate) compiler: Option<Compiler>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Region {
    /// Relative to the layout file.
    pub(crate) file: PathBuf,
    pub(crate) offset: u64,
    pub(crate) length: u64,
    /// Where the bytes load. For a region whose bank is open, the 16-bit address they start at.
    pub(crate) address: u64,
    pub(crate) bank: Option<OpenBank>,
    #[serde(default)]
    pub(crate) executable: bool,
    #[serde(default)]
    pub(crate) writable: bool,
    /// The section's name, which is the file's name and the offset when the layout gives none.
    pub(crate) name: Option<String>,
}

/// What a layout writes for the bank of a region when it does not know it.
#[derive(Deserialize, Clone, Copy)]
pub(crate) enum OpenBank {
    #[serde(rename = "?")]
    Unknown,
}

impl Region {
    /// The section that `data`, which lies `skip` bytes into the region, makes at `addr`.
    pub(crate) fn section(&self, skip: u64, addr: u64, data: &[u8]) -> Section {
        let offset = self.offset + skip;
        let name = self.name.clone().unwrap_or_else(|| format!("{}+{offset:#x}", self.file.display()));
        Section { name, addr, data: data.to_vec(), file_offset: Some(offset), executable: self.executable, writable: self.writable }
    }
}

#[derive(Deserialize, Default, Clone)]
#[serde(deny_unknown_fields)]
pub(crate) struct BankingLayout {
    /// `[start, end)` of the 16-bit addresses that are the same in every bank. None when the
    /// layout leaves them open.
    #[serde(default)]
    pub(crate) common: Vec<(u16, u32)>,
    /// None when the layout leaves them open as well.
    #[serde(default)]
    pub(crate) trampoline: Vec<Trampoline>,
}

/// The trampolines of the compilers recore knows, by what to call each and as a layout writes
/// it, for an image whose layout names none. The first is the table Keil's linker builds from
/// `L51_BANK.A51`: the stub loads the current bank, masks and shifts it, and pushes it and the
/// address of the routine that switches back, all of which vary from one program to the next.
pub(crate) const SCHEMES: [(&str, &str); 2] = [
    ("Keil C51 bank table", "entry = \"90 hh ll 02 ss ss\"\nstub = \"e5 .. 54 .. 23 23 c0 e0 74 .. c0 e0 c0 82 c0 83 02 .. ..\"\n"),
    ("SDCC __sdcc_banked_call", "call = \"78 ll 79 hh 7a bb 12 ss ss\"\nstub = \"c0 b1 c8 c0 e0 e9 c0 e0 ea 54 0f 53 b1 f0 42 b1 c8 22\"\n"),
];

/// How code reaches a function in another bank: through bytes that name the function and go on
/// to a stub, which switches to the function's bank. They say which bank with `bb`. Without
/// it there is one stub per bank, and in address order they select bank 0, bank 1 and so on.
#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub(crate) struct Trampoline {
    /// An entry in the common code, which other code jumps to or calls in place of the function.
    entry: Option<Pattern>,
    /// A call in any code: the instructions that name the function, then the one whose
    /// operand is the stub's address, which is where the function is called.
    call: Option<Pattern>,
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
    /// The number of the function's bank.
    Bank,
}

/// A run of bytes with places in it that vary, written as hex bytes and the placeholders `..`,
/// `hh`, `ll`, `ss` and `bb`.
#[derive(Deserialize, Clone)]
#[serde(try_from = "String")]
struct Pattern(Vec<Unit>);

impl fmt::Display for Pattern {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let word = |unit: &Unit| match unit {
            Unit::Byte(byte) => format!("{byte:02x}"),
            Unit::Any => "..".into(),
            Unit::TargetHigh => "hh".into(),
            Unit::TargetLow => "ll".into(),
            Unit::Stub => "ss".into(),
            Unit::Bank => "bb".into(),
        };
        f.write_str(&self.0.iter().map(word).collect::<Vec<_>>().join(" "))
    }
}

/// The trampoline as a layout writes it.
impl fmt::Display for Trampoline {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let patterns = [("entry", self.entry.as_ref()), ("call", self.call.as_ref()), ("stub", Some(&self.stub))];
        patterns.into_iter().filter_map(|(key, pattern)| Some((key, pattern?))).try_for_each(|(key, pattern)| writeln!(f, "{key} = \"{pattern}\""))
    }
}

impl TryFrom<String> for Pattern {
    type Error = anyhow::Error;

    fn try_from(text: String) -> Result<Pattern> {
        let unit = |word: &str| match word {
            ".." => Ok(Unit::Any),
            "hh" => Ok(Unit::TargetHigh),
            "ll" => Ok(Unit::TargetLow),
            "ss" => Ok(Unit::Stub),
            "bb" => Ok(Unit::Bank),
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
    bank: Option<u8>,
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
                Unit::Bank => found.bank = Some(byte),
            }
        }
        Some(found)
    }
}

impl BankingLayout {
    /// Finds the trampolines in the common code of `sections`, which are sorted by address,
    /// and names the code that is their machinery: each table of entries and each stub.
    pub(crate) fn resolve(&self, sections: &[Section]) -> Result<(Banking, Vec<(u64, String)>)> {
        let mut banking = Banking { common: self.common.iter().map(|&(start, end)| (u64::from(start), u64::from(end))).collect(), ..Banking::default() };
        banking.common.sort_unstable();
        // Every place a pattern can match: each common address with the bytes from there on.
        let places = || {
            let common = sections.iter().flat_map(|section| banking.common.iter().map(move |&(start, end)| (section, start.max(section.addr), end.min(section.end()))));
            common.flat_map(|(section, start, end)| (start..end).map(move |addr| (addr, &section.data[(addr - section.addr) as usize..(end - section.addr) as usize])))
        };
        let (mut trampolines, mut calls) = (FxHashMap::default(), FxHashMap::default());
        let (mut tables, mut names) = (Vec::new(), Vec::new());
        for trampoline in &self.trampoline {
            let Trampoline { entry, call, stub } = trampoline;
            let pattern = match (entry, call) {
                (Some(pattern), None) | (None, Some(pattern)) => pattern,
                _ => anyhow::bail!("a trampoline is either an `entry` or a `call`"),
            };
            let placeholders = |pattern: &Pattern| [Unit::TargetHigh, Unit::TargetLow, Unit::Stub, Unit::Bank].map(|unit| pattern.count(unit));
            ensure!(matches!(placeholders(pattern), [1, 1, 2, 0 | 1]), "a trampoline names its target with `hh ll`, its stub with `ss ss`, and its bank with `bb` if at all");
            ensure!(placeholders(stub) == [0; 4] && !stub.0.is_empty(), "a trampoline stub is bytes and `..` only");
            let bank_of: FxHashMap<u64, u64> = places().filter(|(_, bytes)| stub.matches(bytes).is_some()).map(|(addr, _)| addr).zip(0..).collect();
            let reached = |bytes: &[u8]| {
                let found = pattern.matches(bytes)?;
                let bank = *bank_of.get(&u64::from(found.stub))?;
                Some(banking.address(found.bank.map_or(bank, u64::from), found.target))
            };
            // A stub that the caller tells the bank switches to any; otherwise to its own.
            names.extend(bank_of.iter().map(|(&stub, bank)| (stub, if pattern.count(Unit::Bank) == 1 { "bank_switch".to_string() } else { format!("bank_switch_{bank}") })));
            if entry.is_some() {
                let found: Vec<(u64, u64)> = places().filter_map(|(addr, bytes)| Some((addr, reached(bytes)?))).collect();
                // `places` goes up through the addresses, so entries back to back follow each other.
                for &(addr, _) in &found {
                    match tables.last_mut() {
                        Some((_, end)) if *end == addr => *end += pattern.0.len() as u64,
                        _ => tables.push((addr, addr + pattern.0.len() as u64)),
                    }
                }
                trampolines.extend(found);
            } else {
                // The instruction that calls is the one before the stub's address.
                let call = pattern.0.iter().position(|&unit| unit == Unit::Stub).and_then(|stub| stub.checked_sub(1)).context("a call names its stub after an instruction")?;
                let anywhere = sections.iter().filter(|section| section.executable).flat_map(|section| (0..section.data.len()).map(move |offset| (section.addr + offset as u64, &section.data[offset..])));
                calls.extend(anywhere.filter_map(|(addr, bytes)| Some((addr + call as u64, reached(bytes)?))));
            }
        }
        tables.sort_unstable();
        names.extend(tables.iter().map(|&(start, _)| (start, "bank_trampolines".to_string())));
        names.sort_unstable();
        (banking.trampolines, banking.calls, banking.tables) = (trampolines, calls, tables);
        Ok((banking, names))
    }
}

/// Whether `path` names a layout and not an executable.
pub fn is_layout(path: &Path) -> bool {
    path.extension().is_some_and(|extension| extension == "toml")
}

impl Layout {
    pub(crate) fn read(path: &Path) -> Result<Layout> {
        let text = std::fs::read_to_string(path).with_context(|| format!("reading {path:?}"))?;
        toml::from_str(&text).with_context(|| format!("reading the layout {path:?}"))
    }

    /// The bytes of each region, read from the files beside the layout at `path`.
    pub(crate) fn bytes(&self, path: &Path) -> Result<Vec<Vec<u8>>> {
        let mut files: FxHashMap<&Path, Vec<u8>> = FxHashMap::default();
        let mut bytes = Vec::new();
        for region in &self.region {
            if !files.contains_key(region.file.as_path()) {
                let file = path.with_file_name(&region.file);
                files.insert(&region.file, std::fs::read(&file).with_context(|| format!("reading {file:?}"))?);
            }
            let data = usize::try_from(region.offset)
                .ok()
                .zip(usize::try_from(region.length).ok())
                .and_then(|(offset, length)| files[region.file.as_path()].get(offset..offset.checked_add(length)?))
                .with_context(|| format!("{:?} has no {:#x} bytes at {:#x}", region.file, region.length, region.offset))?;
            bytes.push(data.to_vec());
        }
        Ok(bytes)
    }

    /// The image `sections` make, called `name`, with the trampolines `banking` describes.
    pub(crate) fn image(&self, name: String, mut sections: Vec<Section>, banking: Option<&BankingLayout>) -> Result<Image> {
        let (&entry, vectors) = self.entry.split_first().context("the layout names no entry point")?;
        sections.sort_by_key(|section| section.addr);
        for pair in sections.windows(2) {
            ensure!(pair[0].end() <= pair[1].addr, "the regions `{}` and `{}` overlap", pair[0].name, pair[1].name);
        }

        let (banking, machinery) = banking.map(|banking| banking.resolve(&sections)).transpose()?.unwrap_or_default();
        // A trampoline exists for each function that another bank calls. Nothing calls a stub
        // that discovery sees, since a call through one counts as a call of the function.
        let mut exports = vectors.to_vec();
        exports.extend(banking.trampolines.values().chain(banking.calls.values()));
        exports.extend(machinery.iter().map(|&(addr, _)| addr).filter(|addr| banking.tables.binary_search_by_key(addr, |&(start, _)| start).is_err()));
        // An 8051 is entered at its interrupt vectors, which the image itself shows.
        if let Some(low) = sections.first().filter(|section| self.machine == Machine::I8051 && section.addr == 0 && section.executable) {
            exports.extend(crate::i8051::interrupt_vectors(&low.data));
        }
        exports.sort_unstable();
        exports.dedup();

        Ok(Image {
            name,
            format: Format::Raw,
            machine: self.machine,
            base: 0,
            branch_targets_marked: false,
            entry,
            sections,
            zero_filled: if self.machine == Machine::I8051 { crate::i8051::memory() } else { Vec::new() },
            import_slots: FxHashMap::default(),
            exports,
            symbol_names: machinery.into_iter().collect(),
            frames: Vec::new(),
            relative_targets: Vec::new(),
            // An 8051 reads its constants and its switch tables from the code space.
            data_in_code: self.machine == Machine::I8051,
            banking,
            compiler: self.compiler,
        })
    }
}

/// Loads the image the layout at `path` describes.
pub fn load(path: &Path) -> Result<Image> {
    let layout = Layout::read(path)?;
    let open = layout.region.iter().any(|region| region.bank.is_some()) || layout.banking.as_ref().is_some_and(|banking| banking.common.is_empty());
    ensure!(!open, "the layout {path:?} leaves banks or the common ranges open: `recore sweep` finds them and writes a layout that says");
    let sections = layout.region.iter().zip(layout.bytes(path)?).map(|(region, data)| region.section(0, region.address, &data)).collect();
    let mut image = layout.image(path.file_stem().unwrap_or_default().to_string_lossy().into_owned(), sections, layout.banking.as_ref())?;
    image.symbol_names.extend(crate::hardware::names(layout.machine, layout.names.as_ref().map(|names| path.with_file_name(names)).as_deref())?);
    Ok(image)
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

        let (banking, names) = layout.resolve(&[section]).unwrap();
        let mut trampolines: Vec<(u64, u64)> = banking.trampolines.iter().map(|(&entry, &target)| (entry, target)).collect();
        trampolines.sort_unstable();
        assert_eq!(trampolines, [(0x0A, 0x1_8010), (0x10, 0x8010), (0x16, 0x0020)]);
        // The three entries are one table, and each stub is named for its bank.
        assert_eq!(banking.tables, [(0x0A, 0x1C)]);
        assert_eq!(names, [(0x00, "bank_switch_0".to_string()), (0x05, "bank_switch_1".to_string()), (0x0A, "bank_trampolines".to_string())]);
        // From bank 2: a call to an entry, to common code, and to code of its own.
        assert_eq!([banking.reach(0x2_9000, 0x000A), banking.reach(0x2_9000, 0x0030), banking.reach(0x2_9000, 0x9100)], [0x1_8010, 0x0030, 0x2_9100]);
    }

    #[test]
    fn a_call_reaches_its_target_in_the_bank_it_names() {
        let layout: BankingLayout = toml::from_str(
            r#"
            common = [[0x0000, 0x8000]]
            [[trampoline]]
            call = "78 ll 79 hh 7a bb 12 ss ss"
            stub = "c0 b1 22"
            "#,
        )
        .unwrap();
        // The stub at 0x10. At 0x20, a call of 0x9000 in bank 2; at 0x30, the same bytes with a
        // call of something else.
        let mut common = vec![0; 0x40];
        common[0x10..0x13].copy_from_slice(&[0xC0, 0xB1, 0x22]);
        common[0x20..0x29].copy_from_slice(&[0x78, 0x00, 0x79, 0x90, 0x7A, 0x02, 0x12, 0x00, 0x10]);
        common[0x30..0x39].copy_from_slice(&[0x78, 0x00, 0x79, 0x90, 0x7A, 0x02, 0x12, 0x00, 0x11]);
        // In bank 2 at 0x8000, a call of 0x8123 in bank 1, and of the common address 0x0123.
        let mut bank = vec![0x78, 0x23, 0x79, 0x81, 0x7A, 0x01, 0x12, 0x00, 0x10];
        bank.extend([0x78, 0x23, 0x79, 0x01, 0x7A, 0x01, 0x12, 0x00, 0x10]);
        let section = |addr, data| Section { name: String::new(), addr, data, file_offset: None, executable: true, writable: false };

        let (banking, names) = layout.resolve(&[section(0, common), section(0x2_8000, bank)]).unwrap();
        let mut calls: Vec<(u64, u64)> = banking.calls.iter().map(|(&call, &target)| (call, target)).collect();
        calls.sort_unstable();
        assert_eq!(calls, [(0x26, 0x2_9000), (0x2_8006, 0x1_8123), (0x2_800F, 0x0123)]);
        assert!(banking.trampolines.is_empty() && banking.tables.is_empty());
        assert_eq!(names, [(0x10, "bank_switch".to_string())]);
    }
}
