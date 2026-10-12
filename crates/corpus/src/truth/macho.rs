//! Ground truth for Mach-O images, from a copy of the image that still has its symbols.
//!
//! Homebrew ships its builds unstripped, so the symbol table names every function, local ones
//! included, and `LC_FUNCTION_STARTS` adds those of objects that were stripped before linking.
//! Neither gives a length: a function runs to the next one, or to the data the linker marked
//! after it (`LC_DATA_IN_CODE`, which is where jump tables go).
//!
//! There is no DWARF, so which functions never return is known only for imports. Calls to a
//! local function that never returns are not in `noreturn_calls`, and an analyzer that finds
//! them is counted as reporting extra.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;

use anyhow::{Context, Result, bail};
use object::macho;
use object::read::macho::{LoadCommandVariant, Nlist, Section as _, Segment as _};
use object::{Architecture, Object};

use super::{Callees, Function, Truth, aarch64, classify, is_runtime_noreturn, x86};

/// Imports that never return and that the ELF list does not have under the same name.
const NORETURN: &[&str] = &["__assert_rtn", "objc_exception_throw", "objc_exception_rethrow", "err", "errx", "verr", "verrx"];

/// The piece LLVM's hot-cold splitting moves out of a function, such as `parse.cold.1`.
fn is_fragment(name: &str) -> bool {
    name.contains(".cold.")
}

pub fn extract(binary_path: &Path, debug_path: &Path) -> Result<Truth> {
    let data = std::fs::read(debug_path).with_context(|| format!("reading {debug_path:?}"))?;
    let object::File::MachO64(file) = object::File::parse(&*data)? else { bail!("not a thin 64-bit Mach-O image") };
    let endian = file.endian();
    let architecture = file.architecture();

    // Executable sections, and what the symbol pointer and stub sections bind. An entry of
    // either is named by the indirect symbol table, starting at the section's first index.
    let mut exec = Vec::new();
    let mut text = None;
    let mut base = 0;
    // `(address, entry size, entry count, first indirect symbol, is stubs)`.
    let mut bound = Vec::new();
    let (mut dysymtab, mut function_starts, mut data_in_code) = (None, None, None);
    let mut commands = file.macho_load_commands()?;
    while let Some(command) = commands.next()? {
        match command.variant()? {
            LoadCommandVariant::Segment64(segment, section_data) => {
                if segment.name() == macho::SEG_TEXT.as_bytes() {
                    base = segment.vmaddr(endian);
                }
                for section in segment.sections(endian, section_data)? {
                    let (addr, size) = (section.addr(endian), section.size(endian));
                    if section.flags(endian).0 & (macho::S_ATTR_PURE_INSTRUCTIONS.0 | macho::S_ATTR_SOME_INSTRUCTIONS.0) != 0 {
                        exec.push((addr, addr + size));
                    }
                    if section.name() == b"__text" && section.segment_name() == b"__TEXT" {
                        text = Some((addr, addr + size, section.offset(endian) as usize));
                    }
                    let entry = match section.section_type(endian) {
                        macho::S_SYMBOL_STUBS => u64::from(section.reserved2(endian)),
                        macho::S_NON_LAZY_SYMBOL_POINTERS | macho::S_LAZY_SYMBOL_POINTERS => 8,
                        _ => 0,
                    };
                    if entry != 0 {
                        bound.push((addr, entry, size / entry, section.reserved1(endian), section.section_type(endian) == macho::S_SYMBOL_STUBS));
                    }
                }
            }
            LoadCommandVariant::Dysymtab(command) => dysymtab = Some(command),
            LoadCommandVariant::LinkeditData(command) => match command.cmd.get(endian) {
                macho::LC_FUNCTION_STARTS => function_starts = Some(command),
                macho::LC_DATA_IN_CODE => data_in_code = Some(command),
                _ => {}
            },
            _ => {}
        }
    }
    let (text_start, text_end, text_offset) = text.context("no __TEXT,__text section")?;
    let in_text = |addr: u64| addr >= text_start && addr < text_end;

    let symbols = file.macho_symbol_table();
    let name_of = |symbol: &macho::Nlist64<object::Endianness>| {
        let name = String::from_utf8_lossy(symbol.name(endian, symbols.strings()).unwrap_or_default());
        name.strip_prefix('_').unwrap_or(&name).to_string()
    };
    // A stub is keyed by its own address, standing in for the slot it jumps through.
    let mut slots: HashMap<u64, String> = HashMap::new();
    let mut stubs: HashMap<u64, u64> = HashMap::new();
    let indirect = dysymtab.map(|command| command.indirect_symbols(endian, &*data)).transpose()?.unwrap_or_default();
    for (addr, entry, count, first, is_stubs) in bound {
        for index in 0..count {
            let symbol = indirect.get(first as usize + index as usize).and_then(|entry| symbols.symbol(object::SymbolIndex(entry.get(endian).0 as usize)).ok());
            let Some(symbol) = symbol.filter(|symbol| symbol.is_undefined()) else { continue };
            slots.insert(addr + entry * index, name_of(symbol));
            if is_stubs {
                stubs.insert(addr + entry * index, addr + entry * index);
            }
        }
    }

    let mut data_ranges: Vec<(u64, u64)> = match data_in_code {
        Some(command) => command
            .data(endian, &*data)?
            .chunks_exact(8)
            .map(|entry| {
                let start = base + u64::from(u32::from_le_bytes(entry[..4].try_into().unwrap()));
                (start, start + u64::from(u16::from_le_bytes(entry[4..6].try_into().unwrap())))
            })
            .collect(),
        None => Vec::new(),
    };
    data_ranges.sort_unstable();

    // Aliases share an address; the first name stands. A start the symbols do not name gets
    // none.
    let mut by_addr: BTreeMap<u64, String> = BTreeMap::new();
    for symbol in symbols.iter().filter(|symbol| symbol.is_definition() && !symbol.is_stab() && in_text(symbol.n_value(endian))) {
        by_addr.entry(symbol.n_value(endian)).or_insert_with(|| name_of(symbol));
    }
    if let Some(command) = function_starts {
        for start in command.function_starts(endian, &*data, base)? {
            by_addr.entry(start?).or_default();
        }
    }
    by_addr.retain(|&addr, _| in_text(addr));
    let starts: Vec<u64> = by_addr.keys().copied().collect();
    let functions: Vec<Function> = by_addr
        .into_iter()
        .enumerate()
        .map(|(index, (addr, name))| {
            let next = starts.get(index + 1).copied().unwrap_or(text_end);
            let data = data_ranges.get(data_ranges.partition_point(|&(start, _)| start <= addr)).map_or(u64::MAX, |range| range.0);
            Function { addr, size: next.min(data) - addr, fragment: is_fragment(&name), noreturn: false, thunk: false, name }
        })
        .collect();

    let code = data.get(text_offset..text_offset + (text_end - text_start) as usize).context("__text lies outside the file")?;
    let scans = functions.iter().map(|function| {
        let bytes = &code[(function.addr - text_start) as usize..][..function.size as usize];
        match architecture {
            Architecture::Aarch64 => aarch64::scan(bytes, function.addr, &data_ranges),
            _ => x86::scan(bytes, function.addr, 64),
        }
    });
    let callees = Callees {
        noreturn_addrs: &HashSet::new(),
        stubs: &stubs,
        slots: &slots,
        is_noreturn_import: &|name| is_runtime_noreturn(name) || NORETURN.contains(&name),
        widen_slots: false,
    };
    let calls = classify(scans, &callees);

    Ok(Truth {
        name: binary_path.file_name().unwrap().to_string_lossy().into_owned(),
        exec,
        text: (text_start, text_end),
        functions,
        instructions: calls.instructions,
        noreturn_calls: calls.noreturn_calls,
        terminal_calls: calls.terminal_calls,
        noreturn_imports: calls.noreturn_imports.into_iter().collect(),
        undecodable_bytes: calls.undecodable_bytes,
        data_bytes: calls.data_bytes,
    })
}
