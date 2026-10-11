//! Ground truth for one binary, derived from its separate debug file.
//!
//! The debug file's symbol table gives every function's start and size, DWARF marks functions
//! that never return, and a linear decode inside each known function range gives the true
//! instruction boundaries and call sites. Symbols, DWARF and the classification of calls are
//! shared; only that decode is per architecture (x86-64 and AArch64).

mod aarch64;
mod x86_64;

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::Path;

use anyhow::{Context, Result, bail};
use object::{Architecture, Object, ObjectSection, ObjectSymbol, ObjectSymbolTable, SectionKind, SymbolKind};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Function {
    pub addr: u64,
    pub size: u64,
    pub name: String,
    /// Compiler-split cold or partial fragment (`foo.cold`, `foo.part.0`), not a real entry point.
    pub fragment: bool,
    pub noreturn: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Truth {
    pub name: String,
    /// Executable section ranges as `[start, end)`.
    pub exec: Vec<(u64, u64)>,
    /// The `.text` range. Scoring is limited to it, since PLT stubs carry no symbols.
    pub text: (u64, u64),
    pub functions: Vec<Function>,
    /// Number of instructions inside known function ranges.
    pub instructions: u64,
    /// Addresses of call instructions whose target never returns.
    pub noreturn_calls: Vec<u64>,
    /// Calls whose callee the compiler demonstrably treated as non-returning, whether or not the
    /// debug info says so: somewhere a call to that callee is the last instruction of a function,
    /// with nothing emitted after it. Lists every call to such a callee.
    #[serde(default)]
    pub terminal_calls: Vec<u64>,
    /// Imported function names that never return, according to DWARF.
    pub noreturn_imports: Vec<String>,
    /// Bytes inside function ranges that did not decode. Non-zero means data in code.
    pub undecodable_bytes: u64,
    /// Bytes inside function ranges that Arm mapping symbols (`$d`) mark as literal data. They are
    /// not decoded and count neither as instructions nor as undecodable.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub data_bytes: u64,
}

fn is_zero(value: &u64) -> bool {
    *value == 0
}

/// Where a call instruction goes, as far as the decode alone can tell.
enum Callee {
    Direct(u64),
    /// Through the GOT-style slot at this address.
    Slot(u64),
}

/// The architecture-specific linear decode of one function body.
#[derive(Default)]
struct Scan {
    instructions: u64,
    undecodable_bytes: u64,
    data_bytes: u64,
    /// Calls with a known callee, in address order.
    calls: Vec<(u64, Callee)>,
    /// The call that is the function's last instruction, padding aside.
    final_call: Option<u64>,
}

/// Names and addresses of functions DWARF marks `DW_AT_noreturn`.
#[derive(Default)]
struct NoReturn {
    /// Names of functions defined in this binary.
    names: HashSet<String>,
    /// Names of external declarations, which is what an import can be matched against.
    declared: HashSet<String>,
    addrs: HashSet<u64>,
}

fn dwarf_noreturn(debug: &object::File) -> Result<NoReturn> {
    use gimli::{EndianArcSlice, LittleEndian, Reader};
    let load = |id: gimli::SectionId| -> Result<EndianArcSlice<LittleEndian>> {
        let data = match debug.section_by_name(id.name()) {
            Some(section) => section.uncompressed_data()?.into_owned(),
            None => Vec::new(),
        };
        Ok(EndianArcSlice::new(data.into(), LittleEndian))
    };
    let dwarf = gimli::Dwarf::load(load)?;
    let mut out = NoReturn::default();

    let mut units = dwarf.units();
    while let Some(header) = units.next()? {
        let unit = dwarf.unit(header)?;
        // First pass: which DIEs carry noreturn, and their names.
        let mut flagged: HashMap<gimli::UnitOffset, Option<String>> = HashMap::new();
        // Definitions that point at a declaration: (low_pc, referenced DIE).
        let mut definitions: Vec<(u64, gimli::UnitOffset)> = Vec::new();

        let mut entries = unit.entries();
        while let Some(entry) = entries.next_dfs()? {
            if entry.tag() != gimli::DW_TAG_subprogram {
                continue;
            }
            let name = [gimli::DW_AT_linkage_name, gimli::DW_AT_name].iter().find_map(|&at| {
                let value = entry.attr_value(at)?;
                let s = dwarf.attr_string(&unit, value).ok()?;
                Some(s.to_string_lossy().ok()?.into_owned())
            });
            let low_pc = match entry.attr_value(gimli::DW_AT_low_pc) {
                Some(gimli::AttributeValue::Addr(addr)) => Some(addr),
                Some(gimli::AttributeValue::DebugAddrIndex(index)) => dwarf.address(&unit, index).ok(),
                _ => None,
            };
            if entry.attr_value(gimli::DW_AT_noreturn).is_some() {
                flagged.insert(entry.offset(), name.clone());
                let is_declaration = entry.attr_value(gimli::DW_AT_declaration).is_some() && low_pc.is_none();
                if let Some(name) = name {
                    if is_declaration && entry.attr_value(gimli::DW_AT_external).is_some() {
                        out.declared.insert(name);
                    } else {
                        out.names.insert(name);
                    }
                }
                if let Some(addr) = low_pc {
                    out.addrs.insert(addr);
                }
            }
            if let Some(addr) = low_pc {
                for at in [gimli::DW_AT_specification, gimli::DW_AT_abstract_origin] {
                    if let Some(gimli::AttributeValue::UnitRef(target)) = entry.attr_value(at) {
                        definitions.push((addr, target));
                    }
                }
            }
        }
        for (addr, target) in definitions {
            if flagged.contains_key(&target) {
                out.addrs.insert(addr);
            }
        }
    }
    Ok(out)
}

fn is_fragment(name: &str) -> bool {
    // The AArch64 linker moves an instruction hit by Cortex-A53 erratum 843419 into a veneer
    // named `e843419@...`: a piece of some function, reached and left by a plain branch.
    name.starts_with("e843419@")
        || [".cold", ".part.", ".isra.", ".constprop.", ".lto_priv."].iter().any(|marker| name.contains(marker))
            && (name.contains(".cold") || name.contains(".part."))
}

/// glibc's `error` returns when its status argument is zero, but gnulib declares a noreturn overload.
fn is_conditionally_noreturn(name: &str) -> bool {
    matches!(name, "error" | "error_at_line")
}

/// Imports that never return but that DWARF cannot say so about, because the compiler emits the
/// calls itself and no declaration exists in the debug info.
fn is_runtime_noreturn(name: &str) -> bool {
    const NAMES: &[&str] = &[
        // The C library declares these noreturn, but Debian moves shared declarations out of
        // each debug file with dwz, so DWARF cannot be relied on for them.
        "exit",
        "_exit",
        "abort",
        "__assert_fail",
        "__stack_chk_fail",
        "__cxa_throw",
        "__cxa_rethrow",
        "__cxa_bad_cast",
        "__cxa_bad_typeid",
        "__cxa_throw_bad_array_new_length",
        "__cxa_pure_virtual",
        "__cxa_call_unexpected",
        "_Unwind_Resume",
        "_ZSt9terminatev",
    ];
    // libstdc++ helpers such as `std::__throw_bad_alloc()` mangle to `_ZSt<len>__throw_...`.
    NAMES.contains(&name) || (name.starts_with("_ZSt") && name.contains("__throw_"))
}

/// Maps a GOT-style slot address to the imported symbol name its relocation binds.
fn import_slots(binary: &object::File) -> HashMap<u64, String> {
    let mut slots = HashMap::new();
    let (Some(relocations), Some(dynsyms)) = (binary.dynamic_relocations(), binary.dynamic_symbol_table()) else {
        return slots;
    };
    for (addr, reloc) in relocations {
        if let object::RelocationTarget::Symbol(index) = reloc.target() {
            if let Ok(name) = dynsyms.symbol_by_index(index).and_then(|symbol| symbol.name()) {
                if !name.is_empty() {
                    slots.insert(addr, name.to_string());
                }
            }
        }
    }
    slots
}

/// Arm mapping symbols (`$x`, `$d`, `$x.123`) mark code and data runs; they are not functions.
fn is_mapping_symbol(name: &str) -> bool {
    ["$x", "$d"].iter().any(|prefix| name == *prefix || name.strip_prefix(prefix).is_some_and(|rest| rest.starts_with('.')))
}

pub fn extract(binary_path: &Path, debug_path: &Path) -> Result<Truth> {
    let binary_data = std::fs::read(binary_path).with_context(|| format!("reading {binary_path:?}"))?;
    let debug_data = std::fs::read(debug_path).with_context(|| format!("reading {debug_path:?}"))?;
    let binary = object::File::parse(&*binary_data)?;
    let debug = object::File::parse(&*debug_data)?;
    let architecture = binary.architecture();
    if !matches!(architecture, Architecture::X86_64 | Architecture::Aarch64) {
        bail!("unsupported architecture {architecture:?}");
    }

    let exec_sections: Vec<_> = binary.sections().filter(|s| s.kind() == SectionKind::Text && s.size() > 0).collect();
    let exec: Vec<(u64, u64)> = exec_sections.iter().map(|s| (s.address(), s.address() + s.size())).collect();
    let in_exec = |addr: u64| exec.iter().any(|&(start, end)| addr >= start && addr < end);

    // A debug file without DWARF (some Go builds) still has a usable symbol table.
    let noreturn = dwarf_noreturn(&debug).unwrap_or_default();

    // Aliases share an address; keep one, preferring a non-fragment name.
    let mut by_addr: BTreeMap<u64, Function> = BTreeMap::new();
    for symbol in debug.symbols() {
        // Sizeless function symbols are kept: C runtime stubs such as `frame_dummy` are written
        // in assembly without a size, and they are real entry points.
        if symbol.kind() != SymbolKind::Text || !in_exec(symbol.address()) {
            continue;
        }
        let name = symbol.name().unwrap_or("").to_string();
        if is_mapping_symbol(&name) {
            continue;
        }
        let function = Function {
            addr: symbol.address(),
            size: symbol.size(),
            fragment: is_fragment(&name),
            noreturn: noreturn.addrs.contains(&symbol.address()) || noreturn.names.contains(&name),
            name,
        };
        match by_addr.get(&function.addr) {
            Some(existing) if !existing.fragment && existing.noreturn >= function.noreturn => {}
            _ => {
                by_addr.insert(function.addr, function);
            }
        }
    }
    let noreturn_addrs: HashSet<u64> = by_addr.values().filter(|f| f.noreturn).map(|f| f.addr).collect();

    let slots = import_slots(&binary);
    // AArch64 reaches imports by a direct call to a PLT stub; x86-64 truth does not resolve stubs.
    let (stubs, data) = match architecture {
        Architecture::Aarch64 => (aarch64::plt_stubs(&binary), aarch64::data_ranges(&binary, &debug)),
        _ => Default::default(),
    };
    let mut noreturn_imports: BTreeSet<String> = BTreeSet::new();
    let mut noreturn_import = |slot: &u64| match slots.get(slot) {
        Some(name) if !is_conditionally_noreturn(name) && (noreturn.declared.contains(name) || is_runtime_noreturn(name)) => {
            noreturn_imports.insert(name.clone());
            true
        }
        _ => false,
    };
    let mut noreturn_calls = Vec::new();
    let mut terminal_calls = Vec::new();
    let mut direct_calls: Vec<(u64, u64)> = Vec::new();
    let (mut instructions, mut undecodable_bytes, mut data_bytes) = (0u64, 0u64, 0u64);

    for function in by_addr.values() {
        let Some(section) = exec_sections
            .iter()
            .find(|s| function.addr >= s.address() && function.addr + function.size <= s.address() + s.size())
        else {
            continue;
        };
        let Ok(section_data) = section.data() else { continue };
        let offset = (function.addr - section.address()) as usize;
        let bytes = &section_data[offset..offset + function.size as usize];
        let scan = match architecture {
            Architecture::Aarch64 => aarch64::scan(bytes, function.addr, &data),
            _ => x86_64::scan(bytes, function.addr),
        };
        instructions += scan.instructions;
        undecodable_bytes += scan.undecodable_bytes;
        data_bytes += scan.data_bytes;
        terminal_calls.extend(scan.final_call);
        for (at, callee) in scan.calls {
            let target_noreturn = match callee {
                Callee::Direct(target) => {
                    direct_calls.push((at, target));
                    noreturn_addrs.contains(&target) || stubs.get(&target).is_some_and(&mut noreturn_import)
                }
                Callee::Slot(slot) => noreturn_import(&slot),
            };
            if target_noreturn {
                noreturn_calls.push(at);
            }
        }
    }
    // Widen from the calls that end a function to every call of the same callee.
    let ends_function: HashSet<u64> = terminal_calls.iter().copied().collect();
    let terminal_callees: HashSet<u64> =
        direct_calls.iter().filter(|(at, _)| ends_function.contains(at)).map(|&(_, target)| target).collect();
    terminal_calls.extend(
        direct_calls.iter().filter(|(at, target)| terminal_callees.contains(target) && !ends_function.contains(at)).map(|&(at, _)| at),
    );
    terminal_calls.sort_unstable();

    let text = exec_sections
        .iter()
        .find(|s| s.name() == Ok(".text"))
        .map(|s| (s.address(), s.address() + s.size()))
        .context("no .text section")?;

    Ok(Truth {
        text,
        name: binary_path.file_name().unwrap().to_string_lossy().into_owned(),
        exec,
        functions: by_addr.into_values().collect(),
        instructions,
        noreturn_calls,
        terminal_calls,
        noreturn_imports: noreturn_imports.into_iter().collect(),
        undecodable_bytes,
        data_bytes,
    })
}
