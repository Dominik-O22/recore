//! Ground truth for one binary, derived from its separate debug file.
//!
//! The debug file's symbol table gives every function's start and size, DWARF marks functions
//! that never return, and a linear decode inside each known function range gives the true
//! instruction boundaries and call sites. Symbols, DWARF and the classification of calls are
//! shared; only that decode is per architecture (x86-64, AArch64 and 32-bit ARM, see [`arm`]).
//!
//! PE images take their functions from a PDB instead (see [`pe`]), and Mach-O images from an
//! unstripped copy (see [`macho`]); both share the classification. Raw images take theirs from
//! what built them: 8051 programs from SDCC's debug records (see [`sdcc`]), Cortex-M programs
//! from the ELF they were cut from (see [`thumb`]).

mod aarch64;
pub mod arm;
mod macho;
pub mod pe;
pub mod pe_facts;
pub mod sdcc;
pub mod thumb;
mod x86;

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
    /// PE only: a lone `jmp` to an import or to another function (import thunk, incremental-link
    /// thunk). Always also `fragment`, so scoring neither demands nor penalises reporting it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub thunk: bool,
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
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
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
    name.starts_with("e843419@") || name.contains(".cold") || name.contains(".part.")
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
        if let object::RelocationTarget::Symbol(index) = reloc.target() && let Ok(name) = dynsyms.symbol_by_index(index).and_then(|symbol| symbol.name()) && !name.is_empty() {
            slots.insert(addr, name.to_string());
        }
    }
    slots
}

/// Whether the debug file of a raw image is the ELF it was cut from, and not SDCC's records.
pub fn is_elf_of_raw(debug_path: &Path) -> bool {
    debug_path.extension().is_some_and(|extension| extension == "debug")
}

/// Arm mapping symbols (`$x`, `$d`, `$x.123`) mark code and data runs; they are not functions.
fn is_mapping_symbol(name: &str) -> bool {
    ["$x", "$d"].iter().any(|prefix| name == *prefix || name.strip_prefix(prefix).is_some_and(|rest| rest.starts_with('.')))
}

/// How a call's target is judged to never return.
struct Callees<'a> {
    /// Entry addresses of functions in the binary that never return.
    noreturn_addrs: &'a HashSet<u64>,
    /// Stub address to the import slot it jumps through.
    stubs: &'a HashMap<u64, u64>,
    /// Import slot address to imported name.
    slots: &'a HashMap<u64, String>,
    is_noreturn_import: &'a dyn Fn(&str) -> bool,
    /// Whether calls through an import slot take part in widening terminal calls. PE code reaches
    /// most imports that way; ELF truth has always widened direct calls only.
    widen_slots: bool,
}

/// The decode of every function, with its calls classified.
#[derive(Default)]
struct Classified {
    instructions: u64,
    undecodable_bytes: u64,
    data_bytes: u64,
    noreturn_calls: Vec<u64>,
    terminal_calls: Vec<u64>,
    noreturn_imports: BTreeSet<String>,
}

/// Sums the scans of all functions and classifies their calls.
fn classify(scans: impl Iterator<Item = Scan>, callees: &Callees) -> Classified {
    let mut out = Classified::default();
    let mut noreturn_import = |slot: &u64| match callees.slots.get(slot) {
        Some(name) if (callees.is_noreturn_import)(name) => {
            out.noreturn_imports.insert(name.clone());
            true
        }
        _ => false,
    };
    let mut widened: Vec<(u64, Callee)> = Vec::new();
    for scan in scans {
        out.instructions += scan.instructions;
        out.undecodable_bytes += scan.undecodable_bytes;
        out.data_bytes += scan.data_bytes;
        out.terminal_calls.extend(scan.final_call);
        for (at, callee) in scan.calls {
            let target_noreturn = match callee {
                Callee::Direct(target) => {
                    widened.push((at, callee));
                    callees.noreturn_addrs.contains(&target) || callees.stubs.get(&target).is_some_and(&mut noreturn_import)
                }
                Callee::Slot(slot) => {
                    if callees.widen_slots {
                        widened.push((at, callee));
                    }
                    noreturn_import(&slot)
                }
            };
            if target_noreturn {
                out.noreturn_calls.push(at);
            }
        }
    }
    // Widen from the calls that end a function to every call of the same callee.
    let ends_function: HashSet<u64> = out.terminal_calls.iter().copied().collect();
    let terminal_callees: HashSet<Callee> =
        widened.iter().filter(|(at, _)| ends_function.contains(at)).map(|&(_, callee)| callee).collect();
    out.terminal_calls
        .extend(widened.iter().filter(|(at, callee)| terminal_callees.contains(callee) && !ends_function.contains(at)).map(|&(at, _)| at));
    out.terminal_calls.sort_unstable();
    out
}

pub fn extract(binary_path: &Path, debug_path: &Path) -> Result<Truth> {
    if recore::layout::is_layout(binary_path) {
        return if is_elf_of_raw(debug_path) { thumb::extract(binary_path, debug_path) } else { sdcc::extract(binary_path, debug_path) };
    }
    let binary_data = std::fs::read(binary_path).with_context(|| format!("reading {binary_path:?}"))?;
    let binary = object::File::parse(&*binary_data)?;
    if binary.format() == object::BinaryFormat::Pe {
        return pe::extract(binary_path, &binary_data, debug_path);
    }
    if binary.format() == object::BinaryFormat::MachO {
        return macho::extract(binary_path, debug_path);
    }
    let debug_data = std::fs::read(debug_path).with_context(|| format!("reading {debug_path:?}"))?;
    let debug = object::File::parse(&*debug_data)?;
    elf(binary_path, &binary, &debug)
}

/// Truth for an ELF binary, from its debug file.
fn elf(binary_path: &Path, binary: &object::File, debug: &object::File) -> Result<Truth> {
    let architecture = binary.architecture();
    if architecture == Architecture::Arm {
        return arm::extract(binary_path, binary, debug);
    }
    if !matches!(architecture, Architecture::X86_64 | Architecture::Aarch64) {
        bail!("unsupported architecture {architecture:?}");
    }

    let exec_sections: Vec<_> = binary.sections().filter(|s| s.kind() == SectionKind::Text && s.size() > 0).collect();
    let exec: Vec<(u64, u64)> = exec_sections.iter().map(|s| (s.address(), s.address() + s.size())).collect();
    let in_exec = |addr: u64| exec.iter().any(|&(start, end)| addr >= start && addr < end);

    // A debug file without DWARF (some Go builds) still has a usable symbol table.
    let noreturn = dwarf_noreturn(debug).unwrap_or_default();

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
            thunk: false,
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

    let slots = import_slots(binary);
    // AArch64 reaches imports by a direct call to a PLT stub; x86-64 truth does not resolve stubs.
    let (stubs, data) = match architecture {
        Architecture::Aarch64 => (aarch64::plt_stubs(binary), aarch64::data_ranges(binary, debug)),
        _ => Default::default(),
    };
    let scans = by_addr.values().filter_map(|function| {
        let section = exec_sections
            .iter()
            .find(|s| function.addr >= s.address() && function.addr + function.size <= s.address() + s.size())?;
        let section_data = section.data().ok()?;
        let offset = (function.addr - section.address()) as usize;
        let bytes = &section_data[offset..offset + function.size as usize];
        Some(match architecture {
            Architecture::Aarch64 => aarch64::scan(bytes, function.addr, &data),
            _ => x86::scan(bytes, function.addr, 64),
        })
    });
    let callees = Callees {
        noreturn_addrs: &noreturn_addrs,
        stubs: &stubs,
        slots: &slots,
        is_noreturn_import: &|name| !is_conditionally_noreturn(name) && (noreturn.declared.contains(name) || is_runtime_noreturn(name)),
        widen_slots: false,
    };
    let calls = classify(scans, &callees);

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
        instructions: calls.instructions,
        noreturn_calls: calls.noreturn_calls,
        terminal_calls: calls.terminal_calls,
        noreturn_imports: calls.noreturn_imports.into_iter().collect(),
        undecodable_bytes: calls.undecodable_bytes,
        data_bytes: calls.data_bytes,
    })
}

/// Debug files built inside a test.
#[cfg(test)]
pub(crate) mod fixture {
    use object::write::{Object, StandardSection, Symbol, SymbolSection};
    use object::{Architecture, BinaryFormat, Endianness, SymbolFlags, SymbolKind, SymbolScope};

    /// An ELF relocatable object of `architecture`, whose sections all sit at 0, with `code` in
    /// `.text` and each symbol in it as `(name, address, size)`: a function, or a mapping symbol
    /// where the name starts with `$`. `sections` adds sections of other data by name.
    pub fn elf(architecture: Architecture, code: &[u8], symbols: &[(&str, u64, u64)], sections: &[(&str, &[u8])]) -> Vec<u8> {
        let mut object = Object::new(BinaryFormat::Elf, architecture, Endianness::Little);
        let text = object.section_id(StandardSection::Text);
        object.append_section_data(text, code, 4);
        for &(name, value, size) in symbols {
            let kind = if name.starts_with('$') { SymbolKind::Label } else { SymbolKind::Text };
            let symbol = Symbol { name: name.into(), value, size, kind, scope: SymbolScope::Compilation, weak: false, section: SymbolSection::Section(text), flags: SymbolFlags::None };
            object.add_symbol(symbol);
        }
        for &(name, data) in sections {
            let kind = if name.starts_with(".debug") { object::SectionKind::Debug } else { object::SectionKind::ReadOnlyData };
            let section = object.add_section(Vec::new(), name.into(), kind);
            object.append_section_data(section, data, 1);
        }
        object.write().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use gimli::write::{Address, AttributeValue, DwarfUnit, EndianVec, Sections};
    use gimli::{Encoding, Format, LittleEndian};

    use super::*;

    /// Callees where every import but `printf` never returns.
    fn callees<'a>(noreturn_addrs: &'a HashSet<u64>, stubs: &'a HashMap<u64, u64>, slots: &'a HashMap<u64, String>, widen_slots: bool) -> Callees<'a> {
        Callees { noreturn_addrs, stubs, slots, is_noreturn_import: &|name| name != "printf", widen_slots }
    }

    /// The scan of a function that makes `calls`, and ends with `final_call`.
    fn calls(calls: &[(u64, Callee)], final_call: Option<u64>) -> Scan {
        Scan { calls: calls.to_vec(), final_call, ..Scan::default() }
    }

    #[test]
    fn a_call_never_returns_where_its_callee_does_directly_through_a_stub_or_through_a_slot() {
        let stubs = HashMap::from([(0x600, 0x900)]);
        let slots = HashMap::from([(0x900, "abort".to_string()), (0x908, "exit".to_string()), (0x910, "printf".to_string())]);
        let scan = calls(&[(0x10, Callee::Direct(0x500)), (0x20, Callee::Direct(0x600)), (0x30, Callee::Slot(0x908)), (0x40, Callee::Slot(0x910)), (0x50, Callee::Direct(0x700))], None);
        let out = classify([scan].into_iter(), &callees(&HashSet::from([0x500]), &stubs, &slots, false));
        assert_eq!(out.noreturn_calls, [0x10, 0x20, 0x30]);
        assert_eq!(out.noreturn_imports.into_iter().collect::<Vec<_>>(), ["abort", "exit"]);
    }

    #[test]
    fn a_call_that_ends_a_function_makes_every_call_of_its_callee_terminal() {
        let (noreturn, stubs, slots) = Default::default();
        let ends = calls(&[(0x10, Callee::Direct(0x700))], Some(0x10));
        let other = calls(&[(0x110, Callee::Direct(0x700)), (0x120, Callee::Direct(0x800))], None);
        assert_eq!(classify([ends, other].into_iter(), &callees(&noreturn, &stubs, &slots, false)).terminal_calls, [0x10, 0x110]);
    }

    #[test]
    fn calls_through_a_slot_widen_only_where_the_platform_says_so() {
        let (noreturn, stubs, slots) = Default::default();
        let scans = || [calls(&[(0x10, Callee::Slot(0x900))], Some(0x10)), calls(&[(0x110, Callee::Slot(0x900))], None)].into_iter();
        assert_eq!(classify(scans(), &callees(&noreturn, &stubs, &slots, false)).terminal_calls, [0x10]);
        assert_eq!(classify(scans(), &callees(&noreturn, &stubs, &slots, true)).terminal_calls, [0x10, 0x110]);
    }

    #[test]
    fn cold_and_partial_pieces_and_erratum_veneers_are_fragments_but_clones_are_not() {
        for name in ["f.cold", "f.part.0", "f.constprop.0.cold", "e843419@0002_0000001c_14"] {
            assert!(is_fragment(name), "{name}");
        }
        for name in ["f", "f.isra.0", "f.constprop.0", "f.lto_priv.0", "cold"] {
            assert!(!is_fragment(name), "{name}");
        }
    }

    /// What [`dwarf_noreturn`] reads from a debug file with one unit, which `build` fills in.
    fn noreturn(build: impl FnOnce(&mut gimli::write::Unit)) -> NoReturn {
        let mut dwarf = DwarfUnit::new(Encoding { format: Format::Dwarf32, version: 4, address_size: 8 });
        build(&mut dwarf.unit);
        let mut sections = Sections::new(EndianVec::new(LittleEndian));
        dwarf.write(&mut sections).unwrap();
        let mut written = Vec::new();
        sections
            .for_each(|id, data| {
                written.push((id.name(), data.slice()));
                Ok::<_, ()>(())
            })
            .unwrap();
        let bytes = fixture::elf(Architecture::X86_64, &[0xc3], &[], &written);
        dwarf_noreturn(&object::File::parse(&*bytes).unwrap()).unwrap()
    }

    /// Adds a subprogram named `name` with `attributes`.
    fn subprogram(unit: &mut gimli::write::Unit, name: &str, attributes: &[(gimli::DwAt, AttributeValue)]) -> gimli::write::UnitEntryId {
        let id = unit.add(unit.root(), gimli::DW_TAG_subprogram);
        let entry = unit.get_mut(id);
        entry.set(gimli::DW_AT_name, AttributeValue::String(name.into()));
        for (at, value) in attributes {
            entry.set(*at, value.clone());
        }
        id
    }

    #[test]
    fn a_noreturn_definition_gives_its_name_and_address_and_an_external_declaration_its_name_for_imports() {
        let found = noreturn(|unit| {
            subprogram(unit, "die", &[(gimli::DW_AT_noreturn, AttributeValue::Flag(true)), (gimli::DW_AT_external, AttributeValue::Flag(true)), (gimli::DW_AT_low_pc, AttributeValue::Address(Address::Constant(0x40)))]);
            // The abstract instance of an inlined function has no address and declares nothing.
            subprogram(unit, "inlined", &[(gimli::DW_AT_noreturn, AttributeValue::Flag(true)), (gimli::DW_AT_external, AttributeValue::Flag(true))]);
            subprogram(unit, "abort", &[(gimli::DW_AT_noreturn, AttributeValue::Flag(true)), (gimli::DW_AT_declaration, AttributeValue::Flag(true)), (gimli::DW_AT_external, AttributeValue::Flag(true))]);
            subprogram(unit, "work", &[(gimli::DW_AT_low_pc, AttributeValue::Address(Address::Constant(0x80)))]);
        });
        assert_eq!((found.names, found.declared, found.addrs), (HashSet::from(["die".into(), "inlined".into()]), HashSet::from(["abort".into()]), HashSet::from([0x40])));
    }

    #[test]
    fn a_definition_never_returns_where_the_declaration_it_completes_says_so() {
        let found = noreturn(|unit| {
            let declaration = subprogram(unit, "fatal", &[(gimli::DW_AT_noreturn, AttributeValue::Flag(true)), (gimli::DW_AT_declaration, AttributeValue::Flag(true))]);
            let definition = unit.add(unit.root(), gimli::DW_TAG_subprogram);
            unit.get_mut(definition).set(gimli::DW_AT_specification, AttributeValue::UnitRef(declaration));
            unit.get_mut(definition).set(gimli::DW_AT_low_pc, AttributeValue::Address(Address::Constant(0x40)));
        });
        assert_eq!(found.addrs, HashSet::from([0x40]));
    }

    #[test]
    fn a_function_keeps_the_name_at_its_address_that_is_no_fragment_and_counts_without_a_size() {
        // `push rbp; ret` at 0, `ret` at 2 for a sizeless symbol, as `frame_dummy` is.
        let code = [0x55, 0xc3, 0xc3];
        for symbols in [[("f.cold", 0, 2), ("f", 0, 2), ("stub", 2, 0)], [("f", 0, 2), ("f.cold", 0, 2), ("stub", 2, 0)]] {
            let bytes = fixture::elf(Architecture::X86_64, &code, &symbols, &[]);
            let file = object::File::parse(&*bytes).unwrap();
            let truth = elf(Path::new("t"), &file, &file).unwrap();
            let functions: Vec<_> = truth.functions.iter().map(|f| (f.addr, f.name.as_str(), f.fragment)).collect();
            assert_eq!(functions, [(0, "f", false), (2, "stub", false)], "{symbols:?}");
            assert_eq!(truth.instructions, 2);
        }
    }
}
