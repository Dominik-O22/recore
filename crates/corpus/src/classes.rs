//! Scores the C++ classes recore recovers from Itanium type information against a copy of the
//! binary that still has its symbols.
//!
//! The symbol table gives the true classes: `_ZTV<class>` names each vtable group and
//! `_ZTI<class>` the type information its vtables point at, so the slots of the group that hold
//! that address are where its vtables begin. A class compiled without type information has a
//! group and no such slot; it is counted apart, since nothing in the image names it.
//!
//! DWARF, where the copy has it, gives what symbols cannot: each class's base classes, and for
//! the virtual functions a class declares, the vtable slot and the address of the definition.
//! Classes are matched by name, written the way the demangler writes them, so a class whose
//! name DWARF spells differently is left out of those two scores and counted as not comparable.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;

use anyhow::{Context, Result};
use object::{Object, ObjectSection, ObjectSymbol};
use rayon::prelude::*;
use recore::Image;
use recore::report::Class;

/// One class of the unstripped copy.
struct TrueClass {
    name: String,
    /// Where each vtable of its group begins, in address order: the first is the one objects
    /// of the class point at. Empty for a class without type information.
    vtables: Vec<u64>,
}

/// What DWARF says of a class, under its qualified name.
#[derive(Default, Clone, PartialEq)]
struct Described {
    /// Qualified names of its direct base classes.
    bases: Vec<String>,
    /// `(slot, address)` of each virtual function it declares and the image defines.
    slots: BTreeSet<(u64, u64)>,
}

#[derive(Default, Clone, Copy)]
struct Tally {
    /// Classes with a vtable and type information, and those recore reports at the right
    /// address under the right name.
    classes: usize,
    found: usize,
    /// Classes with a vtable and no type information.
    untyped: usize,
    /// Vtables of the classes with type information, and those recore reports.
    vtables: usize,
    vtables_found: usize,
    /// Vtables recore reports, and those that are not a class's vtable.
    reported: usize,
    wrong: usize,
    /// Found classes DWARF describes, and those whose base classes recore lists exactly.
    described: usize,
    bases_exact: usize,
    /// Virtual functions DWARF places in a slot of a found class, and those recore has there.
    slots: usize,
    slots_right: usize,
}

impl std::ops::AddAssign for Tally {
    fn add_assign(&mut self, other: Tally) {
        self.classes += other.classes;
        self.found += other.found;
        self.untyped += other.untyped;
        self.vtables += other.vtables;
        self.vtables_found += other.vtables_found;
        self.reported += other.reported;
        self.wrong += other.wrong;
        self.described += other.described;
        self.bases_exact += other.bases_exact;
        self.slots += other.slots;
        self.slots_right += other.slots_right;
    }
}

/// A name without the spacing that DWARF producers and the demangler choose differently.
fn normal(name: &str) -> String {
    name.replace(' ', "")
}

/// The classes the symbol table of `debug` names, with their vtables as `image` holds them.
fn true_classes(image: &Image, debug: &object::File) -> Vec<TrueClass> {
    let size = image.machine.pointer_size();
    // Mach-O puts an underscore before every symbol.
    let symbols: Vec<(String, u64, u64)> = debug
        .symbols()
        .filter(|symbol| symbol.is_definition() && symbol.address() != 0)
        .filter_map(|symbol| {
            let name = symbol.name().ok()?;
            let name = if debug.format() == object::BinaryFormat::MachO { name.strip_prefix('_')? } else { name };
            // A symbol with a version is the image's copy of a library's object, filled in at
            // load: `_ZTVSt9basic_iosIcSt11char_traitsIcEE@GLIBCXX_3.4`.
            if name.contains('@') {
                return None;
            }
            Some((name.to_string(), symbol.address(), symbol.size()))
        })
        .collect();
    // Link-time optimization renames a local class's symbols `_ZTV<class>.lto_priv.0`, and two
    // local classes of different files may share a name.
    let plain = |symbol: &'_ str| symbol.split('.').next().unwrap_or(symbol).to_string();
    let mut records: HashMap<String, Vec<u64>> = HashMap::new();
    for (name, addr, _) in &symbols {
        if let Some(mangled) = name.strip_prefix("_ZTI") {
            records.entry(plain(mangled)).or_default().push(*addr);
        }
    }
    // Mach-O symbols have no size: a vtable group runs to the next symbol.
    let addrs: BTreeSet<u64> = symbols.iter().map(|symbol| symbol.1).collect();
    let relocated: HashMap<u64, u64> = image.relative_targets.iter().copied().collect();
    let pointer = |slot: u64| {
        relocated.get(&slot).copied().or_else(|| {
            let bytes = image.bytes_from(slot)?.get(..size as usize)?;
            Some(bytes.iter().rev().fold(0, |value, &byte| value << 8 | u64::from(byte)))
        })
    };
    symbols
        .iter()
        .filter_map(|(symbol, addr, length)| {
            let mangled = plain(symbol.strip_prefix("_ZTV")?);
            let name = recore::itanium::type_name(&mangled);
            let end = if *length > 0 { addr + length } else { addrs.range(addr + 1..).next().copied().unwrap_or(*addr) };
            let is_record = |slot: u64| records.get(&mangled).zip(pointer(slot)).is_some_and(|(records, target)| records.contains(&target));
            let vtables = (*addr..end).step_by(size as usize).filter(|&slot| is_record(slot)).map(|slot| slot + size).collect();
            Some(TrueClass { name, vtables })
        })
        .collect()
}

/// What the DWARF of `debug` says of each class it defines that is not local to a function, by
/// its normalized qualified name. `None` for a name with two different descriptions.
fn described(debug: &object::File) -> Result<HashMap<String, Option<Described>>> {
    use gimli::{AttributeValue, DebugInfoOffset, EndianArcSlice, LittleEndian, Reader};
    let load = |id: gimli::SectionId| -> Result<EndianArcSlice<LittleEndian>> {
        let data = match debug.section_by_name(id.name()) {
            Some(section) => section.uncompressed_data()?.into_owned(),
            None => Vec::new(),
        };
        Ok(EndianArcSlice::new(data.into(), LittleEndian))
    };
    let dwarf = gimli::Dwarf::load(load)?;

    // Qualified name of each class, by where its entry is.
    let mut names: HashMap<DebugInfoOffset, String> = HashMap::new();
    // `(class, base class)` for each inheritance, in declaration order.
    let mut inherits: Vec<(DebugInfoOffset, DebugInfoOffset)> = Vec::new();
    // Declaration of a virtual function to its class and slot.
    let mut virtuals: HashMap<DebugInfoOffset, (DebugInfoOffset, u64)> = HashMap::new();
    // A function entry to the declaration or abstract instance it completes.
    let mut completes: HashMap<DebugInfoOffset, DebugInfoOffset> = HashMap::new();
    let mut entry_points: Vec<(DebugInfoOffset, u64)> = Vec::new();
    let mut classes: HashMap<DebugInfoOffset, Described> = HashMap::new();

    let mut units = dwarf.units();
    while let Some(header) = units.next()? {
        let unit = dwarf.unit(header)?;
        let global = |offset: gimli::UnitOffset| offset.to_debug_info_offset(&unit.header);
        let reference = |value: Option<AttributeValue<_>>| match value? {
            AttributeValue::UnitRef(offset) => global(offset),
            AttributeValue::DebugInfoRef(offset) => Some(offset),
            _ => None,
        };
        // The scopes around the current entry: depth, name, and the class it is if it is one.
        // A scope without a name is a function or block, whose classes are not scored.
        let mut scopes: Vec<(isize, Option<String>, Option<DebugInfoOffset>)> = Vec::new();
        let mut entries = unit.entries();
        while let Some(entry) = entries.next_dfs()? {
            let depth = entry.depth();
            scopes.truncate(scopes.partition_point(|scope| scope.0 < depth));
            let Some(offset) = global(entry.offset()) else { continue };
            let name = entry.attr_value(gimli::DW_AT_name).and_then(|value| Some(dwarf.attr_string(&unit, value).ok()?.to_string_lossy().ok()?.into_owned()));
            match entry.tag() {
                gimli::DW_TAG_namespace => scopes.push((depth, Some(name.unwrap_or_else(|| "(anonymous namespace)".to_string())), None)),
                gimli::DW_TAG_class_type | gimli::DW_TAG_structure_type | gimli::DW_TAG_union_type => {
                    let outer: Option<Vec<&str>> = scopes.iter().map(|scope| scope.1.as_deref()).collect();
                    let qualified = outer.zip(name).map(|(outer, name)| outer.into_iter().chain([name.as_str()]).collect::<Vec<_>>().join("::"));
                    if let Some(qualified) = &qualified {
                        names.insert(offset, qualified.clone());
                        if entry.attr_value(gimli::DW_AT_declaration).is_none() {
                            classes.entry(offset).or_default();
                        }
                    }
                    scopes.push((depth, qualified, Some(offset)));
                }
                gimli::DW_TAG_inheritance => {
                    let class = scopes.last().and_then(|scope| scope.2);
                    inherits.extend(class.zip(reference(entry.attr_value(gimli::DW_AT_type))));
                }
                gimli::DW_TAG_subprogram => {
                    // The slot is written as an expression that pushes one constant.
                    let slot = match entry.attr_value(gimli::DW_AT_vtable_elem_location) {
                        Some(AttributeValue::Exprloc(expression)) => {
                            let mut bytes = expression.0;
                            (bytes.read_u8().ok() == Some(gimli::DW_OP_constu.0)).then(|| bytes.read_uleb128().ok()).flatten()
                        }
                        _ => None,
                    };
                    // A destructor takes two slots, for two functions the entry does not
                    // tell apart.
                    let class = scopes.last().and_then(|scope| scope.2);
                    if let (Some(slot), Some(class), false) = (slot, class, name.is_some_and(|name| name.starts_with('~'))) {
                        virtuals.insert(offset, (class, slot));
                    }
                    for at in [gimli::DW_AT_specification, gimli::DW_AT_abstract_origin] {
                        if let Some(target) = reference(entry.attr_value(at)) {
                            completes.insert(offset, target);
                        }
                    }
                    let low_pc = match entry.attr_value(gimli::DW_AT_low_pc) {
                        Some(AttributeValue::Addr(addr)) => Some(addr),
                        Some(AttributeValue::DebugAddrIndex(index)) => dwarf.address(&unit, index).ok(),
                        _ => None,
                    };
                    entry_points.extend(low_pc.map(|addr| (offset, addr)));
                    scopes.push((depth, None, None));
                }
                gimli::DW_TAG_lexical_block | gimli::DW_TAG_inlined_subroutine => scopes.push((depth, None, None)),
                _ => {}
            }
        }
    }

    for (class, base) in inherits {
        // A base class DWARF does not name is one it does not define either.
        classes.entry(class).or_default().bases.push(names.get(&base).map_or_else(|| "?".to_string(), |name| normal(name)));
    }
    for (mut entry, addr) in entry_points {
        // A definition completes a declaration directly, or through an abstract instance.
        for _ in 0..3 {
            if let Some(&(class, slot)) = virtuals.get(&entry) {
                classes.entry(class).or_default().slots.insert((slot, addr));
            }
            let Some(&next) = completes.get(&entry) else { break };
            entry = next;
        }
    }
    // Each unit that uses a class describes it again, with the functions that unit defines.
    let mut by_name: HashMap<String, Option<Described>> = HashMap::new();
    for (offset, class) in classes {
        let Some(name) = names.get(&offset) else { continue };
        match by_name.entry(normal(name)).or_insert_with(|| Some(Described { bases: class.bases.clone(), slots: BTreeSet::new() })) {
            Some(known) if known.bases == class.bases => known.slots.extend(class.slots),
            ambiguous => *ambiguous = None,
        }
    }
    Ok(by_name)
}

/// Every base class of `name`, direct or not, or `None` if DWARF does not define the class or
/// one of those, or defines one twice.
fn all_bases(name: &str, described: &HashMap<String, Option<Described>>) -> Option<BTreeSet<String>> {
    let mut all = BTreeSet::new();
    let mut pending = vec![name.to_string()];
    while let Some(name) = pending.pop() {
        let class = described.get(&name)?.as_ref()?;
        pending.extend(class.bases.iter().filter(|base| all.insert((*base).clone())).cloned());
    }
    Some(all)
}

fn score_one(binary: &Path, debug_path: &Path, detail: bool) -> Result<Tally> {
    let image = Image::load(binary)?;
    let analysis = recore::analyze(&image);
    let data = std::fs::read(debug_path).with_context(|| format!("reading {debug_path:?}"))?;
    let debug = object::File::parse(&*data)?;
    let truth = true_classes(&image, &debug);
    let reported: BTreeMap<u64, &Class> = analysis.classes.iter().filter(|class| !class.objc).map(|class| (class.vtable, class)).collect();
    let name = binary.file_name().unwrap().to_string_lossy();

    let mut tally = Tally { reported: reported.len(), ..Tally::default() };
    let true_vtables: BTreeSet<u64> = truth.iter().flat_map(|class| class.vtables.iter().copied()).collect();
    for (addr, class) in reported.iter().filter(|(addr, _)| !true_vtables.contains(addr)) {
        tally.wrong += 1;
        if detail {
            println!("{name}: {addr:#x} reported as {} is not a class's vtable", class.name);
        }
    }
    let has_dwarf = debug.section_by_name(".debug_info").is_some();
    let described = if has_dwarf { described(&debug)? } else { HashMap::new() };
    for class in &truth {
        let Some(&first) = class.vtables.first() else {
            tally.untyped += 1;
            continue;
        };
        tally.classes += 1;
        tally.vtables += class.vtables.len();
        tally.vtables_found += class.vtables.iter().filter(|addr| reported.contains_key(addr)).count();
        let Some(found) = reported.get(&first).filter(|found| found.name == class.name) else {
            if detail {
                println!("{name}: {} at {first:#x} missing{}", class.name, reported.get(&first).map_or_else(String::new, |found| format!(", reported as {}", found.name)));
            }
            continue;
        };
        tally.found += 1;
        let key = normal(&class.name);
        if let Some(bases) = all_bases(&key, &described) {
            tally.described += 1;
            let listed: BTreeSet<String> = found.bases.iter().map(|base| normal(base)).collect();
            tally.bases_exact += usize::from(listed == bases);
            if detail && listed != bases {
                println!("{name}: {} bases {listed:?}, DWARF {bases:?}", class.name);
            }
        }
        // Two functions DWARF puts in one slot are the same function under two names, or two
        // classes of one name in different files; either is right.
        let slots: BTreeMap<u64, Vec<u64>> = described.get(&key).into_iter().flatten().flat_map(|class| &class.slots).fold(BTreeMap::new(), |mut slots, &(slot, addr)| {
            slots.entry(slot).or_default().push(addr);
            slots
        });
        for (slot, addrs) in slots {
            tally.slots += 1;
            let right = found.methods.get(slot as usize).is_some_and(|method| addrs.contains(method));
            tally.slots_right += usize::from(right);
            if detail && !right {
                println!("{name}: {} slot {slot} is {:x?}, DWARF {addrs:x?}", class.name, found.methods.get(slot as usize));
            }
        }
    }
    Ok(tally)
}

/// Scores every binary of `corpus` whose unstripped copy names a C++ class.
pub fn score(corpus: &Path, detail: bool) -> Result<()> {
    let rows: Vec<(String, Result<Tally>)> = crate::binaries(corpus)?
        .par_iter()
        .map(|binary| {
            let name = binary.file_name().unwrap().to_string_lossy().into_owned();
            let tally = score_one(binary, &crate::debug_file(corpus, &name), detail);
            (name, tally)
        })
        .collect();
    let line = |label: &str, t: &Tally| {
        println!(
            "{label:28} classes {}/{} (+{} without type information)  vtables {}/{}  reported {} ({} not a vtable)  bases {}/{} exact  slots {}/{}",
            t.found, t.classes, t.untyped, t.vtables_found, t.vtables, t.reported, t.wrong, t.bases_exact, t.described, t.slots_right, t.slots,
        );
    };
    let mut total = Tally::default();
    let mut scored = 0;
    for (name, tally) in rows {
        match tally {
            Ok(tally) if tally.classes + tally.untyped + tally.reported > 0 => {
                line(&name, &tally);
                total += tally;
                scored += 1;
            }
            Ok(_) => {}
            Err(error) => eprintln!("skip {name}: {error:#}"),
        }
    }
    line(&format!("{} ({scored} with classes)", corpus.display()), &total);
    Ok(())
}
