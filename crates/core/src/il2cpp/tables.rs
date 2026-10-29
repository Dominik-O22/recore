//! Finding the tables an IL2CPP binary registers with the runtime, which it does not name.

use rustc_hash::{FxHashMap, FxHashSet};

use super::Words;
use super::metadata::{self, Metadata};

/// Fields of the metadata registration, by offset in it.
mod registration {
    pub const GENERIC_INSTS_COUNT: u64 = 0x10;
    pub const GENERIC_METHOD_TABLE_COUNT: u64 = 0x20;
    pub const TYPES_COUNT: u64 = 0x30;
    pub const METHOD_SPECS_COUNT: u64 = 0x40;
    pub const FIELD_OFFSETS_COUNT: u64 = 0x50;
    pub const FIELD_OFFSETS: u64 = 0x58;
    pub const TYPE_SIZES: u64 = 0x68;
}

/// Fields of a code registration and a code generation module, by offset.
pub(super) mod code {
    pub const GENERIC_METHOD_POINTERS_COUNT: u64 = 0x10;
    pub const GENERIC_METHOD_POINTERS: u64 = 0x18;
    /// From the module list's count.
    pub const MODULES_COUNT: u64 = 0x78;
    pub const MODULE_METHOD_COUNT: u64 = 0x8;
    pub const MODULE_METHODS: u64 = 0x10;
}

/// Where the binary keeps the tables the runtime reads, besides each method's code.
#[derive(Debug, PartialEq)]
pub(super) struct Tables {
    /// `Il2CppType *` by type index, and how many.
    pub(super) types: (u64, u64),
    /// By type definition: a pointer to the offsets of its fields, null for a type without.
    pub(super) field_offsets: Option<u64>,
    /// By type definition: a pointer to its instance, native, static and thread-static sizes.
    pub(super) sizes: Option<u64>,
    /// `Il2CppGenericInst *` by index: a count of type arguments and a pointer to them.
    pub(super) generic_insts: Option<(u64, u64)>,
    /// Method instances: a method definition, the instance of its class's type arguments and
    /// that of its own, 12 bytes each.
    pub(super) method_specs: Option<(u64, u64)>,
    /// Compiled method instances: the method instance, the index of its code, an invoker and an
    /// adjustor thunk, 16 bytes each.
    pub(super) generic_method_table: Option<(u64, u64)>,
    /// The code of compiled method instances, by index.
    pub(super) generic_method_pointers: Option<(u64, u64)>,
}

impl Tables {
    /// The tables of version 39, which the metadata and code registrations point to.
    pub(super) fn registered(words: &Words, metadata: &Metadata, modules: &[(usize, u64)]) -> Option<Tables> {
        let registration = find_registration(words, metadata.types.len() as u64)?;
        let field = |offset: u64| words.pointer(registration + offset);
        let counted = |offset: u64| Some((field(offset + 8)?, words.u64(registration + offset)?));
        let code = code_registration(words, metadata, modules);
        Some(Tables {
            types: counted(registration::TYPES_COUNT)?,
            field_offsets: field(registration::FIELD_OFFSETS),
            sizes: field(registration::TYPE_SIZES),
            generic_insts: counted(registration::GENERIC_INSTS_COUNT),
            method_specs: counted(registration::METHOD_SPECS_COUNT),
            generic_method_table: counted(registration::GENERIC_METHOD_TABLE_COUNT),
            generic_method_pointers: code
                .and_then(|code| Some((words.pointer(code + code::GENERIC_METHOD_POINTERS)?, words.u64(code + code::GENERIC_METHOD_POINTERS_COUNT)?))),
        })
    }

    /// The tables of version 107, which nothing in data points to: the runtime refers to each
    /// directly. Each is found by what it holds.
    pub(super) fn discovered(words: &Words, metadata: &Metadata) -> Option<Tables> {
        let runs = relocated_runs(words);
        let count = metadata.types.len() as u64;
        let types = find_types(words, metadata, &runs)?;
        // One size record per type definition, and every type has one.
        let sizes = runs
            .iter()
            .find(|&&(start, length)| length == count && words.pointer(start).and_then(|record| words.u32(record)).is_some_and(|size| size > 0))
            .map(|&(start, _)| start);
        let field_offsets = find_field_offsets(words, metadata);
        let generic_insts = runs
            .iter()
            .filter(|&&(start, length)| length > 16 && (0..16).all(|index| words.pointer(start + 8 * index).is_some_and(|inst| is_generic_inst(words, inst))))
            .max_by_key(|&&(_, length)| length)
            .copied();
        let method_specs = generic_insts.and_then(|(_, insts)| find_method_specs(words, metadata, insts));
        let generic_method_table = method_specs.and_then(|(specs, spec_count)| {
            // The table of compiled instances ends where the method instances start. Its rows
            // name an instance each, and it begins after the last size record, or failing that
            // at the first row that cannot be one.
            let size_records: FxHashSet<u64> =
                sizes.map_or_else(FxHashSet::default, |sizes| (0..count).filter_map(|index| words.entry(sizes, index)).collect());
            let mut start = specs;
            while start >= 16 && !size_records.contains(&(start - 16)) {
                let row = |at: u64| words.u32(start - 16 + at).map(|value| value as i32);
                let (Some(spec), Some(code), Some(invoker), Some(adjustor)) = (row(0), row(4), row(8), row(12)) else {
                    break;
                };
                if spec < 0 || spec as u64 >= spec_count || code < 0 || invoker < -1 || adjustor < -1 {
                    break;
                }
                start -= 16;
            }
            (start < specs).then_some((start, (specs - start) / 16))
        });
        let generic_method_pointers = generic_method_table.and_then(|(table, rows)| {
            let needed = (0..rows).filter_map(|row| words.u32(table + 16 * row + 4)).max()? as u64 + 1;
            // An array of code in which an instance the build left out is null.
            let is_code_or_null = |slot: u64| match words.relocated.get(&slot) {
                Some(&target) => words.image.is_code(target),
                None => words.u64(slot) == Some(0),
            };
            // Index 0 is no code, so the array opens with a null; the stretch of code that follows
            // is the one closest to the length the table needs.
            let mut stretches = Vec::new();
            for &(start, _) in runs
                .iter()
                .filter(|&&(start, _)| start >= 8 && words.u64(start - 8) == Some(0) && words.pointer(start).is_some_and(|code| words.image.is_code(code)))
            {
                if stretches.last().is_none_or(|&(array, length): &(u64, u64)| start >= array + 8 * length) {
                    stretches.push((start - 8, 1 + (0..).take_while(|&index| is_code_or_null(start + 8 * index)).count() as u64));
                }
            }
            stretches.into_iter().filter(|&(_, length)| length >= needed).min_by_key(|&(_, length)| length).map(|(array, _)| (array, needed))
        });
        Some(Tables { types, field_offsets, sizes, generic_insts, method_specs, generic_method_table, generic_method_pointers })
    }
}

/// Runs of consecutive relocated pointers, as `(first slot, count)`.
fn relocated_runs(words: &Words) -> Vec<(u64, u64)> {
    let mut slots: Vec<u64> = words.relocated.keys().copied().collect();
    slots.sort_unstable();
    let mut runs: Vec<(u64, u64)> = Vec::new();
    for slot in slots {
        match runs.last_mut() {
            Some((start, length)) if *start + 8 * *length == slot => *length += 1,
            _ => runs.push((slot, 1)),
        }
    }
    runs
}

/// The type table, found by the entry for each type definition's own type, which points to a
/// type record whose data is that definition's index.
fn find_types(words: &Words, metadata: &Metadata, runs: &[(u64, u64)]) -> Option<(u64, u64)> {
    let count = metadata.types.len() as u64;
    let mut votes: FxHashMap<u64, u32> = FxHashMap::default();
    for (&slot, &record) in &words.relocated {
        let (Some(data), Some(bits)) = (words.u64(record), words.u32(record + 8)) else {
            continue;
        };
        if data >= count || !matches!((bits >> 16) & 0xff, 0x11 | 0x12) || bits & (1 << 29) != 0 {
            continue;
        }
        if let Some(byval) = metadata.types.get(data as usize).and_then(|def| def.byval) {
            *votes.entry(slot.wrapping_sub(8 * u64::from(byval))).or_default() += 1;
        }
    }
    let (&table, _) = votes.iter().max_by_key(|&(&table, &votes)| (votes, std::cmp::Reverse(table)))?;
    let &(start, length) = runs.iter().find(|&&(start, length)| start <= table && table < start + 8 * length)?;
    Some((table, length - (table - start) / 8))
}

/// The field offset table: by type definition, a pointer for each type with fields and null
/// for each without.
fn find_field_offsets(words: &Words, metadata: &Metadata) -> Option<u64> {
    let has_fields: Vec<bool> = metadata.types.iter().map(|def| def.field_count > 0).collect();
    let first = has_fields.iter().position(|&has| has)? as u64;
    let matches = |table: u64, step: usize| {
        has_fields.iter().enumerate().step_by(step).all(|(index, &has)| words.relocated.contains_key(&(table + 8 * index as u64)) == has)
    };
    words.relocated.keys().map(|&slot| slot.wrapping_sub(8 * first)).find(|&table| matches(table, 97) && matches(table, 1))
}

/// Whether `inst` holds a generic instance: a count of type arguments and a pointer to them.
fn is_generic_inst(words: &Words, inst: u64) -> bool {
    // The pointer is relocated, which the second word of a type record never is.
    words.u32(inst).is_some_and(|count| (1..=32).contains(&count)) && words.relocated.contains_key(&(inst + 8))
}

/// The method instances: rows each of a method definition, the instance of its class's type
/// arguments where the class is generic, and that of its own where the method is.
fn find_method_specs(words: &Words, metadata: &Metadata, insts: u64) -> Option<(u64, u64)> {
    let generic_owner = |method: &metadata::MethodDefinition| {
        method.declaring.and_then(|owner| metadata.types.get(owner as usize)).is_some_and(|owner| owner.generic_container.is_some())
    };
    let valid = |at: u64| -> Option<bool> {
        let row = |offset: u64| words.u32(at + offset).map(|value| value as i32);
        let (method, class, own) = (row(0)?, row(4)?, row(8)?);
        let method = metadata.methods.get(usize::try_from(method).ok()?)?;
        let fits = |inst: i32| inst >= -1 && i64::from(inst) < insts as i64;
        Some(fits(class) && fits(own) && (class >= 0 || own >= 0) && (class < 0 || generic_owner(method)) && (own < 0 || method.generic_container.is_some()))
    };
    let mut best: Option<(u64, u64)> = None;
    for section in words.image.sections.iter().filter(|section| !section.executable && !section.writable) {
        for phase in (0..12).step_by(4) {
            let mut run: Option<(u64, u64)> = None;
            for at in (section.addr + phase..section.end().saturating_sub(12)).step_by(12) {
                if valid(at) == Some(true) {
                    let (start, length) = run.get_or_insert((at, 0));
                    *length += 1;
                    if best.is_none_or(|(_, longest)| *length > longest) {
                        best = Some((*start, *length));
                    }
                } else {
                    run = None;
                }
            }
        }
    }
    best.filter(|&(_, length)| length >= 16)
}

/// Each code generation module with the index of its image, found by the pointer to the
/// image's name that opens it, and checked by its count of methods.
pub(super) fn find_modules(words: &Words, metadata: &Metadata) -> Vec<(usize, u64)> {
    let images: FxHashMap<&str, usize> = metadata.images.iter().enumerate().map(|(index, image)| (image.name.as_str(), index)).collect();
    let mut found: FxHashMap<usize, u64> = FxHashMap::default();
    for (&slot, &target) in &words.relocated {
        let Some(&image) = words.text(target).and_then(|name| images.get(name)) else {
            continue;
        };
        let methods = image_methods(metadata, image);
        let count = words.u32(slot + code::MODULE_METHOD_COUNT).unwrap_or(0) as usize;
        if count >= methods / 2 && count <= methods.max(1) * 2 && words.pointer(slot + code::MODULE_METHODS).is_some() {
            found.insert(image, slot);
        }
    }
    let mut modules: Vec<(usize, u64)> = found.into_iter().collect();
    modules.sort_unstable();
    modules
}

fn image_methods(metadata: &Metadata, image: usize) -> usize {
    let Some(image) = metadata.images.get(image) else {
        return 0;
    };
    let start = image.type_start.unwrap_or(0) as usize;
    metadata.types.iter().skip(start).take(image.type_count as usize).map(|def| usize::from(def.method_count)).sum()
}

/// The code registration of version 39: what holds the count of modules and then the list of
/// them, before which it lists the code of generic method instances.
fn code_registration(words: &Words, metadata: &Metadata, modules: &[(usize, u64)]) -> Option<u64> {
    let is_module: FxHashSet<u64> = modules.iter().map(|&(_, module)| module).collect();
    let &(_, first) = modules.first()?;
    let listed = words.relocated.iter().find(|&(_, &target)| target == first).map(|(&slot, _)| slot)?;
    // The first module found need not be the first listed; step back to the list's start.
    let mut start = listed;
    while start >= 8 && words.pointer(start - 8).is_some_and(|module| is_module.contains(&module)) {
        start -= 8;
    }
    let field = words.relocated.iter().find(|&(_, &target)| target == start).map(|(&slot, _)| slot)?;
    let count = field.checked_sub(8)?;
    (words.u64(count)? as usize == metadata.images.len()).then(|| count.checked_sub(code::MODULES_COUNT)).flatten()
}

/// The metadata registration, found by its counts of field offset arrays and of type sizes,
/// which are next to each other and each the number of type definitions.
fn find_registration(words: &Words, type_count: u64) -> Option<u64> {
    words
        .image
        .sections
        .iter()
        .filter(|section| !section.executable)
        .find_map(|section| {
            let start = section.addr.next_multiple_of(8);
            (start..section.end().saturating_sub(32)).step_by(8).find(|&at| {
                words.u64(at) == Some(type_count)
                    && words.u64(at + 16) == Some(type_count)
                    && words.pointer(at + 8).is_some()
                    && words.pointer(at + 24).is_some()
            })
        })
        .map(|at| at - registration::FIELD_OFFSETS_COUNT)
}
