//! What DWARF debug information says about a program: the parameter counts that signature
//! comparisons are scored against, and the data types the decompiler is given.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;

use anyhow::{Context, Result};
use object::{Object, ObjectSection, ObjectSymbol};
use recore::image::Machine;

use crate::types::{Base, Field, Global, Named, Prototype, Type, TypeId, Types, VOID};

/// What the debug info says about one function.
#[derive(Debug, Clone)]
pub struct Function {
    /// Source-level parameters: `DW_TAG_formal_parameter` children of the `DW_TAG_subprogram`.
    pub params: usize,
    pub variadic: bool,
}

/// The parts of a debug file that signature comparisons need.
#[derive(Debug, Default)]
pub struct DebugInfo {
    /// Every `DW_TAG_subprogram` that has a `DW_AT_low_pc`, by that address.
    pub functions: BTreeMap<u64, Function>,
    /// Names of all code symbols, including pieces like `foo.cold` that have no subprogram entry.
    pub symbols: BTreeMap<u64, String>,
}

impl DebugInfo {
    pub fn load(path: &Path) -> Result<DebugInfo> {
        use gimli::{EndianArcSlice, LittleEndian};
        let data = std::fs::read(path).with_context(|| format!("reading {path:?}"))?;
        let debug = object::File::parse(&*data)?;
        let symbols = debug
            .symbols()
            .filter(|s| s.kind() == object::SymbolKind::Text)
            .filter_map(|s| Some((s.address(), s.name().ok()?.to_string())))
            .collect();
        let dwarf = gimli::Dwarf::load(|id| -> Result<_> {
            let data = match debug.section_by_name(id.name()) {
                Some(section) => section.uncompressed_data()?.into_owned(),
                None => Vec::new(),
            };
            Ok(EndianArcSlice::new(data.into(), LittleEndian))
        })?;

        let mut functions = BTreeMap::new();
        let mut units = dwarf.units();
        while let Some(header) = units.next()? {
            let unit = dwarf.unit(header)?;
            // Subprograms enclosing the current entry, as (depth, address); the address is `None`
            // for declarations and abstract instances, whose parameters do not count.
            let mut open: Vec<(isize, Option<u64>)> = Vec::new();
            let mut entries = unit.entries();
            while let Some(entry) = entries.next_dfs()? {
                while open.last().is_some_and(|&(depth, _)| entry.depth() <= depth) {
                    open.pop();
                }
                match entry.tag() {
                    gimli::DW_TAG_subprogram => {
                        let addr = match entry.attr_value(gimli::DW_AT_low_pc) {
                            Some(gimli::AttributeValue::Addr(addr)) => Some(addr),
                            Some(gimli::AttributeValue::DebugAddrIndex(index)) => dwarf.address(&unit, index).ok(),
                            _ => None,
                        }
                        .filter(|&addr| addr != 0);
                        if let Some(addr) = addr {
                            functions.insert(addr, Function { params: 0, variadic: false });
                        }
                        open.push((entry.depth(), addr));
                    }
                    // Only direct children: deeper ones belong to inlined callees.
                    tag @ (gimli::DW_TAG_formal_parameter | gimli::DW_TAG_unspecified_parameters) => {
                        if let Some(&(_, Some(addr))) = open.last().filter(|&&(depth, _)| entry.depth() == depth + 1) {
                            let function = functions.get_mut(&addr).expect("inserted when opened");
                            if tag == gimli::DW_TAG_formal_parameter {
                                function.params += 1;
                            } else {
                                function.variadic = true;
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        Ok(DebugInfo { functions, symbols })
    }
}

type Slice<'a> = gimli::EndianSlice<'a, gimli::LittleEndian>;

/// One entry of the debug information: the index of its unit and its offset in that unit.
type Die = (usize, gimli::UnitOffset);

/// A namespace or class: the offsets of its entry and of the first entry after its last child,
/// its qualified name with a trailing `::`, and the scope it is in.
struct Scope {
    start: usize,
    end: usize,
    prefix: String,
    parent: Option<usize>,
}

/// Reads the types that the functions and globals of a debug file are declared with. Only
/// those: a program's debug information describes every type of every header it includes, in
/// every unit again, and most are never used by anything that has an address.
struct Reader<'a> {
    dwarf: gimli::Dwarf<Slice<'a>>,
    units: Vec<gimli::Unit<Slice<'a>>>,
    /// Per unit, where it starts in `.debug_info`, for references from one unit into another.
    starts: Vec<usize>,
    /// Per unit, its namespaces and classes in the order they start.
    scopes: Vec<Vec<Scope>>,
    /// The type each entry read so far became.
    seen: HashMap<Die, TypeId>,
    /// Structs and unions whose members are still to be read. Reading them later, not where
    /// the struct is first met, keeps the recursion as shallow as a chain of pointers.
    pending: Vec<(TypeId, Die)>,
    /// Classes that C++ passes and returns through a pointer even where the source says by
    /// value, because copying one runs code: the ones the compiler marks, and the ones with a
    /// destructor.
    by_reference: HashSet<TypeId>,
    types: Types,
}

/// The types, function prototypes and globals in the DWARF of the file at `path`, which is a
/// binary or a separate debug file, for code of `machine`.
pub fn types(path: &Path, machine: Machine) -> Result<Types> {
    let pointer = if machine == Machine::X86 { 4 } else { 8 };
    let data = std::fs::read(path).with_context(|| format!("reading {path:?}"))?;
    let file = object::File::parse(&*data)?;
    // Debian compresses these sections, and unpacking them is then most of the work: only the
    // ones that describe types are unpacked, not variable locations or macros, and each on a
    // thread of its own. The line table is among them because a unit cannot be opened without.
    const NEEDED: [gimli::SectionId; 9] = [
        gimli::SectionId::DebugLine,
        gimli::SectionId::DebugInfo,
        gimli::SectionId::DebugAbbrev,
        gimli::SectionId::DebugStr,
        gimli::SectionId::DebugLineStr,
        gimli::SectionId::DebugStrOffsets,
        gimli::SectionId::DebugAddr,
        gimli::SectionId::DebugRanges,
        gimli::SectionId::DebugRngLists,
    ];
    let unpack = |id: gimli::SectionId| {
        // Mach-O spells `.debug_info` as `__debug_info`.
        let section = file.section_by_name(id.name()).or_else(|| file.section_by_name(&id.name().replacen('.', "__", 1)));
        section.and_then(|section| section.uncompressed_data().ok()).unwrap_or_default()
    };
    let mut unpacked: Vec<std::borrow::Cow<[u8]>> = std::thread::scope(|scope| {
        let threads: Vec<_> = NEEDED.iter().map(|&id| scope.spawn(move || unpack(id))).collect();
        threads.into_iter().map(|thread| thread.join().expect("unpacking does not panic")).collect()
    });
    let sections = gimli::DwarfSections::load(|id| -> Result<std::borrow::Cow<[u8]>> {
        Ok(NEEDED.iter().position(|&needed| needed == id).map(|index| std::mem::take(&mut unpacked[index])).unwrap_or_default())
    })?;
    let dwarf = sections.borrow(|section| gimli::EndianSlice::new(section, gimli::LittleEndian));
    // The compiler's copies of a function that take other parameters than the source says.
    let clones: HashSet<u64> = file.symbols().filter(|symbol| symbol.name().is_ok_and(|name| [".isra.", ".constprop.", ".part."].iter().any(|mark| name.contains(mark)))).map(|symbol| symbol.address()).collect();

    // Walking every entry is most of the work, and each unit can be walked on its own.
    let mut headers = Vec::new();
    let mut walk = dwarf.units();
    while let Some(header) = walk.next()? {
        headers.push(header);
    }
    let next = std::sync::atomic::AtomicUsize::new(0);
    let workers = std::thread::available_parallelism().map_or(1, usize::from).min(8);
    let mut surveyed: Vec<(usize, gimli::Unit<Slice>, Survey)> = std::thread::scope(|scope| {
        let work = || {
            let mut done = Vec::new();
            while let Some(header) = headers.get(next.fetch_add(1, std::sync::atomic::Ordering::Relaxed)) {
                let Some(start) = header.debug_info_offset() else { continue };
                let Ok(unit) = dwarf.unit(*header) else { continue };
                let mut survey = Survey::default();
                // A unit that cannot be read to its end still gave what came before.
                let _ = survey.walk(&dwarf, &unit);
                done.push((start.0, unit, survey));
            }
            done
        };
        let threads: Vec<_> = (0..workers).map(|_| scope.spawn(work)).collect();
        threads.into_iter().flat_map(|thread| thread.join().expect("the survey does not panic")).collect()
    });
    surveyed.sort_by_key(|unit| unit.0);

    let mut reader = Reader { dwarf, units: Vec::new(), starts: Vec::new(), scopes: Vec::new(), seen: HashMap::new(), pending: Vec::new(), by_reference: HashSet::new(), types: Types::new(pointer) };
    let (mut functions, mut globals) = (Vec::new(), Vec::new());
    for (index, (start, unit, survey)) in surveyed.into_iter().enumerate() {
        reader.starts.push(start);
        reader.units.push(unit);
        reader.scopes.push(survey.scopes);
        functions.extend(survey.functions.into_iter().map(|(offset, addr)| ((index, offset), addr)));
        globals.extend(survey.globals.into_iter().map(|(offset, addr)| ((index, offset), addr)));
    }
    for (die, addr) in functions {
        if !clones.contains(&addr) {
            reader.function(die, addr);
        }
    }
    for (die, addr) in globals {
        reader.global(die, addr);
    }
    while let Some((id, die)) = reader.pending.pop() {
        reader.members(id, die);
    }
    reader.as_passed(machine);
    reader.types.finish();
    Ok(reader.types)
}

/// What one unit holds that the reader starts from: its scopes in the order they start, and
/// the functions and variables that have an address, each by offset in the unit.
#[derive(Default)]
struct Survey {
    scopes: Vec<Scope>,
    functions: Vec<(gimli::UnitOffset, u64)>,
    globals: Vec<(gimli::UnitOffset, u64)>,
}

impl Survey {
    /// Walks every entry of `unit` once. Only scopes, functions and variables have their
    /// attributes read; everything else, which is nearly everything, is skipped over.
    fn walk<'a>(&mut self, dwarf: &gimli::Dwarf<Slice<'a>>, unit: &gimli::Unit<Slice<'a>>) -> gimli::Result<()> {
        // The scopes around the current entry, as (depth, index into `scopes`).
        let mut open: Vec<(isize, usize)> = Vec::new();
        let mut attrs = Vec::new();
        let mut entries = unit.entries_raw(None)?;
        while !entries.is_empty() {
            let (offset, depth) = (entries.next_offset(), entries.next_depth());
            // An entry of code 0 only ends a list of children.
            let Some(abbreviation) = entries.read_abbreviation()? else { continue };
            while let Some(&(_, scope)) = open.last().filter(|scope| depth <= scope.0) {
                self.scopes[scope].end = offset.0;
                open.pop();
            }
            let tag = abbreviation.tag();
            let scope = matches!(tag, gimli::DW_TAG_namespace | gimli::DW_TAG_structure_type | gimli::DW_TAG_class_type | gimli::DW_TAG_union_type) && abbreviation.has_children();
            if !scope && !matches!(tag, gimli::DW_TAG_subprogram | gimli::DW_TAG_variable) {
                entries.skip_attributes(abbreviation.attributes())?;
                continue;
            }
            entries.read_attributes(abbreviation.attributes(), &mut attrs)?;
            let value = |name| attrs.iter().find(|attr| attr.name() == name).map(|attr| attr.value());
            match tag {
                gimli::DW_TAG_subprogram => {
                    let addr = match (value(gimli::DW_AT_low_pc), value(gimli::DW_AT_ranges)) {
                        (Some(low), _) => dwarf.attr_address(unit, low).ok().flatten(),
                        // A function in several pieces lists them, the entry first.
                        (None, Some(ranges)) => dwarf.attr_ranges(unit, ranges).ok().flatten().and_then(|mut ranges| ranges.next().ok().flatten()).map(|range| range.begin),
                        (None, None) => None,
                    };
                    if let Some(addr) = addr.filter(|&addr| addr != 0) {
                        self.functions.push((offset, addr));
                    }
                }
                gimli::DW_TAG_variable => {
                    // Only a variable at one fixed address: `DW_OP_addr` and nothing else.
                    if let Some(gimli::AttributeValue::Exprloc(location)) = value(gimli::DW_AT_location) {
                        let mut operations = location.operations(unit.encoding());
                        let addr = match operations.next() {
                            Ok(Some(gimli::Operation::Address { address })) => Some(address),
                            Ok(Some(gimli::Operation::AddressIndex { index })) => dwarf.address(unit, index).ok(),
                            _ => None,
                        };
                        if let (Some(addr), Ok(None)) = (addr.filter(|&addr| addr != 0), operations.next()) {
                            self.globals.push((offset, addr));
                        }
                    }
                }
                _ => {
                    let parent = open.last().map(|scope| scope.1);
                    let name = value(gimli::DW_AT_name).and_then(|name| dwarf.attr_string(unit, name).ok());
                    let mut prefix = parent.map_or_else(String::new, |parent| self.scopes[parent].prefix.clone());
                    match name {
                        Some(name) => prefix.extend([&*name.to_string_lossy(), "::"]),
                        None if tag == gimli::DW_TAG_namespace => prefix.push_str("(anonymous namespace)::"),
                        // What an unnamed struct holds is named as if it were outside it.
                        None => {}
                    }
                    open.push((depth, self.scopes.len()));
                    self.scopes.push(Scope { start: offset.0, end: usize::MAX, prefix, parent });
                }
            }
        }
        Ok(())
    }
}

impl<'a> Reader<'a> {
    fn entry(&self, die: Die) -> Option<gimli::DebuggingInformationEntry<Slice<'a>>> {
        self.units[die.0].entry(die.1).ok()
    }

    /// The entry an attribute of an entry in unit `unit` refers to.
    fn reference(&self, unit: usize, value: gimli::AttributeValue<Slice<'a>>) -> Option<Die> {
        match value {
            gimli::AttributeValue::UnitRef(offset) => Some((unit, offset)),
            gimli::AttributeValue::DebugInfoRef(offset) => {
                let unit = self.starts.partition_point(|&start| start <= offset.0).checked_sub(1)?;
                Some((unit, offset.to_unit_offset(&self.units[unit].header)?))
            }
            _ => None,
        }
    }

    /// An attribute of the entry at `die`, or failing that of the entry it is an instance or
    /// the definition of, with the unit it was found in.
    fn attr(&self, mut die: Die, name: gimli::DwAt) -> Option<(usize, gimli::AttributeValue<Slice<'a>>)> {
        for _ in 0..4 {
            let entry = self.entry(die)?;
            if let Some(value) = entry.attr_value(name) {
                return Some((die.0, value));
            }
            let origin = entry.attr_value(gimli::DW_AT_abstract_origin).or_else(|| entry.attr_value(gimli::DW_AT_specification))?;
            die = self.reference(die.0, origin)?;
        }
        None
    }

    /// The entry that declares what the entry at `die` is an instance or the definition of:
    /// the one that has the name and is in the scope the name belongs to.
    fn declaration(&self, mut die: Die) -> Die {
        for _ in 0..4 {
            let Some(entry) = self.entry(die) else { break };
            let Some(origin) = entry.attr_value(gimli::DW_AT_abstract_origin).or_else(|| entry.attr_value(gimli::DW_AT_specification)) else { break };
            let Some(origin) = self.reference(die.0, origin) else { break };
            die = origin;
        }
        die
    }

    /// The name of the entry at `die` with the namespaces and classes it is declared in, or
    /// the empty string if it has no name.
    fn qualified(&self, die: Die) -> String {
        let die = self.declaration(die);
        let Some(name) = self.entry(die).and_then(|entry| entry.attr_value(gimli::DW_AT_name)).and_then(|name| self.dwarf.attr_string(&self.units[die.0], name).ok()) else {
            return String::new();
        };
        let scopes = &self.scopes[die.0];
        // The last scope that starts before the entry holds it, or one of the scopes around
        // that one does.
        let mut scope = scopes.partition_point(|scope| scope.start < die.1.0).checked_sub(1);
        while let Some(index) = scope.filter(|&index| scopes[index].end <= die.1.0) {
            scope = scopes[index].parent;
        }
        format!("{}{}", scope.map_or("", |index| &scopes[index].prefix), name.to_string_lossy())
    }

    /// The type the entry at `die` says it has, or `void`.
    fn type_of(&mut self, die: Die) -> TypeId {
        match self.attr(die, gimli::DW_AT_type).and_then(|(unit, value)| self.reference(unit, value)) {
            Some(target) => self.resolve(target),
            None => VOID,
        }
    }

    /// The type the entry at `die` describes.
    fn resolve(&mut self, die: Die) -> TypeId {
        if let Some(&id) = self.seen.get(&die) {
            return id;
        }
        let Some(entry) = self.entry(die) else { return VOID };
        let number = |name| entry.attr(name).and_then(|attr| attr.udata_value());
        let id = match entry.tag() {
            gimli::DW_TAG_base_type => {
                let base = match entry.attr_value(gimli::DW_AT_encoding) {
                    Some(gimli::AttributeValue::Encoding(gimli::DW_ATE_float)) => Base::Float,
                    Some(gimli::AttributeValue::Encoding(gimli::DW_ATE_boolean)) => Base::Bool,
                    Some(gimli::AttributeValue::Encoding(gimli::DW_ATE_signed_char | gimli::DW_ATE_UTF | gimli::DW_ATE_ASCII)) => Base::Char,
                    Some(gimli::AttributeValue::Encoding(gimli::DW_ATE_signed)) => Base::Int,
                    _ => Base::Uint,
                };
                // A number of no size, as Rust's `()` is, holds nothing.
                match number(gimli::DW_AT_byte_size) {
                    Some(size) if size > 0 => self.types.add(Type::Base { base, size }),
                    _ => VOID,
                }
            }
            gimli::DW_TAG_pointer_type | gimli::DW_TAG_reference_type | gimli::DW_TAG_rvalue_reference_type => {
                // Entered before its target is read, which may be a function type that takes
                // this very pointer.
                let id = self.types.add(Type::Pointer(VOID));
                self.seen.insert(die, id);
                let target = self.type_of(die);
                self.types.types[id as usize] = Type::Pointer(target);
                id
            }
            // A pointer to a member is an offset, and to a member function two words.
            gimli::DW_TAG_ptr_to_member_type => {
                let word = self.types.add(Type::Base { base: Base::Uint, size: self.types.pointer });
                match number(gimli::DW_AT_byte_size) {
                    Some(size) if size > self.types.pointer => self.types.add(Type::Array { element: word, count: size / self.types.pointer }),
                    _ => word,
                }
            }
            gimli::DW_TAG_const_type | gimli::DW_TAG_volatile_type | gimli::DW_TAG_restrict_type | gimli::DW_TAG_atomic_type | gimli::DW_TAG_packed_type | gimli::DW_TAG_immutable_type => self.type_of(die),
            gimli::DW_TAG_typedef => self.typedef(die),
            gimli::DW_TAG_structure_type | gimli::DW_TAG_class_type | gimli::DW_TAG_union_type | gimli::DW_TAG_enumeration_type => {
                let name = self.qualified(die);
                self.named(die, &entry, &name)
            }
            gimli::DW_TAG_array_type => {
                let mut kind = self.type_of(die);
                // One `DW_TAG_subrange_type` per dimension, the outermost first.
                for count in self.children(die, |_, child| (child.tag() == gimli::DW_TAG_subrange_type).then(|| {
                    let number = |name| child.attr(name).and_then(|attr| attr.udata_value());
                    number(gimli::DW_AT_count).or_else(|| number(gimli::DW_AT_upper_bound).map(|bound| bound.wrapping_add(1))).unwrap_or(0)
                })).into_iter().rev() {
                    kind = self.types.add(Type::Array { element: kind, count });
                }
                kind
            }
            gimli::DW_TAG_subroutine_type => {
                let prototype = self.prototype(die);
                self.types.add(Type::Function(prototype))
            }
            _ => VOID,
        };
        self.seen.insert(die, id);
        id
    }

    /// What `f` makes of each child of the entry at `die`, given the child's entry too.
    fn children<T>(&self, die: Die, mut f: impl FnMut(Die, &gimli::DebuggingInformationEntry<Slice<'a>>) -> Option<T>) -> Vec<T> {
        let mut found = Vec::new();
        let Ok(mut tree) = self.units[die.0].entries_tree(Some(die.1)) else { return found };
        let Ok(root) = tree.root() else { return found };
        let mut children = root.children();
        while let Ok(Some(child)) = children.next() {
            found.extend(f((die.0, child.entry().offset()), child.entry()));
        }
        found
    }

    /// The struct, union or enum at `die` under `name`, which is empty if it has none.
    fn named(&mut self, die: Die, entry: &gimli::DebuggingInformationEntry<Slice<'a>>, name: &str) -> TypeId {
        let size = entry.attr(gimli::DW_AT_byte_size).and_then(|attr| attr.udata_value()).unwrap_or(0);
        if entry.tag() == gimli::DW_TAG_enumeration_type {
            let (id, fill) = self.types.named(Named::Enum, name, size);
            if fill {
                let values = self.children(die, |_, child| {
                    let value = child.attr(gimli::DW_AT_const_value)?;
                    let name = self.dwarf.attr_string(&self.units[die.0], child.attr_value(gimli::DW_AT_name)?).ok()?;
                    Some((name.to_string_lossy().into_owned(), value.sdata_value().or_else(|| value.udata_value().map(|value| value as i64))?))
                });
                self.types.set_values(id, values);
            }
            return id;
        }
        let kind = if entry.tag() == gimli::DW_TAG_union_type { Named::Union } else { Named::Struct };
        let (id, fill) = self.types.named(kind, name, size);
        self.seen.insert(die, id);
        if entry.attr_value(gimli::DW_AT_calling_convention) == Some(gimli::AttributeValue::CallingConvention(gimli::DW_CC_pass_by_reference)) {
            self.by_reference.insert(id);
        }
        if fill && size > 0 {
            self.pending.push((id, die));
        }
        id
    }

    /// The typedef at `die`. One that only gives a struct, union or enum its name, as in
    /// `typedef struct { .. } name;` or `typedef struct name name;`, is that type itself.
    fn typedef(&mut self, die: Die) -> TypeId {
        let name = self.qualified(die);
        let mut target = self.attr(die, gimli::DW_AT_type).and_then(|(unit, value)| self.reference(unit, value));
        if let Some(target) = target.take_if(|target| !self.seen.contains_key(target))
            && let Some(entry) = self.entry(target)
            && matches!(entry.tag(), gimli::DW_TAG_structure_type | gimli::DW_TAG_class_type | gimli::DW_TAG_union_type | gimli::DW_TAG_enumeration_type)
        {
            let own = self.qualified(target);
            if own.is_empty() || own == name {
                let id = self.named(target, &entry, &name);
                self.seen.insert(target, id);
                return id;
            }
        }
        let (id, fill) = self.types.named(Named::Typedef, &name, 0);
        if fill {
            self.seen.insert(die, id);
            match self.type_of(die) {
                // A name for `void` is no type the engine can hold.
                VOID => self.types.types[id as usize] = Type::Alias(VOID),
                target => self.types.set_target(id, target),
            }
        }
        id
    }

    /// Reads the members and base classes of the struct or union at `die` into the type `id`.
    fn members(&mut self, id: TypeId, die: Die) {
        let members: Vec<(Die, gimli::DebuggingInformationEntry<Slice<'a>>)> =
            self.children(die, |child, entry| matches!(entry.tag(), gimli::DW_TAG_member | gimli::DW_TAG_inheritance | gimli::DW_TAG_subprogram).then(|| (child, entry.clone())));
        let mut fields = Vec::new();
        for (member, entry) in members {
            if entry.tag() == gimli::DW_TAG_subprogram {
                // A destructor: copying or dropping a value of this class runs code.
                let name = entry.attr_value(gimli::DW_AT_name).and_then(|name| self.dwarf.attr_string(&self.units[die.0], name).ok());
                if name.is_some_and(|name| name.slice().starts_with(b"~")) {
                    self.by_reference.insert(id);
                }
                continue;
            }
            // A static member is a global, not a part of the struct.
            if entry.has_attr(gimli::DW_AT_external) || entry.has_attr(gimli::DW_AT_declaration) {
                continue;
            }
            let number = |name| entry.attr(name).and_then(|attr| attr.udata_value());
            let offset = match entry.attr_value(gimli::DW_AT_data_member_location) {
                None => 0,
                // Older producers write the offset as an expression that adds it.
                Some(gimli::AttributeValue::Exprloc(location)) => match location.operations(self.units[die.0].encoding()).next() {
                    Ok(Some(gimli::Operation::PlusConstant { value })) => value,
                    Ok(Some(gimli::Operation::UnsignedConstant { value })) => value,
                    // Where a virtual base lies is only known at run time.
                    _ => continue,
                },
                Some(_) => number(gimli::DW_AT_data_member_location).unwrap_or(0),
            };
            let kind = self.type_of(member);
            let name = entry.attr_value(gimli::DW_AT_name).and_then(|name| self.dwarf.attr_string(&self.units[die.0], name).ok()).map(|name| name.to_string_lossy().into_owned());
            let name = match (name, entry.tag()) {
                (Some(name), gimli::DW_TAG_inheritance) | (Some(name), _) if entry.tag() != gimli::DW_TAG_inheritance => name,
                (_, gimli::DW_TAG_inheritance) => match self.types.get(kind) {
                    Type::Composite { name, .. } => crate::types::base_field(name),
                    _ => continue,
                },
                // An unnamed struct or union inside this one.
                _ => format!("anon_{offset:x}"),
            };
            let (offset, bits) = match number(gimli::DW_AT_bit_size) {
                None => (offset, None),
                Some(width) => {
                    // The position of the lowest bit, counted from the start of the struct.
                    let first = match (number(gimli::DW_AT_data_bit_offset), number(gimli::DW_AT_bit_offset)) {
                        (Some(first), _) => first,
                        // The old way counts down from the top of the storage unit.
                        (None, Some(from_top)) => (8 * (offset + number(gimli::DW_AT_byte_size).unwrap_or_else(|| self.types.size(kind)))).saturating_sub(from_top + width),
                        (None, None) => 8 * offset,
                    };
                    (first / 8, Some(((first % 8) as u32, width as u32)))
                }
            };
            fields.push(Field { name, offset, kind, bits });
        }
        self.types.set_fields(id, fields);
    }

    /// The prototype the function or function type at `die` declares, as the source has it.
    /// [`Reader::as_passed`] turns it into what the machine code sees.
    fn prototype(&mut self, die: Die) -> Prototype {
        let returns = self.type_of(die);
        let children: Vec<(Die, gimli::DwTag)> = self.children(die, |child, entry| Some((child, entry.tag())));
        let mut prototype = Prototype { returns, params: Vec::new(), variadic: false, convention: None };
        for (child, tag) in children {
            match tag {
                gimli::DW_TAG_formal_parameter => {
                    let name = self.attr(child, gimli::DW_AT_name).and_then(|(unit, name)| self.dwarf.attr_string(&self.units[unit], name).ok());
                    let kind = self.type_of(child);
                    prototype.params.push((name.map_or_else(String::new, |name| name.to_string_lossy().into_owned()), kind));
                }
                gimli::DW_TAG_unspecified_parameters => prototype.variadic = true,
                _ => {}
            }
        }
        prototype
    }

    /// Rewrites every prototype from what the source says to what the machine code does, once
    /// all structs have their members. C++ hands a class with a destructor around by pointer
    /// even where the source passes or returns it by value, and on x86-64 a class with no data
    /// in it is not passed at all.
    fn as_passed(&mut self, machine: Machine) {
        // A class that holds one passed by pointer is passed by pointer too.
        let held_by_value = |types: &Types, mut id: TypeId| loop {
            match types.get(id) {
                Type::Typedef { target, .. } => id = *target,
                Type::Array { element, .. } => id = *element,
                Type::Composite { .. } => return Some(types.resolve(id)),
                _ => return None,
            }
        };
        loop {
            let before = self.by_reference.len();
            for id in 0..self.types.types.len() as TypeId {
                if let Type::Composite { fields, .. } = &self.types.types[id as usize]
                    && fields.iter().any(|field| held_by_value(&self.types, field.kind).is_some_and(|held| self.by_reference.contains(&held)))
                {
                    self.by_reference.insert(id);
                }
            }
            if self.by_reference.len() == before {
                break;
            }
        }
        for id in 0..self.types.types.len() {
            let Type::Function(prototype) = &self.types.types[id] else { continue };
            let mut prototype = prototype.clone();
            // The struct or union a value of type `id` is, if it is one.
            let class = |types: &Types, mut id: TypeId| loop {
                match types.get(id) {
                    Type::Typedef { target, .. } => id = *target,
                    Type::Composite { .. } => return Some(types.resolve(id)),
                    _ => return None,
                }
            };
            let mut params = Vec::with_capacity(prototype.params.len() + 1);
            if machine != Machine::Aarch64 && class(&self.types, prototype.returns).is_some_and(|class| self.by_reference.contains(&class)) {
                // The caller passes where the result goes, before everything else, and gets
                // that pointer back. AArch64 passes it in a register of its own instead.
                prototype.returns = self.types.add(Type::Pointer(prototype.returns));
                params.push((String::from("result"), prototype.returns));
            }
            for (name, kind) in prototype.params {
                match class(&self.types, kind) {
                    Some(class) if self.by_reference.contains(&class) => params.push((name, self.types.add(Type::Pointer(kind)))),
                    Some(class) if machine == Machine::X86_64 && self.types.size(class) <= 1 && self.types.hollow(class, 8) => {}
                    _ => params.push((name, kind)),
                }
            }
            prototype.params = params;
            self.types.types[id] = Type::Function(prototype);
        }
    }

    fn function(&mut self, die: Die, addr: u64) {
        // The compiler says so itself when a function does not take what its source declares,
        // as a copy specialised for its callers does not.
        if self.attr(die, gimli::DW_AT_calling_convention).is_some_and(|(_, value)| value == gimli::AttributeValue::CallingConvention(gimli::DW_CC_nocall)) {
            return;
        }
        let name = self.qualified(die);
        let prototype = self.prototype(die);
        let prototype = self.types.add(Type::Function(prototype));
        self.types.functions.push(crate::types::Function { addr, name, prototype });
    }

    fn global(&mut self, die: Die, addr: u64) {
        let name = self.qualified(die);
        let kind = self.type_of(die);
        if !name.is_empty() {
            self.types.globals.push(Global { addr, name, kind });
        }
    }
}
