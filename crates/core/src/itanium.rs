//! C++ classes recovered from the run-time type information of the Itanium ABI, which GCC and
//! Clang emit on ELF and Mach-O.
//!
//! A class's type information record starts with a pointer into the vtable of one of three
//! library classes, which says how the record lists base classes, then a pointer to the class's
//! mangled name. A vtable is found from the other side: the slot before its first function
//! points at the record of its class, and the slot before that holds the offset from the
//! subobject the vtable serves to the whole object.
//!
//! Stripping removes none of this. What is not found:
//! - a class compiled with `-fno-rtti`, which has no record;
//! - vtables of the relative layout (`-fexperimental-relative-c++-abi-vtables`, Fuchsia's
//!   default), whose slots are 32-bit offsets;
//! - a class with virtual base classes that other classes derive from, when the compiler
//!   dropped its table of construction vtables: its own vtable then looks like the ones the
//!   derived classes carry for it;
//! - classes of MinGW's PE images, which use the same records.

use rustc_hash::{FxHashMap, FxHashSet};

use crate::image::{Format, Image, Machine};
use crate::report::Class;

/// Most virtual functions read from one vtable, base classes from one record, and characters
/// from one class name.
const LONGEST: u64 = 4096;

/// Which of the library's three record layouts a type information record has.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Shape {
    /// `__class_type_info`: no base classes.
    Leaf,
    /// `__si_class_type_info`: one public, non-virtual base class at offset zero.
    Single,
    /// `__vmi_class_type_info`: a counted list of base classes.
    Multiple,
}

/// The mangled names of the three library classes, as their own records store them.
const SHAPES: [(&str, Shape); 3] = [
    ("N10__cxxabiv117__class_type_infoE", Shape::Leaf),
    ("N10__cxxabiv120__si_class_type_infoE", Shape::Single),
    ("N10__cxxabiv121__vmi_class_type_infoE", Shape::Multiple),
];

/// One class's type information record.
struct Record {
    /// Address of the mangled name.
    name: u64,
    /// The slots that point at the records of its direct base classes, in declaration order.
    bases: Vec<u64>,
    /// Some base class, direct or not, is virtual. Only then can other classes' objects carry
    /// vtables that name this class: the ones in use while they construct this part.
    virtual_bases: bool,
}

/// One vtable: the functions that follow a pointer to a record.
struct Vtable {
    /// Address of the first function slot, which is what an object's vtable pointer holds.
    addr: u64,
    record: u64,
    /// Zero in the first vtable of a group, which is the one an object of the class points at.
    offset_to_top: i64,
    /// Address of the first vtable of the group this one belongs to.
    group: u64,
    methods: Vec<u64>,
}

struct Reader<'a> {
    image: &'a Image,
    /// Slot address to target for the pointers the loader relocates.
    slots: &'a FxHashMap<u64, u64>,
    /// Size of a pointer.
    size: u64,
    /// The image can load at any address, so every pointer in its data is a relocation. In an
    /// image that cannot, a pointer is a word that holds an address.
    relocated: bool,
}

impl Reader<'_> {
    fn u32(&self, addr: u64) -> Option<u64> {
        let bytes = self.image.bytes_from(addr)?.get(..4)?;
        Some(u64::from(u32::from_le_bytes(bytes.try_into().ok()?)))
    }

    /// The pointer-sized number stored at `addr`, sign-extended.
    fn word(&self, addr: u64) -> Option<i64> {
        let bytes = self.image.bytes_from(addr)?.get(..self.size as usize)?;
        let value = bytes.iter().rev().fold(0, |value, &byte| value << 8 | u64::from(byte));
        let unused = 64 - 8 * self.size as u32;
        Some((value << unused) as i64 >> unused)
    }

    /// The address stored at `addr`, if a pointer is stored there.
    fn pointer(&self, addr: u64) -> Option<u64> {
        if self.relocated {
            return self.slots.get(&addr).copied();
        }
        self.word(addr).map(|value| value as u64).filter(|&target| self.image.section_at(target).is_some())
    }

    /// Whether the loader stores an address at `addr`, of this image or of another.
    fn is_pointer(&self, addr: u64) -> bool {
        self.image.import_slots.contains_key(&addr) || self.pointer(addr).is_some()
    }

    /// Every slot in the image's data that points at one of `targets`, with what the target
    /// maps to. One pass over the relocations, or over the data sections where there are none.
    fn pointers_to<T: Copy>(&self, targets: &FxHashMap<u64, T>) -> Vec<(u64, T)> {
        if self.relocated {
            return self.image.relative_targets.iter().filter_map(|&(slot, target)| Some((slot, *targets.get(&target)?))).collect();
        }
        // Most words are not addresses near the targets at all, which is cheaper to tell.
        let (Some(&low), Some(&high)) = (targets.keys().min(), targets.keys().max()) else { return Vec::new() };
        let size = self.size as usize;
        let mut found = Vec::new();
        for section in self.image.sections.iter().filter(|section| !section.executable) {
            let skipped = (section.addr.next_multiple_of(self.size) - section.addr) as usize;
            for (index, bytes) in section.data.get(skipped..).unwrap_or_default().chunks_exact(size).enumerate() {
                let value = bytes.iter().rev().fold(0, |value, &byte| value << 8 | u64::from(byte));
                if value >= low && value <= high && let Some(&target) = targets.get(&value) {
                    found.push((section.addr + (skipped + index * size) as u64, target));
                }
            }
        }
        found
    }

    /// The text at `addr` up to its terminating zero.
    fn text(&self, addr: u64) -> Option<&str> {
        let bytes = self.image.bytes_from(addr)?;
        let bytes = &bytes[..bytes.len().min(LONGEST as usize)];
        std::str::from_utf8(&bytes[..bytes.iter().position(|&byte| byte == 0)?]).ok()
    }

    /// The address of each record in the image with its shape. Empty for an image without C++
    /// classes, which is settled by looking through the imports and one search of the
    /// read-only data.
    fn records(&self) -> Vec<(u64, Shape)> {
        // A record's first slot points into the vtable of its shape's library class. Bound to
        // the C++ library by name, the slot is an import.
        let shape_of = |symbol: &str| {
            let name = symbol.trim_start_matches('_').strip_prefix("ZTV")?;
            SHAPES.iter().find(|shape| shape.0 == name).map(|shape| shape.1)
        };
        let imported: Vec<(u64, Shape)> = self.image.import_slots.iter().filter_map(|(&slot, name)| Some((slot, shape_of(name)?))).collect();
        if !imported.is_empty() {
            return imported;
        }
        // An executable that cannot load anywhere gets its own copy of the library's vtables,
        // under their names.
        let mut tables: FxHashMap<u64, Shape> =
            self.image.symbol_names.iter().filter_map(|(&addr, name)| Some((addr + 2 * self.size, shape_of(name)?))).collect();
        if tables.is_empty() {
            tables = self.linked_in_tables();
        }
        self.pointers_to(&tables)
    }

    /// Where the records of each shape point when the C++ library is linked into the image and
    /// nothing names its vtables: at the vtable whose record carries the library class's name.
    fn linked_in_tables(&self) -> FxHashMap<u64, Shape> {
        const PREFIX: &[u8] = b"N10__cxxabiv1";
        let mut names: FxHashMap<u64, Shape> = FxHashMap::default();
        for section in self.image.sections.iter().filter(|section| !section.executable && !section.writable) {
            for offset in memchr::memmem::find_iter(&section.data, PREFIX) {
                // The same text inside a longer name does no harm: nothing points at it.
                let rest = &section.data[offset..];
                if let Some(shape) = SHAPES.iter().find(|shape| rest.starts_with(shape.0.as_bytes()) && rest.get(shape.0.len()) == Some(&0)) {
                    names.insert(section.addr + offset as u64, shape.1);
                }
            }
        }
        if names.is_empty() {
            return names;
        }
        // The name pointer is a record's second slot, and a vtable's record pointer follows
        // its offset to the top, which is zero here.
        let records: FxHashMap<u64, Shape> = self.pointers_to(&names).into_iter().map(|(slot, shape)| (slot - self.size, shape)).collect();
        let is_vtable = |slot: u64| self.word(slot - self.size) == Some(0) && !self.is_pointer(slot - self.size);
        self.pointers_to(&records).into_iter().filter(|&(slot, _)| is_vtable(slot)).map(|(slot, shape)| (slot + self.size, shape)).collect()
    }

    /// Reads the record at `addr`: its name and the slots that hold its base classes.
    fn record(&self, addr: u64, shape: Shape) -> Option<Record> {
        // Apple's linker sets the top bit of the pointer to a name that other images may
        // hold their own copy of.
        let name = self.pointer(addr + self.size)? & !(1 << 63);
        let first = addr + 2 * self.size;
        let bases = match shape {
            Shape::Leaf => Vec::new(),
            Shape::Single => vec![first],
            // Flags and a count, then for each base class a pointer and its offset and flags.
            Shape::Multiple => (0..self.u32(first + 4)?.min(LONGEST)).map(|index| first + 8 + 2 * index * self.size).collect(),
        };
        // The low bit of a listed base class's flags says it is virtual.
        let virtual_bases = shape == Shape::Multiple && bases.iter().any(|&slot| self.word(slot + self.size).is_some_and(|flags| flags & 1 != 0));
        Some(Record { name, bases, virtual_bases })
    }

    /// The vtable whose record pointer is at `slot`, if the words around it read as one.
    fn vtable(&self, slot: u64, record: u64) -> Option<Vtable> {
        let offset_to_top = self.word(slot - self.size).filter(|_| !self.is_pointer(slot - self.size))?;
        // A subobject lies within its object, and no object is this large.
        if offset_to_top.unsigned_abs() >= 1 << 28 {
            return None;
        }
        let addr = slot + self.size;
        // A slot holds a function of the image, or is bound to one of another image. The two
        // destructor slots of a class that cannot be instantiated are null.
        let function = |entry: u64| match self.image.import_slots.get(&entry) {
            // Records and vtables of another image are bound by name as well.
            Some(name) => (!name.trim_start_matches('_').starts_with("ZT")).then_some(entry),
            None => self.pointer(entry).filter(|&target| self.image.is_code(target)),
        };
        let mut methods = Vec::new();
        let is_null = |entry: u64| self.word(entry) == Some(0) && !self.is_pointer(entry);
        while methods.len() < LONGEST as usize {
            let entry = addr + methods.len() as u64 * self.size;
            // Nulls belong to this vtable only if a function follows: the next vtable starts
            // with zeros as well.
            let nulls = (0..2).take_while(|&index| is_null(entry + index * self.size)).count();
            match function(entry + nulls as u64 * self.size) {
                Some(method) => methods.extend(std::iter::repeat_n(0, nulls).chain([method])),
                None => break,
            }
        }
        Some(Vtable { addr, record, offset_to_top, group: addr, methods })
    }
}

/// A mangled type name as a person would write it. Names GCC marks with `*` as local to their
/// object file read the same.
fn type_name(mangled: &str) -> String {
    let mangled = mangled.trim_start_matches('*');
    let demangled = cpp_demangle::Symbol::new(format!("_ZTS{mangled}")).ok().and_then(|symbol| symbol.demangle().ok());
    demangled.as_deref().and_then(|name| name.strip_prefix("typeinfo name for ")).unwrap_or(mangled).to_string()
}

/// Every class with a vtable and type information, sorted by vtable address. A class with
/// several base classes that have virtual functions appears once per vtable. A slot bound to
/// a function of another image, such as a pure virtual function's, is listed by the slot's own
/// address, and a null slot as zero.
///
/// `slots` maps the address of each relocated pointer to its target.
pub fn classes(image: &Image, slots: &FxHashMap<u64, u64>) -> Vec<Class> {
    // MinGW emits the same records in PE images, where they are not read: no such image was
    // at hand to check against.
    if image.format == Format::Pe {
        return Vec::new();
    }
    // An image that can load anywhere relocates its pointers to data. One that cannot has at
    // most relocations for functions chosen at load time, which point at code.
    let relocated = image.relative_targets.iter().any(|&(_, target)| !image.is_code(target));
    let reader = Reader { image, slots, size: if image.machine == Machine::X86 { 4 } else { 8 }, relocated };
    let found = reader.records();
    if found.is_empty() {
        return Vec::new();
    }
    let records: FxHashMap<u64, Record> = found.into_iter().filter_map(|(addr, shape)| Some((addr, reader.record(addr, shape)?))).collect();

    // The name of the class a base slot points at, and its record if it is in this image.
    let base = |slot: u64| match image.import_slots.get(&slot) {
        Some(symbol) => Some((type_name(symbol.trim_start_matches('_').strip_prefix("ZTI")?), None)),
        None => {
            let addr = reader.pointer(slot)?;
            let record = records.get(&addr)?;
            Some((type_name(reader.text(record.name)?), Some(record)))
        }
    };
    // Base classes nearest first: each direct base, followed by its own.
    let bases_of = |record: &Record| {
        let mut names: Vec<String> = Vec::new();
        let mut pending: Vec<u64> = record.bases.iter().rev().copied().collect();
        while let Some(slot) = pending.pop() {
            let Some((name, record)) = base(slot) else { continue };
            if names.len() < LONGEST as usize && !names.contains(&name) {
                names.push(name);
                pending.extend(record.into_iter().flat_map(|record| record.bases.iter().rev().copied()));
            }
        }
        names
    };
    // The records of the base classes of the class at `addr` that are in this image.
    let ancestors = |addr: u64| {
        let mut found: FxHashSet<u64> = FxHashSet::default();
        let mut pending = vec![addr];
        while let Some(addr) = pending.pop() {
            let bases = records[&addr].bases.iter().filter_map(|&slot| reader.pointer(slot)).filter(|base| records.contains_key(base));
            pending.extend(bases.filter(|&base| found.len() < LONGEST as usize && found.insert(base)));
        }
        found
    };
    let has_virtual_bases = |addr: u64| records[&addr].virtual_bases || ancestors(addr).iter().any(|base| records[base].virtual_bases);

    // Everything else that points at a record is a vtable, a record listing it as a base, or
    // an entry of an exception table.
    let targets: FxHashMap<u64, u64> = records.keys().map(|&addr| (addr, addr)).collect();
    let base_slots: FxHashSet<u64> = records.values().flat_map(|record| record.bases.iter().copied()).collect();
    let mut vtables: Vec<Vtable> = reader
        .pointers_to(&targets)
        .into_iter()
        .filter(|(slot, _)| !base_slots.contains(slot))
        .filter_map(|(slot, record)| reader.vtable(slot, record))
        .collect();
    vtables.sort_by_key(|vtable| vtable.addr);

    // A class's vtables lie together as a group: the one for the whole object, then one for
    // each further base class with virtual functions, at its offset in the object.
    let mut latest: FxHashMap<u64, u64> = FxHashMap::default();
    for vtable in &mut vtables {
        let group = latest.entry(vtable.record).or_insert(vtable.addr);
        if vtable.offset_to_top == 0 {
            *group = vtable.addr;
        }
        vtable.group = *group;
    }

    // A class with virtual base classes has, besides its own group, one in each derived class,
    // in use while that class constructs this part. Each class with such groups also has a
    // table of pointers to them, which starts with its own group and names nothing but its
    // own and those of its base classes. So a group that a table names after the group of a
    // derived class is not a class's own. Code is no guide: a constructor may refer to either.
    let mut borrowed: FxHashSet<u64> = FxHashSet::default();
    let mut heads: FxHashSet<u64> = FxHashSet::default();
    if records.values().any(|record| record.virtual_bases) {
        let at: FxHashMap<u64, usize> = vtables.iter().enumerate().map(|(index, vtable)| (vtable.addr, index)).collect();
        // A vtable that did not read as one, or of a class of another image, still follows a
        // pointer to a record.
        let follows_record = |addr: u64| match image.import_slots.get(&(addr - reader.size)) {
            Some(symbol) => symbol.trim_start_matches('_').starts_with("ZTI"),
            None => reader.pointer(addr - reader.size).is_some_and(|record| records.contains_key(&record)),
        };
        let mut entries: Vec<u64> = reader.pointers_to(&at).into_iter().map(|(slot, _)| slot).collect();
        entries.sort_unstable();
        let mut slot = 0;
        for start in entries {
            // Inside the run of pointers that the entry before started.
            if start < slot {
                continue;
            }
            // The class whose table this is, its base classes, and the group the table has
            // named for each so far.
            let mut owner: Option<(u64, FxHashSet<u64>)> = None;
            let mut named: FxHashMap<u64, u64> = FxHashMap::default();
            slot = start;
            while let Some(target) = reader.pointer(slot) {
                let vtable = at.get(&target).map(|&index| &vtables[index]);
                // Tables lie back to back, and a base class's may follow its derived class's:
                // then this is the second group the table names for the base class.
                let borrows = |vtable: &Vtable| match &owner {
                    Some((_, bases)) => bases.contains(&vtable.record) && named.get(&vtable.record).is_none_or(|&group| group == vtable.group),
                    None => false,
                };
                match vtable {
                    Some(vtable) if owner.as_ref().is_some_and(|owner| owner.0 == vtable.record) => {}
                    Some(vtable) if borrows(vtable) => {
                        named.insert(vtable.record, vtable.group);
                        if has_virtual_bases(vtable.record) {
                            borrowed.insert(vtable.group);
                        }
                    }
                    Some(vtable) => {
                        heads.insert(vtable.group);
                        owner = Some((vtable.record, ancestors(vtable.record)));
                        named.clear();
                    }
                    None if follows_record(target) => {}
                    None => break,
                }
                slot += reader.size;
            }
        }
    }

    let derived_from: FxHashSet<u64> = base_slots.iter().filter_map(|&slot| reader.pointer(slot)).collect();
    let mut groups: FxHashMap<u64, Vec<&Vtable>> = FxHashMap::default();
    for vtable in &vtables {
        groups.entry(vtable.group).or_default().push(vtable);
    }
    let mut reported: FxHashSet<u64> = FxHashSet::default();
    let mut classes: Vec<Class> = Vec::new();
    for first in vtables.iter().filter(|vtable| vtable.group == vtable.addr && vtable.offset_to_top == 0) {
        let group = &groups[&first.addr];
        // A group without functions is an exception table's entry after a zero word, unless
        // the class has nothing but virtual base classes to describe.
        let is_class = group.iter().any(|vtable| !vtable.methods.is_empty()) || has_virtual_bases(first.record);
        // Without a table, a class with virtual base classes that others derive from cannot
        // be told from the groups those carry for it. A class nothing derives from has none.
        let is_own = !has_virtual_bases(first.record) || heads.contains(&first.addr) || !derived_from.contains(&first.record);
        if !is_class || !is_own || borrowed.contains(&first.addr) || !reported.insert(first.record) {
            continue;
        }
        let record = &records[&first.record];
        let Some(name) = reader.text(record.name).map(type_name) else { continue };
        let bases = bases_of(record);
        classes.extend(group.iter().map(|vtable| Class { name: name.clone(), vtable: vtable.addr, methods: vtable.methods.clone(), bases: bases.clone(), objc: false }));
    }
    classes.sort_by_key(|class| class.vtable);
    classes
}
