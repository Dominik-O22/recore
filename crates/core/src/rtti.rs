//! C++ classes recovered from the run-time type information MSVC emits.
//!
//! The slot before a vtable points at a locator, which points at the class's type descriptor,
//! holding its mangled name, and at its list of base classes. In 32-bit images those links are
//! addresses; in 64-bit images they are offsets from the image base.

use rustc_hash::FxHashSet;

use crate::image::{Format, Image};
use crate::report::Class;

/// Most virtual functions read from one vtable, and most base classes from one class.
const LONGEST: u64 = 1024;

struct Reader<'a> {
    image: &'a Image,
    pointer: u64,
}

impl Reader<'_> {
    fn u32(&self, addr: u64) -> Option<u64> {
        let bytes = self.image.bytes_from(addr)?.get(..4)?;
        Some(u64::from(u32::from_le_bytes(bytes.try_into().ok()?)))
    }

    fn pointer(&self, addr: u64) -> Option<u64> {
        let bytes = self.image.bytes_from(addr)?.get(..self.pointer as usize)?;
        Some(bytes.iter().rev().fold(0, |value, &byte| value << 8 | u64::from(byte)))
    }

    /// A link between type-information records: an address, or an offset from the image base.
    fn link(&self, addr: u64) -> Option<u64> {
        let value = self.u32(addr)?;
        Some(if self.pointer == 4 { value } else { self.image.base + value })
    }

    /// The class a type descriptor names, such as `.?AVKey@crypto@@`.
    fn type_name(&self, descriptor: u64) -> Option<String> {
        let bytes = self.image.bytes_from(descriptor + 2 * self.pointer)?;
        let mangled = std::str::from_utf8(&bytes[..bytes.iter().position(|&byte| byte == 0)?]).ok()?;
        mangled.starts_with(".?A").then(|| class_name(mangled))
    }
}

/// `.?AVKey@crypto@@` as `crypto::Key`. Template names are left mangled.
fn class_name(mangled: &str) -> String {
    let scopes = mangled.get(4..).and_then(|rest| rest.strip_suffix("@@")).filter(|rest| !rest.contains(['?', '$']));
    match scopes {
        Some(scopes) => scopes.split('@').rev().collect::<Vec<_>>().join("::"),
        None => mangled.to_string(),
    }
}

/// Every class with a vtable and type information, sorted by vtable address. A class with
/// several base classes that have virtual functions appears once per vtable.
pub fn classes(image: &Image) -> Vec<Class> {
    if image.format != Format::Pe {
        return Vec::new();
    }
    let reader = Reader { image, pointer: image.machine.pointer_size() };
    let relocated: FxHashSet<u64> = image.relative_targets.iter().map(|&(slot, _)| slot).collect();
    let in_data = |addr: u64| image.section_at(addr).is_some_and(|section| !section.executable);
    let mut classes: Vec<Class> = image
        .relative_targets
        .iter()
        .filter(|&&(slot, locator)| in_data(slot) && in_data(locator))
        .filter_map(|&(slot, locator)| {
            // The locator's signature says which kind of link it uses.
            if reader.u32(locator)? != u64::from(reader.pointer == 8) {
                return None;
            }
            let name = reader.type_name(reader.link(locator + 12)?)?;
            let vtable = slot + reader.pointer;
            let methods: Vec<u64> = (0..LONGEST)
                .map(|index| vtable + index * reader.pointer)
                .map_while(|entry| reader.pointer(entry).filter(|&target| relocated.contains(&entry) && image.is_code(target)))
                .collect();
            // The hierarchy lists the class itself first, then every class it derives from.
            let hierarchy = reader.link(locator + 16)?;
            let count = reader.u32(hierarchy + 8)?.min(LONGEST);
            let list = reader.link(hierarchy + 12)?;
            let bases = (1..count).filter_map(|index| reader.type_name(reader.link(reader.link(list + 4 * index)?)?)).collect();
            (!methods.is_empty()).then_some(Class { name, vtable, methods, bases, objc: false })
        })
        .collect();
    classes.sort_by_key(|class| class.vtable);
    classes
}

/// Addresses of the mangled class names in type descriptors, with the names as stored. Nothing
/// points at these strings themselves, only at the descriptor that holds them.
pub fn type_names(image: &Image) -> Vec<(u64, String)> {
    if image.format != Format::Pe {
        return Vec::new();
    }
    let pointer = image.machine.pointer_size();
    let mut names: Vec<(u64, String)> = image
        .sections
        .iter()
        .filter(|section| !section.executable)
        .flat_map(|section| {
            section.data.windows(4).enumerate().filter(|(_, window)| window == b".?AV" || window == b".?AU").filter_map(move |(offset, _)| {
                let rest = &section.data[offset..];
                let text = std::str::from_utf8(&rest[..rest.iter().position(|&byte| byte == 0)?]).ok()?;
                // A descriptor is aligned, and its name follows two pointers.
                let addr = section.addr + offset as u64;
                (addr.is_multiple_of(pointer) && text.ends_with("@@")).then(|| (addr, text.to_string()))
            })
        })
        .collect();
    names.sort();
    names
}
