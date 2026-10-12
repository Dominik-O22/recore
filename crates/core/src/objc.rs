//! Objective-C as a Mach-O image records it: classes, categories and their methods, and the
//! selector each message send passes.
//!
//! The compiler lists every class in `__objc_classlist` and every category in
//! `__objc_catlist`. A class points at a read-only record holding its name and method list,
//! and at its metaclass, whose method list holds the class methods. A message send is a call
//! to `objc_msgSend` with the selector as second argument, loaded from a slot in
//! `__objc_selrefs`: by the caller, or by a stub the linker wrote for that selector.

use rayon::prelude::*;
use rustc_hash::{FxHashMap, FxHashSet};

use crate::arch::{Arch, Flow};
use crate::image::{Format, Image};
use crate::report::{Analysis, CallSite, CallTarget, Class, MessageSend};

/// Most classes, methods or base classes read from one list.
const LONGEST: u64 = 1 << 16;

/// What the image's Objective-C metadata says.
pub struct Metadata {
    /// Classes, then categories, each in the order the image lists them.
    pub classes: Vec<Class>,
    /// Method implementations with their names, such as `-[Square area]`.
    pub methods: Vec<(u64, String)>,
    /// Slot in `__objc_selrefs` to the selector it holds.
    selectors: FxHashMap<u64, String>,
    /// Selector to the implementations of it in this image.
    implementations: FxHashMap<String, Vec<u64>>,
}

struct Reader<'a> {
    image: &'a Image,
}

impl<'a> Reader<'a> {
    fn u32(&self, addr: u64) -> Option<u32> {
        Some(u32::from_le_bytes(self.image.bytes_from(addr)?.get(..4)?.try_into().ok()?))
    }

    fn pointer(&self, addr: u64) -> Option<u64> {
        Some(u64::from_le_bytes(self.image.bytes_from(addr)?.get(..8)?.try_into().ok()?))
    }

    /// The address a 32-bit offset stored at `addr` leads to, counted from `addr` itself.
    fn relative(&self, addr: u64) -> Option<u64> {
        Some(addr.wrapping_add_signed(i64::from(self.u32(addr)? as i32)))
    }

    fn text(&self, addr: u64) -> Option<String> {
        let bytes = self.image.bytes_from(addr)?;
        Some(String::from_utf8_lossy(&bytes[..bytes.iter().position(|&byte| byte == 0)?]).into_owned())
    }

    /// The pointers stored in the section called `name`, whichever segment holds it, with the
    /// slot of each.
    fn pointers(&self, name: &'a str) -> impl Iterator<Item = (u64, u64)> + 'a {
        let named = self.image.sections.iter().filter(move |section| section.name.rsplit_once(',').is_some_and(|(_, section)| section == name));
        named.flat_map(|section| {
            section.data.chunks_exact(8).zip((section.addr..).step_by(8)).map(|(bytes, slot)| (slot, u64::from_le_bytes(bytes.try_into().unwrap())))
        })
    }

    /// The read-only record of the class object at `class`. The low bits of the pointer to it
    /// are flags, one of which marks a Swift class.
    fn read_only(&self, class: u64) -> Option<u64> {
        Some(self.pointer(class + 32)? & 0x0000_7FFF_FFFF_FFF8).filter(|&record| record != 0)
    }

    fn class_name(&self, class: u64) -> Option<String> {
        self.text(self.pointer(self.read_only(class)? + 24)?).map(|name| swift_class_name(&name).unwrap_or(name))
    }

    /// The name of the class a slot refers to: one in this image, which the slot points at, or
    /// an imported one, which the loader binds to it.
    fn class_at(&self, slot: u64) -> Option<String> {
        match self.pointer(slot)? {
            0 => self.image.import_slots.get(&slot).map(|import| import.strip_prefix("OBJC_CLASS_$_").unwrap_or(import).to_string()),
            class => self.class_name(class),
        }
    }

    /// `(selector, implementation)` for each entry of the method list at `list`.
    fn methods(&self, list: u64) -> Vec<(String, u64)> {
        /// Entries are three 32-bit offsets, not three pointers.
        const RELATIVE: u32 = 1 << 31;
        /// A relative entry's name leads to the selector itself, not to a slot holding it.
        const DIRECT_SELECTORS: u32 = 1 << 30;
        let (Some(header), Some(count)) = (self.u32(list), self.u32(list + 4)) else { return Vec::new() };
        let size = u64::from(header & 0xFFFC);
        (0..u64::from(count).min(LONGEST))
            .map(|index| list + 8 + index * size)
            .filter_map(|entry| {
                if header & RELATIVE == 0 {
                    return Some((self.text(self.pointer(entry)?)?, self.pointer(entry + 16)?));
                }
                let name = self.relative(entry)?;
                let selector = if header & DIRECT_SELECTORS != 0 { name } else { self.pointer(name)? };
                Some((self.text(selector)?, self.relative(entry + 8)?))
            })
            .collect()
    }

    /// The methods of the record at `record`, which keeps its method list `offset` bytes in.
    fn methods_of(&self, record: Option<u64>, offset: u64) -> Vec<(String, u64)> {
        record.and_then(|record| self.pointer(record + offset)).filter(|&list| list != 0).map_or_else(Vec::new, |list| self.methods(list))
    }
}

/// `_TtC5Shape6Square` as `Shape.Square`: the name the Objective-C runtime is given for a
/// Swift class, which spells out the module and each enclosing type with its length.
fn swift_class_name(mangled: &str) -> Option<String> {
    let mut rest = mangled.strip_prefix("_Tt")?.trim_start_matches(['C', 'V', 'O']);
    let mut parts = Vec::new();
    while !rest.is_empty() {
        let digits = rest.find(|c: char| !c.is_ascii_digit()).filter(|&digits| digits > 0)?;
        let length: usize = rest[..digits].parse().ok()?;
        parts.push(rest.get(digits..digits + length)?);
        rest = &rest[digits + length..];
    }
    (parts.len() >= 2).then(|| parts.join("."))
}

/// Reads the image's Objective-C metadata. `None` for an image that has none.
pub fn metadata(image: &Image) -> Option<Metadata> {
    if image.format != Format::MachO {
        return None;
    }
    let reader = Reader { image };
    let mut classes = Vec::new();
    let mut methods = Vec::new();
    let mut add = |name: String, object: u64, bases: Vec<String>, instance: Vec<(String, u64)>, class: Vec<(String, u64)>| {
        let named = |kind: char, list: &[(String, u64)]| list.iter().map(|(selector, implementation)| (*implementation, format!("{kind}[{name} {selector}]"))).collect::<Vec<_>>();
        methods.extend(named('-', &instance));
        methods.extend(named('+', &class));
        classes.push(Class { vtable: object, methods: instance.iter().chain(&class).map(|method| method.1).collect(), bases, objc: true, name });
    };

    for (_, class) in reader.pointers("__objc_classlist") {
        let Some(name) = reader.class_name(class) else { continue };
        // Each superclass in turn, for as long as they are classes of this image.
        let mut bases = Vec::new();
        let mut current = class;
        while let Some(base) = reader.class_at(current + 8).filter(|_| bases.len() < 64) {
            bases.push(base);
            let Some(next) = reader.pointer(current + 8).filter(|&next| next != 0) else { break };
            current = next;
        }
        let metaclass = reader.pointer(class).and_then(|metaclass| reader.read_only(metaclass));
        add(name, class, bases, reader.methods_of(reader.read_only(class), 32), reader.methods_of(metaclass, 32));
    }
    // A category adds methods to a class, often one from another library. Its record holds
    // its name, the class, and the lists of instance and class methods.
    for (_, category) in reader.pointers("__objc_catlist") {
        let (Some(name), Some(class)) = (reader.pointer(category).and_then(|name| reader.text(name)), reader.class_at(category + 8)) else { continue };
        add(format!("{class}({name})"), category, Vec::new(), reader.methods_of(Some(category), 16), reader.methods_of(Some(category), 24));
    }

    let selectors: FxHashMap<u64, String> = reader.pointers("__objc_selrefs").filter_map(|(slot, selector)| Some((slot, reader.text(selector)?))).collect();
    if classes.is_empty() && selectors.is_empty() {
        return None;
    }
    let mut implementations: FxHashMap<String, Vec<u64>> = FxHashMap::default();
    for (implementation, name) in &methods {
        // `-[Class selector]`: the selector follows the only space.
        let selector = name.rsplit_once(' ').map_or("", |(_, selector)| selector.trim_end_matches(']'));
        implementations.entry(selector.to_string()).or_default().push(*implementation);
    }
    Some(Metadata { classes, methods, selectors, implementations })
}

/// The message send that the call at `at` makes, if its selector is known.
pub fn send_at(analysis: &Analysis, at: u64) -> Option<&MessageSend> {
    analysis.sends.binary_search_by_key(&at, |send| send.at).ok().map(|index| &analysis.sends[index])
}

/// The selector each of the linker's message-send stubs passes, by stub address. A stub loads
/// its selector into the second argument register and jumps to `objc_msgSend`.
fn stub_selectors<'a, A: Arch>(image: &Image, metadata: &'a Metadata) -> FxHashMap<u64, &'a str> {
    let mut stubs = FxHashMap::default();
    for section in image.sections.iter().filter(|section| section.name == "__TEXT,__objc_stubs") {
        let mut state = A::State::default();
        let mut start = None;
        for decoded in A::decode(&section.data, section.addr) {
            let Some(insn) = decoded.insn else { continue };
            match A::flow(&insn, &state) {
                // Traps pad the space between stubs.
                Some(Flow::Halt) => {}
                Some(_) => {
                    let selector = A::second_argument_slot(&state).and_then(|slot| metadata.selectors.get(&slot));
                    stubs.extend(selector.map(|selector| (start.unwrap_or(decoded.addr), selector.as_str())));
                    (state, start) = (A::State::default(), None);
                }
                None => {
                    start.get_or_insert(decoded.addr);
                    A::step(&mut state, &insn);
                }
            }
        }
    }
    stubs
}

/// Whether an import is one of the runtime's message dispatchers, and if so whether it sends
/// to the superclass, whose implementation is never the one the selector alone suggests.
/// The variants that return a structure through a pointer take the selector third, and are
/// left out.
fn dispatcher(import: &str) -> Option<bool> {
    match import {
        "objc_msgSend" | "objc_msgSend_fpret" | "objc_msgSend_fp2ret" => Some(false),
        "objc_msgSendSuper" | "objc_msgSendSuper2" => Some(true),
        _ => None,
    }
}

/// The message sends among `calls`, sorted by address: every call to a message dispatcher whose
/// selector is known where the call is made. `pieces` are the `[start, end)` stretches of code
/// the calls were found in, and `join_points` the targets of the image's jump tables.
///
/// One pass over each piece that sends anything. Registers are followed in a straight line and
/// forgotten wherever paths meet, so a selector is reported only when every path to the call
/// loads the same one.
pub fn sends<A: Arch>(image: &Image, metadata: &Metadata, pieces: &[(u64, u64)], calls: &[CallSite], join_points: &FxHashSet<u64>) -> Vec<MessageSend> {
    let stubs = stub_selectors::<A>(image, metadata);
    let dispatchers: FxHashMap<u64, bool> = image.import_slots.iter().filter_map(|(&slot, name)| Some((slot, dispatcher(name)?))).collect();
    let dispatched = |call: &CallSite| match call.target {
        CallTarget::Import(slot) => dispatchers.get(&slot).copied(),
        CallTarget::Function(_) => None,
    };
    let mut sends: Vec<MessageSend> = pieces
        .par_iter()
        .flat_map_iter(|&(start, end)| {
            let calls = &calls[calls.partition_point(|call| call.at < start)..calls.partition_point(|call| call.at < end)];
            let mut found = Vec::new();
            let bytes = image.bytes_from(start).filter(|_| calls.iter().any(|call| dispatched(call).is_some())).unwrap_or(&[]);
            let bytes = &bytes[..bytes.len().min((end - start) as usize)];
            // Where paths meet: every address a branch in the piece goes to.
            let fresh = A::State::default();
            let joins: FxHashSet<u64> = A::decode(bytes, start)
                .filter_map(|decoded| match A::flow(&decoded.insn?, &fresh)? {
                    Flow::Branch(target) | Flow::Jump(target) => Some(target),
                    _ => None,
                })
                .collect();

            let mut state = A::State::default();
            for decoded in A::decode(bytes, start) {
                let Some(insn) = decoded.insn else { continue };
                if joins.contains(&decoded.addr) || join_points.contains(&decoded.addr) {
                    state = A::State::default();
                }
                let Some(flow) = A::flow(&insn, &state) else {
                    A::step(&mut state, &insn);
                    continue;
                };
                let call = calls.binary_search_by_key(&decoded.addr, |call| call.at).ok().map(|index| &calls[index]);
                if let Some((call, to_super)) = call.and_then(|call| Some((call, dispatched(call)?))) {
                    let through_stub = match flow {
                        Flow::Call(target) | Flow::Jump(target) | Flow::Branch(target) => stubs.get(&target).copied(),
                        _ => None,
                    };
                    let selector = through_stub.or_else(|| A::second_argument_slot(&state).and_then(|slot| metadata.selectors.get(&slot)).map(String::as_str));
                    found.extend(selector.map(|selector| MessageSend {
                        at: call.at,
                        selector: selector.to_string(),
                        implementation: match metadata.implementations.get(selector).map(Vec::as_slice) {
                            Some(&[only]) if !to_super => Some(only),
                            _ => None,
                        },
                    }));
                }
                match flow {
                    Flow::Call(_) | Flow::CallIndirect(_) => A::step(&mut state, &insn),
                    Flow::Branch(_) => drop(A::branch(&mut state, &insn)),
                    // Nothing falls through to what follows.
                    _ => state = A::State::default(),
                }
            }
            found
        })
        .collect();
    sends.sort_unstable_by_key(|send| send.at);
    sends.dedup_by_key(|send| send.at);
    sends
}

#[cfg(test)]
mod tests {
    use super::swift_class_name;

    #[test]
    fn swift_class_names_spell_out_module_and_type() {
        assert_eq!(swift_class_name("_TtC14coconutBattery11AppDelegate").as_deref(), Some("coconutBattery.AppDelegate"));
        assert_eq!(swift_class_name("_TtCC3App5Outer5Inner").as_deref(), Some("App.Outer.Inner"));
        // Newer manglings and plain Objective-C names are left as they are.
        assert_eq!(swift_class_name("_TtCs12_SwiftObject"), None);
        assert_eq!(swift_class_name("NSObject"), None);
    }
}
