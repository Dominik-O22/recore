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
    pub selectors: FxHashMap<u64, String>,
    /// Slot that holds a class, in `__objc_classrefs` or among the import slots, to the name of
    /// the class, which is in this image or imported.
    pub class_refs: FxHashMap<u64, String>,
    /// Selector to the implementations of it in this image.
    implementations: FxHashMap<String, Vec<u64>>,
}

/// Reads the image's metadata records: Objective-C's here, and Swift's in [`crate::swift`].
pub(crate) struct Reader<'a> {
    pub(crate) image: &'a Image,
}

impl<'a> Reader<'a> {
    pub(crate) fn u16(&self, addr: u64) -> Option<u16> {
        Some(u16::from_le_bytes(self.image.bytes_from(addr)?.get(..2)?.try_into().ok()?))
    }

    pub(crate) fn u32(&self, addr: u64) -> Option<u32> {
        Some(u32::from_le_bytes(self.image.bytes_from(addr)?.get(..4)?.try_into().ok()?))
    }

    pub(crate) fn pointer(&self, addr: u64) -> Option<u64> {
        Some(u64::from_le_bytes(self.image.bytes_from(addr)?.get(..8)?.try_into().ok()?))
    }

    /// The address a 32-bit offset stored at `addr` leads to, counted from `addr` itself.
    pub(crate) fn relative(&self, addr: u64) -> Option<u64> {
        Some(addr.wrapping_add_signed(i64::from(self.u32(addr)? as i32)))
    }

    pub(crate) fn text(&self, addr: u64) -> Option<String> {
        let bytes = self.image.bytes_from(addr)?;
        Some(String::from_utf8_lossy(&bytes[..bytes.iter().position(|&byte| byte == 0)?]).into_owned())
    }

    /// The sections called `name`, whichever segment holds them.
    pub(crate) fn sections(&self, name: &'a str) -> impl Iterator<Item = &'a crate::image::Section> + 'a {
        self.image.sections.iter().filter(move |section| section.name.rsplit_once(',').is_some_and(|(_, section)| section == name))
    }

    /// The 32-bit words stored in the section called `name`, with the address of each.
    pub(crate) fn words(&self, name: &'a str) -> impl Iterator<Item = (u64, u32)> + 'a {
        self.sections(name).flat_map(|section| {
            section.data.as_chunks::<4>().0.iter().zip((section.addr..).step_by(4)).map(|(bytes, slot)| (slot, u32::from_le_bytes(*bytes)))
        })
    }

    /// The pointers stored in the section called `name`, with the slot of each.
    fn pointers(&self, name: &'a str) -> impl Iterator<Item = (u64, u64)> + 'a {
        self.sections(name).flat_map(|section| {
            section.data.as_chunks::<8>().0.iter().zip((section.addr..).step_by(8)).map(|(bytes, slot)| (slot, u64::from_le_bytes(*bytes)))
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
    pub(crate) fn class_at(&self, slot: u64) -> Option<String> {
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
    let mut class_refs: FxHashMap<u64, String> = reader.pointers("__objc_classrefs").filter_map(|(slot, _)| Some((slot, reader.class_at(slot)?))).collect();
    // Newer linkers reach an imported class through an ordinary import slot instead.
    class_refs.extend(image.import_slots.iter().filter_map(|(&slot, import)| Some((slot, import.strip_prefix("OBJC_CLASS_$_")?.to_string()))));
    let mut implementations: FxHashMap<String, Vec<u64>> = FxHashMap::default();
    for (implementation, name) in &methods {
        // `-[Class selector]`: the selector follows the only space.
        let selector = name.rsplit_once(' ').map_or("", |(_, selector)| selector.trim_end_matches(']'));
        implementations.entry(selector.to_string()).or_default().push(*implementation);
    }
    Some(Metadata { classes, methods, selectors, class_refs, implementations })
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
        for decoded in A::decode(image, &section.data, section.addr) {
            let Some(insn) = decoded.insn else { continue };
            match A::flow(&insn, &state, image) {
                // Traps pad the space between stubs.
                Some(Flow::Halt) => {}
                Some(_) => {
                    let selector = A::argument_slot(&state, 1).and_then(|slot| metadata.selectors.get(&slot));
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

/// What a call to one of the Objective-C runtime's functions does with its first argument.
#[derive(Clone, Copy)]
enum Runtime {
    /// Sends a message to it, or with `true` to its superclass, whose implementation is never
    /// the one the selector alone suggests.
    Send(bool),
    /// Returns it: `objc_opt_self`, and the functions that retain or release.
    Returns,
    /// Returns its class: `objc_opt_class`.
    ClassOf,
    /// Takes a class and returns a new object of it: `objc_alloc` and the like.
    Allocates,
}

/// What an import does, if it is one of the runtime's functions that take an object and are
/// followed here. The dispatchers that return a structure through a pointer take the receiver
/// second and the selector third, and are left out.
fn runtime(import: &str) -> Option<Runtime> {
    Some(match import {
        "objc_msgSend" | "objc_msgSend_fpret" | "objc_msgSend_fp2ret" => Runtime::Send(false),
        "objc_msgSendSuper" | "objc_msgSendSuper2" => Runtime::Send(true),
        "objc_opt_class" => Runtime::ClassOf,
        "objc_alloc" | "objc_allocWithZone" | "objc_alloc_init" | "objc_opt_new" => Runtime::Allocates,
        "objc_opt_self" | "objc_retain" | "objc_autorelease" | "objc_retainAutorelease" | "objc_retainAutoreleasedReturnValue" | "objc_retainAutoreleaseReturnValue" => Runtime::Returns,
        "objc_autoreleaseReturnValue" | "objc_claimAutoreleasedReturnValue" | "objc_unsafeClaimAutoreleasedReturnValue" => Runtime::Returns,
        _ => return None,
    })
}

/// A class, or an object of one, as a number the architecture's register tracking carries
/// along: four times the class's place in a list of names, plus one for an object, plus two
/// when it may as well be a subclass or an object of one, as `self` in a method may.
#[derive(Clone, Copy, PartialEq)]
struct Object(u32);

impl Object {
    fn is_instance(self) -> bool {
        self.0 & 1 == 1
    }

    fn may_be_subclass(self) -> bool {
        self.0 & 2 == 2
    }

    fn class(self) -> Object {
        Object(self.0 & !1)
    }

    fn instance(self) -> Object {
        Object(self.0 | 1)
    }

    fn or_subclass(self) -> Object {
        Object(self.0 | 2)
    }

    /// What a message with `selector` sent to this returns, where the selector says: a new
    /// object of the class, the object itself once initialized, or its class.
    fn after(self, selector: &str) -> Option<Object> {
        match selector {
            "alloc" | "allocWithZone:" | "new" if !self.is_instance() => Some(self.instance()),
            "self" | "retain" | "autorelease" => Some(self),
            "class" => Some(self.class()),
            _ if self.is_instance() && selector.starts_with("init") => Some(self),
            _ => None,
        }
    }
}

/// The class names the image's code can be seen to use, each under a number.
#[derive(Default)]
struct ClassNames<'a> {
    names: Vec<&'a str>,
    numbers: FxHashMap<&'a str, u32>,
}

impl<'a> ClassNames<'a> {
    /// The class called `name`, itself and not an object of it.
    fn class(&mut self, name: &'a str) -> Object {
        let next = self.names.len() as u32;
        let number = *self.numbers.entry(name).or_insert(next);
        if number == next {
            self.names.push(name);
        }
        Object(4 * number)
    }

    fn name(&self, object: Object) -> &'a str {
        self.names[(object.0 / 4) as usize]
    }
}

/// `(whether it is an instance method, class, selector)` of a method name such as
/// `-[Square(Drawing) area]`, the category left out.
fn method_parts(name: &str) -> Option<(bool, &str, &str)> {
    let (class, selector) = name.get(2..name.len() - 1)?.split_once(' ')?;
    Some((name.starts_with('-'), class.split('(').next()?, selector))
}

/// The message sends among `calls`, sorted by address: every call to a message dispatcher whose
/// selector is known where the call is made. `pieces` are the `[start, end)` stretches of code
/// the calls were found in, and `join_points` the targets of the image's jump tables.
///
/// One pass over each piece that sends anything. Registers are followed in a straight line and
/// forgotten wherever paths meet, so a selector is reported only when every path to the call
/// loads the same one. A receiver is followed the same way from where its class is known: a
/// class loaded from a class reference, through the runtime calls that return it or allocate
/// an object of it and through `alloc` and `init`, and `self` from the entry of a method.
/// Swift fetches a class with `objc_opt_self` and keeps it in a register across calls, where
/// Objective-C loads it right before the send.
///
/// `swift_methods` are the entries of Swift methods with the class of the object each is
/// called on, which Swift passes in a register of its own.
pub fn sends<A: Arch>(image: &Image, metadata: &Metadata, swift_methods: &[(u64, &str)], pieces: &[(u64, u64)], calls: &[CallSite], join_points: &FxHashSet<u64>) -> Vec<MessageSend> {
    let stubs = stub_selectors::<A>(image, metadata);
    let runtime: FxHashMap<u64, Runtime> = image.import_slots.iter().filter_map(|(&slot, name)| Some((slot, runtime(name)?))).collect();
    let called = |call: &CallSite| match call.target {
        CallTarget::Import(slot) => runtime.get(&slot).copied(),
        CallTarget::Function(_) => None,
    };
    let mut classes = ClassNames::default();
    let class_refs: FxHashMap<u64, Object> = metadata.class_refs.iter().map(|(&slot, name)| (slot, classes.class(name))).collect();
    // `self` where a method starts, and each method under its name without the category.
    let mut receivers: FxHashMap<u64, Object> = FxHashMap::default();
    let mut methods: FxHashMap<(bool, &str, &str), u64> = FxHashMap::default();
    for (method, name) in &metadata.methods {
        let Some((instance, class, selector)) = method_parts(name) else { continue };
        let class_object = classes.class(class);
        receivers.insert(*method, if instance { class_object.instance() } else { class_object }.or_subclass());
        methods.entry((instance, class, selector)).or_insert(*method);
    }
    let swift_receivers: FxHashMap<u64, Object> = swift_methods.iter().map(|&(method, class)| (method, classes.class(class).instance().or_subclass())).collect();
    let bases: FxHashMap<&str, &[String]> = metadata.classes.iter().map(|class| (class.name.as_str(), class.bases.as_slice())).collect();
    // Methods some subclass in the image overrides, under the name of the class they are
    // inherited from.
    let mut overridden: FxHashSet<(bool, &str, &str)> = FxHashSet::default();
    for &(instance, class, selector) in methods.keys() {
        overridden.extend(bases.get(class).into_iter().flat_map(|bases| bases.iter().map(|base| (instance, base.as_str(), selector))));
    }
    // The method a message to `receiver` runs, if this image implements it: the class's own
    // or the nearest superclass's, unless the receiver may be of a subclass that has its own.
    let implementation = |receiver: Object, selector: &str| {
        let class = classes.name(receiver);
        if receiver.may_be_subclass() && overridden.contains(&(receiver.is_instance(), class, selector)) {
            return None;
        }
        let chain = std::iter::once(class).chain(bases.get(class).into_iter().flat_map(|bases| bases.iter().map(String::as_str)));
        chain.into_iter().find_map(|class| methods.get(&(receiver.is_instance(), class, selector)).copied())
    };

    let mut sends: Vec<MessageSend> = pieces
        .par_iter()
        .flat_map_iter(|&(start, end)| {
            let calls = &calls[calls.partition_point(|call| call.at < start)..calls.partition_point(|call| call.at < end)];
            let mut found = Vec::new();
            let bytes = image.bytes_from(start).filter(|_| calls.iter().any(|call| matches!(called(call), Some(Runtime::Send(_))))).unwrap_or(&[]);
            let bytes = &bytes[..bytes.len().min((end - start) as usize)];
            // Where paths meet: every address a branch in the piece goes to.
            let fresh = A::State::default();
            let joins: FxHashSet<u64> = A::decode(image, bytes, start)
                .filter_map(|decoded| match A::flow(&decoded.insn?, &fresh, image)? {
                    Flow::Branch(target) | Flow::Jump(target) => Some(target),
                    _ => None,
                })
                .collect();

            let mut state = A::State::default();
            if let Some(receiver) = receivers.get(&start) {
                A::set_argument_object(&mut state, 0, receiver.0);
            }
            if let Some(receiver) = swift_receivers.get(&start) {
                A::set_self_object(&mut state, receiver.0);
            }
            for decoded in A::decode(image, bytes, start) {
                let Some(insn) = decoded.insn else { continue };
                if joins.contains(&decoded.addr) || join_points.contains(&decoded.addr) {
                    state = A::State::default();
                }
                let Some(flow) = A::flow(&insn, &state, image) else {
                    A::step_following(&mut state, &insn);
                    continue;
                };
                let call = calls.binary_search_by_key(&decoded.addr, |call| call.at).ok().map(|index| &calls[index]);
                // What the call returns, when that is the class or object it is given.
                let mut result = None;
                if let Some((call, runtime)) = call.and_then(|call| Some((call, called(call)?))) {
                    let loaded = A::argument_slot(&state, 0).and_then(|slot| class_refs.get(&slot)).copied();
                    let receiver = loaded.or_else(|| A::argument_object(&state, 0).map(Object));
                    result = match runtime {
                        Runtime::Returns => receiver,
                        Runtime::ClassOf => receiver.map(Object::class),
                        Runtime::Allocates => receiver.filter(|receiver| !receiver.is_instance()).map(Object::instance),
                        Runtime::Send(_) => None,
                    };
                    if let Runtime::Send(to_super) = runtime {
                        let through_stub = match flow {
                            Flow::Call(target) | Flow::Jump(target) | Flow::Branch(target) => stubs.get(&target).copied(),
                            _ => None,
                        };
                        let selector = through_stub.or_else(|| A::argument_slot(&state, 1).and_then(|slot| metadata.selectors.get(&slot)).map(String::as_str));
                        // A send to the superclass takes a record of the receiver and the
                        // class, not the receiver.
                        let receiver = receiver.filter(|_| !to_super);
                        result = receiver.zip(selector).and_then(|(receiver, selector)| receiver.after(selector));
                        found.extend(selector.map(|selector| MessageSend {
                            at: call.at,
                            selector: selector.to_string(),
                            implementation: match (receiver, metadata.implementations.get(selector).map(Vec::as_slice)) {
                                (Some(receiver), _) => implementation(receiver, selector),
                                (None, Some(&[only])) if !to_super => Some(only),
                                _ => None,
                            },
                            receiver: receiver.map(|receiver| classes.name(receiver).to_string()),
                            instance: receiver.is_some_and(Object::is_instance),
                        }));
                    }
                }
                match flow {
                    Flow::Call(_) | Flow::CallIndirect(_) => {
                        A::step(&mut state, &insn);
                        if let Some(result) = result {
                            A::set_result_object(&mut state, result.0);
                        }
                    }
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
