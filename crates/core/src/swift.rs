//! Swift as a Mach-O image records it: the nominal types with their fields and methods, their
//! conformances to protocols, and the functions the runtime reaches through them.
//!
//! The compiler lists every type in `__swift5_types`, every conformance in `__swift5_proto`
//! and every protocol in `__swift5_protos`, each entry a 32-bit offset to a descriptor. A
//! descriptor refers to everything else the same way, so the loader has no pointer to rebase
//! and nothing but the descriptor says that a metadata accessor, a method in a vtable or a
//! protocol witness is code. Reading them is one pass over those three sections.
//!
//! Names come from the same records. A type's descriptor names it and the module or type it
//! is declared in, and a conformance names its protocol and, for a protocol of another
//! library, each requirement a witness implements. A method in a vtable has no name of its
//! own in the image: it is named by its kind and its place, as `Shapes.Shape.getter_2`.

use rustc_hash::FxHashMap;

use crate::image::{Format, Image, Machine};
use crate::objc::Reader;
use crate::report::{Field, SwiftType};

/// Most entries read from one list in a descriptor.
const LONGEST: u64 = 1 << 16;

/// The kinds of context descriptor, in the low five bits of its flags.
const MODULE: u32 = 0;
const EXTENSION: u32 = 1;
const ANONYMOUS: u32 = 2;
const PROTOCOL: u32 = 3;
const CLASS: u32 = 16;
const STRUCT: u32 = 17;
const ENUM: u32 = 18;

/// What the image's Swift metadata says.
#[derive(Default)]
pub struct Metadata {
    /// Entry points of the functions the metadata refers to, sorted.
    pub functions: Vec<u64>,
    /// The names the metadata gives some of them, such as `type metadata accessor for
    /// Shapes.Shape`, spelled as Swift's demangler spells the symbol where the metadata says
    /// enough for that.
    pub names: Vec<(u64, String)>,
    /// Classes, structs and enums in the order the image lists them.
    pub types: Vec<SwiftType>,
    /// The instance methods in the vtables of classes, each with its class's place in
    /// `types`: where a function is entered with an object of that class as `self`.
    pub instance_methods: Vec<(u64, usize)>,
}

/// Where the objects that trail a generic context's header end. The header at `header` counts
/// them: parameters of a byte each, requirements of three words, and what newer compilers add
/// for parameter packs, suppressed protocols and value parameters.
fn generic_end(reader: &Reader, header: u64) -> Option<u64> {
    const HAS_PACKS: u16 = 1;
    const HAS_CONDITIONAL_INVERTED_PROTOCOLS: u16 = 2;
    const HAS_VALUES: u16 = 4;
    let (parameters, requirements, flags) = (reader.u16(header)?, reader.u16(header + 2)?, reader.u16(header + 6)?);
    let mut at = (header + 8 + u64::from(parameters)).next_multiple_of(4) + 12 * u64::from(requirements);
    if flags & HAS_PACKS != 0 {
        at += 4 + 8 * u64::from(reader.u16(at)?);
    }
    if flags & HAS_CONDITIONAL_INVERTED_PROTOCOLS != 0 {
        // A set of protocols, and for each a running total of the requirements that follow.
        let protocols = u64::from(reader.u16(at)?.count_ones());
        let total = if protocols == 0 { 0 } else { reader.u16(at + 2 * protocols)? };
        at = (at + 2 + 2 * protocols).next_multiple_of(4) + 12 * u64::from(total);
    }
    if flags & HAS_VALUES != 0 {
        at += 4 + 4 * u64::from(reader.u32(at)?);
    }
    Some(at)
}

/// What an offset that may go through a slot leads to: a record in this image, or the symbol
/// of another image the loader binds the slot to, demangled.
#[derive(Clone, Copy)]
enum Target<'a> {
    Local(u64),
    Import(&'a str),
}

/// A method override whose name waits until every vtable has been read: the class it is in,
/// what the method it replaces is, and its own code.
struct Override<'a> {
    class: usize,
    replaces: Target<'a>,
    implementation: u64,
}

/// Reads descriptors, and with `naming` also what they are called. Finding functions alone,
/// which loading an image needs, formats nothing.
struct Collector<'a> {
    reader: Reader<'a>,
    naming: bool,
    functions: Vec<u64>,
    names: Vec<(u64, String)>,
    types: Vec<SwiftType>,
    /// Context descriptor to its qualified name, for the ones looked up so far.
    contexts: FxHashMap<u64, Option<String>>,
    /// Type descriptor to its place in `types`.
    type_index: FxHashMap<u64, usize>,
    /// A vtable's method descriptor, or a protocol's requirement, to what names it apart from
    /// the type: `getter_2`.
    members: FxHashMap<u64, String>,
    overrides: Vec<Override<'a>>,
    instance_methods: Vec<(u64, usize)>,
}

/// What a method or requirement is, from the low four bits of its flags.
fn member_kind(flags: u32, of_protocol: bool) -> &'static str {
    match (flags & 0xF, of_protocol) {
        (0, true) => "base",
        (0, false) | (1, true) => "method",
        (1, false) | (2, true) => "init",
        (2, false) | (3, true) => "getter",
        (3, false) | (4, true) => "setter",
        (4, false) | (6, true) => "modify",
        (5, _) => "read",
        _ => "requirement",
    }
}

impl<'a> Collector<'a> {
    /// Notes the function a 32-bit offset at `addr` leads to, and returns it. A zero offset is
    /// no function.
    fn function(&mut self, addr: u64) -> Option<u64> {
        let target = self.reader.relative(addr).filter(|&target| target != addr)?;
        self.functions.push(target);
        Some(target)
    }

    /// Notes the function a 32-bit offset at `addr` leads to under the name `name` makes.
    fn named(&mut self, addr: u64, name: impl FnOnce() -> String) {
        if let Some(function) = self.function(addr).filter(|_| self.naming) {
            self.names.push((function, name()));
        }
    }

    /// What the slot at `slot` holds.
    fn through(&self, slot: u64) -> Option<Target<'a>> {
        match self.reader.pointer(slot)? {
            0 => self.reader.image.import_slots.get(&slot).map(|import| Target::Import(import)),
            record => Some(Target::Local(record)),
        }
    }

    /// What the offset at `addr` leads to. An odd offset leads to a slot holding the address.
    fn target(&self, addr: u64) -> Option<Target<'a>> {
        let offset = self.reader.u32(addr).filter(|&offset| offset != 0)? as i32;
        let to = addr.wrapping_add_signed(i64::from(offset & !1));
        if offset & 1 == 0 { Some(Target::Local(to)) } else { self.through(to) }
    }

    /// The qualified name of what `target` leads to, a type or a protocol: the context's own
    /// when it is in this image, and otherwise what the demangled symbol says the descriptor
    /// is for.
    fn named_target(&mut self, target: Target) -> Option<String> {
        match target {
            Target::Local(descriptor) => self.context(descriptor),
            Target::Import(symbol) => symbol.split_once(" descriptor for ").map(|(_, name)| name.to_string()),
        }
    }

    /// The qualified name of the context at `descriptor`: `Module.Outer.Inner`. A private
    /// type sits in an anonymous context, which adds nothing to the name.
    fn context(&mut self, descriptor: u64) -> Option<String> {
        if let Some(known) = self.contexts.get(&descriptor) {
            return known.clone();
        }
        // Guards against a parent chain that loops.
        self.contexts.insert(descriptor, None);
        let kind = self.reader.u32(descriptor)? & 0x1F;
        let own = self.reader.relative(descriptor + 8);
        let name = match kind {
            MODULE => self.reader.text(own?),
            // An extension stands for the type it extends.
            EXTENSION => self.type_name(own?),
            _ => {
                let parent = self.target(descriptor + 4).and_then(|parent| self.named_target(parent));
                match (kind, parent) {
                    (ANONYMOUS, parent) => parent,
                    (_, Some(parent)) => Some(format!("{parent}.{}", self.own_name(descriptor)?)),
                    (_, None) => self.own_name(descriptor),
                }
            }
        };
        self.contexts.insert(descriptor, name.clone());
        name
    }

    /// The name the type or protocol at `descriptor` is declared under. A type imported from
    /// C under another name than its own keeps the C name after its Swift one, marked `N`,
    /// and symbols are spelled with that.
    fn own_name(&self, descriptor: u64) -> Option<String> {
        const HAS_IMPORT_INFO: u32 = 1 << 18;
        let at = self.reader.relative(descriptor + 8)?;
        let name = self.reader.text(at)?;
        if self.reader.u32(descriptor)? & HAS_IMPORT_INFO == 0 || self.reader.u32(descriptor)? & 0x1F < CLASS {
            return Some(name);
        }
        let bytes = self.reader.image.bytes_from(at)?;
        let imported = bytes.split(|&byte| byte == 0).skip(1).take_while(|part| !part.is_empty()).find_map(|part| part.strip_prefix(b"N"));
        Some(imported.map_or(name, |imported| String::from_utf8_lossy(imported).into_owned()))
    }

    /// The module the context at `descriptor` is declared in, which for a type declared in
    /// an extension is the extension's and not that of the type it extends.
    fn module(&self, mut descriptor: u64) -> Option<String> {
        for _ in 0..64 {
            if self.reader.u32(descriptor)? & 0x1F == MODULE {
                return self.reader.text(self.reader.relative(descriptor + 8)?);
            }
            match self.target(descriptor + 4)? {
                Target::Local(parent) => descriptor = parent,
                Target::Import(_) => return None,
            }
        }
        None
    }

    /// The type a mangled name at `addr` spells, as Swift writes it: `Swift.Array<Shapes.Box>`.
    ///
    /// The image's names refer to its own types by offset and not by name, which the
    /// demangler cannot follow. Each reference is replaced by a made-up type the demangler
    /// prints as `Swift._000`, and that by the real name afterwards. Such a name holds no
    /// word a later part of the mangled name could refer back to, so the rest reads as it did.
    fn type_name(&mut self, addr: u64) -> Option<String> {
        let bytes = self.reader.image.bytes_from(addr)?;
        let mut mangled = String::from("$s");
        let mut referenced = Vec::new();
        let mut at = 0;
        loop {
            match *bytes.get(at)? {
                0 => break,
                // A context descriptor, direct or through a slot.
                kind @ (1 | 2) => {
                    let offset = addr + at as u64 + 1;
                    let to = offset.wrapping_add_signed(i64::from(self.reader.u32(offset)? as i32));
                    let target = if kind == 1 { Target::Local(to) } else { self.through(to)? };
                    let is_protocol = match target {
                        Target::Local(descriptor) => self.reader.u32(descriptor)? & 0x1F == PROTOCOL,
                        Target::Import(symbol) => symbol.starts_with("protocol descriptor"),
                    };
                    mangled.push_str(&format!("s4_{:03}{}", referenced.len(), if is_protocol { 'P' } else { 'V' }));
                    referenced.push(self.named_target(target)?);
                    at += 5;
                }
                // Other references stand for things that have no name to print.
                0x03..=0x1F => return None,
                byte if byte.is_ascii() => {
                    mangled.push(byte as char);
                    at += 1;
                }
                _ => return None,
            }
        }
        mangled.push('D');
        // A lone reference needs no demangler.
        if let ([name], 10) = (referenced.as_slice(), mangled.len()) {
            return Some(name.clone());
        }
        let mut name = swift_demangler::demangle(&mangled)?;
        for (index, real) in referenced.iter().enumerate() {
            name = name.replace(&format!("Swift._{index:03}"), real);
        }
        Some(name)
    }

    /// The fields the field descriptor at `descriptor` lists: stored properties, or the cases
    /// of an enum, of which those without a payload have no type.
    fn fields(&mut self, descriptor: u64) -> Vec<Field> {
        let (Some(size), Some(count)) = (self.reader.u16(descriptor + 10), self.reader.u32(descriptor + 12)) else { return Vec::new() };
        (0..u64::from(count).min(LONGEST))
            .map(|index| descriptor + 16 + index * u64::from(size))
            .filter_map(|record| {
                // Flags, then the type's mangled name and the field's name.
                let name = self.reader.text(self.reader.relative(record + 8)?)?;
                let type_name = self.reader.relative(record + 4).filter(|&mangled| mangled != record + 4).and_then(|mangled| self.type_name(mangled));
                Some(Field { name, type_name })
            })
            .collect()
    }

    /// The descriptor of a class, struct or enum: its metadata accessor, the functions that
    /// build the metadata of a generic or lazily completed type, and a class's methods.
    fn nominal_type(&mut self, descriptor: u64) -> Option<()> {
        const GENERIC: u32 = 1 << 7;
        /// How the metadata is completed at run time, in the low two bits of the kind's flags.
        const SINGLETON: u32 = 1;
        const FOREIGN: u32 = 2;
        const HAS_RESILIENT_SUPERCLASS: u32 = 1 << 13;
        const HAS_OVERRIDE_TABLE: u32 = 1 << 14;
        const HAS_VTABLE: u32 = 1 << 15;
        let flags = self.reader.u32(descriptor)?;
        let (kind, kind_flags) = (flags & 0x1F, flags >> 16);
        if !matches!(kind, CLASS | STRUCT | ENUM) {
            return None;
        }
        let name = if self.naming { self.context(descriptor)? } else { String::new() };
        let name = name.as_str();
        // Flags, parent, name, accessor and fields come first, then two words in a struct or
        // an enum and six in a class, the first of which names the superclass.
        let mut at = descriptor + if kind == CLASS { 44 } else { 28 };
        self.named(descriptor + 12, || format!("type metadata accessor for {name}"));
        let class = self.types.len();
        if self.naming {
            let fields = self.reader.relative(descriptor + 16).filter(|&fields| fields != descriptor + 16).map_or_else(Vec::new, |fields| self.fields(fields));
            let superclass = self.reader.relative(descriptor + 20).filter(|&mangled| kind == CLASS && mangled != descriptor + 20);
            let bases = superclass.and_then(|mangled| self.type_name(mangled)).into_iter().collect();
            let kind = if kind == CLASS { "class" } else if kind == STRUCT { "struct" } else { "enum" };
            self.type_index.insert(descriptor, class);
            self.types.push(SwiftType { name: name.to_string(), kind: kind.to_string(), descriptor, bases, fields, methods: Vec::new(), conformances: Vec::new() });
        }
        if flags & GENERIC != 0 {
            // An instantiation cache and a pattern precede the generic header. The pattern
            // opens with the functions that instantiate and complete the metadata, and a
            // class's goes on with its destructor and the one for its instance variables.
            if let Some(pattern) = self.reader.relative(at + 4).filter(|&pattern| pattern != at + 4) {
                self.named(pattern, || format!("type metadata instantiation function for {name}"));
                self.named(pattern + 4, || format!("type metadata completion function for {name}"));
                if kind == CLASS {
                    self.named(pattern + 8, || format!("{name}.__deallocating_deinit"));
                    self.function(pattern + 12);
                }
            }
            at = generic_end(&self.reader, at + 8)?;
        }
        if kind == CLASS && kind_flags & HAS_RESILIENT_SUPERCLASS != 0 {
            at += 4;
        }
        match kind_flags & 3 {
            FOREIGN => {
                self.function(at);
                at += 4;
            }
            // A cache and the incomplete metadata, then the function that completes it.
            SINGLETON => {
                self.named(at + 8, || format!("type metadata completion function for {name}"));
                at += 12;
            }
            _ => {}
        }
        if kind != CLASS {
            return Some(());
        }
        if kind_flags & HAS_VTABLE != 0 {
            // The vtable's place in the class metadata and its length, then for each method
            // its flags and its implementation.
            let methods = u64::from(self.reader.u32(at + 4)?).min(LONGEST);
            for index in 0..methods {
                let method = at + 8 + 8 * index;
                let implementation = self.function(method + 4);
                if self.naming {
                    /// Set for a method of an object, and clear for one of the type.
                    const INSTANCE: u32 = 1 << 4;
                    let flags = self.reader.u32(method)?;
                    self.instance_methods.extend(implementation.filter(|_| flags & INSTANCE != 0).map(|implementation| (implementation, class)));
                    let member = format!("{}_{index}", member_kind(flags, false));
                    self.names.extend(implementation.map(|implementation| (implementation, format!("{name}.{member}"))));
                    // An abstract method has no code, and still takes up its place.
                    self.types[class].methods.push(implementation.unwrap_or(0));
                    self.members.insert(method, member);
                }
            }
            at += 8 + 8 * methods;
        }
        if kind_flags & HAS_OVERRIDE_TABLE != 0 {
            // Each override names the class and the method it replaces before its own code.
            let overrides = u64::from(self.reader.u32(at)?).min(LONGEST);
            for entry in (0..overrides).map(|index| at + 4 + 12 * index) {
                let implementation = self.function(entry + 8);
                if let (Some(implementation), Some(replaces), true) = (implementation, self.target(entry + 4), self.naming) {
                    self.overrides.push(Override { class, replaces, implementation });
                }
            }
        }
        Some(())
    }

    /// Names each override after the method it replaces: by that method's place in the vtable
    /// of a class of this image, and by its symbol when another library declares it.
    fn name_overrides(&mut self) {
        for Override { class, replaces, implementation } in std::mem::take(&mut self.overrides) {
            let class = &mut self.types[class];
            let member = match replaces {
                Target::Local(method) => self.members.get(&method).cloned(),
                // `method descriptor for Base.draw() -> ()`, of which the part after the
                // superclass is the member.
                Target::Import(symbol) => symbol.strip_prefix("method descriptor for ").and_then(|method| {
                    class.bases.iter().find_map(|base| Some(method.strip_prefix(base.as_str())?.strip_prefix('.')?.to_string()))
                }),
            };
            class.methods.push(implementation);
            self.names.extend(member.map(|member| (implementation, format!("{}.{member}", class.name))));
        }
    }

    /// Where the requirements of the protocol at `descriptor` start, and how many it has.
    fn requirements(&self, descriptor: u64) -> Option<(u64, u64)> {
        let (in_signature, requirements) = (self.reader.u32(descriptor + 12)?, self.reader.u32(descriptor + 16)?);
        Some((descriptor + 24 + 12 * u64::from(in_signature).min(LONGEST), u64::from(requirements).min(LONGEST)))
    }

    /// A protocol's descriptor: the default implementations of its requirements.
    fn protocol(&mut self, descriptor: u64) -> Option<()> {
        let (first, requirements) = self.requirements(descriptor)?;
        for index in 0..requirements {
            // Flags, then the default implementation.
            let requirement = first + 8 * index;
            self.function(requirement + 4);
            if self.naming {
                self.members.insert(requirement, format!("{}_{index}", member_kind(self.reader.u32(requirement)?, true)));
            }
        }
        Some(())
    }

    /// A conformance's descriptor: the witnesses the runtime copies into a witness table it
    /// builds, and the function that instantiates the table of a generic conformance. A
    /// witness that is no function is a mangled name, and not in code. A witness table that
    /// is complete in the file holds plain pointers, which the loader rebases; its witnesses
    /// are named here when the protocol is one of this image.
    fn conformance(&mut self, descriptor: u64) -> Option<()> {
        const RETROACTIVE: u32 = 1 << 6;
        const HAS_RESILIENT_WITNESSES: u32 = 1 << 16;
        const HAS_GENERIC_WITNESS_TABLE: u32 = 1 << 17;
        let flags = self.reader.u32(descriptor + 12)?;
        let mut at = descriptor + 16;
        let conformance = if self.naming { self.conformance_name(descriptor, flags) } else { None };
        let conformance = conformance.as_deref();
        if flags & RETROACTIVE != 0 {
            at += 4;
        }
        // Conditional requirements, then the shapes of conditional parameter packs.
        at += 12 * u64::from(flags >> 8 & 0xFF) + 8 * u64::from(flags >> 24);
        if flags & HAS_RESILIENT_WITNESSES != 0 {
            let witnesses = u64::from(self.reader.u32(at)?).min(LONGEST);
            for entry in (0..witnesses).map(|index| at + 4 + 8 * index) {
                let witness = self.function(entry + 4);
                if let (Some(witness), Some(requirement), Some(conformance)) = (witness, self.target(entry), conformance) {
                    self.name_witness(witness, requirement, conformance);
                }
            }
            at += 4 + 8 * witnesses;
        }
        if flags & HAS_GENERIC_WITNESS_TABLE != 0 {
            // The table's sizes, then its instantiator.
            let instantiator = self.function(at + 4);
            let name = |conformance| format!("instantiation function for generic protocol witness table for {conformance}");
            self.names.extend(instantiator.zip(conformance.map(name)));
        }
        // The table in the file: the descriptor, then a witness for each requirement.
        let table = self.reader.relative(descriptor + 8).filter(|&table| table != descriptor + 8);
        if let (Some(conformance), Some(Target::Local(protocol)), Some(table)) = (conformance, self.target(descriptor), table) {
            let (first, requirements) = self.requirements(protocol)?;
            for index in 0..requirements {
                let witness = self.reader.pointer(table + 8 + 8 * index)?;
                self.name_witness(witness, Target::Local(first + 8 * index), conformance);
            }
        }
        Some(())
    }

    /// `Type : Protocol in Module` for the conformance at `descriptor`, and the protocol added
    /// to the type's conformances. The module is the one stated for a conformance declared
    /// apart from both its type and its protocol, and otherwise taken to be the one that
    /// declares the type when the type is of this image, and the protocol's when not: a guess
    /// where the image declares the two in different modules, as either may hold it.
    fn conformance_name(&mut self, descriptor: u64, flags: u32) -> Option<String> {
        const RETROACTIVE: u32 = 1 << 6;
        let protocol = self.target(descriptor).and_then(|protocol| self.named_target(protocol))?;
        let to = self.reader.relative(descriptor + 4)?;
        // How the type is referred to: its descriptor, a slot holding that, the name of an
        // Objective-C class, or a slot holding such a class.
        let local = match flags >> 3 & 7 {
            0 => Some(Target::Local(to)),
            1 => self.through(to),
            _ => None,
        };
        let (name, module) = match (local, flags >> 3 & 7) {
            (Some(Target::Local(local)), _) => {
                if let Some(index) = self.type_index.get(&local) {
                    self.types[*index].conformances.push(protocol.clone());
                }
                (self.context(local)?, self.module(local))
            }
            (Some(import), _) => (self.named_target(import)?, None),
            (None, 2) => (format!("__C.{}", self.reader.text(to)?), None),
            (None, _) => (format!("__C.{}", self.reader.class_at(to)?), None),
        };
        let stated = if flags & RETROACTIVE != 0 { self.target(descriptor + 16).and_then(|context| self.named_target(context)) } else { None };
        let module = match stated.or(module) {
            // The compiler writes the conformances of a type imported from C itself, into a
            // module of their own.
            _ if name.starts_with("__C.") => "__C_Synthesized".to_string(),
            Some(module) => module,
            None => protocol.split('.').next().unwrap_or_default().to_string(),
        };
        Some(format!("{name} : {protocol} in {module}"))
    }

    /// Names `witness`, the code that implements `requirement` in `conformance`: after the
    /// requirement's symbol when another library declares the protocol, and after its kind
    /// and place when this image does.
    fn name_witness(&mut self, witness: u64, requirement: Target, conformance: &str) {
        let protocol = || Some(conformance.split_once(" : ")?.1.rsplit_once(" in ")?.0);
        let requirement = match requirement {
            Target::Import(symbol) => symbol.strip_prefix("method descriptor for ").map(str::to_string),
            Target::Local(requirement) => self.members.get(&requirement).and_then(|member| Some(format!("{}.{member}", protocol()?))),
        };
        self.names.extend(requirement.map(|requirement| (witness, format!("protocol witness for {requirement} in conformance {conformance}"))));
    }
}

/// The functions the mangled names in `names`, a `__swift5_typeref` section at `addr`, refer
/// to. Names lie back to back, each ended by a zero byte. A control byte in one opens a
/// symbolic reference: a 32-bit offset in place of the spelled-out name of a type, or of a
/// function that finds one, which is what witness tables hold for the conformances of
/// associated types and inherited protocols until the runtime calls it.
fn accessors(names: &[u8], addr: u64) -> Vec<u64> {
    /// A function that returns type metadata.
    const METADATA_ACCESSOR: u8 = 0x09;
    /// Follows `0xFF`: a function that returns the witness table of an associated conformance.
    const CONFORMANCE_ACCESSOR: u8 = 0x07;
    let mut found = Vec::new();
    let mut at = 0;
    while let Some(&byte) = names.get(at) {
        // The byte before an offset, and how far the reference reaches: offsets are four
        // bytes, and the references above 0x17 hold whole pointers.
        let (accessor, length) = match byte {
            0xFF if names.get(at + 1) == Some(&CONFORMANCE_ACCESSOR) => (true, 6),
            0x01..=0x17 => (byte == METADATA_ACCESSOR, 5),
            0x18..=0x1F => (false, 9),
            _ => (false, 1),
        };
        if let Some(offset) = names.get(at + length - 4..at + length).filter(|_| accessor) {
            let offset = i32::from_le_bytes(offset.try_into().unwrap());
            found.push((addr + (at + length - 4) as u64).wrapping_add_signed(offset.into()));
        }
        at += length;
    }
    found
}

/// Reads the image's Swift metadata. `None` for an image that has none.
pub fn metadata(image: &Image) -> Option<Metadata> {
    read(image, true)
}

/// Entry points of the functions the image's Swift metadata refers to, sorted: what
/// [`metadata`] finds, without the names.
pub fn functions(image: &Image) -> Vec<u64> {
    read(image, false).map(|metadata| metadata.functions).unwrap_or_default()
}

fn read(image: &Image, naming: bool) -> Option<Metadata> {
    if image.format != Format::MachO {
        return None;
    }
    let reader = Reader { image };
    let mut collector = Collector {
        reader: Reader { image },
        naming,
        functions: Vec::new(),
        names: Vec::new(),
        types: Vec::new(),
        contexts: FxHashMap::default(),
        type_index: FxHashMap::default(),
        members: FxHashMap::default(),
        overrides: Vec::new(),
        instance_methods: Vec::new(),
    };
    let mut found = false;
    // The low bits of an entry say whether it leads to the descriptor or to a slot the loader
    // binds to one in another image.
    let local = |(slot, offset): (u64, u32)| (offset & 1 == 0).then(|| slot.wrapping_add_signed(i64::from((offset & !3) as i32)));
    for descriptor in reader.words("__swift5_types").inspect(|_| found = true).filter_map(local) {
        collector.nominal_type(descriptor);
    }
    collector.name_overrides();
    for descriptor in reader.words("__swift5_protos").inspect(|_| found = true).filter_map(local) {
        if reader.u32(descriptor).is_some_and(|flags| flags & 0x1F == PROTOCOL) {
            collector.protocol(descriptor);
        }
    }
    for descriptor in reader.words("__swift5_proto").inspect(|_| found = true).filter_map(local) {
        collector.conformance(descriptor);
    }
    if !found {
        return None;
    }
    for section in reader.sections("__swift5_typeref") {
        collector.functions.extend(accessors(&section.data, section.addr));
    }
    // Where each asynchronous function is entered, which a caller finds through a record
    // of that offset and the size of the frame to allocate.
    collector.functions.extend(reader.words("__swift_as_entry").map(|(slot, offset)| slot.wrapping_add_signed(i64::from(offset as i32))));

    let aligned = |addr: u64| image.machine != Machine::Aarch64 || addr.is_multiple_of(4);
    let is_function = |addr: u64| aligned(addr) && image.section_at(addr).is_some_and(|section| section.executable && !section.is_stubs());
    let Collector { mut functions, mut names, types, instance_methods, .. } = collector;
    functions.retain(|&addr| is_function(addr));
    functions.sort_unstable();
    functions.dedup();
    // Functions that compile to the same code are one function under several names, of which
    // none is truer than another: the first read stands.
    names.retain(|&(addr, _)| is_function(addr));
    names.sort_by_key(|name| name.0);
    names.dedup_by_key(|name| name.0);
    Some(Metadata { functions, names, types, instance_methods })
}
