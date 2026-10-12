//! Swift as a Mach-O image records it: the nominal types, their conformances to protocols, and
//! the functions the runtime reaches through them.
//!
//! The compiler lists every type in `__swift5_types`, every conformance in `__swift5_proto`
//! and every protocol in `__swift5_protos`, each entry a 32-bit offset to a descriptor. A
//! descriptor refers to everything else the same way, so the loader has no pointer to rebase
//! and nothing but the descriptor says that a metadata accessor, a method in a vtable or a
//! protocol witness is code. Reading them is one pass over those three sections.

use crate::image::{Format, Image, Machine};
use crate::objc::Reader;

/// Most entries read from one list in a descriptor.
const LONGEST: u64 = 1 << 16;

/// The kinds of context descriptor, in the low five bits of its flags.
const PROTOCOL: u32 = 3;
const CLASS: u32 = 16;

/// What the image's Swift metadata says.
#[derive(Default)]
pub struct Metadata {
    /// Entry points of the functions the metadata refers to.
    pub functions: Vec<u64>,
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

struct Collector<'a> {
    reader: Reader<'a>,
    functions: Vec<u64>,
}

impl Collector<'_> {
    /// Notes the function a 32-bit offset at `addr` leads to. A zero offset is no function.
    fn function(&mut self, addr: u64) {
        let target = self.reader.relative(addr).filter(|&target| target != addr);
        self.functions.extend(target);
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
        // Flags, parent, name, accessor and fields come first, then two words in a struct or
        // an enum and six in a class.
        let mut at = descriptor + if kind == CLASS { 44 } else { 28 };
        self.function(descriptor + 12);
        if flags & GENERIC != 0 {
            // An instantiation cache and a pattern precede the generic header. The pattern
            // opens with the functions that instantiate and complete the metadata, and a
            // class's goes on with its destructor and the one for its instance variables.
            if let Some(pattern) = self.reader.relative(at + 4).filter(|&pattern| pattern != at + 4) {
                (0..if kind == CLASS { 4 } else { 2 }).for_each(|word| self.function(pattern + 4 * word));
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
                self.function(at + 8);
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
            (0..methods).for_each(|index| self.function(at + 8 + 8 * index + 4));
            at += 8 + 8 * methods;
        }
        if kind_flags & HAS_OVERRIDE_TABLE != 0 {
            // Each override names the class and the method it replaces before its own code.
            let overrides = u64::from(self.reader.u32(at)?).min(LONGEST);
            (0..overrides).for_each(|index| self.function(at + 4 + 12 * index + 8));
        }
        Some(())
    }

    /// A protocol's descriptor: the default implementations of its requirements.
    fn protocol(&mut self, descriptor: u64) -> Option<()> {
        let (in_signature, requirements) = (self.reader.u32(descriptor + 12)?, self.reader.u32(descriptor + 16)?);
        let first = descriptor + 24 + 12 * u64::from(in_signature).min(LONGEST);
        (0..u64::from(requirements).min(LONGEST)).for_each(|index| self.function(first + 8 * index + 4));
        Some(())
    }

    /// A conformance's descriptor: the witnesses the runtime copies into a witness table it
    /// builds, and the function that instantiates the table of a generic conformance. A
    /// witness that is no function is a mangled name, and not in code. A witness table that
    /// is complete in the file holds plain pointers, which the loader rebases.
    fn conformance(&mut self, descriptor: u64) -> Option<()> {
        const RETROACTIVE: u32 = 1 << 6;
        const HAS_RESILIENT_WITNESSES: u32 = 1 << 16;
        const HAS_GENERIC_WITNESS_TABLE: u32 = 1 << 17;
        let flags = self.reader.u32(descriptor + 12)?;
        let mut at = descriptor + 16;
        if flags & RETROACTIVE != 0 {
            at += 4;
        }
        // Conditional requirements, then the shapes of conditional parameter packs.
        at += 12 * u64::from(flags >> 8 & 0xFF) + 8 * u64::from(flags >> 24);
        if flags & HAS_RESILIENT_WITNESSES != 0 {
            let witnesses = u64::from(self.reader.u32(at)?).min(LONGEST);
            (0..witnesses).for_each(|index| self.function(at + 4 + 8 * index + 4));
            at += 4 + 8 * witnesses;
        }
        if flags & HAS_GENERIC_WITNESS_TABLE != 0 {
            // The table's sizes, then its instantiator.
            self.function(at + 4);
        }
        Some(())
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
    if image.format != Format::MachO {
        return None;
    }
    let reader = Reader { image };
    let mut collector = Collector { reader: Reader { image }, functions: Vec::new() };
    let mut found = false;
    // The low bits of an entry say whether it leads to the descriptor or to a slot the loader
    // binds to one in another image.
    let local = |(slot, offset): (u64, u32)| (offset & 1 == 0).then(|| slot.wrapping_add_signed(i64::from((offset & !3) as i32)));
    for descriptor in reader.words("__swift5_types").inspect(|_| found = true).filter_map(local) {
        collector.nominal_type(descriptor);
    }
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

    let aligned = |addr: u64| image.machine != Machine::Aarch64 || addr % 4 == 0;
    let mut functions = collector.functions;
    functions.retain(|&addr| aligned(addr) && image.section_at(addr).is_some_and(|section| section.executable && !section.is_stubs()));
    functions.sort_unstable();
    functions.dedup();
    Some(Metadata { functions })
}
