//! Swift metadata, read from records laid out by hand: no Swift compiler builds for Mach-O
//! where these tests run, so each record is written word by word as the compiler emits it.

use recore::image::{Format, Image, Machine, Section};

/// A section's bytes as they are written, knowing where they will be loaded.
struct Words {
    addr: u64,
    data: Vec<u8>,
}

impl Words {
    fn at(addr: u64) -> Words {
        Words { addr, data: Vec::new() }
    }

    fn word(mut self, word: u32) -> Self {
        self.data.extend(word.to_le_bytes());
        self
    }

    fn bytes(mut self, bytes: &[u8]) -> Self {
        self.data.extend(bytes);
        self
    }

    /// A 32-bit offset from where it is stored to `target`.
    fn to(self, target: u64) -> Self {
        let here = self.addr + self.data.len() as u64;
        self.word(target.wrapping_sub(here) as u32)
    }

    /// Zero bytes up to `addr`.
    fn until(mut self, addr: u64) -> Self {
        assert!(self.addr + self.data.len() as u64 <= addr, "the record before {addr:#x} runs past it");
        self.data.resize((addr - self.addr) as usize, 0);
        self
    }

    fn section(self, name: &str) -> Section {
        Section { name: name.into(), addr: self.addr, data: self.data, file_offset: None, executable: name.ends_with("__text"), writable: false }
    }
}

const UNIQUE: u32 = 1 << 6;
const GENERIC: u32 = 1 << 7;
const PROTOCOL: u32 = 3;
const CLASS: u32 = 16;
const STRUCT: u32 = 17;

/// An image of a module `Shapes`: a class `Shape` with two fields and two methods, a generic
/// struct `Box` whose metadata is completed at run time, a protocol `Drawable` with one
/// method, and a conformance of the class to it that the runtime instantiates.
fn shapes() -> Image {
    let records = Words::at(0x2000)
        // The class: flags saying it has a vtable, parent, name, accessor, fields, superclass
        // and five words of metadata layout, then the vtable's place and its two methods, an
        // instance method and a getter.
        .word(CLASS | UNIQUE | 1 << 31)
        .to(0x2100)
        .to(0x2110)
        .to(0x1000)
        .to(0x2180)
        .bytes(&[0; 24])
        .word(10)
        .word(2)
        .word(0x10)
        .to(0x1010)
        .word(0x12)
        .to(0x1020)
        .until(0x2050)
        // The struct: generic, with metadata initialized once. Two words of layout, the
        // instantiation cache and pattern, one parameter, then the completion function.
        .word(STRUCT | UNIQUE | GENERIC | 1 << 16)
        .to(0x2100)
        .to(0x2116)
        .to(0x1030)
        .bytes(&[0; 12])
        .word(0)
        .to(0x2090)
        .bytes(&[1, 0, 0, 0, 1, 0, 0, 0, 0x80, 0, 0, 0])
        .bytes(&[0; 8])
        .to(0x1050)
        .until(0x2090)
        // The struct's metadata pattern: its instantiation function and no completion.
        .to(0x1040)
        .word(0)
        .until(0x20a0)
        // The conformance: protocol, type, no witness table in the file, and flags for the
        // two witnesses and the instantiator that follow. The first witness implements the
        // protocol's method, and the second is a name.
        .to(0x2140)
        .to(0x2000)
        .word(0)
        .word(1 << 16 | 1 << 17)
        .word(2)
        .to(0x2158)
        .to(0x1060)
        .word(0)
        .to(0x3200)
        .word(0)
        .to(0x1070)
        .until(0x2100)
        // The module all three are in, and the names.
        .word(UNIQUE)
        .word(0)
        .to(0x2120)
        .until(0x2110)
        .bytes(b"Shape\0Box\0\0\0\0\0\0\0Shapes\0\0Drawable\0side\0box\0")
        .until(0x2140)
        // The protocol: parent, name, nothing in its signature, and one requirement, a method
        // without a default implementation.
        .word(PROTOCOL | UNIQUE)
        .to(0x2100)
        .to(0x2128)
        .word(0)
        .word(1)
        .word(0)
        .word(1)
        .word(0)
        .until(0x2180)
        // The class's fields: no names of the type itself, the size of a record and their
        // number, then for each its flags, type and name.
        .bytes(&[0; 10])
        .bytes(&[12, 0, 2, 0, 0, 0])
        .word(0)
        .to(0x3210)
        .to(0x2131)
        .word(0)
        .to(0x3218)
        .to(0x2136);
    // A reference to the accessor of an associated conformance, then the fields' types:
    // `Double`, and `Box<Int>` with the struct referred to by offset.
    let names = Words::at(0x3200).bytes(&[0xFF, 0x07]).to(0x1080).until(0x3210).bytes(b"Sd\0").until(0x3218).bytes(&[1]).to(0x2050).bytes(b"ySiG\0");
    let sections = vec![
        Words::at(0x1000).until(0x1100).section("__TEXT,__text"),
        records.section("__TEXT,__const"),
        Words::at(0x3000).to(0x2000).to(0x2050).section("__TEXT,__swift5_types"),
        Words::at(0x3100).to(0x20a0).section("__TEXT,__swift5_proto"),
        Words::at(0x3180).to(0x2140).section("__TEXT,__swift5_protos"),
        names.section("__TEXT,__swift5_typeref"),
    ];
    Image::bare("shapes".into(), Format::MachO, Machine::Aarch64, 0x1000, sections)
}

#[test]
fn descriptors_lead_to_the_functions_the_runtime_calls() {
    // The class's accessor and methods, the struct's accessor, instantiation and completion,
    // the conformance's witness and instantiator, and the accessor a name refers to.
    assert_eq!(recore::swift::functions(&shapes()), [0x1000, 0x1010, 0x1020, 0x1030, 0x1040, 0x1050, 0x1060, 0x1070, 0x1080]);
}

#[test]
fn functions_are_named_by_what_refers_to_them() {
    let metadata = recore::swift::metadata(&shapes()).unwrap();
    let names: Vec<(u64, &str)> = metadata.names.iter().map(|(addr, name)| (*addr, name.as_str())).collect();
    assert_eq!(
        names,
        [
            (0x1000, "type metadata accessor for Shapes.Shape"),
            // A method has no name in the image: its kind and its place in the vtable.
            (0x1010, "Shapes.Shape.method_0"),
            (0x1020, "Shapes.Shape.getter_1"),
            (0x1030, "type metadata accessor for Shapes.Box"),
            (0x1040, "type metadata instantiation function for Shapes.Box"),
            (0x1050, "type metadata completion function for Shapes.Box"),
            (0x1060, "protocol witness for Shapes.Drawable.method_0 in conformance Shapes.Shape : Shapes.Drawable in Shapes"),
            (0x1070, "instantiation function for generic protocol witness table for Shapes.Shape : Shapes.Drawable in Shapes"),
        ]
    );
}

#[test]
fn types_list_their_fields_methods_and_conformances() {
    let metadata = recore::swift::metadata(&shapes()).unwrap();
    let [shape, shape_box] = metadata.types.as_slice() else { panic!("{} types", metadata.types.len()) };
    assert_eq!((shape.name.as_str(), shape.kind.as_str(), shape.descriptor), ("Shapes.Shape", "class", 0x2000));
    let fields: Vec<(&str, Option<&str>)> = shape.fields.iter().map(|field| (field.name.as_str(), field.type_name.as_deref())).collect();
    // The second field's type refers to the struct by offset, where a symbol would spell it.
    assert_eq!(fields, [("side", Some("Swift.Double")), ("box", Some("Shapes.Box<Swift.Int>"))]);
    assert_eq!(shape.methods, [0x1010, 0x1020]);
    assert_eq!(shape.conformances, ["Shapes.Drawable"]);
    assert_eq!((shape_box.name.as_str(), shape_box.kind.as_str(), shape_box.fields.len()), ("Shapes.Box", "struct", 0));
}

#[test]
fn an_image_without_swift_has_no_metadata() {
    let mut image = shapes();
    image.sections.retain(|section| !section.name.contains("__swift5"));
    assert!(recore::swift::metadata(&image).is_none());
}
