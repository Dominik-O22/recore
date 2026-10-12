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
const CLASS: u32 = 16;
const STRUCT: u32 = 17;

/// An image with a class `Shapes.Shape` of two methods, a generic struct `Shapes.Box` whose
/// metadata is completed at run time, and a conformance of the class that the runtime
/// instantiates.
fn shapes() -> Image {
    let records = Words::at(0x2000)
        // The class: flags saying it has a vtable, parent, name, accessor, fields, superclass
        // and five words of metadata layout, then the vtable's place and its two methods.
        .word(CLASS | UNIQUE | 1 << 31)
        .to(0x2100)
        .to(0x2110)
        .to(0x1000)
        .bytes(&[0; 28])
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
        // two witnesses and the instantiator that follow. The second witness is a name.
        .word(0)
        .to(0x2000)
        .word(0)
        .word(1 << 16 | 1 << 17)
        .word(2)
        .word(0)
        .to(0x1060)
        .word(0)
        .to(0x3200)
        .word(0)
        .to(0x1070)
        .until(0x2100)
        // The module both types are in, and the names.
        .word(UNIQUE)
        .word(0)
        .to(0x2120)
        .until(0x2110)
        .bytes(b"Shape\0Box\0\0\0\0\0\0\0Shapes\0");
    // A reference to the accessor of an associated conformance, then a name with a reference
    // to a type, whose offset is not a function's even if it would lead into code.
    let names = Words::at(0x3200).bytes(&[0xFF, 0x07]).to(0x1080).bytes(b"\0Si\0\x01").to(0x1090).bytes(b"V\0");
    let sections = vec![
        Words::at(0x1000).until(0x1100).section("__TEXT,__text"),
        records.section("__TEXT,__const"),
        Words::at(0x3000).to(0x2000).to(0x2050).section("__TEXT,__swift5_types"),
        Words::at(0x3100).to(0x20a0).section("__TEXT,__swift5_proto"),
        names.section("__TEXT,__swift5_typeref"),
    ];
    Image {
        name: "shapes".into(),
        format: Format::MachO,
        machine: Machine::Aarch64,
        base: 0,
        branch_targets_marked: false,
        entry: 0x1000,
        sections,
        zero_filled: Vec::new(),
        import_slots: Default::default(),
        exports: Vec::new(),
        symbol_names: Default::default(),
        frames: Vec::new(),
        relative_targets: Vec::new(),
        data_in_code: false,
    }
}

#[test]
fn descriptors_lead_to_the_functions_the_runtime_calls() {
    let metadata = recore::swift::metadata(&shapes()).unwrap();
    // The class's accessor and methods, the struct's accessor, instantiation and completion,
    // the conformance's witness and instantiator, and the accessor a name refers to.
    assert_eq!(metadata.functions, [0x1000, 0x1010, 0x1020, 0x1030, 0x1040, 0x1050, 0x1060, 0x1070, 0x1080]);
}

#[test]
fn an_image_without_swift_has_no_metadata() {
    let mut image = shapes();
    image.sections.retain(|section| !section.name.contains("__swift5"));
    assert!(recore::swift::metadata(&image).is_none());
}
