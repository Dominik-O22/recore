//! Loading a raw image through a layout file.

use std::path::PathBuf;

use recore::image::{Format, Image, Machine};
use recore::report::CallTarget;

/// Writes a layout and the bytes it places into a directory of their own, and returns the
/// layout's path.
fn write(name: &str, layout: &str, bytes: &[u8]) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("code.bin"), bytes).unwrap();
    let path = dir.join("image.toml");
    std::fs::write(&path, layout).unwrap();
    path
}

#[test]
fn a_region_loads_at_its_address_and_its_code_is_followed() {
    // Two bytes the layout skips, then at 0x401000: call 0x401006; ret; and at 0x401006: ret.
    let bytes = [0xAA, 0xAA, 0xE8, 0x01, 0x00, 0x00, 0x00, 0xC3, 0xC3, 0xAA];
    let layout = r#"
        machine = "x86-64"
        entry = [0x401000]

        [[region]]
        file = "code.bin"
        offset = 2
        length = 7
        address = 0x401000
        executable = true
        name = ".text"
    "#;
    let image = Image::load(&write("followed", layout, &bytes)).unwrap();
    assert_eq!((image.format, image.machine, image.entry, image.name.as_str()), (Format::Raw, Machine::X86_64, 0x401000, "image"));
    assert_eq!(image.text().map(|text| (text.addr, text.end())), Some((0x401000, 0x401007)));
    let functions: Vec<u64> = recore::analyze(&image).functions.iter().map(|function| function.addr).collect();
    assert_eq!(functions, [0x401000, 0x401006]);
}

#[test]
fn a_region_the_file_does_not_hold_is_refused() {
    let layout = r#"
        machine = "x86-64"
        entry = [0]

        [[region]]
        file = "code.bin"
        offset = 2
        length = 7
        address = 0
    "#;
    let error = Image::load(&write("refused", layout, &[0xC3; 8])).err().unwrap();
    assert_eq!(error.to_string(), r#""code.bin" has no 0x7 bytes at 0x2"#);
}

#[test]
fn banked_code_calls_through_a_trampoline_into_the_bank_it_names() {
    let mut bytes = vec![0; 0x80];
    let mut place = |at: usize, code: &[u8]| bytes[at..at + code.len()].copy_from_slice(code);
    // Common code. Reset: LJMP 0x0010. The stubs of bank 0 and bank 1.
    place(0x00, &[0x02, 0x00, 0x10]);
    place(0x03, &[0xE5, 0x30, 0x22, 0x00, 0x00, 0xE5, 0x30, 0x22, 0x00, 0x04]);
    // LCALL 0x0020, the entry; LCALL 0x0050, which no bank is named for; RET.
    place(0x10, &[0x12, 0x00, 0x20, 0x12, 0x00, 0x50, 0x22]);
    // The entry: 0x0040 by way of the stub of bank 1.
    place(0x20, &[0x90, 0x00, 0x40, 0x02, 0x00, 0x08]);
    place(0x30, &[0x22]);
    // Bank 0 past the common code.
    place(0x50, &[0x22]);
    // Bank 1, which the file holds after bank 0: at 0x0040, LCALL 0x0030 in the common code; RET.
    place(0x60, &[0x12, 0x00, 0x30, 0x22]);
    let layout = r#"
        machine = "8051"
        entry = [0x0000]

        [[region]]
        file = "code.bin"
        offset = 0
        length = 0x60
        address = 0x000000
        executable = true

        [[region]]
        file = "code.bin"
        offset = 0x60
        length = 0x20
        address = 0x010040
        executable = true

        [banking]
        common = [[0x0000, 0x0040]]

        [[banking.trampoline]]
        entry = "90 hh ll 02 ss ss"
        stub = "e5 30 22 00 .."
    "#;
    let image = Image::load(&write("banked", layout, &bytes)).unwrap();
    let analysis = recore::analyze(&image);
    // The stubs and the table of entries are code too, named for what they are.
    let functions: Vec<(u64, Option<&str>)> = analysis.functions.iter().map(|function| (function.addr, function.name.as_deref())).collect();
    let expected = [
        (0x0000, None),
        (0x0003, Some("bank_switch_0")),
        (0x0008, Some("bank_switch_1")),
        (0x0010, None),
        (0x0020, Some("bank_trampolines")),
        (0x0030, None),
        (0x0050, None),
        (0x1_0040, None),
    ];
    assert_eq!(functions, expected);
    assert_eq!(analysis.functions[4].ranges, [(0x0020, 0x0026)]);
    // A call of the entry is a call of the function, which the entry reaches by its stub.
    let calls: Vec<(u64, CallTarget)> = analysis.calls.iter().map(|call| (call.at, call.target)).collect();
    let function = CallTarget::Function;
    let expected = [
        (0x0000, function(0x0010)),
        (0x0010, function(0x1_0040)),
        (0x0013, function(0x0050)),
        (0x0020, function(0x1_0040)),
        (0x0023, function(0x0008)),
        (0x1_0040, function(0x0030)),
    ];
    assert_eq!(calls, expected);
    assert_eq!(recore::i8051::unbanked_transfers(&image, &analysis), [(0x0013, 0x0050)]);
}

#[test]
fn a_start_inside_the_first_instruction_of_a_shared_tail_ends_the_analysis() {
    // Two LJMP 0x0010; at 0x0010: MOV A, #0x22; RET. The second entry is the MOV's operand,
    // which reads as a RET, so the function the two jumps share has no room for an instruction.
    let mut bytes = vec![0; 0x13];
    bytes[..6].copy_from_slice(&[0x02, 0x00, 0x10, 0x02, 0x00, 0x10]);
    bytes[0x10..].copy_from_slice(&[0x74, 0x22, 0x22]);
    let layout = r#"
        machine = "8051"
        entry = [0x0000, 0x0003, 0x0011]

        [[region]]
        file = "code.bin"
        offset = 0
        length = 0x13
        address = 0
        executable = true
    "#;
    let image = Image::load(&write("shared-tail", layout, &bytes)).unwrap();
    let functions: Vec<u64> = recore::analyze(&image).functions.iter().map(|function| function.addr).collect();
    assert_eq!(functions, [0x0000, 0x0003, 0x0010, 0x0011]);
}

#[test]
fn a_layout_that_places_nothing_where_it_can_load_is_refused() {
    let region = |address: &str, length: &str| format!("[[region]]\nfile = \"code.bin\"\noffset = 0\nlength = {length}\naddress = {address}\nexecutable = true\n");
    let refused = |name: &str, layout: String| format!("{:#}", Image::load(&write(name, &layout, &[0x22; 0x100])).err().unwrap());
    let head = "machine = \"8051\"\nentry = [0]\n";
    let cases = [
        ("past-the-end", format!("{head}{}", region("0xfffffffffffffff0", "0x20")), "runs past the end of the address space"),
        ("past-the-bank", format!("{head}{}", region("0x1ff80", "0x100")), "runs past the 64 KB of its bank"),
        ("past-4-gb", format!("machine = \"cortex-m\"\n{}", region("0xffffff80", "0x100")), "runs past a Cortex-M's 4 GB of addresses"),
        ("entry-outside", format!("machine = \"8051\"\nentry = [0x9999]\n{}", region("0", "0x100")), "the entry point 0x9999 is in no region"),
        ("backward-common", format!("{head}{}[banking]\ncommon = [[0x80, 0x10]]\n", region("0", "0x100")), "is no range of 16-bit addresses"),
        ("wide-common", format!("{head}{}[banking]\ncommon = [[0, 0x20000]]\n", region("0", "0x100")), "is no range of 16-bit addresses"),
        ("no-entry", format!("machine = \"cortex-m\"\nvectors = \"none\"\n{}", region("0", "0x100")), "the layout names no entry point"),
        ("8051-vectors", format!("{head}vectors = 0\n{}", region("0", "0x100")), "only a Cortex-M has a vector table"),
        ("signed-byte", format!("{head}{}[banking]\ncommon = [[0, 0x100]]\n[[banking.trampoline]]\nentry = \"+1 hh ll 02 ss ss\"\nstub = \"22\"\n", region("0", "0x100")), "`+1` in the pattern"),
    ];
    for (name, layout, message) in cases {
        let error = refused(name, layout);
        assert!(error.contains(message), "{name}: {error}");
    }
}

#[test]
fn a_cortex_m_starts_at_the_handlers_its_vector_table_names() {
    // At 0x08000000 the vector table: the stack pointer, reset at 0x08000010, a slot not in
    // use, and a fault handler at 0x0800004A. Reset: PUSH {R4, LR}; LDR R0, =callback;
    // BL install; MOVS R0, #2; BL choose; LDR R0, ="hello"; POP {R4, PC}; padding, and the two
    // literals. At 0x0800002C install: BX LR. At 0x0800002E callback, which only the literal
    // names: MOVS R0, #0; BX LR. At 0x08000032 choose: CMP R0, #2; BHI 0x08000048;
    // TBB [PC, R0] and its three entries and a byte of padding; three cases, the last of which
    // runs on into the BX LR the BHI goes to. At 0x0800004A the fault handler: B itself; then
    // the text.
    let bytes = [
        0x00, 0x10, 0x00, 0x20, 0x11, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x4b, 0x00, 0x00, 0x08, 0x10, 0xb5, 0x04, 0x48, 0x00, 0xf0,
        0x0a, 0xf8, 0x02, 0x20, 0x00, 0xf0, 0x0a, 0xf8, 0x02, 0x48, 0x10, 0xbd, 0x00, 0x00, 0x2f, 0x00, 0x00, 0x08, 0x4c, 0x00, 0x00, 0x08,
        0x70, 0x47, 0x00, 0x20, 0x70, 0x47, 0x02, 0x28, 0x08, 0xd8, 0xdf, 0xe8, 0x00, 0xf0, 0x02, 0x04, 0x06, 0x00, 0x0a, 0x20, 0x70, 0x47,
        0x14, 0x20, 0x70, 0x47, 0x1e, 0x20, 0x70, 0x47, 0xfe, 0xe7, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x00,
    ];
    let layout = r#"
        machine = "cortex-m"

        [[region]]
        file = "code.bin"
        offset = 0
        length = 82
        address = 0x08000000
        executable = true
    "#;
    let image = Image::load(&write("cortex-m", layout, &bytes)).unwrap();
    assert_eq!((image.machine, image.entry, image.exports.as_slice()), (Machine::Thumb, 0x0800_0010, &[0x0800_004A][..]));
    let sections: Vec<(&str, u64, bool)> = image.sections.iter().map(|section| (section.name.as_str(), section.addr, section.executable)).collect();
    assert_eq!(sections, [("vectors", 0x0800_0000, false), ("code.bin+0x0", 0x0800_0010, true)]);
    let analysis = recore::analyze(&image);
    let functions: Vec<u64> = analysis.functions.iter().map(|function| function.addr).collect();
    assert_eq!(functions, [0x0800_0010, 0x0800_002C, 0x0800_002E, 0x0800_0032, 0x0800_004A]);
    // The literals are no part of reset's code, nor the table of choose's.
    assert_eq!(analysis.functions[0].ranges, [(0x0800_0010, 0x0800_0022)]);
    let tables: Vec<(u64, &[u64])> = analysis.jump_tables.iter().map(|table| (table.jump, table.targets.as_slice())).collect();
    assert_eq!(tables, [(0x0800_0036, &[0x0800_003E, 0x0800_0042, 0x0800_0046][..])]);
    let strings: Vec<(u64, &str)> = analysis.strings.iter().map(|string| (string.addr, string.text.as_str())).collect();
    assert_eq!(strings, [(0x0800_004C, "hello")]);
}

#[test]
fn a_cortex_m_vector_table_is_where_the_layout_says() {
    // Boot code as an RP2040 has before its table: at 0x10000000, MOVS R0, #0; BX LR and
    // padding. At 0x10000010 the table: the stack pointer, reset at 0x10000020, a slot not in
    // use, a fault handler at 0x10000024. Then both handlers: B itself.
    let mut bytes = vec![0x00, 0x20, 0x70, 0x47];
    bytes.resize(0x10, 0);
    for word in [0x2004_2000u32, 0x1000_0021, 0, 0x1000_0025] {
        bytes.extend(word.to_le_bytes());
    }
    bytes.extend([0xFE, 0xE7, 0x00, 0x00, 0xFE, 0xE7]);
    let region = |address: &str, executable: bool| format!("[[region]]\nfile = \"code.bin\"\noffset = 0\nlength = {:#x}\naddress = {address}\nexecutable = {executable}\n", bytes.len());
    let load = |name: &str, layout: String| Image::load(&write(name, &layout, &bytes)).unwrap();
    let sections = |image: &Image| image.sections.iter().map(|section| (section.addr, section.end(), section.executable)).collect::<Vec<_>>();
    let functions = |image: &Image| recore::analyze(image).functions.iter().map(|function| function.addr).collect::<Vec<_>>();

    let image = load("rp2040", format!("machine = \"cortex-m\"\nentry = [0x10000000]\nvectors = 0x10000010\n{}", region("0x10000000", true)));
    assert_eq!((image.entry, image.exports.as_slice()), (0x1000_0020, &[0x1000_0000, 0x1000_0024][..]));
    assert_eq!(sections(&image), [(0x1000_0000, 0x1000_0010, true), (0x1000_0010, 0x1000_0020, false), (0x1000_0020, 0x1000_0026, true)]);
    assert_eq!(functions(&image), [0x1000_0000, 0x1000_0020, 0x1000_0024]);

    // Without `vectors` the table starts the lowest executable region, past data below it.
    let flash = "[[region]]\nfile = \"code.bin\"\noffset = 0x10\nlength = 0x16\naddress = 0x10000010\nexecutable = true\n";
    let image = load("data-below", format!("machine = \"cortex-m\"\n{}{flash}", region("0x0", false)));
    assert_eq!(image.entry, 0x1000_0020);
    assert_eq!(sections(&image), [(0x0, 0x26, false), (0x1000_0010, 0x1000_0020, false), (0x1000_0020, 0x1000_0026, true)]);

    // With `vectors = "none"` the entry points are the layout's alone, and the table is code.
    let image = load("no-vectors", format!("machine = \"cortex-m\"\nentry = [0x10000000]\nvectors = \"none\"\n{}", region("0x10000000", true)));
    assert_eq!((image.entry, sections(&image)), (0x1000_0000, vec![(0x1000_0000, 0x1000_0026, true)]));
}
