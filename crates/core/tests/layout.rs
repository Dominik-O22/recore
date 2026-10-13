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
    place(0x03, &[0xE5, 0x49, 0x22, 0x00, 0x00, 0xE5, 0x49, 0x22, 0x00, 0x04]);
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
        stub = "e5 49 22 00 .."
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
