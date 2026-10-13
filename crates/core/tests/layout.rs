//! Loading a raw image through a layout file.

use std::path::PathBuf;

use recore::image::{Format, Image, Machine};

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
