//! A binary whose section headers were removed, as OpenWrt's sstrip removes them, analyzes as
//! the same binary with them.

use std::path::PathBuf;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name)
}

#[test]
fn a_binary_without_section_headers_analyzes_as_it_does_with_them() {
    let original = std::fs::read(fixture("classes-x86_64-pie")).unwrap();
    let mut stripped = original.clone();
    // e_shoff, then e_shentsize, e_shnum and e_shstrndx.
    stripped[0x28..0x30].fill(0);
    stripped[0x3A..0x40].fill(0);
    let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("classes-x86_64-pie-sectionless");
    std::fs::write(&path, &stripped).unwrap();

    let with = recore::analyze(&recore::Image::load(&fixture("classes-x86_64-pie")).unwrap());
    let without = recore::analyze(&recore::Image::load(&path).unwrap());
    let starts = |analysis: &recore::report::Analysis| analysis.functions.iter().map(|function| function.addr).collect::<Vec<_>>();
    let vtables = |analysis: &recore::report::Analysis| analysis.classes.iter().map(|class| class.vtable).collect::<Vec<_>>();
    assert_eq!(starts(&without), starts(&with));
    assert_eq!(vtables(&without), [0x3b28, 0x3b58, 0x3b90, 0x3bd8, 0x3ca8, 0x3d90]);
}
