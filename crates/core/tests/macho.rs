//! Loading the Mach-O fixtures built by `fixtures/build.sh` from `fixtures/shapes.m`.

use std::path::PathBuf;

use recore::image::{Format, Image, Machine};
use recore::report::CallTarget;

fn fixture(name: &str) -> Image {
    Image::load(&PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name)).unwrap()
}

/// The slot the loader binds the import called `name` to.
fn slot_of(image: &Image, name: &str) -> u64 {
    *image.import_slots.iter().find(|(_, import)| *import == name).unwrap_or_else(|| panic!("no import {name}")).0
}

/// `(address, import, never returns)` of each call to an import.
fn import_calls(image: &Image) -> Vec<(u64, String, bool)> {
    let imported = |call: &recore::report::CallSite| match call.target {
        CallTarget::Import(slot) => Some((call.at, image.import_slots[&slot].clone(), call.noreturn)),
        CallTarget::Function(_) => None,
    };
    recore::analyze(image).calls.iter().filter_map(imported).collect()
}

#[test]
fn chained_fixups_bind_imports_and_rebase_pointers() {
    let image = fixture("shapes-arm64");
    assert_eq!((image.format, image.machine, image.entry), (Format::MachO, Machine::Aarch64, 0x1000009e8));
    assert_eq!(slot_of(&image, "puts"), 0x100004020);
    // The superclass of a category's class, in a record among the program's data.
    assert!(image.import_slots.values().any(|import| import == "OBJC_CLASS_$_NSObject"));
    // The table of shape names starts with a pointer to "circle": listed as rebased, and
    // stored in the section's bytes, where the file holds an encoded fixup.
    let circle = u64::from_le_bytes(image.bytes_from(0x100004028).unwrap()[..8].try_into().unwrap());
    assert!(image.bytes_from(circle).unwrap().starts_with(b"circle\0"));
    assert!(image.relative_targets.contains(&(0x100004028, circle)));
    assert_eq!(image.bytes_from(0x100004020).unwrap()[..8], [0; 8]);
}

#[test]
fn function_starts_bound_every_function() {
    let image = fixture("shapes-arm64");
    let starts = [0x1000008e0, 0x1000008e8, 0x1000008f0, 0x10000091c, 0x100000990, 0x1000009d0, 0x1000009d8, 0x1000009e0, 0x1000009e8];
    assert_eq!(image.frames.iter().map(|frame| frame.0).collect::<Vec<_>>(), starts);
    assert_eq!(image.frames[2], (0x1000008f0, 0x10000091c));
    // The last function runs to the end of `__text`, not into the stubs.
    assert_eq!(image.frames[8], (0x1000009e8, 0x100000a50));
    assert_eq!(recore::analyze(&image).functions.iter().map(|f| f.addr).collect::<Vec<_>>(), starts);
}

#[test]
fn calls_through_stubs_reach_imports() {
    let calls = import_calls(&fixture("shapes-arm64"));
    assert!(calls.contains(&(0x100000a34, "puts".into(), false)));
    assert!(calls.contains(&(0x100000a4c, "abort".into(), true)));
    // A jump to the stub that loads a selector and sends it.
    assert!(calls.contains(&(0x100000a48, "objc_msgSend".into(), false)));
}

#[test]
fn a_universal_file_loads_its_arm64_slice() {
    let image = fixture("shapes-universal");
    assert_eq!((image.machine, image.entry), (Machine::Aarch64, 0x1000009e8));
    // Addresses and file offsets are those of the slice.
    let text = image.text().unwrap();
    assert_eq!((text.addr, text.file_offset), (0x1000008e0, Some(0x8e0)));
}

#[test]
fn bind_opcodes_and_lazy_pointers_name_imports() {
    let image = fixture("shapes-x86_64");
    assert_eq!((image.format, image.machine, image.entry), (Format::MachO, Machine::X86_64, 0x100000b40));
    assert_eq!(slot_of(&image, "objc_msgSend"), 0x100002000);
    // A lazily bound slot, which the file fills with the address of its binding helper.
    assert_eq!(slot_of(&image, "puts"), 0x100003018);
    assert!(image.relative_targets.iter().all(|(slot, _)| !image.import_slots.contains_key(slot)));
    // The rebased pointers include every selector reference.
    let points_at = |text: &[u8]| image.relative_targets.iter().any(|&(_, target)| image.bytes_from(target).is_some_and(|bytes| bytes.starts_with(text)));
    assert!(points_at(b"withSide:\0") && points_at(b"scaledBy:\0"));
    let calls = import_calls(&image);
    assert!(calls.contains(&(0x100000b8b, "puts".into(), false)));
    assert!(calls.contains(&(0x100000b9e, "abort".into(), true)));
}

#[test]
fn symbols_name_functions_without_their_underscore() {
    let image = fixture("shapes-x86_64");
    assert_eq!(image.symbol_names[&0x100000b40], "main");
    assert_eq!(image.symbol_names[&0x100000ad0], "+[Square withSide:]");
    assert!(image.exports.contains(&0x100000b40));
}

#[test]
fn compact_unwind_tables_list_function_starts() {
    let image = fixture("shapes-arm64");
    let unwind = image.sections.iter().find(|section| section.name == "__TEXT,__unwind_info").unwrap();
    // Neighbours that unwind alike share an entry: the two leaf functions at the start, and
    // the three before `main`.
    let starts = recore::macho::unwind_starts(&unwind.data, 0x100000000);
    assert_eq!(starts, [0x1000008e0, 0x1000008f0, 0x10000091c, 0x100000990, 0x1000009d0, 0x1000009e8]);
}

#[test]
fn string_literals_are_listed_without_a_pointer_to_them() {
    // Method type encodings are reached through the 32-bit offsets of a method list, which no
    // rebased pointer or instruction operand spells out.
    let strings = recore::analyze(&fixture("shapes-x86_64")).strings;
    let text: Vec<&str> = strings.iter().map(|string| string.text.as_str()).collect();
    assert!(text.contains(&"i20@0:8i16") && text.contains(&"@16@0:8"), "{text:?}");
}
