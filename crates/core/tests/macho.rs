//! Loading the Mach-O fixtures built by `fixtures/build.sh` from `fixtures/shapes.m`.

use std::path::PathBuf;

use recore::image::{Format, Image, Machine};
use recore::report::{Analysis, CallTarget};

fn fixture(name: &str) -> Image {
    Image::load(&PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name)).unwrap()
}

/// The import each call in `analysis` goes to, by call address.
fn import_calls(image: &Image, analysis: &Analysis) -> Vec<(u64, String, bool)> {
    let imported = |call: &recore::report::CallSite| match call.target {
        CallTarget::Import(slot) => Some((call.at, image.import_slots[&slot].clone(), call.noreturn)),
        CallTarget::Function(_) => None,
    };
    analysis.calls.iter().filter_map(imported).collect()
}

#[test]
fn chained_fixups_bind_imports_and_rebase_pointers() {
    let image = fixture("shapes-arm64");
    assert_eq!((image.format, image.machine, image.entry), (Format::MachO, Machine::Aarch64, 0x10000096c));
    assert_eq!(image.import_slots[&0x100004018], "puts");
    assert_eq!(image.import_slots[&0x100008268], "OBJC_CLASS_$_NSObject");
    // The table of shape names: its first slot points at "circle", in the list of rebased
    // pointers and in the section's bytes, where the file holds an encoded fixup.
    assert!(image.relative_targets.contains(&(0x100004020, 0x100000acc)));
    assert_eq!(image.bytes_from(0x100004020).unwrap()[..8], 0x100000accu64.to_le_bytes());
    assert_eq!(image.bytes_from(0x100004018).unwrap()[..8], [0; 8]);
}

#[test]
fn function_starts_bound_every_function() {
    let image = fixture("shapes-arm64");
    assert_eq!(image.frames.len(), 9);
    assert_eq!(image.frames[2], (0x1000008a0, 0x1000008cc));
    // The last function runs to the end of `__text`, not into the stubs.
    assert_eq!(image.frames[8], (0x10000096c, 0x1000009d4));
    let analysis = recore::analyze(&image);
    assert_eq!(analysis.functions.iter().map(|f| f.addr).collect::<Vec<_>>(), image.frames.iter().map(|f| f.0).collect::<Vec<_>>());
}

#[test]
fn calls_through_stubs_reach_imports() {
    let image = fixture("shapes-arm64");
    let calls = import_calls(&image, &recore::analyze(&image));
    assert!(calls.contains(&(0x1000009b8, "puts".into(), false)));
    assert!(calls.contains(&(0x1000009d0, "abort".into(), true)));
    // A jump to the stub that loads a selector and sends it.
    assert!(calls.contains(&(0x1000009cc, "objc_msgSend".into(), false)));
}

#[test]
fn a_universal_file_loads_its_arm64_slice() {
    let image = fixture("shapes-universal");
    assert_eq!((image.machine, image.entry), (Machine::Aarch64, 0x10000096c));
    // File offsets are those of the slice, which is what the addresses were linked against.
    assert_eq!(image.text().unwrap().addr, 0x100000890);
}

#[test]
fn bind_opcodes_and_lazy_pointers_name_imports() {
    let image = fixture("shapes-x86_64");
    assert_eq!((image.format, image.machine, image.entry), (Format::MachO, Machine::X86_64, 0x100000ac0));
    assert_eq!(image.import_slots[&0x100002000], "objc_msgSend");
    // A lazily bound slot, which the file fills with the address of its binding helper.
    assert_eq!(image.import_slots[&0x100003010], "puts");
    assert!(image.relative_targets.iter().all(|(slot, _)| !image.import_slots.contains_key(slot)));
    // A selector reference.
    assert!(image.relative_targets.contains(&(0x100003030, 0x100000b96)));
    let calls = import_calls(&image, &recore::analyze(&image));
    assert!(calls.contains(&(0x100000b0b, "puts".into(), false)));
    assert!(calls.contains(&(0x100000b1e, "abort".into(), true)));
}

#[test]
fn symbols_name_functions_without_their_underscore() {
    let image = fixture("shapes-x86_64");
    assert_eq!(image.symbol_names[&0x100000ac0], "main");
    assert_eq!(image.symbol_names[&0x100000a50], "+[Square withSide:]");
    assert_eq!(image.exports, [0x100000ac0]);
}

#[test]
fn compact_unwind_tables_list_function_starts() {
    let image = fixture("shapes-arm64");
    let unwind = image.sections.iter().find(|section| section.name == "__TEXT,__unwind_info").unwrap();
    let starts = recore::macho::unwind_starts(&unwind.data, 0x100000000);
    // Neighbours that unwind alike share an entry: the two leaf functions at the start, and
    // the three before `main`.
    assert_eq!(starts, [0x100000890, 0x1000008a0, 0x1000008cc, 0x100000914, 0x100000954, 0x10000096c]);
}
