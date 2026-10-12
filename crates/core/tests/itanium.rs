//! C++ classes in the fixtures built from `fixtures/classes.cc`, checked against the symbols of
//! the same builds before stripping.

use std::path::PathBuf;

use recore::report::{Analysis, Origin};

fn analyze(name: &str) -> Analysis {
    recore::analyze(&recore::Image::load(&PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name)).unwrap())
}

/// `(name, base classes, vtable, virtual functions)` of each class.
fn classes(analysis: &Analysis) -> Vec<(&str, Vec<&str>, u64, &[u64])> {
    analysis.classes.iter().map(|class| (class.name.as_str(), class.bases.iter().map(String::as_str).collect(), class.vtable, class.methods.as_slice())).collect()
}

#[test]
fn classes_of_a_relocated_image_that_imports_the_library() {
    let analysis = analyze("classes-x86_64-pie");
    assert_eq!(
        classes(&analysis),
        [
            // Both destructors, then `legs` and `speak`.
            ("zoo::Dog", vec!["zoo::Animal"], 0x3b28, &[0x1342, 0x138a, 0x12fc, 0x1302][..]),
            // One vtable per base class with virtual functions; the second holds a thunk.
            ("zoo::Duck", vec!["zoo::Animal", "zoo::Swimmer"], 0x3b58, &[0x1344, 0x1376, 0x1308, 0x12f6, 0x130e][..]),
            ("zoo::Duck", vec!["zoo::Animal", "zoo::Swimmer"], 0x3b90, &[0x1314][..]),
            // The vtable at 0x3c30 also names `Winged`, but is the one `Bat` constructs it with.
            ("zoo::Winged", vec!["zoo::Animal"], 0x3bd8, &[0x1340, 0x1348, 0x131a, 0x12f6, 0x1326][..]),
            ("zoo::Bat", vec!["zoo::Winged", "zoo::Animal"], 0x3ca8, &[0x1346, 0x139e, 0x132a, 0x12f6, 0x133a][..]),
            // Null destructor slots, and `legs` bound to the library's pure virtual handler
            // through the slot itself.
            ("zoo::Animal", vec![], 0x3d90, &[0, 0, 0x3da0, 0x12f6][..]),
        ]
    );
    let name = |addr: u64| analysis.functions.iter().find(|function| function.addr == addr).and_then(|function| function.name.as_deref());
    // Named by the class that introduced the slot, and a second vtable's slots do not take
    // the names of the first's.
    assert_eq!(name(0x12f6), Some("zoo::Animal::vfunc_3"));
    assert_eq!(name(0x1344), Some("zoo::Duck::vfunc_0"));
    assert_eq!(name(0x1314), None);
}

#[test]
fn classes_of_a_fixed_image_with_the_library_linked_in() {
    let analysis = analyze("classes-x86_64-static");
    let found: Vec<(&str, u64)> = analysis.classes.iter().map(|class| (class.name.as_str(), class.vtable)).collect();
    assert_eq!(
        found,
        [
            ("zoo::Dog", 0x403ca0),
            ("zoo::Duck", 0x403cd0),
            ("zoo::Duck", 0x403d08),
            ("zoo::Winged", 0x403d50),
            ("zoo::Bat", 0x403e20),
            ("std::type_info", 0x403eb0),
            ("__cxxabiv1::__class_type_info", 0x403ed0),
            ("__cxxabiv1::__si_class_type_info", 0x403ef0),
            ("__cxxabiv1::__vmi_class_type_info", 0x403f10),
            ("zoo::Animal", 0x403fe0),
        ]
    );
    // Nothing calls `Dog::legs` by address and no relocation or unwind entry names it: its
    // vtable slot is what makes it a function.
    let legs = analysis.functions.iter().find(|function| function.addr == 0x401188).expect("found through the vtable");
    assert_eq!(legs.origin, Origin::DataPointer);
    assert_eq!(analysis.classes[0].methods, [0x4011ce, 0x401216, 0x401188, 0x40118e]);
}

#[test]
fn classes_of_an_image_with_32_bit_pointers() {
    let analysis = analyze("classes-x86-static");
    let found: Vec<(&str, Vec<&str>, u64)> = classes(&analysis).into_iter().map(|(name, bases, vtable, _)| (name, bases, vtable)).take(6).collect();
    assert_eq!(
        found,
        [
            ("zoo::Animal", vec![], 0x804a0bc),
            ("zoo::Dog", vec!["zoo::Animal"], 0x804a0d4),
            ("zoo::Duck", vec!["zoo::Animal", "zoo::Swimmer"], 0x804a0ec),
            ("zoo::Duck", vec!["zoo::Animal", "zoo::Swimmer"], 0x804a108),
            ("zoo::Winged", vec!["zoo::Animal"], 0x804a12c),
            ("zoo::Bat", vec!["zoo::Winged", "zoo::Animal"], 0x804a194),
        ]
    );
}
