//! Objective-C metadata and message sends in the fixtures built from `fixtures/shapes.m`.

use std::path::PathBuf;

use recore::report::Analysis;

fn analyze(name: &str) -> Analysis {
    recore::analyze(&recore::Image::load(&PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name)).unwrap())
}

/// `(address, selector, implementation)` of each message send.
fn sends(analysis: &Analysis) -> Vec<(u64, &str, Option<u64>)> {
    analysis.sends.iter().map(|send| (send.at, send.selector.as_str(), send.implementation)).collect()
}

#[test]
fn classes_and_categories_list_their_methods() {
    let analysis = analyze("shapes-arm64");
    let classes: Vec<_> = analysis.classes.iter().map(|class| (class.name.as_str(), class.bases.as_slice(), class.methods.as_slice())).collect();
    assert_eq!(
        classes,
        [
            // Instance methods, then class methods.
            ("Shape", &[][..], &[0x1000008e8, 0x1000008f0, 0x1000008e0][..]),
            ("Square", &["Shape".to_string()][..], &[0x10000091c, 0x1000009d0, 0x1000009d8, 0x100000990][..]),
            ("NSObject(Shapes)", &[][..], &[0x1000009e0][..]),
        ]
    );
    assert!(analysis.classes.iter().all(|class| class.objc));
}

#[test]
fn a_stripped_image_names_methods_from_its_metadata() {
    let analysis = analyze("shapes-arm64");
    let name = |addr: u64| analysis.functions.iter().find(|f| f.addr == addr).and_then(|f| f.name.as_deref());
    assert_eq!(name(0x1000008e0), Some("+[Shape alloc]"));
    assert_eq!(name(0x1000009d8), Some("-[Square setSide:]"));
    assert_eq!(name(0x1000009e0), Some("-[NSObject(Shapes) corners]"));
}

#[test]
fn message_sends_carry_their_selector() {
    let analysis = analyze("shapes-arm64");
    assert_eq!(
        sends(&analysis),
        [
            // Two classes implement `area`, so the selector alone does not say which runs.
            (0x100000908, "area", None),
            // To the superclass.
            (0x10000094c, "area", None),
            (0x100000964, "side", Some(0x1000009d0)),
            // The selector was loaded once and kept in a register across the call before.
            (0x100000974, "side", Some(0x1000009d0)),
            (0x1000009bc, "setSide:", Some(0x1000009d8)),
            (0x100000a08, "withSide:", Some(0x100000990)),
            (0x100000a1c, "scaledBy:", Some(0x1000008f0)),
            // A jump to the linker's stub for the selector.
            (0x100000a48, "area", None),
        ]
    );
}

#[test]
fn message_sends_resolve_on_x86_64() {
    let analysis = analyze("shapes-x86_64");
    assert_eq!(
        sends(&analysis),
        [
            (0x100000a4f, "area", None),
            (0x100000a8e, "area", None),
            // The dispatcher was loaded into a register, which these call.
            (0x100000aaa, "side", Some(0x100000b10)),
            (0x100000ab6, "side", Some(0x100000b10)),
            (0x100000af4, "setSide:", Some(0x100000b20)),
            (0x100000b5e, "withSide:", Some(0x100000ad0)),
            (0x100000b73, "scaledBy:", Some(0x100000a40)),
            (0x100000b99, "area", None),
        ]
    );
}

#[test]
fn a_send_names_its_receiver_where_the_code_says_which() {
    let analysis = analyze("shapes-arm64");
    let known: Vec<_> = analysis.sends.iter().filter_map(|send| Some((send.at, send.label(), send.implementation))).filter(|send| !send.1.contains('?')).collect();
    assert_eq!(
        known,
        [
            // `[self area]` in a method of `Shape`: `self` may be a `Square`, which has its own.
            (0x100000908, "-[Shape area]".to_string(), None),
            // `self` in methods of `Square`, kept in a register across a call.
            (0x100000964, "-[Square side]".to_string(), Some(0x1000009d0)),
            (0x100000974, "-[Square side]".to_string(), Some(0x1000009d0)),
            // To the object `[Square alloc]` returned, in a class method of `Square`.
            (0x1000009bc, "-[Square setSide:]".to_string(), Some(0x1000009d8)),
            // `[Square withSide:argc]` in `main`: the receiver is loaded from a class reference.
            (0x100000a08, "+[Square withSide:]".to_string(), Some(0x100000990)),
        ]
    );
}
