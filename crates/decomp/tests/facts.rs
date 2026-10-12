//! What `Facts::derive` attributes to a function whose body is several ranges.

use std::collections::HashMap;

use recore::Image;
use recore::image::{Format, Machine, Section};
use recore::report::Analysis;
use recore_decomp::Facts;

const A: u64 = 0x1000;
const B: u64 = 0x1020;
const FRAGMENT: u64 = 0x1060;
const SHARED: u64 = 0x1084;

fn image() -> Image {
    Image {
        name: "test".into(),
        format: Format::Elf,
        machine: Machine::X86_64,
        base: 0,
        branch_targets_marked: false,
        entry: A,
        sections: vec![Section { name: ".text".into(), addr: 0x1000, data: vec![0x90; 0x100], file_offset: None, executable: true, writable: false }],
        import_slots: HashMap::new(),
        exports: Vec::new(),
        symbol_names: HashMap::new(),
        frames: Vec::new(),
        relative_targets: Vec::new(),
        data_in_code: false,
    }
}

/// `A` has a main extent and a block at 0x1080 that it shares with the function `SHARED`, plus
/// a cold fragment listed as an entry of its own.
fn analysis() -> Analysis {
    serde_json::from_value(serde_json::json!({
        "name": "test",
        "noreturn_calls": [],
        "functions": [
            { "addr": A, "ranges": [[0x1000, 0x1010], [0x1080, 0x1090]] },
            { "addr": B, "ranges": [[0x1020, 0x1030]] },
            { "addr": FRAGMENT, "ranges": [[0x1060, 0x1070]], "fragment_of": A, "name": "a.cold" },
            { "addr": SHARED, "ranges": [[0x1084, 0x1090]], "name": "shared" },
        ],
        "calls": [
            { "at": 0x1064, "target": { "function": B }, "tail": true },
            { "at": 0x1088, "target": { "function": B }, "tail": true },
        ],
        "jump_tables": [{ "jump": 0x1082, "targets": [0x1084, 0x1086] }],
    }))
    .unwrap()
}

#[test]
fn every_range_of_a_function_is_its_own() {
    let facts = Facts::derive(&image(), &analysis());
    // The jump in the second range leaves A, and also SHARED, which has it too.
    assert!(facts.tail_calls.contains(&(A, 0x1088)));
    assert!(facts.tail_calls.contains(&(SHARED, 0x1088)));
    assert_eq!(facts.jump_tables, [(A, 0)]);
    // Flow from A may pass the entry of the function that starts inside its second range.
    assert_eq!(facts.own_entries, [(A, SHARED)]);
}

#[test]
fn a_fragment_is_part_of_its_owner() {
    let facts = Facts::derive(&image(), &analysis());
    let declared: Vec<u64> = facts.functions.iter().map(|f| f.0).collect();
    assert_eq!(declared, [A, B, SHARED]);
    // Not named either: naming would declare it, and a declared entry stops flow from A.
    assert_eq!(facts.names, [(SHARED, "shared".to_string())]);
    assert!(facts.tail_calls.contains(&(A, 0x1064)));
}
