//! Cortex-M code, Thumb and Thumb-2, as clang compiles it.

use recore_decomp::Session;
use recore_decomp::facts::Facts;

/// The C of the function at `addr` of `code`, loaded at 0, with everything the analysis says.
fn decompiled(code: &[u8], exports: &[u64], addr: u64) -> String {
    let image = recore::Image {
        name: String::new(),
        format: recore::image::Format::Raw,
        machine: recore::image::Machine::Thumb,
        base: 0,
        branch_targets_marked: false,
        entry: 0,
        sections: vec![recore::image::Section { name: String::new(), addr: 0, data: code.to_vec(), file_offset: None, executable: true, writable: false }],
        zero_filled: Vec::new(),
        import_slots: Default::default(),
        exports: exports.to_vec(),
        symbol_names: Default::default(),
        frames: Vec::new(),
        relative_targets: Vec::new(),
        data_in_code: true,
        banking: Default::default(),
        compiler: None,
    };
    let analysis = recore::analyze(&image);
    let facts = Facts::derive(&image, &analysis);
    let mut session = Session::from_image(&image, &analysis).unwrap();
    session.add_functions(&facts).unwrap();
    session.override_jump_tables(&analysis, &facts).unwrap();
    session.decompile(addr).unwrap().c_text
}

#[rustfmt::skip]
const CODE: [u8; 42] = [
    // 00: CMP R0, #2; BHI 0x18; TBB [PC, R0], then the table and a byte of padding.
    0x02, 0x28, 0x09, 0xd8, 0xdf, 0xe8, 0x00, 0xf0, 0x02, 0x04, 0x06, 0x00,
    // 0C: MOVS R0, #10; BX LR; MOVS R0, #20; BX LR; MOVS R0, #30; BX LR; MOVS R0, #0; BX LR.
    0x0a, 0x20, 0x70, 0x47, 0x14, 0x20, 0x70, 0x47, 0x1e, 0x20, 0x70, 0x47, 0x00, 0x20, 0x70, 0x47,
    // 1C: SUB SP, #12; PUSH {R4, LR}; MOVS R0, #7; POP {R4}; POP {R1}; ADD SP, #12; BX R1, the way
    // Thumb-1 code returns from a function that takes a variable number of arguments.
    0x83, 0xb0, 0x10, 0xb5, 0x07, 0x20, 0x10, 0xbc, 0x02, 0xbc, 0x03, 0xb0, 0x08, 0x47,
];

#[test]
fn a_switch_through_a_table_of_branch_offsets_has_each_case_by_its_value() {
    let c = decompiled(&CODE, &[], 0);
    let after = |label: &str| c.split_once(label).unwrap_or_else(|| panic!("no `{label}` in {c}")).1.trim_start().lines().next().unwrap().to_string();
    assert_eq!(after("case 0:"), "return 10;");
    assert_eq!(after("case 1:"), "return 0x14;");
    assert_eq!(after("case 2:"), "return 0x1e;");
}

#[test]
fn a_branch_through_the_return_address_popped_off_the_stack_returns() {
    // The engine takes the return address it sees put in R1 for the high half of a result.
    let c = decompiled(&CODE, &[0x1c], 0x1c);
    assert!(c.contains("return CONCAT44(unaff_lr,7);") && !c.contains("UNRECOVERED"), "{c}");
}
