//! The 8051 as Keil's C51 compiles for it.

use recore_decomp::facts::{Facts, SwitchCall};
use recore_decomp::{Section, Session, Target, vendored_spec_dir};

#[test]
fn a_switch_through_a_list_of_cases_after_a_call_has_each_case_by_its_value() {
    #[rustfmt::skip]
    let code = [
        0xef,                   // 00  MOV A,R7
        0x12, 0x00, 0x40,       // 01  LCALL the routine that finds the case
        0x00, 0x10, 0x05,       // 04  case 5 is at 0x10
        0x00, 0x13, 0x09,       // 07  case 9 is at 0x13
        0x00, 0x00, 0x00, 0x16, // 0a  the default is at 0x16
        0x00, 0x00,
        0x7f, 0x11, 0x22,       // 10  MOV R7,#0x11; RET
        0x7f, 0x22, 0x22,       // 13  MOV R7,#0x22; RET
        0x7f, 0x33, 0x22,       // 16  MOV R7,#0x33; RET
    ];
    let mut session = Session::new(&vendored_spec_dir().unwrap(), Target::I8051, &[Section { addr: 0, data: &code, readonly: true, code: true }]).unwrap();
    let facts = Facts { functions: vec![(0, false)], switch_calls: vec![SwitchCall { call: 1, selector: c"ACC", cases: Some((c"byteCases", 2, 4)) }], ..Facts::default() };
    session.add_functions(&facts).unwrap();
    let c = session.decompile(0).unwrap().c_text;
    let after = |label: &str| c.split_once(label).unwrap_or_else(|| panic!("no `{label}` in {c}")).1.trim_start().lines().next().unwrap().to_string();
    assert_eq!(after("case 5:"), "return 0x11;");
    assert_eq!(after("case 9:"), "return 0x22;");
    assert_eq!(after("default:"), "return 0x33;");
}

#[test]
fn a_pointer_argument_read_byte_by_byte_is_one_parameter() {
    #[rustfmt::skip]
    let code = [
        0x90, 0x12, 0x34,                   // mov dptr, #0x1234
        0xeb, 0xf0, 0xa3,                   // mov a, r3; movx @dptr, a; inc dptr
        0xea, 0xf0, 0xa3,                   // mov a, r2; movx @dptr, a; inc dptr
        0xe9, 0xf0, 0x22,                   // mov a, r1; movx @dptr, a; ret
    ];
    let mut session = Session::new(&vendored_spec_dir().unwrap(), Target::I8051, &[Section { addr: 0, data: &code, readonly: true, code: true }]).unwrap();
    let decompiled = session.decompile(0).unwrap();
    let parameters: Vec<u32> = decompiled.params.iter().map(|param| param.size).collect();
    assert_eq!(parameters, [3], "{}", decompiled.c_text);
    assert!(!decompiled.c_text.contains("in_R1"), "{}", decompiled.c_text);
}

#[test]
fn a_call_after_a_library_operation_on_four_bytes_keeps_its_argument() {
    #[rustfmt::skip]
    let code = [
        0x12, 0x00, 0x10,       // 00  LCALL the routine that divides R4 to R7 by R0 to R3
        0x7e, 0x00, 0x7f, 0x02, // 03  MOV R6,#0; MOV R7,#2
        0x12, 0x00, 0x11,       // 07  LCALL a function
        0x22,                   // 0a  RET
        0, 0, 0, 0, 0,
        0x22,                   // 10  the routine
        0x22,                   // 11  the function
    ];
    let mut session = Session::new(&vendored_spec_dir().unwrap(), Target::I8051, &[Section { addr: 0, data: &code, readonly: true, code: true }]).unwrap();
    let facts = Facts {
        functions: vec![(0, false), (0x10, false), (0x11, false)],
        names: vec![(0x10, "?C?ULDIV".into())],
        call_fixups: vec![(0x10, "?C?ULDIV".into())],
        ..Facts::default()
    };
    session.add_functions(&facts).unwrap();
    let c = session.decompile(0).unwrap().c_text;
    // Whatever else the registers hold, the first argument is the one the code loads.
    assert!(c.contains("func_0x000011(2"), "{c}");
}

#[test]
fn a_call_to_a_function_that_returns_what_it_jumps_to_keeps_its_argument() {
    #[rustfmt::skip]
    let code = [
        0x7f, 0x05,             // 00  MOV R7,#5
        0x12, 0x00, 0x10,       // 02  LCALL the function that jumps
        0x22,                   // 05  RET
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0x02, 0x00, 0x20,       // 10  LJMP the function that returns a value
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0xef, 0x04, 0xff, 0x22, // 20  MOV A,R7; INC A; MOV R7,A; RET
    ];
    let mut session = Session::new(&vendored_spec_dir().unwrap(), Target::I8051, &[Section { addr: 0, data: &code, readonly: true, code: true }]).unwrap();
    let facts = Facts { functions: vec![(0, false), (0x10, false), (0x20, false)], tail_calls: vec![(0x10, 0x10)], ..Facts::default() };
    session.add_functions(&facts).unwrap();
    assert!(session.decompile(0x20).unwrap().returns_value);
    assert!(session.returns_like(0x10, recore::report::CallTarget::Function(0x20)));
    assert!(session.decompile(0x10).unwrap().returns_value);
    let c = session.decompile(0).unwrap().c_text;
    assert!(c.contains("func_0x000010(5)"), "{c}");
}
