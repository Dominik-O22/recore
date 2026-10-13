//! How the engine reads 8051 code that SDCC compiled.

use recore_decomp::{Section, Session, Target, vendored_spec_dir};

/// Decompiles the function at 0 of `code`, in which the byte of internal memory at 8 is the
/// frame pointer, and returns where it takes its parameters.
fn parameters(code: &[u8]) -> Vec<String> {
    let mut session = Session::new(&vendored_spec_dir().unwrap(), Target::I8051Sdcc, &[Section { addr: 0, data: code, readonly: true, code: true }]).unwrap();
    session.register_at(recore::i8051::IDATA + 8).unwrap();
    session.decompile(0).unwrap().params.into_iter().map(|param| param.storage).collect()
}

#[test]
fn an_argument_read_through_the_frame_pointer_after_a_call_is_a_parameter() {
    let mut code = vec![
        0xc0, 0x08, // push 8
        0x85, 0x81, 0x08, // mov 8, sp
        0x12, 0x00, 0x20, // lcall 0x20
        0xe5, 0x08, // mov a, 8
        0x24, 0xfd, // add a, #-3
        0xf8, // mov r0, a
        0xe6, // mov a, @r0
        0xf5, 0x82, // mov dpl, a
        0xd0, 0x08, // pop 8
        0x22, // ret
    ];
    code.resize(0x20, 0);
    code.push(0x22);
    // The byte pushed last before the call: below the two of the return address.
    assert_eq!(parameters(&code), ["stack:0xfe"]);
}

#[test]
fn the_first_argument_is_in_dptr_and_the_stack_pointer_by_its_address_is_the_register() {
    // mov a, sp; add a, #-3; mov r0, a; mov a, @r0; add a, dpl; mov dpl, a; ret
    let code = [0xe5, 0x81, 0x24, 0xfd, 0xf8, 0xe6, 0x25, 0x82, 0xf5, 0x82, 0x22];
    assert_eq!(parameters(&code), ["DPL", "stack:0xfd"]);
}

#[test]
fn a_first_argument_of_three_bytes_read_byte_by_byte_is_one_parameter() {
    #[rustfmt::skip]
    let code = [
        0xad, 0x82, 0xae, 0x83, 0xaf, 0xf0, // mov r5, dpl; mov r6, dph; mov r7, b
        0x90, 0x12, 0x34,                   // mov dptr, #0x1234
        0xed, 0xf0, 0xa3,                   // mov a, r5; movx @dptr, a; inc dptr
        0xee, 0xf0, 0xa3,                   // mov a, r6; movx @dptr, a; inc dptr
        0xef, 0xf0, 0x22,                   // mov a, r7; movx @dptr, a; ret
    ];
    let mut session = Session::new(&vendored_spec_dir().unwrap(), Target::I8051Sdcc, &[Section { addr: 0, data: &code, readonly: true, code: true }]).unwrap();
    let decompiled = session.decompile(0).unwrap();
    let parameters: Vec<u32> = decompiled.params.iter().map(|param| param.size).collect();
    assert_eq!(parameters, [3], "{}", decompiled.c_text);
    assert!(!decompiled.c_text.contains("in_B"), "{}", decompiled.c_text);
}
