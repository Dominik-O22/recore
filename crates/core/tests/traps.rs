//! A trap after a call says the compiler knows the code after it can't run. That is how clang
//! marks a call that never returns, and also how it marks a call followed by undefined
//! behavior, such as a use of a null pointer, where the callee returns as usual.

use recore::image::{Format, Image, Machine, Section};

fn analyze(code: &[u8]) -> recore::report::Analysis {
    let text = Section { name: ".text".into(), addr: 0x401000, data: code.to_vec(), file_offset: None, executable: true, writable: false };
    let image = Image { base: 0x400000, ..Image::bare("traps".into(), Format::Pe, Machine::X86, 0x401000, vec![text]) };
    recore::analyze(&image)
}

#[test]
fn a_callee_that_most_callers_go_on_from_returns_though_one_call_is_followed_by_a_trap() {
    #[rustfmt::skip]
    let code = [
        0xe8, 0x0b, 0x00, 0x00, 0x00,  // 0x401000  call 0x401010
        0xe8, 0x16, 0x00, 0x00, 0x00,  // 0x401005  call 0x401020
        0xc3,                          // 0x40100a  ret
        0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
        0xe8, 0x1b, 0x00, 0x00, 0x00,  // 0x401010  call 0x401030
        0xe8, 0x16, 0x00, 0x00, 0x00,  // 0x401015  call 0x401030
        0xe8, 0x11, 0x00, 0x00, 0x00,  // 0x40101a  call 0x401030
        0xc3,                          // 0x40101f  ret
        0xe8, 0x0b, 0x00, 0x00, 0x00,  // 0x401020  call 0x401030
        0xcc,                          // 0x401025  int3, as what follows uses a null pointer
        0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
        0x31, 0xc0,                    // 0x401030  xor eax, eax
        0xc3,                          // 0x401032  ret
    ];

    let analysis = analyze(&code);

    let callee = analysis.functions.iter().find(|function| function.addr == 0x401030).unwrap();
    assert!(!callee.noreturn);
}

#[test]
fn a_callee_whose_only_call_is_followed_by_a_trap_never_returns_though_it_has_a_return() {
    #[rustfmt::skip]
    let code = [
        0xe8, 0x0b, 0x00, 0x00, 0x00,  // 0x401000  call 0x401010
        0xcc,                          // 0x401005  int3
        0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
        0x31, 0xc0,                    // 0x401010  xor eax, eax
        0xc3,                          // 0x401012  ret
    ];

    let analysis = analyze(&code);

    let callee = analysis.functions.iter().find(|function| function.addr == 0x401010).unwrap();
    assert!(callee.noreturn);
}

#[test]
fn code_after_a_call_that_a_jump_also_leads_to_does_not_say_the_callee_returns() {
    #[rustfmt::skip]
    let code = [
        0xe8, 0x0b, 0x00, 0x00, 0x00,  // 0x401000  call 0x401010
        0xe8, 0x26, 0x00, 0x00, 0x00,  // 0x401005  call 0x401030
        0xc3,                          // 0x40100a  ret
        0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
        0x85, 0xc9,                    // 0x401010  test ecx, ecx
        0x74, 0x05,                    // 0x401012  jz 0x401019
        0xe8, 0x27, 0x00, 0x00, 0x00,  // 0x401014  call 0x401040
        0x85, 0xd2,                    // 0x401019  test edx, edx
        0x74, 0x05,                    // 0x40101b  jz 0x401022
        0xe8, 0x1e, 0x00, 0x00, 0x00,  // 0x40101d  call 0x401040
        0x85, 0xdb,                    // 0x401022  test ebx, ebx
        0x74, 0x05,                    // 0x401024  jz 0x40102b
        0xe8, 0x15, 0x00, 0x00, 0x00,  // 0x401026  call 0x401040
        0xc3,                          // 0x40102b  ret
        0xcc, 0xcc, 0xcc, 0xcc,
        0xe8, 0x0b, 0x00, 0x00, 0x00,  // 0x401030  call 0x401040
        0xcc,                          // 0x401035  int3
        0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
        0x31, 0xc0,                    // 0x401040  xor eax, eax
        0xc3,                          // 0x401042  ret
    ];

    let analysis = analyze(&code);

    let callee = analysis.functions.iter().find(|function| function.addr == 0x401040).unwrap();
    assert!(callee.noreturn);
}
