//! Sessions over hand-assembled code, so the tests need no corpus binary.

use recore_decomp::{Section, Session, vendored_spec_dir};

fn session(code: &[u8]) -> Session {
    Session::new(&vendored_spec_dir(), &[Section { addr: 0x1000, data: code, readonly: true, code: true }]).unwrap()
}

#[test]
fn recovers_register_parameters() {
    // lea eax, [rdi+rsi]; ret
    let function = session(&[0x8d, 0x04, 0x37, 0xc3]).decompile(0x1000).unwrap();
    assert_eq!(function.param_count(), 2);
    assert!(function.returns_value);
    assert!(function.c_text.contains("param_1 + param_2"), "{}", function.c_text);
}

#[test]
fn noreturn_callee_ends_flow() {
    // 0x1000: call 0x1008; then bytes that are not code. 0x1008: ret.
    let code = [0xe8, 0x03, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xc3];
    assert!(session(&code).decompile(0x1000).unwrap().bad_data);

    let mut informed = session(&code);
    informed.add_function(0x1008, true).unwrap();
    assert!(!informed.decompile(0x1000).unwrap().bad_data);
}

#[test]
fn flow_stops_at_the_declared_end() {
    // 0x1000: call 0x1010; 0x1005: mov eax, 7; ret. Without the bound, flow returns from the
    // call into what could be the next function.
    let mut code = vec![0xe8, 0x0b, 0x00, 0x00, 0x00, 0xb8, 0x07, 0x00, 0x00, 0x00, 0xc3];
    code.resize(0x10, 0x90);
    code.push(0xc3);
    assert!(!session(&code).decompile(0x1000).unwrap().bad_data);

    let mut bounded = session(&code);
    bounded.bound_flow(0x1000, 0x1005).unwrap();
    assert!(bounded.decompile(0x1000).unwrap().bad_data);
}
