//! Sessions over hand-assembled code, so the tests need no corpus binary.

use recore_decomp::{Facts, Section, Session, Target, vendored_spec_dir};

fn session(code: &[u8]) -> Session {
    Session::new(&vendored_spec_dir(), Target::X86_64Gcc, &[Section { addr: 0x1000, data: code, readonly: true, code: true }]).unwrap()
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
fn flow_stops_at_another_function() {
    // 0x1000: call 0x1010, then fall through into 0x1005: mov eax, 7; ret. 0x1010: ret.
    let mut code = vec![0xe8, 0x0b, 0x00, 0x00, 0x00, 0xb8, 0x07, 0x00, 0x00, 0x00, 0xc3];
    code.resize(0x10, 0x90);
    code.push(0xc3);
    assert!(!session(&code).decompile(0x1000).unwrap().bad_data);

    let mut informed = session(&code);
    informed.add_function(0x1005, false).unwrap();
    assert!(informed.decompile(0x1000).unwrap().bad_data);
    assert!(!informed.decompile(0x1005).unwrap().bad_data);
}

#[test]
fn flow_passes_an_entry_inside_the_functions_own_range() {
    // 0x1000: mov eax, 1. 0x1005: add eax, 2; ret. Both addresses are declared functions, and
    // the first one's extent covers the second, as when two functions share an exit.
    let code = [0xb8, 0x01, 0x00, 0x00, 0x00, 0x83, 0xc0, 0x02, 0xc3];
    let declared = Facts { functions: vec![(0x1000, false), (0x1005, false)], ..Facts::default() };
    let mut hidden = session(&code);
    hidden.add_functions(&declared).unwrap();
    assert!(hidden.decompile(0x1000).unwrap().bad_data);

    let mut allowed = session(&code);
    allowed.add_functions(&Facts { own_entries: vec![(0x1000, 0x1005)], ..declared }).unwrap();
    let function = allowed.decompile(0x1000).unwrap();
    assert!(!function.bad_data);
    assert!(function.c_text.contains("return 3"), "{}", function.c_text);
}

#[test]
fn every_builtin_prototype_parses() {
    use recore_decomp::prototypes;
    for target in [Target::X86Windows, Target::X86_64Windows, Target::X86_64Gcc] {
        let mut session = Session::new(&vendored_spec_dir(), target, &[Section { addr: 0x1000, data: &[0xc3], readonly: true, code: true }]).unwrap();
        for (index, name) in prototypes::known().enumerate() {
            session.add_import(0x2000 + 8 * index as u64, name, false).unwrap();
        }
        prototypes::declare(&mut session, target, prototypes::known()).unwrap();
    }
}

#[test]
fn stdcall_callee_cleanup_gives_stack_parameters() {
    // 32-bit: mov eax, [esp+4]; add eax, [esp+8]; ret 8
    let code = [0x8b, 0x44, 0x24, 0x04, 0x03, 0x44, 0x24, 0x08, 0xc2, 0x08, 0x00];
    let mut session = Session::new(&vendored_spec_dir(), Target::X86Windows, &[Section { addr: 0x1000, data: &code, readonly: true, code: true }]).unwrap();
    let function = session.decompile(0x1000).unwrap();
    let storage: Vec<&str> = function.params.iter().map(|p| p.storage.as_str()).collect();
    assert_eq!(storage, ["stack:0x4", "stack:0x8"]);
    assert!(function.c_text.contains("param_1 + param_2"), "{}", function.c_text);
}
