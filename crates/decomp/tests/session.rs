//! Sessions over hand-assembled code, so the tests need no corpus binary.

use recore_decomp::{Facts, Section, Session, Target, vendored_spec_dir};

fn session(code: &[u8]) -> Session {
    Session::new(&vendored_spec_dir().unwrap(), Target::X86_64Gcc, &[Section { addr: 0x1000, data: code, readonly: true, code: true }]).unwrap()
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
    use recore::image::Format;
    use recore_decomp::prototypes;
    for (target, format) in [(Target::X86Windows, Format::Pe), (Target::X86_64Windows, Format::Pe), (Target::X86_64Gcc, Format::Elf), (Target::X86Gcc, Format::Elf)] {
        let mut session = Session::new(&vendored_spec_dir().unwrap(), target, &[Section { addr: 0x1000, data: &[0xc3], readonly: true, code: true }]).unwrap();
        for (index, name) in prototypes::known().enumerate() {
            session.add_import(0x2000 + 8 * index as u64, name, false).unwrap();
        }
        // The archives are left out here: a failure in the tables written by hand is an error.
        prototypes::declare(&mut session, target, format, prototypes::known()).unwrap();
    }
}

#[test]
fn stdcall_callee_cleanup_gives_stack_parameters() {
    // 32-bit: mov eax, [esp+4]; add eax, [esp+8]; ret 8
    let code = [0x8b, 0x44, 0x24, 0x04, 0x03, 0x44, 0x24, 0x08, 0xc2, 0x08, 0x00];
    let mut session = Session::new(&vendored_spec_dir().unwrap(), Target::X86Windows, &[Section { addr: 0x1000, data: &code, readonly: true, code: true }]).unwrap();
    let function = session.decompile(0x1000).unwrap();
    let storage: Vec<&str> = function.params.iter().map(|p| p.storage.as_str()).collect();
    assert_eq!(storage, ["stack:0x4", "stack:0x8"]);
    assert!(function.c_text.contains("param_1 + param_2"), "{}", function.c_text);
}

/// The engine's C parser accepts the exported prototypes of every archive, bar a few.
#[test]
fn archive_prototypes_parse() {
    use recore::image::Format;
    for (target, format) in [(Target::X86Windows, Format::Pe), (Target::X86_64Gcc, Format::Elf), (Target::Aarch64, Format::MachO)] {
        let mut session = Session::new(&vendored_spec_dir().unwrap(), target, &[Section { addr: 0x1000, data: &[0xc3], readonly: true, code: true }]).unwrap();
        recore_decomp::prototypes::declare(&mut session, target, format, std::iter::empty()).unwrap();
        let declarations: Vec<(&str, String)> = recore_decomp::prototypes::archive_declarations(target, format).collect();
        let mut rejected = Vec::new();
        for (index, (name, declaration)) in declarations.iter().enumerate() {
            session.add_import(0x10_0000 + 4 * index as u64, name, false).unwrap();
            if let Err(error) = session.declare(declaration) {
                rejected.push(format!("{declaration}: {error}"));
            }
        }
        assert!(rejected.len() * 200 < declarations.len(), "{format:?}: {} of {} rejected, such as {:?}", rejected.len(), declarations.len(), &rejected[..rejected.len().min(5)]);
    }
}

/// A Linux import takes its arguments from the C library archive: `long` is as wide as the
/// target makes it, and a function no table written by hand lists still gets its three.
#[test]
fn elf_imports_take_archive_prototypes() {
    use recore::image::Format;
    // mov edi, 3; call [rip+0xff5] (the slot at 0x2000); ret
    let code = [0xbf, 0x03, 0x00, 0x00, 0x00, 0xff, 0x15, 0xf5, 0x0f, 0x00, 0x00, 0xc3];
    let mut session = session(&code);
    session.add_import(0x2000, "lseek", false).unwrap();
    recore_decomp::prototypes::declare(&mut session, Target::X86_64Gcc, Format::Elf, ["lseek"].into_iter()).unwrap();
    let function = session.decompile(0x1000).unwrap();
    let types: Vec<&str> = function.params.iter().map(|param| param.type_name.as_str()).collect();
    // The first register is taken by the constant, and kept as a parameter to hold its place.
    assert_eq!(types, ["undefined8", "long", "int4"], "{}", function.c_text);
    assert!(function.c_text.contains("lseek(3,param_2,param_3)"), "{}", function.c_text);
    assert_eq!(session.type_layout("long").unwrap().lines().next(), Some("typedef long, 8 bytes, alignment 8"));
}

#[test]
fn lists_instructions_with_their_pcode() {
    // lea eax, [rdi+rsi]; ret; then a byte that starts no instruction in 64-bit mode.
    let listing = session(&[0x8d, 0x04, 0x37, 0xc3, 0x06]).listing(0x1000, 0x1005, true).unwrap();
    let lines: Vec<(u64, u64, &str)> = listing.iter().map(|i| (i.addr, i.len, i.text.as_str())).collect();
    assert_eq!(lines, [(0x1000, 3, "LEA EAX,[RDI + RSI*0x1]"), (0x1003, 1, "RET"), (0x1004, 1, "(bad)")]);
    assert_eq!(listing[1].pcode, ["RIP = LOAD ram, RSP", "RSP = INT_ADD RSP, 0x8", "RETURN RIP"]);
}

#[test]
fn data_flow_links_the_return_value_to_the_parameters() {
    use recore_decomp::flow::Kind;
    // lea eax, [rdi+rsi]; ret
    let mut session = session(&[0x8d, 0x04, 0x37, 0xc3]);
    session.keep_flow(true);
    let flow = session.decompile(0x1000).unwrap().flow.unwrap();
    let returned = flow.ops.iter().find(|op| op.code == "RETURN").unwrap().inputs[0];
    // The sum is copied into the return register.
    let copy = flow.definition(returned).unwrap();
    assert_eq!(copy.code, "COPY");
    let sum = flow.definition(copy.inputs[0]).unwrap();
    assert_eq!(sum.code, "INT_ADD");
    let parameters: Vec<usize> = sum.inputs.iter().map(|id| match &flow.values[id].kind {
        Kind::Param { index, .. } => *index,
        other => panic!("{other:?}"),
    }).collect();
    assert_eq!(parameters, [0, 1]);
}

#[test]
fn a_function_that_jumps_to_another_returns_what_that_one_returns() {
    use recore::report::CallTarget;
    // 0x1000: jmp 0x1010. 0x1010: mov eax, 7; ret.
    let mut code = vec![0xe9, 0x0b, 0x00, 0x00, 0x00];
    code.resize(0x10, 0x90);
    code.extend([0xb8, 0x07, 0x00, 0x00, 0x00, 0xc3]);
    let mut session = session(&code);
    session.add_functions(&Facts { functions: vec![(0x1000, false), (0x1010, false)], tail_calls: vec![(0x1000, 0x1000)], ..Facts::default() }).unwrap();
    // The engine sees a call and then a return, and does not hand the one's result to the other.
    assert!(!session.decompile(0x1000).unwrap().returns_value);
    // Nothing is known of the callee until it has been decompiled.
    assert!(!session.returns_like(0x1000, CallTarget::Function(0x1010)));
    assert!(session.decompile(0x1010).unwrap().returns_value);
    assert!(session.returns_like(0x1000, CallTarget::Function(0x1010)));
    let function = session.decompile(0x1000).unwrap();
    assert!(function.returns_value);
    assert!(function.c_text.contains("= func_0x00001010();"), "{}", function.c_text);
}

/// 8051 code at `addr`, which is `bank << 16 | address`.
fn session_8051(code: &[u8], addr: u64) -> Session {
    Session::new(&vendored_spec_dir().unwrap(), Target::I8051, &[Section { addr, data: code, readonly: true, code: true }]).unwrap()
}

#[test]
fn an_8051_jump_stays_in_the_bank_of_its_instruction() {
    // In bank 2: LCALL 0x9000; AJMP 0x8123; SJMP -2
    let listing = session_8051(&[0x12, 0x90, 0x00, 0x01, 0x23, 0x80, 0xfe], 0x02_8000).listing(0x02_8000, 0x02_8007, false).unwrap();
    let text: Vec<&str> = listing.iter().map(|instruction| instruction.text.as_str()).collect();
    assert_eq!(text, ["LCALL 0x29000", "AJMP 0x28023", "SJMP 0x28005"]);
}

#[test]
fn every_8051_opcode_is_as_long_as_recore_decodes_it() {
    use recore::arch::Arch;
    for opcode in 0..=255u8 {
        let code = [opcode, 0x00, 0x00];
        let listed = &session_8051(&code, 0).listing(0, 1, false).unwrap()[0];
        let decoded = recore::i8051::I8051::decode(&code, 0).next().unwrap();
        let expected = if decoded.insn.is_some() { u64::from(decoded.len) } else { 1 };
        assert_eq!((listed.len, listed.text == "(bad)"), (expected, decoded.insn.is_none()), "opcode {opcode:#04x}: {}", listed.text);
    }
}

/// 8051 code in pieces, each at its `bank << 16 | address`.
fn banked_session(pieces: &[(u64, &[u8])]) -> Session {
    let sections: Vec<Section> = pieces.iter().map(|&(addr, data)| Section { addr, data, readonly: true, code: true }).collect();
    Session::new(&vendored_spec_dir().unwrap(), Target::I8051, &sections).unwrap()
}

#[test]
fn a_call_from_a_bank_reaches_shared_code_and_what_a_trampoline_stands_for() {
    // Shared by every bank: 0x0100: RET, and at 0x0200 a trampoline entry, which is never run:
    // MOV DPTR, #0x9000; LJMP 0x0300.
    let mut shared = vec![0x00; 0x100];
    shared.push(0x22);
    shared.resize(0x200, 0x00);
    shared.extend([0x90, 0x90, 0x00, 0x02, 0x03, 0x00]);
    // Bank 1, 0x8000: LCALL 0x0100; LCALL 0x0200; RET. Bank 2, 0x9000: RET.
    let mut session = banked_session(&[(0, &shared), (0x01_8000, &[0x12, 0x01, 0x00, 0x12, 0x02, 0x00, 0x22]), (0x02_9000, &[0x22])]);
    session.mirror(0x01_0000, 0x4000, 0);
    session.redirect(0x0200, 0x02_9000);
    session.name_function(0x0100, "shared").unwrap();
    session.name_function(0x02_9000, "far").unwrap();
    let function = session.decompile(0x01_8000).unwrap();
    assert!(function.c_text.contains("shared();\n  far();"), "{}", function.c_text);
}

#[test]
fn flow_stops_at_another_8051_function() {
    // 0x0000: LCALL 0x0010, then fall through into 0x0003: MOV R7, #7; RET. 0x0010: RET.
    let mut code = vec![0x12, 0x00, 0x10, 0x7f, 0x07, 0x22];
    code.resize(0x10, 0x00);
    code.push(0x22);
    assert!(!banked_session(&[(0, &code)]).decompile(0).unwrap().bad_data);

    let mut informed = banked_session(&[(0, &code)]);
    informed.add_function(0x0003, false).unwrap();
    assert!(informed.decompile(0).unwrap().bad_data);
    assert!(!informed.decompile(0x0003).unwrap().bad_data);
}

#[test]
fn memory_outside_the_code_is_named_in_its_own_address_space() {
    use recore::i8051::{IDATA, SFR, XDATA};
    // MOV DPTR, #0x1234; MOVX A, @DPTR; ADD A, 0x30; ADD A, 0xC1; MOV R7, A; RET
    let code = [0x90, 0x12, 0x34, 0xe0, 0x25, 0x30, 0x25, 0xc1, 0xff, 0x22];
    let mut session = banked_session(&[(0, &code)]);
    session.add_global(XDATA + 0x1234, "reading", None).unwrap();
    session.add_global(IDATA + 0x30, "offset", None).unwrap();
    session.add_global(SFR + 0xc1, "port", None).unwrap();
    let function = session.decompile(0).unwrap();
    // A register is read once, into a variable, since reading it may change it.
    assert!(function.c_text.contains("= port;") && function.c_text.contains("return reading + offset + "), "{}", function.c_text);
}
