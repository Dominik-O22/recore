//! Sessions over hand-assembled code, so the tests need no corpus binary.

use recore_decomp::facts::SwitchCall;
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

/// A callee that reads one of its two arguments still pops both, with `RET 8`, and the caller's
/// stack is where the callee left it.
#[test]
fn a_callee_takes_every_argument_it_pops() {
    use recore::image::{Format, Machine};
    #[rustfmt::skip]
    let code = [
        // 0x1000: sub esp, 8; mov dword [esp+4], 0x2a; push 0; push 7; call 0x1020;
        // mov eax, [esp+4]; add esp, 8; ret
        0x83, 0xec, 0x08, 0xc7, 0x44, 0x24, 0x04, 0x2a, 0x00, 0x00, 0x00, 0x6a, 0x00, 0x6a, 0x07,
        0xe8, 0x0c, 0x00, 0x00, 0x00, 0x8b, 0x44, 0x24, 0x04, 0x83, 0xc4, 0x08, 0xc3, 0xcc, 0xcc, 0xcc, 0xcc,
        // 0x1020: mov eax, [esp+4]; ret 8
        0x8b, 0x44, 0x24, 0x04, 0xc2, 0x08, 0x00,
    ];
    let section = recore::image::Section { name: ".text".into(), addr: 0x1000, data: code.to_vec(), file_offset: None, executable: true, writable: false };
    let image = recore::Image::bare("test".into(), Format::Pe, Machine::X86, 0x1000, vec![section]);
    let analysis = recore::analyze(&image);
    let mut session = Session::from_image(&image, &analysis).unwrap();
    session.add_functions(&Facts::derive(&image, &analysis)).unwrap();

    let callee = session.decompile(0x1020).unwrap();
    let storage: Vec<&str> = callee.params.iter().map(|p| p.storage.as_str()).collect();
    assert_eq!(storage, ["stack:0x4", "stack:0x8"], "{}", callee.c_text);
    // The local the caller set before the call, not the argument it pushed.
    let caller = session.decompile(0x1000).unwrap();
    assert!(caller.c_text.contains("return 0x2a;"), "{}", caller.c_text);
}

/// A fastcall callee that only stores the register it is passed still takes it, and its caller
/// passes it.
#[test]
fn a_fastcall_callee_takes_the_registers_it_stores() {
    use recore::image::{Format, Machine};
    #[rustfmt::skip]
    let code = [
        0xb9, 0x2a, 0x00, 0x00, 0x00,              // 0x1000  mov ecx, 0x2a
        0xe8, 0x16, 0x00, 0x00, 0x00,              // 0x1005  call 0x1020
        0xba, 0x07, 0x00, 0x00, 0x00,              // 0x100a  mov edx, 7
        0xe8, 0x17, 0x00, 0x00, 0x00,              // 0x100f  call 0x102b
        0xc3,                                      // 0x1014  ret
        0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
        0x89, 0x0d, 0x00, 0x20, 0x00, 0x00,        // 0x1020  mov [0x2000], ecx
        0xc3,                                      // 0x1026  ret
        0xcc, 0xcc, 0xcc, 0xcc,
        0x89, 0x15, 0x04, 0x20, 0x00, 0x00,        // 0x102b  mov [0x2004], edx
        0xc3,                                      // 0x1031  ret
    ];
    let text = recore::image::Section { name: ".text".into(), addr: 0x1000, data: code.to_vec(), file_offset: None, executable: true, writable: false };
    let data = recore::image::Section { name: ".data".into(), addr: 0x2000, data: vec![0; 8], file_offset: None, executable: false, writable: true };
    let image = recore::Image::bare("test".into(), Format::Pe, Machine::X86, 0x1000, vec![text, data]);
    let analysis = recore::analyze(&image);
    let mut session = Session::from_image(&image, &analysis).unwrap();
    session.add_functions(&Facts::derive(&image, &analysis)).unwrap();
    session.keep_prototypes(true);

    for (callee, register) in [(0x1020, "ECX"), (0x102b, "EDX")] {
        let function = session.decompile(callee).unwrap();
        let storage: Vec<&str> = function.params.iter().map(|p| p.storage.as_str()).collect();
        assert_eq!(storage.last(), Some(&register), "{}", function.c_text);
    }
    let caller = session.decompile(0x1000).unwrap();
    assert!(caller.c_text.contains("(0x2a);") && caller.c_text.contains(",7);"), "{}", caller.c_text);
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
    for opcode in 0..=255u8 {
        let code = [opcode, 0x00, 0x00];
        let listed = &session_8051(&code, 0).listing(0, 1, false).unwrap()[0];
        let decoded = recore::i8051::decode(&code, 0).next().unwrap();
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
fn a_branch_stops_at_another_8051_function() {
    // 0x0000: MOV A, R7; JZ 0x0004; RET. 0x0004: MOV R7, #7; RET.
    let code = [0xef, 0x60, 0x01, 0x22, 0x7f, 0x07, 0x22];
    assert!(!banked_session(&[(0, &code)]).decompile(0).unwrap().bad_data);

    let mut informed = banked_session(&[(0, &code)]);
    informed.add_function(0x0004, false).unwrap();
    assert!(informed.decompile(0).unwrap().bad_data);
    assert!(!informed.decompile(0x0004).unwrap().bad_data);
}

#[test]
fn a_call_to_a_switch_routine_is_a_switch_over_its_table() {
    // MOV A, R7; LCALL 0x0100, then four bytes that are a table and no code. The cases, at
    // 0x0008 and 0x000B: MOV R7, #1; RET and MOV R7, #2; RET.
    let mut code = vec![0xef, 0x12, 0x01, 0x00, 0xa5, 0xa5, 0xa5, 0xa5, 0x7f, 0x01, 0x22, 0x7f, 0x02, 0x22];
    code.resize(0x100, 0x00);
    code.push(0x22);
    let mut session = banked_session(&[(0, &code)]);
    session.add_functions(&Facts { functions: vec![(0, false), (0x100, false)], switch_calls: vec![SwitchCall { call: 0x0001, selector: c"ACC", cases: None }], ..Facts::default() }).unwrap();
    session.override_jump_table(0, 0x0001, &[0x0008, 0x000b]).unwrap();
    let function = session.decompile(0).unwrap();
    assert!(!function.bad_data, "{}", function.c_text);
    let c: String = function.c_text.split_whitespace().collect::<Vec<_>>().join(" ");
    // The engine labels the cases of a table it is handed by where they are.
    assert!(c.contains("switch(param_1) { case 8: return 1; case 0xb: return 2; }"), "{}", function.c_text);
}

#[test]
fn a_call_returns_past_the_data_its_routine_reads() {
    // LCALL 0x0100; four bytes that are no code; MOV R7, #5; RET.
    let mut code = vec![0x12, 0x01, 0x00, 0xa5, 0xa5, 0xa5, 0xa5, 0x7f, 0x05, 0x22];
    code.resize(0x100, 0x00);
    code.push(0x22);
    let mut session = banked_session(&[(0, &code)]);
    session.add_functions(&Facts { functions: vec![(0, false)], names: vec![(0x100, "store".into())], data_after_calls: vec![(0, 4)], ..Facts::default() }).unwrap();
    let function = session.decompile(0).unwrap();
    assert!(!function.bad_data, "{}", function.c_text);
    assert!(function.c_text.contains("store();\n  return 5;"), "{}", function.c_text);
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

#[test]
fn an_8051_function_that_runs_into_the_next_one_calls_it() {
    // 0x0000: MOV R7, #1, and then the function at 0x0002: MOV A, R7; MOV R6, A; RET.
    let mut session = banked_session(&[(0, &[0x7f, 0x01, 0xef, 0xfe, 0x22])]);
    session.name_function(0x0002, "next").unwrap();
    let function = session.decompile(0).unwrap();
    assert!(!function.bad_data, "{}", function.c_text);
    assert!(function.c_text.contains("next(1);\n  return;"), "{}", function.c_text);
}

#[test]
fn an_8051_register_copied_by_its_address_keeps_its_value() {
    // MOV 0x05, 0x07 (R5 from R7, by their addresses); MOV A, R5; INC A; MOV R7, A; RET
    let function = banked_session(&[(0, &[0x85, 0x07, 0x05, 0xed, 0x04, 0xff, 0x22])]).decompile(0).unwrap();
    assert!(function.c_text.contains("return param_1 + '\\x01';"), "{}", function.c_text);
}

#[test]
fn an_8051_table_is_read_in_the_bank_of_the_code_that_reads_it() {
    // In bank 2: MOV DPTR, #0x9000; MOV A, R7; MOVC A, @A+DPTR; MOV R7, A; RET
    let function = session_8051(&[0x90, 0x90, 0x00, 0xef, 0x93, 0xff, 0x22], 0x02_8000).decompile(0x02_8000).unwrap();
    assert!(function.c_text.contains("+ 0x29000)"), "{}", function.c_text);
}
