//! Whether a function returns a value, where only the code that calls it shows that it does.

use std::path::Path;
use std::process::Command;
use std::time::Duration;

use recore::program::Program;
use recore_decomp::isolate::{Options, Status, Worker, returning_callers};
use recore_decomp::{Section, Session, Target, vendored_spec_dir};

/// Whether the worker takes the function at 0x1010 of `code`, raw x86-64 code at 0x1000, for one
/// that returns a value. Execution starts at 0x1000.
fn returns_value(name: &str, code: &[u8]) -> bool {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("code.bin"), code).unwrap();
    let layout = format!("machine = \"x86-64\"\nentry = [0x1000]\n[[region]]\nfile = \"code.bin\"\noffset = 0\nlength = {}\naddress = 0x1000\nexecutable = true\n", code.len());
    std::fs::write(dir.join("image.toml"), layout).unwrap();
    let command = || {
        let mut command = Command::new(env!("CARGO_BIN_EXE_recore-decompile"));
        command.arg("worker");
        command
    };
    let mut worker = Worker::new(command, &dir.join("image.toml"), &Options::default());
    let program = Program::load(&dir.join("image.toml")).unwrap();
    worker.callers(0x1010, || returning_callers(&program, 0x1010));
    let (record, c_text) = worker.decompile(0x1010, Duration::from_secs(60));
    assert_eq!(record.status, Status::Ok, "{:?}", record.message);
    println!("{}", c_text.unwrap_or_default());
    record.returns_value
}

/// The code at 0x1000 calls the function at 0x1010, which ends by calling through a pointer and
/// so shows no value returned: `call [rdi]; ret`. `after` is the code after the call.
fn called(after: &[u8]) -> Vec<u8> {
    calling(after, &[0xff, 0x17, 0xc3])
}

/// The code at 0x1000 calls `callee`, at 0x1010, and runs on into `after`.
fn calling(after: &[u8], callee: &[u8]) -> Vec<u8> {
    let mut code = vec![0xe8, 0x0b, 0x00, 0x00, 0x00];
    code.extend(after);
    code.resize(0x10, 0xcc);
    code.extend(callee);
    code
}

/// Whether one decompilation of the function at 0x1010 of `code`, raw x86-64 code at 0x1000,
/// returns a value, given the call at 0x1000 as its caller and the functions at `entries`.
fn one_decompilation_returns(code: &[u8], entries: &[u64]) -> bool {
    let mut session = Session::new(&vendored_spec_dir().unwrap(), Target::X86_64Gcc, &[Section { addr: 0x1000, data: code, readonly: true, code: true }]).unwrap();
    for &entry in entries {
        session.add_function(entry, false).unwrap();
    }
    session.callers(0x1010, &[0x1000]);
    let function = session.decompile(0x1010).unwrap();
    println!("{}", function.c_text);
    function.returns_value
}

#[test]
fn a_function_returns_what_a_caller_reads() {
    // add eax, 1; ret
    assert!(returns_value("caller-reads", &called(&[0x83, 0xc0, 0x01, 0xc3])));
}

#[test]
fn one_decompilation_returns_what_a_caller_reads() {
    // add eax, 1; ret: the caller reads the low four bytes.
    let code = called(&[0x83, 0xc0, 0x01, 0xc3]);
    let mut session = Session::new(&vendored_spec_dir().unwrap(), Target::X86_64Gcc, &[Section { addr: 0x1000, data: &code, readonly: true, code: true }]).unwrap();
    session.callers(0x1010, &[0x1000]);
    let function = session.decompile(0x1010).unwrap();
    assert!(function.returns_value, "{}", function.c_text);
    assert_eq!(function.return_shape.size, 4, "{}", function.c_text);
}

#[test]
fn a_function_with_no_return_left_returns_what_a_caller_reads() {
    // The function at 0x1010 calls through a pointer and runs into bytes that do not decode, so
    // the engine finds no return in it: call [rdi]; then 0xff 0xff.
    let mut code = called(&[0x83, 0xc0, 0x01, 0xc3]);
    code.truncate(0x12);
    code.extend([0xff, 0xff]);
    let mut session = Session::new(&vendored_spec_dir().unwrap(), Target::X86_64Gcc, &[Section { addr: 0x1000, data: &code, readonly: true, code: true }]).unwrap();
    session.callers(0x1010, &[0x1000]);
    let function = session.decompile(0x1010).unwrap();
    assert!(function.bad_data, "{}", function.c_text);
    assert!(function.returns_value, "{}", function.c_text);
}

#[test]
fn a_caller_that_sets_the_register_first_reads_nothing() {
    // xor eax, eax; ret
    assert!(!returns_value("caller-sets", &called(&[0x31, 0xc0, 0xc3])));
}

#[test]
fn a_function_does_not_vouch_for_itself() {
    // 0x1000 calls 0x1010 and returns. 0x1010 calls itself until edi is 0, storing what each
    // call left in eax: test edi, edi; je ret; dec edi; call 0x1010; mov [rsi], eax; ret.
    let mut code = vec![0xe8, 0x0b, 0x00, 0x00, 0x00, 0xc3];
    code.resize(0x10, 0xcc);
    code.extend([0x85, 0xff, 0x74, 0x09, 0xff, 0xcf, 0xe8, 0xf5, 0xff, 0xff, 0xff, 0x89, 0x06, 0xc3]);
    assert!(!returns_value("only-itself", &code));
}

#[test]
fn a_function_that_leaves_the_register_as_it_found_it_returns_nothing_whatever_a_caller_reads() {
    // The caller reads eax: add eax, 1; ret. Compilers that see the callee know it leaves eax
    // alone and keep using their own value.
    let after = [0x83, 0xc0, 0x01, 0xc3];
    // mov [rdi], rsi; ret: the callee never names rax.
    assert!(!one_decompilation_returns(&calling(&after, &[0x48, 0x89, 0x37, 0xc3]), &[]));
    // mov [rdi], rax; ret: it reads rax and never writes it.
    assert!(!one_decompilation_returns(&calling(&after, &[0x48, 0x89, 0x07, 0xc3]), &[]));
}

#[test]
fn a_caller_that_pushes_the_register_reads_nothing() {
    // push rax; call [rbx]; pop rcx; ret: the push keeps the stack aligned for the next call.
    assert!(!one_decompilation_returns(&called(&[0x50, 0xff, 0x13, 0x59, 0xc3]), &[]));
}

#[test]
fn a_caller_that_sets_every_bit_or_none_reads_nothing() {
    // or eax, -1; ret
    assert!(!one_decompilation_returns(&called(&[0x83, 0xc8, 0xff, 0xc3]), &[]));
    // and eax, 0; ret
    assert!(!one_decompilation_returns(&called(&[0x83, 0xe0, 0x00, 0xc3]), &[]));
}

#[test]
fn the_function_after_a_call_that_never_comes_back_is_no_caller_reading() {
    // The function at 0x1010 loops forever: jmp $. Right after the call to it at 0x1000 the
    // function at 0x1005 starts, which reads rax: mov rbx, rax; ret.
    let code = calling(&[0x48, 0x89, 0xc3, 0xc3], &[0xeb, 0xfe]);
    assert!(!one_decompilation_returns(&code, &[0x1005]));
    // The same with a nop to pad the function at 0x1006.
    let code = calling(&[0x90, 0x48, 0x89, 0xc3, 0xc3], &[0xeb, 0xfe]);
    assert!(!one_decompilation_returns(&code, &[0x1006]));
}

