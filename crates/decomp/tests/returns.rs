//! Whether a function returns a value, where only the code that calls it shows that it does.

use std::path::Path;
use std::process::Command;
use std::time::Duration;

use recore_decomp::isolate::{Options, Status, Worker};

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
    let (record, c_text) = Worker::new(command, &dir.join("image.toml"), &Options::default()).decompile(0x1010, Duration::from_secs(60));
    assert_eq!(record.status, Status::Ok, "{:?}", record.message);
    println!("{}", c_text.unwrap_or_default());
    record.returns_value
}

/// The code at 0x1000 calls the function at 0x1010, which ends by calling through a pointer and
/// so shows no value returned: `call [rdi]; ret`. `after` is the code after the call.
fn called(after: &[u8]) -> Vec<u8> {
    let mut code = vec![0xe8, 0x0b, 0x00, 0x00, 0x00];
    code.extend(after);
    code.resize(0x10, 0xcc);
    code.extend([0xff, 0x17, 0xc3]);
    code
}

#[test]
fn a_function_returns_what_a_caller_reads() {
    // add eax, 1; ret
    assert!(returns_value("caller-reads", &called(&[0x83, 0xc0, 0x01, 0xc3])));
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
