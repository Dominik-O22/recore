//! What a value passed to a variadic function after its fixed parameters is taken for. Each
//! program is the function at 0x1000, then `g`, `printk` and the format `"%s: failed: %d\n"`:
//!
//! ```c
//! int f(struct device *dev, size_t *count) {
//!     int ret = -22;
//!     for (size_t i = 0; i < *count; i++) {
//!         ret = g(dev, i);
//!         if (ret) {
//!             printk("%s: failed: %d\n", dev->name, ret);
//!             break;
//!         }
//!     }
//!     return ret;
//! }
//! ```
//!
//! The int travels to `printk` in a whole register, whose upper half the caller never set.

use recore::report::CallTarget;
use recore_decomp::{Decompiled, Section, Session, Target, vendored_spec_dir};

/// Decompiles `f` of `code` with `printk` at `printk`, and the format at `format`, set up by
/// `prepare`. `g`, at `g`, has no prototype: its call site shows what it returns.
fn decompile(target: Target, code: &[u8], g: u64, printk: u64, prepare: impl FnOnce(&mut Session)) -> Decompiled {
    let mut session = Session::new(&vendored_spec_dir().unwrap(), target, &[Section { addr: 0x1000, data: code, readonly: true, code: true }]).unwrap();
    session.name_function(g, "g").unwrap();
    session.name_function(printk, "printk").unwrap();
    prepare(&mut session);
    session.decompile(0x1000).unwrap()
}

#[test]
fn an_int_passed_through_dots_keeps_its_width() {
    #[rustfmt::skip]
    let words: [u32; 31] = [
        0xa9bd7bfd, 0x910003fd, 0xa90153f3, 0xa9025bf5, 0xaa0003f5, 0xaa0103f6, // stp x29, x30, [sp, #-48]!; ...; mov x21, x0; mov x22, x1
        0x128002b4, 0xd2800013, // mov w20, #-22; mov x19, #0
        0xf94002c3, 0xeb03027f, 0x54000102, // loop: ldr x3, [x22]; cmp x19, x3; b.hs exit
        0xaa1503e0, 0xaa1303e1, 0x9400000f, 0x2a0003f4, 0x35000100, // mov x0, x21; mov x1, x19; bl g; mov w20, w0; cbnz w0, error
        0x91000673, 0x17fffff7, // add x19, x19, #1; b loop
        0x2a1403e0, 0xa94153f3, 0xa9425bf5, 0xa8c37bfd, 0xd65f03c0, // exit: mov w0, w20; ldp ...; ret
        0xf9402ea1, 0x2a1403e2, 0x100000c0, 0x94000004, 0x17fffff7, // error: ldr x1, [x21, #0x58]; mov w2, w20; adr x0, format; bl printk; b exit
        0xb9400000, 0xd65f03c0, // g: ldr w0, [x0]; ret
        0xd65f03c0, // printk: ret
    ];
    let mut code: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
    code.extend(b"%s: failed: %d\n\0");
    let function = decompile(Target::Aarch64, &code, 0x1070, 0x1078, |session| session.declare("extern int4 printk(char *fmt, ...);").unwrap());
    assert!(function.c_text.contains("printk(\"%s: failed: %d\\n\""), "{}", function.c_text);
    assert_eq!(function.return_shape.size, 4, "{}", function.c_text);
}

#[test]
fn an_int_a_format_asks_for_keeps_its_width() {
    #[rustfmt::skip]
    let mut code = vec![
        0x41, 0x55, 0x41, 0x54, 0x55, 0x53, 0x49, 0x89, 0xfc, 0x49, 0x89, 0xf5, // push r13; push r12; push rbp; push rbx; mov r12, rdi; mov r13, rsi
        0xbd, 0xea, 0xff, 0xff, 0xff, 0x31, 0xdb, // mov ebp, -22; xor ebx, ebx
        0x49, 0x3b, 0x5d, 0x00, 0x73, 0x17, // loop: cmp rbx, [r13]; jae exit
        0x4c, 0x89, 0xe7, 0x48, 0x89, 0xde, 0xe8, 0x2c, 0x00, 0x00, 0x00, // mov rdi, r12; mov rsi, rbx; call g
        0x89, 0xc5, 0x85, 0xc0, 0x75, 0x0f, // mov ebp, eax; test eax, eax; jne error
        0x48, 0x83, 0xc3, 0x01, 0xeb, 0xe3, // add rbx, 1; jmp loop
        0x89, 0xe8, 0x5b, 0x5d, 0x41, 0x5c, 0x41, 0x5d, 0xc3, // exit: mov eax, ebp; pop ...; ret
        0x49, 0x8b, 0x74, 0x24, 0x58, 0x89, 0xea, // error: mov rsi, [r12+0x58]; mov edx, ebp
        0x48, 0x8d, 0x3d, 0x0d, 0x00, 0x00, 0x00, 0x31, 0xc0, 0xe8, 0x05, 0x00, 0x00, 0x00, 0xeb, 0xe0, // lea rdi, [format]; xor eax, eax; call printk; jmp exit
        0x8b, 0x07, 0xc3, // g: mov eax, [rdi]; ret
        0xc3, // printk: ret
    ];
    code.extend(b"%s: failed: %d\n\0");
    // The call at 0x1049 is given the arguments its format asks for before `f` is decompiled.
    let function = decompile(Target::X86_64Gcc, &code, 0x1050, 0x1053, |session| {
        session.takes_variable_arguments(0x1053);
        session.format_call(0x1000, 0x1049, CallTarget::Function(0x1053), 0, 0x1054).unwrap();
    });
    assert_eq!(function.param_count(), 2, "{}", function.c_text);
    assert_eq!(function.return_shape.size, 4, "{}", function.c_text);
}
