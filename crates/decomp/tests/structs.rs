//! Structs recovered from how a function uses the pointers it is passed, in the programs built
//! from `data/structs.c`: an x86-64 ELF, whose functions take their parameters in registers,
//! and a 32-bit PE, whose functions take them on the stack.

use std::path::Path;

use recore_decomp::Session;

// The functions of the two builds, which are stripped.
const ELF_TOUCH: u64 = 0x401000;
const ELF_SUM: u64 = 0x401018;
const ELF_SPREAD: u64 = 0x401042;
const PE_TOUCH: u64 = 0x401000;
const PE_SUM: u64 = 0x401030;

fn session(name: &str) -> Session {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data").join(name);
    let image = recore::Image::load(&path).unwrap();
    Session::from_image(&image, &recore::analyze(&image)).unwrap()
}

#[test]
fn a_register_parameter_shows_its_fields_and_the_struct_one_points_to() {
    let mut session = session("structs.elf");
    let c_text = session.decompile(ELF_TOUCH).unwrap().c_text;
    assert!(c_text.contains("(S_401000_RDI *param_1,int4 param_2)"), "{c_text}");
    assert!(c_text.contains("if (param_1->field_0x10 < param_2)"), "{c_text}");
    assert!(c_text.contains("param_1->field_0x8->field_0x4 = param_2;"), "{c_text}");
    assert_eq!(
        session.type_layout("S_401000_RDI").unwrap(),
        "struct S_401000_RDI, 32 bytes, alignment 8
  +0x4 undefined4 field_0x4 (4 bytes)
  +0x8 S_401000_RDI_8 * field_0x8 (8 bytes)
  +0x10 int4 field_0x10 (4 bytes)
  +0x18 undefined8 field_0x18 (8 bytes)
"
    );
}

#[test]
fn a_list_points_to_its_own_struct() {
    let mut session = session("structs.elf");
    let c_text = session.decompile(ELF_SUM).unwrap().c_text;
    assert!(c_text.contains("iVar1 = iVar1 + param_1->field_0x0;"), "{c_text}");
    assert!(c_text.contains("param_1 = param_1->field_0x8;"), "{c_text}");
    assert_eq!(
        session.type_layout("S_401018_RDI").unwrap(),
        "struct S_401018_RDI, 16 bytes, alignment 8
  +0x0 int4 field_0x0 (4 bytes)
  +0x8 S_401018_RDI * field_0x8 (8 bytes)
"
    );
}

#[test]
fn a_pointer_stepped_through_an_array_points_to_one_element() {
    let mut session = session("structs.elf");
    let c_text = session.decompile(ELF_SPREAD).unwrap().c_text;
    assert!(c_text.contains("param_1->field_0x0 * param_1->field_0x8"), "{c_text}");
    assert!(c_text.contains("param_1 = param_1 + 1;"), "{c_text}");
    assert!(session.type_layout("S_401042_RDI").unwrap().starts_with("struct S_401042_RDI, 12 bytes"));
}

#[test]
fn a_stack_parameter_shows_its_fields() {
    let mut session = session("structs.exe");
    let c_text = session.decompile(PE_TOUCH).unwrap().c_text;
    assert!(c_text.contains("(S_401000_stack4 *param_1,int4 param_2)"), "{c_text}");
    assert!(c_text.contains("param_1->field_0x8->field_0x4 = param_2;"), "{c_text}");
    let c_text = session.decompile(PE_SUM).unwrap().c_text;
    assert!(c_text.contains("param_1 = param_1->field_0x4"), "{c_text}");
}

/// The engine cannot redefine a struct, and a parameter it locked once must not stay locked.
#[test]
fn decompiling_again_shows_the_same_structs() {
    let mut session = session("structs.elf");
    let first = session.decompile(ELF_TOUCH).unwrap().c_text;
    assert_eq!(session.decompile(ELF_TOUCH).unwrap().c_text, first);
}
