//! Structs recovered from how a function uses the pointers it is passed, in the programs built
//! from `data/structs.c`: an x86-64 ELF, whose functions take their parameters in registers,
//! and a 32-bit PE, whose functions take them on the stack; and checked against the debug
//! information of the programs built from `data/types.c`.

use std::collections::BTreeSet;
use std::path::Path;

use recore::edits::Edits;
use recore::structs::Slot;
use recore_decomp::{Converged, Session};
use recore_decomp::types::{self, Type};

// The functions of the two builds, which are stripped.
const ELF_TOUCH: u64 = 0x401000;
const ELF_SUM: u64 = 0x401018;
const ELF_SPREAD: u64 = 0x401042;
const ELF_RELAY: u64 = 0x40107b;
const ELF_LOWER: u64 = 0x401090;
const PE_TOUCH: u64 = 0x401000;
const PE_SUM: u64 = 0x401030;
const PE_RELAY: u64 = 0x4010f0;

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

/// The tree's nodes and its header link to the header, 8 bytes into the tree: those fields
/// point into the middle of the tree's struct and not to it.
#[test]
fn a_link_into_the_middle_of_a_struct_does_not_point_to_it() {
    let mut session = session("structs.elf");
    session.decompile(ELF_LOWER).unwrap();
    assert_eq!(
        session.type_layout("S_401090_RDI").unwrap(),
        "struct S_401090_RDI, 28 bytes, alignment 8
  +0x8 undefined8 field_0x8 (8 bytes)
  +0x10 undefined8 field_0x10 (8 bytes)
  +0x18 int4 field_0x18 (4 bytes)
"
    );
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

/// A recovered struct covers what one function reads. Kept prototypes carry what a function
/// takes to the callers decompiled after it, and those must not see the callee's struct.
#[test]
fn a_caller_never_shows_its_callees_struct() {
    let mut session = session("structs.elf");
    session.keep_prototypes(true);
    assert!(session.decompile(ELF_TOUCH).unwrap().c_text.contains("S_401000_RDI *param_1"));
    let c_text = session.decompile(ELF_RELAY).unwrap().c_text;
    assert!(c_text.contains("(undefined8 param_1)"), "{c_text}");
    assert!(!c_text.contains("S_"), "{c_text}");
}

/// `touch`'s struct named `Connection`, the one its field points to `Session`, and a field
/// of each named, as an agent's renames leave the edits.
fn named_edits(session: &mut Session) -> Edits {
    session.decompile(ELF_TOUCH).unwrap();
    let mut edits = Edits::default();
    edits.adopt(&session.recovered("S_401000_RDI_8").unwrap());
    edits.name_struct("S_401000_RDI", "Connection").unwrap();
    edits.name_struct("S_401000_RDI_8", "Session").unwrap();
    edits
}

/// The caller hands its parameter to `touch` and reads nothing through it, which alone would
/// leave it `undefined8`.
#[test]
fn a_named_struct_shows_in_its_function_and_in_a_caller_that_passes_it() {
    let mut session = session("structs.elf");
    let mut edits = named_edits(&mut session);
    edits.name_field("Connection", "field_0x8", "session").unwrap();
    assert_eq!(edits.holders[&ELF_TOUCH][&Slot::Register("RDI".into())], "Connection");
    // A new session, as a new process starts from the saved edits.
    let mut session = self::session("structs.elf");
    assert_eq!(session.set_structs(&edits.structs, &edits.holders).unwrap(), Converged::InPlace);
    // The caller finds where `touch` takes the pointer in the prototype kept for it.
    session.keep_prototypes(true);
    let c_text = session.decompile(ELF_TOUCH).unwrap().c_text;
    assert!(c_text.contains("(Connection *param_1,int4 param_2)"), "{c_text}");
    assert!(c_text.contains("param_1->session->field_0x4 = param_2;"), "{c_text}");
    let c_text = session.decompile(ELF_RELAY).unwrap().c_text;
    assert!(c_text.contains("(Connection *param_1)"), "{c_text}");
}

/// The same through the stack: `touch` takes the pointer 4 bytes above the return address.
#[test]
fn a_named_struct_passed_on_the_stack_shows_in_the_caller() {
    let mut session = session("structs.exe");
    session.keep_prototypes(true);
    session.decompile(PE_TOUCH).unwrap();
    let mut edits = Edits::default();
    edits.adopt(&session.recovered("S_401000_stack4").unwrap());
    edits.name_struct("S_401000_stack4", "Connection").unwrap();
    assert_eq!(session.set_structs(&edits.structs, &edits.holders).unwrap(), Converged::InPlace);
    assert!(session.decompile(PE_TOUCH).unwrap().c_text.contains("(Connection *param_1,int4 param_2)"));
    let c_text = session.decompile(PE_RELAY).unwrap().c_text;
    assert!(c_text.contains("(Connection *param_1)"), "{c_text}");
}

#[test]
fn a_field_takes_its_new_name_in_the_running_session() {
    let mut session = session("structs.elf");
    let mut edits = named_edits(&mut session);
    assert_eq!(session.set_structs(&edits.structs, &edits.holders).unwrap(), Converged::InPlace);
    assert!(session.decompile(ELF_TOUCH).unwrap().c_text.contains("param_1->field_0x8->field_0x4 = param_2;"));
    edits.name_field("Session", "field_0x4", "retries").unwrap();
    assert_eq!(session.set_structs(&edits.structs, &edits.holders).unwrap(), Converged::InPlace);
    let c_text = session.decompile(ELF_TOUCH).unwrap().c_text;
    assert!(c_text.contains("param_1->field_0x8->retries = param_2;"), "{c_text}");
    assert!(session.type_layout("Session").unwrap().contains("+0x4 int4 retries (4 bytes)"));
}

/// Naming the struct a named one points to renames the type the session holds, and the field
/// that points to it follows.
#[test]
fn renaming_a_struct_a_named_one_points_to_stays_in_the_session() {
    let mut session = session("structs.elf");
    let mut edits = Edits::default();
    session.decompile(ELF_TOUCH).unwrap();
    edits.adopt(&session.recovered("S_401000_RDI").unwrap());
    edits.name_struct("S_401000_RDI", "Connection").unwrap();
    assert_eq!(session.set_structs(&edits.structs, &edits.holders).unwrap(), Converged::InPlace);
    edits.name_struct("S_401000_RDI_8", "Session").unwrap();
    assert_eq!(session.set_structs(&edits.structs, &edits.holders).unwrap(), Converged::InPlace);
    let c_text = session.decompile(ELF_TOUCH).unwrap().c_text;
    assert!(c_text.contains("(Connection *param_1,int4 param_2)"), "{c_text}");
    assert!(session.type_layout("Connection").unwrap().contains("+0x8 Session * field_0x8 (8 bytes)"));
}

#[test]
fn a_named_struct_that_grows_needs_a_new_session() {
    let mut session = session("structs.elf");
    let mut edits = named_edits(&mut session);
    assert_eq!(session.set_structs(&edits.structs, &edits.holders).unwrap(), Converged::InPlace);
    edits.structs.insert("Session".into(), recore::structs::Layout::new(0x20, edits.structs["Session"].fields().clone()).unwrap());
    assert_eq!(session.set_structs(&edits.structs, &edits.holders).unwrap(), Converged::Restart);
}

/// Where fields start in a type of the debug information, descending into the structs and
/// arrays inside it, and its size.
fn true_layout(debug: &types::Types, id: types::TypeId) -> (u64, BTreeSet<u64>) {
    fn starts(debug: &types::Types, id: types::TypeId, base: u64, out: &mut BTreeSet<u64>) {
        match debug.get(id) {
            Type::Composite { fields, .. } => fields.iter().for_each(|field| starts(debug, field.kind, base + field.offset, out)),
            Type::Array { element, count } => (0..*count).for_each(|index| starts(debug, *element, base + index * debug.size(*element), out)),
            Type::Typedef { target, .. } => starts(debug, *target, base, out),
            _ => {
                out.insert(base);
            }
        }
    }
    let mut out = BTreeSet::new();
    starts(debug, id, 0, &mut out);
    (debug.size(id), out)
}

/// The size and field offsets of a struct as `Session::type_layout` describes it.
fn recovered_layout(text: &str) -> (u64, BTreeSet<u64>) {
    let size = text.split(", ").nth(1).and_then(|part| part.strip_suffix(" bytes")).unwrap().parse().unwrap();
    let offsets = text.lines().skip(1).map(|line| u64::from_str_radix(line.trim().strip_prefix("+0x").unwrap().split(' ').next().unwrap(), 16).unwrap()).collect();
    (size, offsets)
}

/// The two programs built from `data/types.c` carry DWARF and a PDB, which say what each
/// parameter really points to. Decompiled without them, every recovered field starts where
/// a true field does, and no recovered struct is larger than the true one.
#[test]
fn recovered_structs_agree_with_the_debug_information() {
    for name in ["types.elf", "types.exe"] {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data").join(name);
        let image = recore::Image::load(&path).unwrap();
        let debug = types::load(&path, &image).unwrap();
        let mut session = Session::from_image(&image, &recore::analyze(&image)).unwrap();
        let mut checked = 0;
        for function in &debug.functions {
            let Type::Function(prototype) = debug.get(function.prototype) else { continue };
            let c_text = session.decompile(function.addr).unwrap().c_text;
            let signature = c_text.lines().find(|line| line.contains('(')).unwrap();
            let params = signature.split_once('(').unwrap().1.trim_end_matches(')').split(',');
            for (param, (_, kind)) in params.zip(&prototype.params) {
                let Some(recovered) = param.split(' ').next().filter(|type_name| type_name.starts_with("S_")) else { continue };
                let Type::Pointer(target) = debug.get(*kind) else { panic!("{name}: {recovered} for a parameter that is no pointer") };
                let (true_size, true_starts) = true_layout(&debug, *target);
                let (size, starts) = recovered_layout(&session.type_layout(recovered).unwrap());
                assert!(size <= true_size, "{name}: {recovered} is {size} bytes, the true struct {true_size}");
                assert!(starts.is_subset(&true_starts), "{name}: {recovered} has fields at {starts:x?}, the true struct at {true_starts:x?}");
                checked += 1;
            }
        }
        // `total` takes a list and `draw` a shape.
        assert_eq!(checked, 2, "{name}");
    }
}
