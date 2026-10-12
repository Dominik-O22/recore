//! Types from debug information, read from the two small programs built from `data/types.c`:
//! an ELF that carries DWARF, and a PE with a PDB next to it.

use std::path::{Path, PathBuf};

use recore_decomp::Session;
use recore_decomp::types::{self, Importer, Type};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data").join(name)
}

/// The C of `function` in the fixture `name`, decompiled with its debug information, and the
/// engine's layout of `struct shape`.
fn decompiled(name: &str, function: &str) -> (String, String) {
    let path = fixture(name);
    let image = recore::Image::load(&path).unwrap();
    let analysis = recore::analyze(&image);
    let debug = types::load(&path, &image).expect("the fixture has debug information");
    let mut session = Session::from_image(&image, &analysis).unwrap();
    let mut importer = Importer::new(&debug, Default::default());
    importer.globals(&mut session);
    let addr = debug.functions.iter().find(|found| found.name == function).expect("the function is described").addr;
    importer.functions(&mut session, [addr]);
    (session.decompile(addr).unwrap().c_text, session.type_layout("shape").unwrap())
}

const SHAPE: &str = "struct shape, 32 bytes, alignment 8
  +0x0 color tint (4 bytes)
  +0x4 number size (4 bytes)
  +0x10 node * points (8 bytes)
  +0x18 _func_int4_shape_ptr_int4() * area (8 bytes)
";

#[test]
fn dwarf_gives_fields_their_names() {
    let (c_text, layout) = decompiled("types.elf", "draw");
    assert!(c_text.contains("(shape *shape)\n"), "{c_text}");
    // A bitfield, a call through a typed function pointer, and an enum field.
    assert!(c_text.contains("if (shape->visible == 0)"), "{c_text}");
    assert!(c_text.contains("(*shape->area)(shape,3)"), "{c_text}");
    assert!(c_text.contains("shape->tint"), "{c_text}");
    assert_eq!(layout, SHAPE);
}

#[test]
fn a_pdb_gives_fields_their_names() {
    let (c_text, layout) = decompiled("types.exe", "draw");
    assert!(c_text.contains("(shape *shape)\n"), "{c_text}");
    assert!(c_text.contains("if (shape->visible == 0)"), "{c_text}");
    assert!(c_text.contains("(*shape->area)(shape,3)"), "{c_text}");
    assert_eq!(layout, SHAPE);
}

#[test]
fn both_readers_find_the_same_program() {
    for name in ["types.elf", "types.exe"] {
        let path = fixture(name);
        let image = recore::Image::load(&path).unwrap();
        let debug = types::load(&path, &image).unwrap();
        let mut functions: Vec<&str> = debug.functions.iter().map(|function| function.name.as_str()).collect();
        functions.sort_unstable();
        assert_eq!(functions, ["draw", "start", "total"], "{name}");
        let globals: Vec<&str> = debug.globals.iter().map(|global| global.name.as_str()).collect();
        assert_eq!(globals, ["head"], "{name}");
        let total = debug.functions.iter().find(|function| function.name == "total").unwrap();
        let Type::Function(prototype) = debug.get(total.prototype) else { panic!("{name}: not a function type") };
        let params: Vec<&str> = prototype.params.iter().map(|param| param.0.as_str()).collect();
        assert_eq!(params, ["list", "scale"], "{name}");
        let Type::Pointer(node) = debug.get(prototype.params[0].1) else { panic!("{name}: not a pointer") };
        let Type::Composite { name: node_name, size, fields, .. } = debug.get(*node) else { panic!("{name}: not a struct") };
        let fields: Vec<(&str, u64)> = fields.iter().map(|field| (field.name.as_str(), field.offset)).collect();
        assert_eq!((node_name.as_str(), *size, fields), ("node", 16, vec![("value", 0), ("next", 8)]), "{name}");
    }
}

/// A session is not given a type until something needs it, and naming it is such a need.
#[test]
fn a_type_is_given_when_it_is_named() {
    let path = fixture("types.elf");
    let image = recore::Image::load(&path).unwrap();
    let analysis = recore::analyze(&image);
    let debug = types::load(&path, &image).unwrap();
    let mut session = Session::from_image(&image, &analysis).unwrap();
    let mut importer = Importer::new(&debug, Default::default());
    assert!(session.type_layout("number").is_err());
    importer.mentioned(&mut session, "struct holder { number count; };");
    assert_eq!(session.type_layout("number").unwrap(), "union number, 4 bytes, alignment 4\n  +0x0 int4 whole (4 bytes)\n  +0x0 float4 real (4 bytes)\n");
}

#[test]
fn debug_information_is_found_in_the_binary_and_next_to_it() {
    let path = fixture("types.elf");
    let image = recore::Image::load(&path).unwrap();
    assert_eq!(types::debug_file(&path, &image), Some(path.clone()));
    let path = fixture("types.exe");
    let image = recore::Image::load(&path).unwrap();
    assert_eq!(types::debug_file(&path, &image), Some(fixture("types.pdb")));
}
