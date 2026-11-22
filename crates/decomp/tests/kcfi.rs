//! A kernel's or module's functions take the prototypes their kCFI hashes name. The fixture is
//! `module-arm64.o` of the analysis's tests, which clang built as a kernel that does not
//! normalize integers builds its modules: see `crates/core/tests/fixtures/build-module.sh`.

use std::path::{Path, PathBuf};

use recore_decomp::Session;
use recore_decomp::kcfi::{self, Spelling};
use recore_decomp::types::{self, Importer};

fn module() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../core/tests/fixtures/module-arm64.o")
}

/// The C of `function`, decompiled with the prototypes the module's hashes name or without.
fn decompiled(function: &str, hashes: bool) -> String {
    let path = module();
    let image = recore::Image::load(&path).unwrap();
    let analysis = recore::analyze(&image);
    let addr = analysis.functions.iter().find(|found| found.name.as_deref() == Some(function)).unwrap().addr;
    let mut session = Session::from_image(&image, &analysis).unwrap();
    let types = types::load(&path, &image).expect("the module's hashes name prototypes");
    let mut importer = Importer::new(&types, Default::default());
    if hashes {
        importer.functions(&mut session, [addr]);
    }
    session.decompile(addr).unwrap().c_text
}

#[test]
fn a_function_takes_the_prototype_its_hash_names() {
    let c_text = decompiled("kernel_probe", true);
    assert!(c_text.contains("int4 func_0xffff800000000258(platform_device *param_1)\n"), "{c_text}");
}

#[test]
fn a_function_whose_hash_names_no_kernel_type_keeps_what_is_inferred() {
    assert_eq!(decompiled("kcfi_word", true), decompiled("kcfi_word", false));
}

#[test]
fn a_module_of_a_kernel_that_does_not_normalize_is_read_in_the_plain_spelling() {
    let image = recore::Image::load(&module()).unwrap();
    assert_eq!(kcfi::types(&image).map(|(spelling, _)| spelling), Some(Spelling::Plain));
}

/// `module-unnamed.o` is `module-arm64.o` without `kernel_probe`'s symbol, made with
/// `llvm-objcopy --strip-symbol=kernel_probe`. Its hash is followed by four ftrace `nop`s, two
/// of them before the function.
fn unnamed() -> recore::Image {
    recore::Image::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/module-unnamed.o")).unwrap()
}

#[test]
fn a_hash_names_the_function_after_ftraces_nops_without_a_symbol() {
    assert!(kcfi::hashes(&unnamed()).contains(&(0xffff_8000_0000_0258, 0x63df_1691)));
}

/// A `vmlinux` is no module. The hash of `kernel_probe`'s type, found in its code where nothing
/// marks it, names that prototype too.
#[test]
fn a_kernels_hash_names_the_function_after_it() {
    let addr = 0xffff_ffc0_8000_0000;
    let data = [0x63df_1691u32, 0xd65f_03c0].iter().flat_map(|word| word.to_le_bytes()).collect();
    let text = recore::image::Section { name: ".text".into(), addr, data, file_offset: None, executable: true, writable: false };
    let mut image = recore::Image::bare("vmlinux".into(), recore::image::Format::Elf, recore::image::Machine::Aarch64, addr, vec![text]);
    image.marked_data = vec![(addr, addr + 4)];
    let (_, types) = kcfi::types(&image).expect("the hash names a prototype");
    assert_eq!(types.functions.iter().map(|function| function.addr).collect::<Vec<_>>(), vec![addr + 4]);
}
