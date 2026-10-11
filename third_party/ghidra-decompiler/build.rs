//! Compiles the vendored engine once. Dependents get the header directory as
//! `DEP_GHIDRA_DECOMP_INCLUDE` and compile their own shim against it, so editing a shim does not
//! rebuild the engine.

use std::path::{Path, PathBuf};

fn sources(dir: &Path, extension: &str) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("reading {dir:?}: {e}"))
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|e| e == extension))
        .collect();
    files.sort();
    files
}

fn main() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let (cpp, zlib) = (root.join("cpp"), root.join("zlib"));

    // The engine is far too slow unoptimized, so it is built at -O2 in every profile.
    cc::Build::new()
        .cpp(true)
        .std("c++11")
        .define("LOCAL_ZLIB", None)
        .files(sources(&cpp, "cc"))
        .opt_level(2)
        .warnings(false)
        .compile("ghidra_decomp");
    // Linked after the engine, which is its only user. NO_GZIP as in Ghidra's own build: the
    // vendored subset has no crc32.c.
    cc::Build::new().files(sources(&zlib, "c")).define("NO_GZIP", None).opt_level(2).warnings(false).compile("ghidra_zlib");

    println!("cargo:include={}", cpp.display());
    println!("cargo:rerun-if-changed={}", cpp.display());
    println!("cargo:rerun-if-changed={}", zlib.display());
    println!("cargo:rerun-if-changed=build.rs");
}
