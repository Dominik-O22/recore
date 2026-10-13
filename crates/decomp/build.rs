//! Compiles the C shim against the engine headers exported by `ghidra-decompiler-sys`.

fn main() {
    cc::Build::new()
        .cpp(true)
        .std("c++11")
        .define("LOCAL_ZLIB", None)
        .include(std::env::var("DEP_GHIDRA_DECOMP_INCLUDE").expect("set by ghidra-decompiler-sys"))
        .file("shim/shim.cc")
        .opt_level(2)
        // The engine headers are not clean under -Wextra; upstream builds with these settings.
        .extra_warnings(false)
        .flag("-Wno-sign-compare")
        .compile("recore_decomp_shim");
    println!("cargo:rerun-if-changed=shim/shim.cc");
    embed_languages();
}

/// Writes `languages.rs`: the engine's language files as bytes of the program, so that it runs
/// on a machine that has no copy of the sources, and a number that changes when they do.
fn embed_languages() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../third_party/ghidra-decompiler/languages").canonicalize().expect("the language files are vendored");
    println!("cargo:rerun-if-changed={}", dir.display());
    let mut files: Vec<_> = std::fs::read_dir(&dir).unwrap().map(|entry| entry.unwrap().path()).collect();
    files.sort();
    let mut id: u64 = 0xcbf2_9ce4_8422_2325;
    let mut list = String::new();
    for file in &files {
        let name = file.file_name().unwrap().to_str().unwrap();
        for byte in name.bytes().chain(std::fs::read(file).unwrap()) {
            id = (id ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3);
        }
        list += &format!("    ({name:?}, include_bytes!({:?})),\n", file.display().to_string());
    }
    let source = format!("pub const ID: u64 = {id:#x};\npub static FILES: &[(&str, &[u8])] = &[\n{list}];\n");
    std::fs::write(std::path::Path::new(&std::env::var("OUT_DIR").unwrap()).join("languages.rs"), source).unwrap();
}
