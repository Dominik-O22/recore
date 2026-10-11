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
}
