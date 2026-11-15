//! Parses the bytes as an executable and analyzes what loads: every number in the file reaches
//! the loaders' arithmetic, and the build has overflow checks on.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    if let Ok(image) = recore::Image::parse("fuzz".into(), data.to_vec()) {
        recore::analyze(&image);
    }
});
