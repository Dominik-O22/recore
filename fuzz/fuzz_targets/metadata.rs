//! Parses the bytes as an IL2CPP `global-metadata.dat`, whose offsets and counts the parser
//! reads by hand.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let _ = recore::il2cpp::metadata::parse(data);
});
