//! Data among AArch64 code, from fixtures/arm64-data-in-code.s: what a `$d` mapping symbol marks
//! is not decoded, the code it leaves out is, and a word of unmarked data that reads as `adr` to
//! an address off a word takes no address.

use std::path::Path;

use recore::report::{Analysis, CallTarget};

struct Fixture {
    image: recore::Image,
    analysis: Analysis,
}

impl Fixture {
    fn load() -> Self {
        let image = recore::Image::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/arm64-data-in-code.o")).unwrap();
        let analysis = recore::analyze(&image);
        Self { image, analysis }
    }

    fn address(&self, name: &str) -> u64 {
        self.image.symbol_names.iter().find(|(_, n)| *n == name).map(|(&addr, _)| addr).unwrap_or_else(|| panic!("no symbol {name}"))
    }

    fn is_function(&self, addr: u64) -> bool {
        self.analysis.functions.iter().any(|function| function.addr == addr)
    }
}

/// LLVM marks a zero-length data directive with a `$d` and a `$x` at one address, which marks no
/// data: among code, at a section's start, and at a section's end before one that opens with code.
#[test]
fn zero_length_data_marks_no_code_as_data() {
    let fixture = Fixture::load();
    // Each helper is 0x10 bytes past its caller, in the section after it for `end`.
    for caller in ["mid", "start", "end"] {
        let helper = fixture.address(caller) + 0x10;
        let call = fixture.analysis.calls.iter().find(|call| call.target == CallTarget::Function(helper));
        assert!(call.is_some_and(|call| call.at > fixture.address(caller)), "{caller} calls its helper");
        assert!(fixture.is_function(helper), "{caller}'s helper is a function");
    }
}

/// A `$d` at a section's start marks data, though the section before ends at the same address.
#[test]
fn data_at_a_section_start_is_not_decoded() {
    let fixture = Fixture::load();
    assert!(!fixture.is_function(fixture.address("hashed") + 4), "the word before `hashed` is no `bl`");
}

/// The jump back after a warning's trap is the last instruction before the next function's kCFI
/// hash. It is decoded, so the block it ends belongs to the function it jumps back into.
#[test]
fn code_right_before_marked_data_is_decoded() {
    let fixture = Fixture::load();
    let (split, cold) = (fixture.address("warn") + 0x1c, fixture.address("warn") + 0x28);
    assert!(fixture.is_function(split), "warn_split");
    assert!(!fixture.is_function(cold), "warn_cold");
}

/// The `adr` an unmarked hash reads as forms an address off a word. That is no function's start,
/// so the `cbnz` that branches past it to a cold block is no tail call.
#[test]
fn an_adr_off_a_word_takes_no_address() {
    let fixture = Fixture::load();
    assert!(!fixture.is_function(fixture.address("jumps") + 0x18), "jumps_fail");
}
