//! A Linux kernel module, for x86-64 or AArch64, analyzes as if the kernel had loaded it: its
//! functions where its symbols put them, and none inside one where no symbol names it, its calls
//! to the kernel named, and on x86-64 its calls and jumps through the kernel's thunks read as the
//! returns and indirect calls the kernel patches them to. On AArch64 the type hash kCFI puts
//! before each function is data, and two of them read as `adr` into other functions: see
//! module.c.

use std::collections::BTreeSet;
use std::path::Path;

use recore::report::CallTarget;

#[test]
fn a_kernel_module_analyzes_as_the_kernel_loads_it() {
    for fixture in ["module.o", "module-arm64.o"] {
        analyzes_as_loaded(fixture);
    }
}

fn load(fixture: &str) -> recore::Image {
    recore::Image::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(fixture)).unwrap()
}

fn analyzes_as_loaded(fixture: &str) {
    let image = load(fixture);
    let analysis = recore::analyze(&image);
    let address = |name: &str| image.symbol_names.iter().find(|(_, n)| *n == name).map(|(&addr, _)| addr).unwrap();

    let mut starts: Vec<u64> = analysis.functions.iter().map(|function| function.addr).collect();
    starts.sort_unstable();
    let kcfi: &[&str] = if fixture == "module-arm64.o" { &["kcfi_word", "kcfi_off_word", "kernel_probe"] } else { &[] };
    if !kcfi.is_empty() {
        // The symbols' sizes alone keep the `adr` targets from starting functions, and a stripped
        // module keeps none. Without them the `$d` marks must.
        let targets = hashes_read_as_adr(&image);
        let mut without_sizes = load(fixture);
        without_sizes.symbol_extents.clear();
        let started: Vec<u64> = recore::analyze(&without_sizes).functions.iter().map(|function| function.addr).filter(|addr| targets.contains(addr)).collect();
        assert_eq!(started, Vec::<u64>::new());
    }
    let named = ["remove", "probe", "call_probe", "call_twice", "init_module", "traced", "checked", "outer", "inner"];
    let mut expected: Vec<u64> = named.iter().chain(kcfi).map(|name| address(name)).collect();
    expected.sort_unstable();
    assert_eq!(starts, expected, "{fixture}");
    assert_eq!(image.entry, address("init_module"));

    let called: BTreeSet<&str> = analysis
        .calls
        .iter()
        .filter_map(|call| match call.target {
            CallTarget::Import(slot) => image.import_slots.get(&slot).map(String::as_str),
            CallTarget::Function(_) => None,
        })
        .collect();
    assert_eq!(called, BTreeSet::from(["kfree", "kmalloc", "panic", "printk"]));
    assert!(image.symbol_names.values().any(|name| name == "jiffies"));

    let pointed_to: BTreeSet<u64> = image.relative_targets.iter().map(|&(_, target)| target).collect();
    assert!(pointed_to.contains(&address("probe")) && pointed_to.contains(&address("remove")));
}

/// `panic` is the kernel's, which never returns, in a module alone. In a program that is no
/// kernel module an import of that name is some library's own function.
#[test]
fn a_call_to_the_kernels_panic_never_returns_only_in_a_kernel_module() {
    for fixture in ["module.o", "module-arm64.o"] {
        let mut image = load(fixture);
        assert!(image.kernel_module, "{fixture}");
        assert_eq!(panic_calls(&image), (1, 1), "{fixture}");
        image.kernel_module = false;
        assert_eq!(panic_calls(&image), (1, 0), "{fixture}");
    }
}

/// How many calls to `panic` the analysis finds, and how many of them never return.
fn panic_calls(image: &recore::Image) -> (usize, usize) {
    let analysis = recore::analyze(image);
    let calls: Vec<u64> = analysis
        .calls
        .iter()
        .filter(|call| matches!(call.target, CallTarget::Import(slot) if image.import_slots[&slot] == "panic"))
        .map(|call| call.at)
        .collect();
    (calls.len(), calls.iter().filter(|at| analysis.noreturn_calls.contains(at)).count())
}

/// Without the mapping symbols nothing says the hashes are data, and they are decoded. The one
/// that reads as an `adr` off a word still starts no function: no AArch64 instruction is there.
/// Nor do the symbols' sizes say so, as a stripped module keeps none.
#[test]
fn an_aarch64_function_starts_on_a_word() {
    let mut image = load("module-arm64-unmarked.o");
    hashes_read_as_adr(&image);
    image.symbol_extents.clear();
    let off_word: Vec<u64> = recore::analyze(&image).functions.iter().map(|function| function.addr).filter(|addr| !addr.is_multiple_of(4)).collect();
    assert_eq!(off_word, Vec::<u64>::new());
}

/// What the AArch64 tests stand on: the hash clang chose for `kcfi_word` reads as `adr` to an
/// instruction of `probe`, and the one for `kcfi_off_word` to a byte off a word in `call_twice`.
/// Each hash is three words before its function, ahead of the two `nop`s for ftrace. Returns the
/// two targets.
fn hashes_read_as_adr(image: &recore::Image) -> [u64; 2] {
    let address = |name: &str| image.symbol_names.iter().find(|(_, n)| *n == name).map(|(&addr, _)| addr).unwrap();
    let adr_before = |function: &str| {
        let at = address(function) - 12;
        let word = u32::from_le_bytes(image.bytes_from(at).unwrap()[..4].try_into().unwrap());
        assert_eq!(word & 0x9f00_0000, 0x1000_0000, "the hash of {function} is no `adr`");
        let offset = i64::from((word >> 5 & 0x7_ffff) << 2 | word >> 29 & 3) << 43 >> 43;
        at.wrapping_add_signed(offset)
    };
    let targets = [adr_before("kcfi_word"), adr_before("kcfi_off_word")];
    assert_eq!(targets, [address("probe") + 0x48, address("call_twice") + 0x55]);
    targets
}
