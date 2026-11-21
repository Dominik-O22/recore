//! A Linux kernel module, for x86-64 or AArch64, analyzes as if the kernel had loaded it: its
//! functions where its symbols put them, its calls to the kernel named, and on x86-64 its calls
//! and jumps through the kernel's thunks read as the returns and indirect calls the kernel
//! patches them to. On AArch64 the type hash kCFI puts before each function is data, and two of
//! them read as `adr` into other functions: see module.c.

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
    let kcfi: &[&str] = if fixture == "module-arm64.o" { &["kcfi_word", "kcfi_off_word"] } else { &[] };
    let mut expected: Vec<u64> = ["remove", "probe", "call_probe", "call_twice", "init_module"].iter().chain(kcfi).map(|name| address(name)).collect();
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
    assert_eq!(called, BTreeSet::from(["kfree", "kmalloc", "printk"]));
    assert!(image.symbol_names.values().any(|name| name == "jiffies"));

    let pointed_to: BTreeSet<u64> = image.relative_targets.iter().map(|&(_, target)| target).collect();
    assert!(pointed_to.contains(&address("probe")) && pointed_to.contains(&address("remove")));
}

/// Without the mapping symbols nothing says the hashes are data, and they are decoded. The one
/// that reads as an `adr` off a word still starts no function: no AArch64 instruction is there.
#[test]
fn an_aarch64_function_starts_on_a_word() {
    let image = load("module-arm64-unmarked.o");
    let off_word: Vec<u64> = recore::analyze(&image).functions.iter().map(|function| function.addr).filter(|addr| !addr.is_multiple_of(4)).collect();
    assert_eq!(off_word, Vec::<u64>::new());
}
