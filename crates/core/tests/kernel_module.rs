//! A Linux kernel module analyzes as if the kernel had loaded it: its functions where its symbols
//! put them, its calls to the kernel named, and its calls and jumps through the kernel's thunks
//! read as the returns and indirect calls the kernel patches them to.

use std::collections::BTreeSet;
use std::path::Path;

use recore::report::CallTarget;

#[test]
fn a_kernel_module_analyzes_as_the_kernel_loads_it() {
    let image = recore::Image::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/module.o")).unwrap();
    let analysis = recore::analyze(&image);
    let address = |name: &str| image.symbol_names.iter().find(|(_, n)| *n == name).map(|(&addr, _)| addr).unwrap();

    let mut starts: Vec<u64> = analysis.functions.iter().map(|function| function.addr).collect();
    starts.sort_unstable();
    assert_eq!(starts, ["remove", "probe", "call_probe", "call_twice", "init_module"].map(address));
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
