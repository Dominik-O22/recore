//! How many of a corpus's calls to imports the prototype tables cover.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::Result;
use recore::report::CallTarget;
use recore_decomp::prototypes;

/// Prints, over every binary in `bin_dir`, the share of call sites of imported functions whose
/// import has a prototype, by where the prototype comes from, and the `list` most-called
/// imports that have none.
pub fn coverage(bin_dir: &Path, list: usize) -> Result<()> {
    let mut by_source: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
    let mut uncovered: BTreeMap<String, usize> = BTreeMap::new();
    let mut binaries: Vec<std::path::PathBuf> = std::fs::read_dir(bin_dir)?.map(|entry| Ok(entry?.path())).collect::<Result<_>>()?;
    binaries.sort();
    for binary in binaries {
        // A directory of binaries also holds what is no binary.
        let Ok(image) = recore::Image::load(&binary) else { continue };
        let analysis = recore::analyze(&image);
        for import in &analysis.imports {
            let calls = analysis.calls.iter().filter(|call| call.target == CallTarget::Import(import.slot)).count();
            let source = prototypes::source(image.format, &import.name).unwrap_or("none");
            let entry = by_source.entry(source).or_default();
            *entry = (entry.0 + 1, entry.1 + calls);
            if source == "none" {
                *uncovered.entry(import.name.clone()).or_default() += calls;
            }
        }
    }
    let (imports, calls) = by_source.values().fold((0, 0), |sum, entry| (sum.0 + entry.0, sum.1 + entry.1));
    println!("{imports} imports, {calls} calls to them");
    for (source, (count, sites)) in &by_source {
        println!("{source:12} {count:7} imports {:5.1}%  {sites:8} calls {:5.1}%", 100.0 * *count as f64 / imports.max(1) as f64, 100.0 * *sites as f64 / calls.max(1) as f64);
    }
    let mut uncovered: Vec<(String, usize)> = uncovered.into_iter().collect();
    uncovered.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    for (name, sites) in uncovered.iter().take(list) {
        println!("  {sites:7} {name}");
    }
    Ok(())
}
