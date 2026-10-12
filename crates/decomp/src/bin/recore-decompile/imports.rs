//! Measurements of where the decompiler's types come from: the prototype tables for imports, and
//! debug information.

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

/// Reads the debug information of `binary` as the decompiler's child process does, applies it
/// to a session, and prints what was found and how long each step took. What the engine
/// rejects goes to stderr.
pub fn debug_info(binary: &Path) -> Result<()> {
    use recore_decomp::{Session, types};
    let image = recore::Image::load(binary)?;
    let analysis = recore::analyze(&image);
    let Some(file) = types::debug_file(binary, &image) else {
        println!("no debug information for {binary:?}");
        return Ok(());
    };
    let start = std::time::Instant::now();
    let Some(debug) = types::load(binary, &image) else { return Ok(()) };
    let read = start.elapsed();
    let mut session = Session::from_image(&image, &analysis)?;
    let described = |addr: u64| analysis.functions.binary_search_by_key(&addr, |f| f.addr).is_ok_and(|index| analysis.functions[index].fragment_of.is_none());
    // The child gives a session the globals at once and each prototype when it is needed;
    // giving it all of them here is the most that can cost.
    let mut importer = types::Importer::new(&debug, Default::default());
    let start = std::time::Instant::now();
    importer.globals(&mut session);
    let globals = start.elapsed();
    importer.functions(&mut session, debug.functions.iter().map(|f| f.addr).filter(|&addr| described(addr)));
    let applied = start.elapsed();
    let functions = analysis.functions.iter().filter(|f| f.fragment_of.is_none()).count();
    let covered = debug.functions.iter().filter(|f| described(f.addr)).count();
    println!("{}: {} MB", file.display(), std::fs::metadata(&file)?.len() >> 20);
    println!("{} types, {} globals, prototypes for {covered} of {functions} functions", debug.types.len(), debug.globals.len());
    println!("read in {:.0} ms; globals applied in {:.0} ms, everything in {:.0} ms", read.as_secs_f64() * 1e3, globals.as_secs_f64() * 1e3, applied.as_secs_f64() * 1e3);
    // How long a decompiler child takes until it can answer, with the debug information and
    // without: the best of three each, taken in turns so that both see the same machine.
    let ready = |debug: bool| {
        let command = move || {
            let mut command = std::process::Command::new(std::env::current_exe().unwrap_or_default());
            command.arg("worker");
            if !debug {
                command.env(types::DEBUG_VAR, "off");
            }
            command
        };
        let start = std::time::Instant::now();
        let mut worker = recore_decomp::isolate::Worker::new(command, binary, &Default::default());
        worker.ready().then(|| start.elapsed().as_secs_f64() * 1e3)
    };
    let (mut with, mut without) = (f64::INFINITY, f64::INFINITY);
    for _ in 0..3 {
        without = without.min(ready(false).unwrap_or(f64::INFINITY));
        with = with.min(ready(true).unwrap_or(f64::INFINITY));
    }
    println!("child ready in {without:.0} ms without debug information, {with:.0} ms with");
    Ok(())
}
