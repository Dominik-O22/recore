//! Compares the parameter counts of a corpus run with the debug info of each binary.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Mutex;

use anyhow::{Context, Result};
use recore_decomp::dwarf::DebugInfo;

use recore_decomp::isolate::Status;

use crate::report::BinaryReport;

/// Source language and build of a corpus file, from its name: `[deb__]<package>__<binary>`.
/// The `deb` binaries are distribution builds of the same packages.
fn group(binary: &str) -> String {
    let (package, build) = match binary.strip_prefix("deb__") {
        Some(rest) => (rest, " (deb)"),
        None => (binary, ""),
    };
    let language = match package.split("__").next().unwrap_or(package) {
        "ripgrep" | "fish" | "bat" | "fd" | "eza" | "hyperfine" => "Rust",
        "cmake" | "ninja" | "ninja-build" | "re2c" | "gperf" => "C++",
        "fzf" => "Go",
        _ => "C",
    };
    format!("{language}{build}")
}

/// Why a count can differ for reasons the decompiler cannot see in the machine code.
fn cause(name: &str, difference: i64) -> &'static str {
    let clone = [".isra.", ".constprop.", ".part.", ".cold", ".lto_priv."].iter().any(|marker| name.contains(marker));
    match (clone, difference < 0) {
        (true, _) => "compiler clone (.isra, .constprop, .part)",
        (false, true) => "decompiler found fewer",
        (false, false) => "decompiler found more",
    }
}

/// Counts for one group of functions.
#[derive(Default, Clone)]
struct Tally {
    /// Functions with DWARF parameters that the run decompiled successfully.
    compared: usize,
    matched: usize,
    /// The same, of the functions in C units.
    compared_c: usize,
    matched_c: usize,
    /// Variadic functions, which are left out of the comparison.
    variadic: usize,
    /// Functions with DWARF parameters that the run has no successful result for.
    missing: usize,
    /// `decompiler - DWARF` to number of functions.
    differences: BTreeMap<i64, usize>,
    causes: BTreeMap<&'static str, usize>,
    mismatches: Vec<String>,
}

impl Tally {
    fn add(&mut self, other: &Tally) {
        self.compared += other.compared;
        self.matched += other.matched;
        self.compared_c += other.compared_c;
        self.matched_c += other.matched_c;
        self.variadic += other.variadic;
        self.missing += other.missing;
        for (&difference, count) in &other.differences {
            *self.differences.entry(difference).or_default() += count;
        }
        for (&cause, count) in &other.causes {
            *self.causes.entry(cause).or_default() += count;
        }
        self.mismatches.extend(other.mismatches.iter().cloned());
    }

    fn print(&self, label: &str) {
        println!(
            "{label}: {} of {} match ({:.1}%); {} variadic skipped, {} without a result",
            self.matched,
            self.compared,
            100.0 * self.matched as f64 / self.compared.max(1) as f64,
            self.variadic,
            self.missing
        );
    }
}

fn tally(report: &BinaryReport, debug: &DebugInfo) -> Tally {
    let mut tally = Tally::default();
    let results: BTreeMap<u64, usize> = report.functions.iter().filter(|r| r.status == Status::Ok).map(|r| (r.addr, r.params)).collect();
    for (addr, expected) in &debug.functions {
        let Some(&found) = results.get(addr) else {
            tally.missing += 1;
            continue;
        };
        // The fixed parameters of a variadic function say little about the registers it reads.
        if expected.variadic {
            tally.variadic += 1;
            continue;
        }
        let difference = found as i64 - expected.params as i64;
        tally.compared += 1;
        tally.compared_c += usize::from(expected.c);
        tally.matched_c += usize::from(expected.c && difference == 0);
        *tally.differences.entry(difference).or_default() += 1;
        if difference == 0 {
            tally.matched += 1;
        } else {
            let name = debug.symbols.get(addr).map_or("", String::as_str);
            *tally.causes.entry(cause(name, difference)).or_default() += 1;
            tally.mismatches.push(format!("{} {addr:#x} {name}: DWARF {}, decompiler {found}", report.name, expected.params));
        }
    }
    tally
}

pub fn compare(out_dir: &Path, debug_dir: &Path, jobs: usize, list: usize) -> Result<()> {
    let mut reports: Vec<_> = std::fs::read_dir(out_dir)?
        .filter_map(|entry| Some(entry.ok()?.path()))
        .filter(|path| path.extension().is_some_and(|e| e == "json") && path.file_stem().is_some_and(|s| s != "summary"))
        .collect();
    reports.sort();

    // Reading DWARF dominates, so binaries are compared in parallel.
    let tallies: Mutex<BTreeMap<String, Tally>> = Mutex::new(BTreeMap::new());
    let next = std::sync::atomic::AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for _ in 0..jobs.max(1) {
            scope.spawn(|| {
                while let Some(path) = reports.get(next.fetch_add(1, std::sync::atomic::Ordering::Relaxed)) {
                    let one = || -> Result<Option<(String, Tally)>> {
                        let report: BinaryReport = serde_json::from_slice(&std::fs::read(path)?).with_context(|| format!("parsing {path:?}"))?;
                        let debug_path = debug_dir.join(format!("{}.debug", report.name));
                        if !debug_path.exists() {
                            return Ok(None);
                        }
                        let tally = tally(&report, &DebugInfo::load(&debug_path)?);
                        Ok(Some((report.name, tally)))
                    };
                    match one() {
                        Ok(Some((name, tally))) => drop(tallies.lock().unwrap().insert(name, tally)),
                        Ok(None) => {}
                        Err(error) => eprintln!("{}: {error:#}", path.display()),
                    }
                }
            });
        }
    });
    let tallies = tallies.into_inner().unwrap();

    let mut total = Tally::default();
    let mut groups: BTreeMap<String, Tally> = BTreeMap::new();
    for (name, tally) in &tallies {
        total.add(tally);
        groups.entry(group(name)).or_default().add(tally);
    }
    total.print(&format!("{} binaries with debug info", tallies.len()));
    println!("of them in C units: {} of {} match ({:.1}%)", total.matched_c, total.compared_c, 100.0 * total.matched_c as f64 / total.compared_c.max(1) as f64);
    for (group, tally) in &groups {
        tally.print(group);
    }
    println!("decompiler minus DWARF: {:?}", total.differences);
    println!("mismatches: {:?}", total.causes);
    for (group, tally) in &groups {
        println!("  {group}: {:?}", tally.causes);
    }
    println!("lowest match rates:");
    let mut worst: Vec<(&String, &Tally)> = tallies.iter().filter(|(_, t)| t.compared >= 50).collect();
    worst.sort_by(|a, b| (a.1.matched * b.1.compared).cmp(&(b.1.matched * a.1.compared)));
    for (name, tally) in worst.iter().take(8) {
        tally.print(&format!("  {name}"));
    }
    // An even sample across the corpus, since the list is sorted by binary.
    for line in total.mismatches.iter().step_by((total.mismatches.len() / list.max(1)).max(1)).take(list) {
        println!("  {line}");
    }
    Ok(())
}
