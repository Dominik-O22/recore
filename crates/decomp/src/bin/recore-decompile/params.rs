//! Compares the parameter counts of a corpus run, and whether each function returns a value,
//! with the debug info of each binary.

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
    /// Functions whose debug info says whether they return a value, and of them those the
    /// decompiler agrees with. Variadic functions count here.
    returns_compared: usize,
    returns_matched: usize,
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
        self.returns_compared += other.returns_compared;
        self.returns_matched += other.returns_matched;
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
    let results: BTreeMap<u64, (usize, bool)> = report.functions.iter().filter(|r| r.status == Status::Ok).map(|r| (r.addr, (r.params, r.returns_value))).collect();
    for (addr, expected) in &debug.functions {
        let Some(&(found, returns_value)) = results.get(addr) else {
            tally.missing += 1;
            continue;
        };
        if let Some(expected) = expected.returns_value {
            tally.returns_compared += 1;
            tally.returns_matched += usize::from(returns_value == expected);
        }
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

/// The reports of a corpus run in `out_dir`, sorted.
fn reports(out_dir: &Path) -> Result<Vec<std::path::PathBuf>> {
    let mut reports: Vec<_> = std::fs::read_dir(out_dir)?
        .filter_map(|entry| Some(entry.ok()?.path()))
        .filter(|path| path.extension().is_some_and(|e| e == "json") && path.file_stem().is_some_and(|s| s != "summary"))
        .collect();
    reports.sort();
    Ok(reports)
}

/// Runs `work` on each of `items` on up to `jobs` threads, and collects what it returns.
fn in_parallel<T: Sync, R: Send>(items: &[T], jobs: usize, work: impl Fn(&T) -> R + Sync) -> Vec<R> {
    let results = Mutex::new(Vec::new());
    let next = std::sync::atomic::AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for _ in 0..jobs.max(1) {
            scope.spawn(|| {
                while let Some(item) = items.get(next.fetch_add(1, std::sync::atomic::Ordering::Relaxed)) {
                    let result = work(item);
                    results.lock().unwrap().push(result);
                }
            });
        }
    });
    results.into_inner().unwrap()
}

pub fn compare(out_dir: &Path, debug_dir: &Path, jobs: usize, list: usize) -> Result<()> {
    let reports = reports(out_dir)?;

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
    println!("returns a value or not: {} of {} match ({:.1}%)", total.returns_matched, total.returns_compared, 100.0 * total.returns_matched as f64 / total.returns_compared.max(1) as f64);
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

/// The counts [`against`] holds a run to, each with whether more of it is better.
const MEASURES: [(&str, bool); 3] = [("parameter counts right", true), ("returns a value or not right", true), ("failed or crashed", false)];

/// One binary's [`MEASURES`] in a run, over the functions that both runs decompiled.
type Counts = [usize; 3];

/// The [`MEASURES`] of `base` and of `head`, two runs of the same functions of one binary.
fn counted(base: &BinaryReport, head: &BinaryReport, debug: &DebugInfo) -> (Counts, Counts) {
    let ok = |report: &BinaryReport| -> BTreeMap<u64, (usize, bool)> { report.functions.iter().filter(|r| r.status == Status::Ok).map(|r| (r.addr, (r.params, r.returns_value))).collect() };
    let (base_ok, head_ok) = (ok(base), ok(head));
    // Over every function: a decompiler that starts to fail drops functions from the ones both
    // runs finished. A timeout depends on the load and is left out.
    let failed = |report: &BinaryReport| report.functions.iter().filter(|r| matches!(r.status, Status::Error | Status::Crash)).count();
    let (mut base_counts, mut head_counts) = ([0, 0, failed(base)], [0, 0, failed(head)]);
    for (addr, expected) in &debug.functions {
        // A function that timed out in one run says nothing about the other.
        let (Some(&base_found), Some(&head_found)) = (base_ok.get(addr), head_ok.get(addr)) else { continue };
        for (counts, (params, returns_value)) in [(&mut base_counts, base_found), (&mut head_counts, head_found)] {
            counts[0] += usize::from(!expected.variadic && params == expected.params);
            counts[1] += usize::from(expected.returns_value == Some(returns_value));
        }
    }
    (base_counts, head_counts)
}

/// Prints each of [`MEASURES`] that moved from the corpus run in `base_dir` to the one in
/// `head_dir`, over the functions both decompiled, with the binaries it moved in. Fails when
/// one got worse.
pub fn against(base_dir: &Path, head_dir: &Path, debug_dir: &Path, jobs: usize) -> Result<()> {
    let reports = reports(head_dir)?;
    let read = |path: &Path| -> Result<BinaryReport> { serde_json::from_slice(&std::fs::read(path)?).with_context(|| format!("parsing {path:?}")) };
    let mut binaries: Vec<(String, Counts, Counts)> = in_parallel(&reports, jobs, |path| -> Result<Option<(String, Counts, Counts)>> {
        let head = read(path)?;
        let base_path = base_dir.join(path.file_name().context("no file name")?);
        let debug_path = debug_dir.join(format!("{}.debug", head.name));
        if !base_path.exists() || !debug_path.exists() {
            return Ok(None);
        }
        let (base, head_counts) = counted(&read(&base_path)?, &head, &DebugInfo::load(&debug_path)?);
        Ok(Some((head.name, base, head_counts)))
    })
    .into_iter()
    .collect::<Result<Vec<_>>>()?
    .into_iter()
    .flatten()
    .collect();
    binaries.sort_by(|a, b| a.0.cmp(&b.0));

    let mut worse = Vec::new();
    for (index, (measure, more_is_better)) in MEASURES.into_iter().enumerate() {
        let (base, head): (usize, usize) = (binaries.iter().map(|b| b.1[index]).sum(), binaries.iter().map(|b| b.2[index]).sum());
        if base == head {
            continue;
        }
        let better = (head > base) == more_is_better;
        if !better {
            worse.push(measure);
        }
        println!("  {:<7} {measure:<30} {base} -> {head} ({:+})", if better { "better" } else { "worse" }, head as i64 - base as i64);
        for gained in [true, false] {
            let moved: Vec<(&str, usize)> = binaries.iter().filter_map(|(name, b, h)| {
                let (b, h) = (b[index], h[index]);
                ((h > b) == gained && h != b).then(|| (name.as_str(), h.abs_diff(b)))
            }).collect();
            if !moved.is_empty() {
                let total: usize = moved.iter().map(|m| m.1).sum();
                let list: Vec<String> = moved.iter().take(8).map(|(name, count)| format!("{name} {count}")).collect();
                println!("            {} {total} in {} binaries ({})", if gained { "gained" } else { "lost  " }, moved.len(), list.join(", "));
            }
        }
    }
    if worse.is_empty() {
        if binaries.iter().all(|b| b.1 == b.2) {
            println!("  no count changed");
        }
        Ok(())
    } else {
        anyhow::bail!("{} is worse than {}: {}", head_dir.display(), base_dir.display(), worse.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use recore_decomp::dwarf::Function;
    use recore_decomp::isolate::FunctionRecord;

    fn run(records: &[(u64, Status, usize, bool)]) -> BinaryReport {
        let functions = records.iter().map(|&(addr, status, params, returns_value)| FunctionRecord { status, params, returns_value, ..FunctionRecord::failed(addr, status, String::new(), 0.0) }).collect();
        BinaryReport { name: "b".into(), fragments_skipped: 0, functions }
    }

    #[test]
    fn a_return_gone_wrong_counts_and_a_timeout_counts_for_neither_run() {
        let function = |params, returns_value| Function { params, variadic: false, returns_value, c: true };
        let debug = DebugInfo { functions: BTreeMap::from([(0x10, function(1, Some(false))), (0x20, function(2, Some(true))), (0x30, function(0, None))]), symbols: BTreeMap::new() };
        let base = run(&[(0x10, Status::Ok, 1, false), (0x20, Status::Ok, 2, true), (0x30, Status::Ok, 0, true)]);
        // 0x10 now reads as returning a value, and 0x20 timed out.
        let head = run(&[(0x10, Status::Ok, 1, true), (0x20, Status::Timeout, 0, false), (0x30, Status::Ok, 0, false)]);
        assert_eq!(counted(&base, &head, &debug), ([2, 1, 0], [2, 0, 0]));
        // A function that fails drops out of the comparison, and counts as failed.
        let head = run(&[(0x10, Status::Error, 0, false), (0x20, Status::Ok, 2, true), (0x30, Status::Ok, 0, false)]);
        assert_eq!(counted(&base, &head, &debug), ([2, 1, 0], [2, 1, 1]));
    }
}
