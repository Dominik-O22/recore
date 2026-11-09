//! Compares the parameter counts of a corpus run, whether each function returns a value, and
//! what its parameters and its return are, with the debug info of each binary.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Mutex;

use anyhow::{Context, Result};
use object::Object;
use recore::image::Machine;
use recore_decomp::dwarf::{self, DebugInfo};
use recore_decomp::isolate::{FunctionRecord, Status};
use recore_decomp::types::{Base, Type, TypeId, Types};
use recore_decomp::{Kind, Shape};

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

/// What the debug information says a value of type `id` is, as the machine code holds it. `None`
/// for nothing at all, for bytes it gives no type, and for a struct or union by value: that
/// arrives split among registers or on the stack as the ABI says, which the parameter count
/// already scores. Also for a float wider than a double, which the engine sizes by the 10
/// bytes x87 holds and DWARF by the 16 it is stored in, and for an array that is `returned`:
/// C returns none, and the reader spells a pointer to a member function as one, two words wide.
fn shape(types: &Types, mut id: TypeId, returned: bool) -> Option<Shape> {
    loop {
        let (kind, size) = match types.get(id) {
            Type::Typedef { target, .. } | Type::Alias(target) => {
                id = *target;
                continue;
            }
            Type::Base { base: Base::Float, size } if *size <= 8 => (Kind::Float, *size),
            Type::Base { base: Base::Float | Base::Unknown, .. } | Type::Void | Type::Composite { .. } => return None,
            Type::Array { .. } if returned => return None,
            Type::Base { size, .. } | Type::Enum { size, .. } => (Kind::Int, *size),
            // An array parameter is a pointer to its first element, and a function one a
            // pointer to the function.
            Type::Pointer(_) | Type::Array { .. } | Type::Function(_) => (Kind::Pointer, types.pointer),
        };
        return Some(Shape { kind, size: size as u32 });
    }
}

/// `found` as it is compared: the decompiler calls a value it did arithmetic on or passed along
/// `undefinedN` or an integer from one build to the next, and either reads as a number of that
/// size. Calling a number a pointer, or a pointer a number, is what the score is after.
fn comparable(found: Shape) -> Shape {
    Shape { kind: if found.kind == Kind::Unknown { Kind::Int } else { found.kind }, ..found }
}

/// What [`Typed::score`] counts.
#[derive(Default, Clone, Copy, PartialEq, Debug)]
struct Shapes {
    params: usize,
    params_matched: usize,
    returns: usize,
    returns_matched: usize,
    /// Of `params`, the pointers, and of `params_matched`. Typing every untyped value a pointer
    /// would raise these two and `params_matched` with them, so `pointers_claimed` counts the
    /// parameters the decompiler calls a pointer, right or wrong.
    pointers: usize,
    pointers_matched: usize,
    pointers_claimed: usize,
}

impl std::ops::AddAssign for Shapes {
    fn add_assign(&mut self, other: Shapes) {
        self.params += other.params;
        self.params_matched += other.params_matched;
        self.returns += other.returns;
        self.returns_matched += other.returns_matched;
        self.pointers += other.pointers;
        self.pointers_matched += other.pointers_matched;
        self.pointers_claimed += other.pointers_claimed;
    }
}

fn spelled(shape: Shape) -> String {
    let kind = match shape.kind {
        Kind::Unknown | Kind::Int => "a number",
        Kind::Float => "a float",
        Kind::Pointer => "a pointer",
        Kind::Aggregate => "a struct",
    };
    format!("{kind} of {}", shape.size)
}

/// What the debug information says each function's parameters and return are.
struct Typed {
    /// By address: each parameter's shape, and the return's.
    functions: BTreeMap<u64, (Vec<Option<Shape>>, Option<Shape>)>,
}

impl Typed {
    fn load(debug: &Path) -> Result<Typed> {
        let data = std::fs::read(debug)?;
        // Reading types needs the size of a pointer and the ABI, which the instruction set
        // within 32-bit ARM does not change.
        let machine = match object::File::parse(&*data)?.architecture() {
            object::Architecture::X86_64 => Machine::X86_64,
            object::Architecture::I386 => Machine::X86,
            object::Architecture::Aarch64 => Machine::Aarch64,
            object::Architecture::Arm => Machine::Arm,
            other => anyhow::bail!("{}: no types are read for {other:?}", debug.display()),
        };
        drop(data);
        let types = dwarf::types(debug, machine)?;
        let functions = types
            .functions
            .iter()
            .filter_map(|function| match types.get(function.prototype) {
                Type::Function(prototype) if !prototype.variadic => Some((function.addr, (prototype.params.iter().map(|&(_, kind)| shape(&types, kind, false)).collect(), shape(&types, prototype.returns, true)))),
                _ => None,
            })
            .collect();
        Ok(Typed { functions })
    }

    /// For the function `record` is of, its parameters the decompiler has a parameter of the
    /// same shape for, and whether its return is of the right one. Parameters pair off by shape
    /// and not by position, since the decompiler lists the ones in integer registers before the
    /// ones in float registers whatever order the source has them in, so two it swapped still
    /// count. Nothing is counted for parameters where the count is wrong, which that score
    /// already says, or where the debug information gives one of them no shape: what the
    /// decompiler made of that one could pair with another. Nor for a return that only one of
    /// the two accounts has. `misses` counts what was taken for what, as `a pointer of 8 as a
    /// number of 8`: a return, and a parameter where the function has one miss, so that it is
    /// plain which was which.
    fn score(&self, record: &FunctionRecord, misses: &mut BTreeMap<String, usize>) -> Shapes {
        let mut counts = Shapes::default();
        let Some((params, returns)) = self.functions.get(&record.addr) else { return counts };
        let mut miss = |what: &str, expected: Shape, found: Shape| *misses.entry(format!("{what}: {} as {}", spelled(expected), spelled(found))).or_default() += 1;
        if let Some(params) = params.iter().copied().collect::<Option<Vec<Shape>>>().filter(|params| params.len() == record.shapes.len()) {
            let mut found: Vec<Shape> = record.shapes.iter().copied().map(comparable).collect();
            counts.pointers_claimed = found.iter().filter(|found| found.kind == Kind::Pointer).count();
            let mut missed = Vec::new();
            for expected in params {
                let pointer = usize::from(expected.kind == Kind::Pointer);
                counts.params += 1;
                counts.pointers += pointer;
                match found.iter().position(|&found| found == expected) {
                    Some(at) => {
                        found.swap_remove(at);
                        counts.params_matched += 1;
                        counts.pointers_matched += pointer;
                    }
                    None => missed.push(expected),
                }
            }
            if let ([expected], [found]) = (missed.as_slice(), found.as_slice()) {
                miss("parameter", *expected, *found);
            }
        }
        if let (Some(expected), Some(found)) = (*returns, record.return_shape.map(comparable)) {
            counts.returns += 1;
            if found == expected {
                counts.returns_matched += 1;
            } else {
                miss("return", expected, found);
            }
        }
        counts
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
    types: Shapes,
    /// What was taken for what, as [`Typed::score`] words it.
    type_misses: BTreeMap<String, usize>,
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
        self.types += other.types;
        for (miss, count) in &other.type_misses {
            *self.type_misses.entry(miss.clone()).or_default() += count;
        }
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

fn tally(report: &BinaryReport, debug: &DebugInfo, typed: &Typed) -> Tally {
    let mut tally = Tally::default();
    for record in report.functions.iter().filter(|record| record.status == Status::Ok) {
        tally.types += typed.score(record, &mut tally.type_misses);
    }
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
                        let tally = tally(&report, &DebugInfo::load(&debug_path)?, &Typed::load(&debug_path)?);
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
    let Shapes { params, params_matched, returns, returns_matched, pointers, pointers_matched, pointers_claimed } = total.types;
    println!("parameter types, a number, a float or a pointer of the size: {params_matched} of {params} match ({:.1}%)", 100.0 * params_matched as f64 / params.max(1) as f64);
    println!("return types: {returns_matched} of {returns} match ({:.1}%)", 100.0 * returns_matched as f64 / returns.max(1) as f64);
    println!("of the parameters, pointers: {pointers_matched} of {pointers} match ({:.1}%), and the decompiler calls {pointers_claimed} one", 100.0 * pointers_matched as f64 / pointers.max(1) as f64);
    for (group, tally) in &groups {
        tally.print(group);
    }
    let mut misses: Vec<(&String, &usize)> = total.type_misses.iter().collect();
    misses.sort_by_key(|&(_, &count)| std::cmp::Reverse(count));
    println!("types taken for another, the most often:");
    for (miss, count) in misses.iter().take(10) {
        println!("  {count} {miss}");
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
const MEASURES: [(&str, bool); 6] = [
    ("parameter counts right", true),
    ("returns a value or not right", true),
    ("failed or crashed", false),
    ("parameter types right", true),
    ("return types right", true),
    // What keeps typing every untyped value a pointer from passing for better types.
    ("parameters wrongly called a pointer", false),
];

/// One binary's [`MEASURES`] in a run, over the functions that both runs decompiled.
type Counts = [usize; 6];

/// The [`MEASURES`] of `base` and of `head`, two runs of the same functions of one binary, and
/// how many functions have their parameters' types scored in both.
fn counted(base: &BinaryReport, head: &BinaryReport, debug: &DebugInfo, typed: &Typed) -> (Counts, Counts, usize) {
    let ok = |report: &BinaryReport| -> BTreeMap<u64, (usize, bool)> { report.functions.iter().filter(|r| r.status == Status::Ok).map(|r| (r.addr, (r.params, r.returns_value))).collect() };
    let (base_ok, head_ok) = (ok(base), ok(head));
    // Over every function: a decompiler that starts to fail drops functions from the ones both
    // runs finished. A timeout depends on the load and is left out.
    let failed = |report: &BinaryReport| report.functions.iter().filter(|r| matches!(r.status, Status::Error | Status::Crash)).count();
    let (mut base_counts, mut head_counts) = ([0, 0, failed(base), 0, 0, 0], [0, 0, failed(head), 0, 0, 0]);
    // Types count where both runs have them scored: a function whose parameter count one run
    // got wrong has no parameters scored in that run, and a build from before shapes were
    // recorded has none scored at all. Its wrong pointers would otherwise read as new ones.
    let scored = |report: &BinaryReport| -> BTreeMap<u64, Shapes> { report.functions.iter().filter(|r| r.status == Status::Ok).map(|r| (r.addr, typed.score(r, &mut BTreeMap::new()))).collect() };
    let (base_scored, head_scored) = (scored(base), scored(head));
    let mut typed_in_both = 0;
    for (addr, base_shapes) in &base_scored {
        let Some(head_shapes) = head_scored.get(addr) else { continue };
        typed_in_both += usize::from(base_shapes.params > 0 && head_shapes.params > 0);
        for (counts, shapes) in [(&mut base_counts, base_shapes), (&mut head_counts, head_shapes)] {
            if base_shapes.params > 0 && head_shapes.params > 0 {
                counts[3] += shapes.params_matched;
                counts[5] += shapes.pointers_claimed - shapes.pointers_matched;
            }
            if base_shapes.returns > 0 && head_shapes.returns > 0 {
                counts[4] += shapes.returns_matched;
            }
        }
    }
    for (addr, expected) in &debug.functions {
        // A function that timed out in one run says nothing about the other.
        let (Some(&base_found), Some(&head_found)) = (base_ok.get(addr), head_ok.get(addr)) else { continue };
        for (counts, (params, returns_value)) in [(&mut base_counts, base_found), (&mut head_counts, head_found)] {
            counts[0] += usize::from(!expected.variadic && params == expected.params);
            counts[1] += usize::from(expected.returns_value == Some(returns_value));
        }
    }
    (base_counts, head_counts, typed_in_both)
}

/// Prints each of [`MEASURES`] that moved from the corpus run in `base_dir` to the one in
/// `head_dir`, over the functions both decompiled, with the binaries it moved in. Fails when
/// one got worse.
pub fn against(base_dir: &Path, head_dir: &Path, debug_dir: &Path, jobs: usize) -> Result<()> {
    let reports = reports(head_dir)?;
    let read = |path: &Path| -> Result<BinaryReport> { serde_json::from_slice(&std::fs::read(path)?).with_context(|| format!("parsing {path:?}")) };
    let mut binaries: Vec<(String, Counts, Counts, usize)> = in_parallel(&reports, jobs, |path| -> Result<Option<(String, Counts, Counts, usize)>> {
        let head = read(path)?;
        let base_path = base_dir.join(path.file_name().context("no file name")?);
        let debug_path = debug_dir.join(format!("{}.debug", head.name));
        if !base_path.exists() || !debug_path.exists() {
            return Ok(None);
        }
        let (base, head_counts, typed_in_both) = counted(&read(&base_path)?, &head, &DebugInfo::load(&debug_path)?, &Typed::load(&debug_path)?);
        Ok(Some((head.name, base, head_counts, typed_in_both)))
    })
    .into_iter()
    .collect::<Result<Vec<_>>>()?
    .into_iter()
    .flatten()
    .collect();
    binaries.sort_by(|a, b| a.0.cmp(&b.0));
    // A base from before shapes were recorded has none, and then no type count can move.
    println!("  parameter types compared in {} functions", binaries.iter().map(|binary| binary.3).sum::<usize>());

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
            let moved: Vec<(&str, usize)> = binaries.iter().filter_map(|(name, b, h, _)| {
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
        let typed = Typed { functions: BTreeMap::new() };
        assert_eq!(counted(&base, &head, &debug, &typed), ([2, 1, 0, 0, 0, 0], [2, 0, 0, 0, 0, 0], 0));
        // A function that fails drops out of the comparison, and counts as failed.
        let head = run(&[(0x10, Status::Error, 0, false), (0x20, Status::Ok, 2, true), (0x30, Status::Ok, 0, false)]);
        assert_eq!(counted(&base, &head, &debug, &typed), ([2, 1, 0, 0, 0, 0], [2, 1, 1, 0, 0, 0], 0));
    }

    #[test]
    fn parameters_pair_off_by_shape_and_an_untyped_value_reads_as_a_number() {
        let shape = |kind, size| Shape { kind, size };
        // f(double, char *, int) returning a pointer.
        let expected = (vec![Some(shape(Kind::Float, 8)), Some(shape(Kind::Pointer, 8)), Some(shape(Kind::Int, 4))], Some(shape(Kind::Pointer, 8)));
        let typed = Typed { functions: BTreeMap::from([(0x10, expected)]) };
        let record = |shapes: &[Shape], return_shape| FunctionRecord { shapes: shapes.to_vec(), return_shape, ..FunctionRecord::failed(0x10, Status::Ok, String::new(), 0.0) };
        // The integer registers first, the pointer taken for a number, and the int untyped.
        let found = record(&[shape(Kind::Unknown, 8), shape(Kind::Unknown, 4), shape(Kind::Float, 8)], Some(shape(Kind::Pointer, 8)));
        let mut misses = BTreeMap::new();
        let scored = Shapes { params: 3, params_matched: 2, returns: 1, returns_matched: 1, pointers: 1, pointers_matched: 0, pointers_claimed: 0 };
        assert_eq!(typed.score(&found, &mut misses), scored);
        assert_eq!(misses, BTreeMap::from([("parameter: a pointer of 8 as a number of 8".to_string(), 1)]));
        // With a parameter missing the count is what is wrong, and a return the decompiler
        // does not see is scored as whether it returns.
        assert_eq!(typed.score(&record(&[shape(Kind::Float, 8)], None), &mut misses), Shapes::default());
    }

    #[test]
    fn types_count_only_where_both_runs_have_them_scored() {
        let shape = |kind, size| Shape { kind, size };
        let function = |params| Function { params, variadic: false, returns_value: Some(false), c: true };
        let debug = DebugInfo { functions: BTreeMap::from([(0x10, function(1)), (0x20, function(1))]), symbols: BTreeMap::new() };
        // Both take a number of 8.
        let typed = Typed { functions: BTreeMap::from([(0x10, (vec![Some(shape(Kind::Int, 8))], None)), (0x20, (vec![Some(shape(Kind::Int, 8))], None))]) };
        let run = |shapes: [&[Shape]; 2]| {
            let functions = [0x10, 0x20].into_iter().zip(shapes).map(|(addr, shapes)| FunctionRecord { params: shapes.len(), shapes: shapes.to_vec(), ..FunctionRecord::failed(addr, Status::Ok, String::new(), 0.0) }).collect();
            BinaryReport { name: "b".into(), fragments_skipped: 0, functions }
        };
        let (number, pointer) = (shape(Kind::Int, 8), shape(Kind::Pointer, 8));
        // A build that records no shapes has no type scored, so the head's wrong pointer is no
        // loss. Its records here have no parameters either, which is what the first count says.
        let head = run([&[pointer], &[number]]);
        assert_eq!(counted(&run([&[], &[]]), &head, &debug, &typed), ([0, 2, 0, 0, 0, 0], [2, 2, 0, 0, 0, 0], 0));
        // Against a run that had both right, it is one: a type lost and a pointer wrongly called.
        assert_eq!(counted(&run([&[number], &[number]]), &head, &debug, &typed), ([2, 2, 0, 2, 0, 0], [2, 2, 0, 1, 0, 1], 2));
    }

    #[test]
    fn a_parameter_without_a_shape_leaves_the_others_unscored() {
        let shape = |kind, size| Shape { kind, size };
        // f(struct by value, char *): the struct arrives as a pointer the debug information
        // does not describe, which would pair with the `char *` the decompiler took for a number.
        let typed = Typed { functions: BTreeMap::from([(0x10, (vec![None, Some(shape(Kind::Pointer, 8))], None))]) };
        let found = FunctionRecord { shapes: vec![shape(Kind::Pointer, 8), shape(Kind::Int, 8)], ..FunctionRecord::failed(0x10, Status::Ok, String::new(), 0.0) };
        assert_eq!(typed.score(&found, &mut BTreeMap::new()), Shapes::default());
    }
}
