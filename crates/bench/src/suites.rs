//! The three suites, their results, and the tables.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, ensure};
use recore::program::Program;
use recore_decomp::isolate::{Options, Status, Worker};
use serde::{Deserialize, Serialize};

/// The fastest and the middle of several runs, in milliseconds.
#[derive(Serialize, Deserialize, Clone, Copy, Default)]
pub struct Stat {
    pub min: f64,
    pub median: f64,
}

impl Stat {
    fn of(mut times: Vec<f64>) -> Stat {
        times.sort_by(f64::total_cmp);
        Stat { min: times[0], median: times[times.len() / 2] }
    }

    /// How far the middle run was above the fastest, as a fraction.
    fn noise(self) -> f64 {
        (self.median - self.min) / self.min.max(1e-9)
    }
}

#[derive(Serialize, Deserialize, Default)]
pub struct Results {
    pub analysis: Vec<AnalysisRow>,
    pub cold: Vec<ColdRow>,
    pub decompile: Vec<DecompileRow>,
}

#[derive(Serialize, Deserialize)]
pub struct AnalysisRow {
    pub binary: String,
    pub instructions: u64,
    pub functions: usize,
    /// Reading and parsing the file.
    pub load: Stat,
    pub analyze: Stat,
}

#[derive(Serialize, Deserialize)]
pub struct ColdRow {
    pub binary: String,
    /// The function decompiled: the one of middle size.
    pub function: u64,
    /// `recore-mcp summary`, from process start to exit.
    pub summary: Stat,
    /// `recore-mcp decompile` of the one function, from process start to exit.
    pub decompile: Stat,
}

#[derive(Serialize, Deserialize)]
pub struct DecompileRow {
    pub binary: String,
    /// Sampled functions the engine gave up on or died in.
    pub failed: usize,
    /// Sampled functions that ran past [`SLOW`]. They are left out of the times: a handful of
    /// them would outweigh everything else, and `profile` is the tool for those.
    pub slow: Vec<u64>,
    /// `(function, engine, waited)`: the time inside the engine and the time the caller waits,
    /// which on 32-bit x86 includes the function's callees. Each is the fastest run.
    pub times: Vec<(u64, f64, f64)>,
    /// The sum of the middle runs of the engine time over the sum of the fastest, minus one.
    pub noise: f64,
}

/// A function gets this long in the decompile suite.
const SLOW: Duration = Duration::from_secs(2);

fn ms(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1e3
}

fn name(binary: &Path) -> String {
    binary.display().to_string()
}

/// A program built next to this one.
fn sibling(program: &str) -> Result<PathBuf> {
    let path = std::env::current_exe()?.with_file_name(program);
    ensure!(path.exists(), "{} is not built; run `cargo build --release`", path.display());
    Ok(path)
}

pub fn analysis(binaries: &[PathBuf], runs: usize) -> Result<Vec<AnalysisRow>> {
    let mut rows = Vec::new();
    for binary in binaries {
        // Once untimed, so that every timed run finds the file in the page cache.
        std::fs::read(binary).with_context(|| format!("reading {}", binary.display()))?;
        let (mut load, mut analyze) = (Vec::new(), Vec::new());
        let mut counts = (0, 0);
        for _ in 0..runs {
            let start = Instant::now();
            let image = recore::Image::load(binary)?;
            load.push(ms(start));
            let start = Instant::now();
            let analysis = recore::analyze(&image);
            analyze.push(ms(start));
            counts = (analysis.instructions, analysis.functions.len());
        }
        rows.push(AnalysisRow { binary: name(binary), instructions: counts.0, functions: counts.1, load: Stat::of(load), analyze: Stat::of(analyze) });
    }
    Ok(rows)
}

/// Runs a program to its end and returns the wall time.
fn timed(command: &mut Command) -> Result<f64> {
    let start = Instant::now();
    let status = command.stdout(Stdio::null()).stderr(Stdio::null()).status()?;
    let elapsed = ms(start);
    ensure!(status.success(), "{command:?} failed");
    Ok(elapsed)
}

pub fn cold(binaries: &[PathBuf], runs: usize) -> Result<Vec<ColdRow>> {
    let tool = sibling("recore-mcp")?;
    let mut rows = Vec::new();
    for binary in binaries {
        let program = Program::load(binary)?;
        let mut by_size: Vec<(u64, u64)> = program.sizes().into_iter().map(|(entry, size)| (size, entry)).collect();
        by_size.sort_unstable();
        let function = by_size[by_size.len() / 2].1;
        let run = |arguments: &[&str]| -> Result<Stat> {
            let times = (0..runs).map(|_| timed(Command::new(&tool).arg(arguments[0]).arg(binary).args(&arguments[1..])));
            Ok(Stat::of(times.collect::<Result<_>>()?))
        };
        rows.push(ColdRow { binary: name(binary), function, summary: run(&["summary"])?, decompile: run(&["decompile", &format!("{function:#x}")])? });
    }
    Ok(rows)
}

/// At most `count` of the binary's functions, evenly spaced by address.
pub fn sample(program: &Program, count: usize) -> Vec<u64> {
    let entries: Vec<u64> = program.functions().map(|f| f.addr).collect();
    let step = entries.len().div_ceil(count.max(1)).max(1);
    entries.into_iter().step_by(step).collect()
}

pub fn decompile(binaries: &[PathBuf], runs: usize, count: usize) -> Result<Vec<DecompileRow>> {
    let tool = sibling("recore-decompile")?;
    let mut rows = Vec::new();
    for binary in binaries {
        let mut functions = sample(&Program::load(binary)?, count);
        // Per function: engine time and time waited, one of each per run.
        let mut times: Vec<(Vec<f64>, Vec<f64>)> = vec![Default::default(); functions.len()];
        let (mut failed, mut slow) = (0, Vec::new());
        for run in 0..runs {
            let tool = tool.clone();
            let command = move || {
                let mut command = Command::new(&tool);
                command.arg("worker");
                command
            };
            // A new process each run, so that every run starts knowing the same nothing.
            let mut worker = Worker::new(command, binary, &Options::default());
            ensure!(worker.ready(), "no decompiler for {}", binary.display());
            let mut index = 0;
            while index < functions.len() {
                let start = Instant::now();
                let (record, _) = worker.decompile(functions[index], SLOW);
                if record.status == Status::Ok {
                    times[index].1.push(ms(start));
                    times[index].0.push(record.ms);
                    index += 1;
                    continue;
                }
                // Dropped for the runs to come as well. A function at the limit that makes it
                // in one run and not in the next is only dropped late.
                match record.status {
                    Status::Timeout => slow.push(functions[index]),
                    _ => failed += usize::from(run == 0),
                }
                functions.remove(index);
                times.remove(index);
                ensure!(worker.ready(), "no decompiler for {}", binary.display());
            }
        }
        let fastest = |times: &[f64]| times.iter().copied().fold(f64::INFINITY, f64::min);
        let middle: f64 = times.iter().map(|t| Stat::of(t.0.clone()).median).sum();
        let times: Vec<(u64, f64, f64)> = functions.iter().zip(&times).map(|(&function, t)| (function, fastest(&t.0), fastest(&t.1))).collect();
        let engine: f64 = times.iter().map(|t| t.1).sum();
        rows.push(DecompileRow { binary: name(binary), failed, slow, times, noise: middle / engine.max(1e-9) - 1.0 });
    }
    Ok(rows)
}

/// The change from `before` to `now` as a signed percentage, or nothing without a `before`.
fn change(now: f64, before: Option<f64>) -> String {
    before.map_or(String::new(), |before| format!("{:+6.1}%", (now / before.max(1e-9) - 1.0) * 100.0))
}

fn short(binary: &str) -> &str {
    binary.strip_prefix("corpus").map_or(binary, |rest| rest.trim_start_matches('-'))
}

/// The middle of the rows' noise, as a percentage.
fn typical_noise(mut noise: Vec<f64>) -> f64 {
    noise.sort_by(f64::total_cmp);
    noise.get(noise.len() / 2).copied().unwrap_or(0.0) * 100.0
}

pub fn print_analysis(rows: &[AnalysisRow], before: Option<&[AnalysisRow]>) {
    let before_of = |binary: &str| before.and_then(|rows| rows.iter().find(|row| row.binary == binary));
    println!("\nanalysis: load and analyze, fastest run");
    println!("{:<46} {:>9} {:>8} {:>9} {:>10} {:>8} {:>7}", "binary", "insns", "load ms", "analyze", "ns/insn", "noise", "change");
    let total = |rows: &[AnalysisRow]| rows.iter().map(|r| r.load.min + r.analyze.min).sum::<f64>();
    for row in rows {
        let time = row.load.min + row.analyze.min;
        println!(
            "{:<46} {:>9} {:>8.2} {:>9.2} {:>10.1} {:>7.1}% {:>7}",
            short(&row.binary),
            row.instructions,
            row.load.min,
            row.analyze.min,
            time * 1e6 / row.instructions.max(1) as f64,
            row.analyze.noise() * 100.0,
            change(time, before_of(&row.binary).map(|b| b.load.min + b.analyze.min)),
        );
    }
    let instructions: u64 = rows.iter().map(|r| r.instructions).sum();
    // Only the rows both runs have count towards the change of the total.
    let shared: Vec<&AnalysisRow> = rows.iter().filter(|row| before_of(&row.binary).is_some()).collect();
    let shared_before: f64 = shared.iter().filter_map(|row| before_of(&row.binary)).map(|b| b.load.min + b.analyze.min).sum();
    let shared_now: f64 = shared.iter().map(|r| r.load.min + r.analyze.min).sum();
    println!(
        "{:<46} {:>9} {:>18.1} {:>10.1} {:>7.1}% {:>7}",
        "total",
        instructions,
        total(rows),
        total(rows) * 1e6 / instructions.max(1) as f64,
        typical_noise(rows.iter().map(|r| r.analyze.noise()).collect()),
        change(shared_now, before.map(|_| shared_before)),
    );
}

pub fn print_cold(rows: &[ColdRow], before: Option<&[ColdRow]>) {
    let before_of = |binary: &str| before.and_then(|rows| rows.iter().find(|row| row.binary == binary));
    println!("\ncold: a new process to the answer, fastest run, ms");
    println!("{:<46} {:>9} {:>7} {:>10} {:>7} {:>8}", "binary", "summary", "change", "decompile", "change", "noise");
    for row in rows {
        let old = before_of(&row.binary);
        println!(
            "{:<46} {:>9.1} {:>7} {:>10.1} {:>7} {:>7.1}%",
            short(&row.binary),
            row.summary.min,
            change(row.summary.min, old.map(|b| b.summary.min)),
            row.decompile.min,
            change(row.decompile.min, old.map(|b| b.decompile.min)),
            row.decompile.noise() * 100.0,
        );
    }
    let shared: Vec<(&ColdRow, &ColdRow)> = rows.iter().filter_map(|row| Some((row, before_of(&row.binary)?))).collect();
    let sum = |pick: fn(&ColdRow) -> f64, rows: &mut dyn Iterator<Item = &ColdRow>| rows.map(pick).sum::<f64>();
    let (summary, decompile): (fn(&ColdRow) -> f64, fn(&ColdRow) -> f64) = (|r| r.summary.min, |r| r.decompile.min);
    println!(
        "{:<46} {:>9.1} {:>7} {:>10.1} {:>7} {:>7.1}%",
        "total",
        sum(summary, &mut rows.iter()),
        change(sum(summary, &mut shared.iter().map(|s| s.0)), before.map(|_| sum(summary, &mut shared.iter().map(|s| s.1)))),
        sum(decompile, &mut rows.iter()),
        change(sum(decompile, &mut shared.iter().map(|s| s.0)), before.map(|_| sum(decompile, &mut shared.iter().map(|s| s.1)))),
        typical_noise(rows.iter().map(|r| r.decompile.noise()).collect()),
    );
}

pub fn print_decompile(rows: &[DecompileRow], before: Option<&[DecompileRow]>) {
    let before_of = |binary: &str| before.and_then(|rows| rows.iter().find(|row| row.binary == binary));
    println!("\ndecompile: a sample of functions in one process, each at its fastest, ms");
    println!("{:<46} {:>5} {:>4} {:>4} {:>9} {:>7} {:>9} {:>7} {:>7} {:>7} {:>7}", "binary", "fns", "bad", "slow", "engine", "change", "waited", "change", "median", "p99", "noise");
    // Sums over the functions both runs finished, so that one dropping out is not a speedup.
    let (mut engine, mut waited) = ((0.0, 0.0), (0.0, 0.0));
    for row in rows {
        let old: std::collections::HashMap<u64, (f64, f64)> = before_of(&row.binary).into_iter().flat_map(|b| &b.times).map(|t| (t.0, (t.1, t.2))).collect();
        let shared = |pick: fn((f64, f64)) -> f64| -> (f64, f64) {
            let pairs = row.times.iter().filter_map(|t| Some((pick((t.1, t.2)), pick(*old.get(&t.0)?))));
            pairs.fold((0.0, 0.0), |sum, pair| (sum.0 + pair.0, sum.1 + pair.1))
        };
        let (row_engine, row_waited) = (shared(|t| t.0), shared(|t| t.1));
        engine = (engine.0 + row_engine.0, engine.1 + row_engine.1);
        waited = (waited.0 + row_waited.0, waited.1 + row_waited.1);
        let mut sorted: Vec<f64> = row.times.iter().map(|t| t.1).collect();
        sorted.sort_by(f64::total_cmp);
        let at = |q: f64| sorted.get(((sorted.len().max(1) - 1) as f64 * q) as usize).copied().unwrap_or(0.0);
        println!(
            "{:<46} {:>5} {:>4} {:>4} {:>9.1} {:>7} {:>9.1} {:>7} {:>7.2} {:>7.1} {:>6.1}%",
            short(&row.binary),
            row.times.len(),
            row.failed,
            row.slow.len(),
            sorted.iter().sum::<f64>(),
            change(row_engine.0, before.map(|_| row_engine.1)),
            row.times.iter().map(|t| t.2).sum::<f64>(),
            change(row_waited.0, before.map(|_| row_waited.1)),
            at(0.5),
            at(0.99),
            row.noise * 100.0,
        );
    }
    println!(
        "{:<46} {:>5} {:>4} {:>4} {:>9.1} {:>7} {:>9.1} {:>7} {:>22.1}%",
        "total",
        rows.iter().map(|r| r.times.len()).sum::<usize>(),
        rows.iter().map(|r| r.failed).sum::<usize>(),
        rows.iter().map(|r| r.slow.len()).sum::<usize>(),
        rows.iter().flat_map(|r| &r.times).map(|t| t.1).sum::<f64>(),
        change(engine.0, before.map(|_| engine.1)),
        rows.iter().flat_map(|r| &r.times).map(|t| t.2).sum::<f64>(),
        change(waited.0, before.map(|_| waited.1)),
        typical_noise(rows.iter().map(|r| r.noise).collect()),
    );
    for row in rows.iter().filter(|row| !row.slow.is_empty()) {
        let slow: Vec<String> = row.slow.iter().map(|addr| format!("{addr:#x}")).collect();
        println!("slow in {}: {}", short(&row.binary), slow.join(" "));
    }
}
