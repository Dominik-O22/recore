//! The four suites, their results, and the tables.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, ensure};
use recore::edits::Edits;
use recore::program::Program;
use recore::report::CallTarget;
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
    #[serde(default)]
    pub session: Vec<SessionRow>,
}

#[derive(Serialize, Deserialize)]
pub struct AnalysisRow {
    pub binary: String,
    pub instructions: u64,
    pub functions: usize,
    /// Reading and parsing the file.
    pub load: Stat,
    pub analyze: Stat,
    /// Processor instructions executed to load and analyze on one thread, where the kernel
    /// lets them be counted. Unlike the times, this does not move with the machine's load.
    #[serde(default)]
    pub work: Option<u64>,
}

#[derive(Serialize, Deserialize)]
pub struct ColdRow {
    pub binary: String,
    /// The function decompiled and looked up: the one of middle size.
    pub function: u64,
    /// `recore-mcp summary`, from process start to exit.
    pub summary: Stat,
    /// `recore-mcp xrefs` of the function, with nothing kept from an earlier run, and then again.
    #[serde(default)]
    pub xrefs: Stat,
    #[serde(default)]
    pub xrefs_again: Stat,
    /// `recore-mcp decompile` of the function, with nothing kept from an earlier run.
    pub decompile: Stat,
    /// The same right after, with what the runs before kept.
    #[serde(default)]
    pub decompile_again: Stat,
    /// From starting a decompiler process to its answer for the function, after the runs above.
    #[serde(default)]
    pub first: Stat,
    /// The most memory that process held, in MiB.
    #[serde(default, alias = "peak_mib")]
    pub worker_mib: f64,
    /// The most memory `summary` held, in MiB, analyzing with nothing kept from an earlier run.
    #[serde(default)]
    pub analyzing_mib: f64,
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

#[derive(Serialize, Deserialize)]
pub struct SessionRow {
    pub binary: String,
    /// Functions the walk starts from, each with a callee.
    pub starts: usize,
    /// One whole walk, renames included. A rename that replaces the decompiler process shows up
    /// in the decompilation after it, which waits for the new process.
    pub walk: Stat,
}

/// A function gets this long in the decompile suite.
const SLOW: Duration = Duration::from_secs(2);

fn ms(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1e3
}

/// A binary as `bench/set.txt` names it, so that saved results compare wherever the corpora are.
pub(crate) fn name(binary: &Path) -> String {
    binary.strip_prefix(crate::corpora()).unwrap_or(binary).display().to_string()
}

/// A program built next to this one.
fn sibling(program: &str) -> Result<PathBuf> {
    let path = std::env::current_exe()?.with_file_name(program);
    ensure!(path.exists(), "{} is not built; run `cargo build --release`", path.display());
    Ok(path)
}

pub fn analysis(binaries: &[PathBuf], runs: usize) -> Result<Vec<AnalysisRow>> {
    // Once untimed, so that every timed run finds the file in the page cache.
    for binary in binaries {
        std::fs::read(binary).with_context(|| format!("reading {}", binary.display()))?;
    }
    let mut times: Vec<(Vec<f64>, Vec<f64>)> = vec![Default::default(); binaries.len()];
    let mut counts = vec![(0, 0); binaries.len()];
    // Round after round over all binaries, not run after run of one: a slow spell of the
    // machine then costs every binary one run and no binary all of its runs.
    for _ in 0..runs {
        for (index, binary) in binaries.iter().enumerate() {
            let start = Instant::now();
            let image = recore::Image::load(binary)?;
            times[index].0.push(ms(start));
            let start = Instant::now();
            let analysis = recore::analyze(&image);
            times[index].1.push(ms(start));
            counts[index] = (analysis.instructions, analysis.functions.len());
        }
    }
    let work = binaries.iter().map(|binary| crate::work::instructions(|| recore::Image::load(binary).map(|image| recore::analyze(&image).instructions)).1);
    let rows = binaries.iter().zip(times).zip(counts).zip(work.collect::<Vec<_>>());
    Ok(rows
        .map(|(((binary, (load, analyze)), (instructions, functions)), work)| AnalysisRow { binary: name(binary), instructions, functions, load: Stat::of(load), analyze: Stat::of(analyze), work })
        .collect())
}

/// Prints where the time of analyzing one binary goes, phase by phase. A phase named
/// `outer/inner` is part of `outer` and counted in it.
pub fn phases(binary: &Path, runs: usize) -> Result<()> {
    std::fs::read(binary).with_context(|| format!("reading {}", binary.display()))?;
    let mut fastest: Vec<(&'static str, f64)> = Vec::new();
    let mut whole = Vec::new();
    recore::phase::enable(true);
    for _ in 0..runs {
        let start = Instant::now();
        let image = {
            let _phase = recore::phase::scope("load");
            recore::Image::load(binary)?
        };
        std::hint::black_box(recore::analyze(&image));
        whole.push(ms(start));
        for (name, time) in recore::phase::take() {
            let time = time.as_secs_f64() * 1e3;
            match fastest.iter_mut().find(|phase| phase.0 == name) {
                Some(phase) => phase.1 = phase.1.min(time),
                None => fastest.push((name, time)),
            }
        }
    }
    recore::phase::enable(false);
    let whole = Stat::of(whole).min;
    println!("{:>9.2} ms  everything", whole);
    for (name, time) in fastest {
        let depth = name.matches('/').count();
        let label = name.rsplit('/').next().unwrap_or(name);
        println!("{time:>9.2} ms {:>5.1}%  {}{label}", time * 100.0 / whole, "  ".repeat(depth));
    }
    Ok(())
}

/// Runs a program to its end and returns the wall time.
fn timed(command: &mut Command) -> Result<f64> {
    Ok(measured(command)?.0)
}

/// Runs a program to its end and returns the wall time and the most memory its process held,
/// in bytes. That is read from /proc while it runs, every few milliseconds: what the kernel
/// reports once it ends also counts this process's own, which the program started from.
fn measured(command: &mut Command) -> Result<(f64, u64)> {
    let start = Instant::now();
    let mut child = command.stdout(Stdio::null()).stderr(Stdio::null()).spawn()?;
    let status_file = format!("/proc/{}/status", child.id());
    let ended = std::sync::atomic::AtomicBool::new(false);
    let (status, peak) = std::thread::scope(|scope| {
        let watch = scope.spawn(|| {
            let mut peak = 0;
            while !ended.load(std::sync::atomic::Ordering::Relaxed) {
                let status = std::fs::read_to_string(&status_file).unwrap_or_default();
                let kib = status.lines().find_map(|line| line.strip_prefix("VmHWM:")).and_then(|value| value.trim().strip_suffix("kB")?.trim().parse::<u64>().ok());
                peak = peak.max(kib.unwrap_or(0) * 1024);
                std::thread::sleep(Duration::from_millis(2));
            }
            peak
        });
        let status = child.wait();
        ended.store(true, std::sync::atomic::Ordering::Relaxed);
        (status, watch.join().expect("the watch does not panic"))
    });
    let elapsed = ms(start);
    ensure!(status?.success(), "{command:?} failed");
    Ok((elapsed, peak))
}

pub fn cold(binaries: &[PathBuf], runs: usize) -> Result<Vec<ColdRow>> {
    let tool = sibling("recore-mcp")?;
    let mut functions = Vec::new();
    for binary in binaries {
        let program = Program::load(binary)?;
        let mut by_size: Vec<(u64, u64)> = program.sizes().into_iter().map(|(entry, size)| (size, entry)).collect();
        by_size.sort_unstable();
        functions.push(by_size[by_size.len() / 2].1);
    }
    // The analyses recore keeps between runs go here, emptied where a run is to start from
    // nothing.
    let cache = std::path::absolute("target/bench/analyses")?;
    let one_shot = |tool_name: &str, binary: &Path, function: u64| {
        let mut command = Command::new(&tool);
        command.env(recore::cache::DIR_VAR, &cache).arg(tool_name).arg(binary).arg(format!("{function:#x}"));
        command
    };
    let mut rows: Vec<ColdRow> = Vec::new();
    let mut times: Vec<[Vec<f64>; 6]> = binaries.iter().map(|_| Default::default()).collect();
    let mut peaks = vec![(0u64, 0u64); binaries.len()];
    // In rounds, as the analysis suite does.
    for _ in 0..runs {
        for (index, (binary, &function)) in binaries.iter().zip(&functions).enumerate() {
            let times = &mut times[index];
            let _ = std::fs::remove_dir_all(&cache);
            let (summary, analyzing) = measured(Command::new(&tool).env(recore::cache::DIR_VAR, &cache).arg("summary").arg(binary))?;
            times[0].push(summary);
            peaks[index].1 = peaks[index].1.max(analyzing);
            let _ = std::fs::remove_dir_all(&cache);
            times[1].push(timed(&mut one_shot("xrefs", binary, function))?);
            times[2].push(timed(&mut one_shot("xrefs", binary, function))?);
            let _ = std::fs::remove_dir_all(&cache);
            times[3].push(timed(&mut one_shot("decompile", binary, function))?);
            times[4].push(timed(&mut one_shot("decompile", binary, function))?);
            let (tool, cache) = (tool.clone(), cache.clone());
            let start = Instant::now();
            let mut worker = Worker::new(
                move || {
                    let mut command = Command::new(&tool);
                    command.env(recore::cache::DIR_VAR, &cache).arg("decompile-worker");
                    command
                },
                binary,
                &Options::default(),
            );
            let (record, _) = worker.decompile(function, SLOW * 30);
            ensure!(record.status == Status::Ok, "{} at {function:#x}: {}", binary.display(), record.message.unwrap_or_default());
            times[5].push(ms(start));
            peaks[index].0 = peaks[index].0.max(worker.peak_bytes().unwrap_or(0));
        }
    }
    let _ = std::fs::remove_dir_all(&cache);
    let mib = |bytes: u64| bytes as f64 / (1 << 20) as f64;
    for ((binary, function), (times, (worker, analyzing))) in binaries.iter().zip(functions).zip(times.into_iter().zip(peaks)) {
        let [summary, xrefs, xrefs_again, decompile, decompile_again, first] = times.map(Stat::of);
        rows.push(ColdRow { binary: name(binary), function, summary, xrefs, xrefs_again, decompile, decompile_again, first, worker_mib: mib(worker), analyzing_mib: mib(analyzing) });
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

/// Walks each binary as an agent does: decompiles a function, names it, decompiles a function
/// it calls, names that, and decompiles the first again. Each run starts a new process with
/// no edits. Walks start from `count` functions that call another, evenly spaced by address.
pub fn session(binaries: &[PathBuf], runs: usize, count: usize) -> Result<Vec<SessionRow>> {
    let tool = sibling("recore-decompile")?;
    let mut rows = Vec::new();
    for binary in binaries {
        let program = Program::load(binary)?;
        let callee_of = |entry: u64| {
            program.body(entry).into_iter().flat_map(|(start, end)| program.calls_in(start, end)).find_map(|call| match call.target {
                CallTarget::Function(callee) if callee != entry && program.function(callee).is_some() => Some(callee),
                _ => None,
            })
        };
        let callers: Vec<(u64, u64)> = program.functions().filter_map(|f| Some((f.addr, callee_of(f.addr)?))).collect();
        let starts: Vec<(u64, u64)> = callers.iter().copied().step_by(callers.len().div_ceil(count.max(1)).max(1)).collect();
        let mut walks = Vec::new();
        for _ in 0..runs {
            let _ = std::fs::remove_file(Edits::file(binary)?);
            let tool = tool.clone();
            let command = move || {
                let mut command = Command::new(&tool);
                command.arg("worker");
                command
            };
            let mut worker = Worker::new(command, binary, &Options::default());
            ensure!(worker.ready(), "no decompiler for {}", binary.display());
            let mut edits = Edits::default();
            let start = Instant::now();
            for (index, &(function, callee)) in starts.iter().enumerate() {
                for (addr, name) in [(function, None), (function, Some("walked")), (callee, None), (callee, Some("called")), (function, None)] {
                    let Some(name) = name else {
                        worker.decompile(addr, SLOW);
                        continue;
                    };
                    edits.names.insert(addr, format!("{name}_{index}"));
                    edits.save(binary)?;
                    worker.update(&edits, SLOW);
                }
            }
            walks.push(ms(start));
        }
        let _ = std::fs::remove_file(Edits::file(binary)?);
        rows.push(SessionRow { binary: name(binary), starts: starts.len(), walk: Stat::of(walks) });
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
    println!("{:<46} {:>9} {:>8} {:>9} {:>10} {:>8} {:>7} {:>9} {:>7}", "binary", "insns", "load ms", "analyze", "ns/insn", "noise", "change", "work M", "change");
    // Work is executed instructions in millions: the measure that the machine's load leaves alone.
    let millions = |work: Option<u64>| work.map_or_else(|| "-".to_string(), |work| format!("{:.1}", work as f64 / 1e6));
    let work_change = |now: Option<u64>, before: Option<u64>| now.map_or_else(String::new, |now| change(now as f64, before.map(|before| before as f64)));
    let total = |rows: &[AnalysisRow]| rows.iter().map(|r| r.load.min + r.analyze.min).sum::<f64>();
    for row in rows {
        let time = row.load.min + row.analyze.min;
        println!(
            "{:<46} {:>9} {:>8.2} {:>9.2} {:>10.1} {:>7.1}% {:>7} {:>9} {:>7}",
            short(&row.binary),
            row.instructions,
            row.load.min,
            row.analyze.min,
            time * 1e6 / row.instructions.max(1) as f64,
            row.analyze.noise() * 100.0,
            change(time, before_of(&row.binary).map(|b| b.load.min + b.analyze.min)),
            millions(row.work),
            work_change(row.work, before_of(&row.binary).and_then(|b| b.work)),
        );
    }
    let instructions: u64 = rows.iter().map(|r| r.instructions).sum();
    // Only the rows both runs have count towards the change of the total.
    let shared: Vec<&AnalysisRow> = rows.iter().filter(|row| before_of(&row.binary).is_some()).collect();
    let shared_before: f64 = shared.iter().filter_map(|row| before_of(&row.binary)).map(|b| b.load.min + b.analyze.min).sum();
    let shared_now: f64 = shared.iter().map(|r| r.load.min + r.analyze.min).sum();
    let work_of = |rows: &mut dyn Iterator<Item = &AnalysisRow>| rows.map(|row| row.work).sum::<Option<u64>>();
    let shared_work_before = work_of(&mut shared.iter().filter_map(|row| before_of(&row.binary)));
    println!(
        "{:<46} {:>9} {:>18.1} {:>10.1} {:>7.1}% {:>7} {:>9} {:>7}",
        "total",
        instructions,
        total(rows),
        total(rows) * 1e6 / instructions.max(1) as f64,
        typical_noise(rows.iter().map(|r| r.analyze.noise()).collect()),
        change(shared_now, before.map(|_| shared_before)),
        millions(work_of(&mut rows.iter())),
        if before.is_some() { work_change(work_of(&mut shared.iter().copied()), shared_work_before) } else { String::new() },
    );
}

/// A column of the cold table: what it reads from a row.
type Column = fn(&ColdRow) -> f64;

pub fn print_cold(rows: &[ColdRow], before: Option<&[ColdRow]>) {
    let before_of = |binary: &str| before.and_then(|rows| rows.iter().find(|row| row.binary == binary));
    let columns: [(&str, Column); 8] = [
        ("summary", |row| row.summary.min),
        ("xrefs", |row| row.xrefs.min),
        ("again", |row| row.xrefs_again.min),
        ("decompile", |row| row.decompile.min),
        ("again", |row| row.decompile_again.min),
        ("first", |row| row.first.min),
        ("worker MiB", |row| row.worker_mib),
        ("summary MiB", |row| row.analyzing_mib),
    ];
    println!("\ncold: a new process to the answer, fastest run, ms; `again` reruns it at once, and `first` is a new decompiler process to its first function; MiB is the most that decompiler process and a `summary` with nothing kept held");
    print!("{:<46}", "binary");
    for (title, _) in &columns {
        print!(" {title:>9} {:>7}", "change");
    }
    println!(" {:>8}", "noise");
    // Each column's value and its change.
    let line = |label: &str, cells: Vec<(f64, String)>, noise: f64| {
        print!("{label:<46}");
        for (now, change) in cells {
            print!(" {now:>9.1} {change:>7}");
        }
        println!(" {:>7.1}%", noise * 100.0);
    };
    for row in rows {
        let old = before_of(&row.binary);
        line(short(&row.binary), columns.iter().map(|(_, column)| (column(row), change(column(row), old.map(column)))).collect(), row.decompile.noise());
    }
    // Only the rows both runs have count towards the change of a total.
    let shared: Vec<(&ColdRow, &ColdRow)> = rows.iter().filter_map(|row| Some((row, before_of(&row.binary)?))).collect();
    let totals = columns.iter().map(|(_, column)| {
        let (now, old): (f64, f64) = shared.iter().map(|(row, old)| (column(row), column(old))).fold((0.0, 0.0), |sum, pair| (sum.0 + pair.0, sum.1 + pair.1));
        (rows.iter().map(column).sum(), change(now, before.map(|_| old)))
    });
    line("total", totals.collect(), typical_noise(rows.iter().map(|r| r.decompile.noise()).collect()) / 100.0);
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

pub fn print_session(rows: &[SessionRow], before: Option<&[SessionRow]>) {
    let before_of = |binary: &str| before.and_then(|rows| rows.iter().find(|row| row.binary == binary));
    println!("\nsession: decompile, rename, decompile a callee, rename it, decompile again; fastest run, ms");
    println!("{:<46} {:>6} {:>9} {:>7} {:>8}", "binary", "starts", "walk", "change", "noise");
    for row in rows {
        let old = before_of(&row.binary);
        println!("{:<46} {:>6} {:>9.1} {:>7} {:>7.1}%", short(&row.binary), row.starts, row.walk.min, change(row.walk.min, old.map(|b| b.walk.min)), row.walk.noise() * 100.0);
    }
    // Only the rows both runs have count towards the change of the total.
    let shared: Vec<(&SessionRow, &SessionRow)> = rows.iter().filter_map(|row| Some((row, before_of(&row.binary)?))).collect();
    println!(
        "{:<46} {:>6} {:>9.1} {:>7} {:>7.1}%",
        "total",
        rows.iter().map(|row| row.starts).sum::<usize>(),
        rows.iter().map(|row| row.walk.min).sum::<f64>(),
        change(shared.iter().map(|pair| pair.0.walk.min).sum(), before.map(|_| shared.iter().map(|pair| pair.1.walk.min).sum())),
        typical_noise(rows.iter().map(|r| r.walk.noise()).collect()),
    );
}

/// Times walking every instruction of the binary's code once, with more of what discovery does
/// per instruction at each level: decoding alone is the floor under any analysis, and the steps
/// from level to level are what the pieces cost.
pub fn decode_floor(binary: &Path, runs: usize) -> Result<()> {
    use recore::arch::Arch;
    use recore::image::Machine;
    let program = Program::load(binary)?;
    let image = &program.image;
    let ranges: Vec<(u64, u64)> = program.analysis.functions.iter().flat_map(|f| f.ranges.iter().copied()).collect();
    fn walk<A: Arch>(image: &recore::Image, ranges: &[(u64, u64)], level: usize) -> u64 {
        let mut instructions = 0;
        let mut found = 0u64;
        for &(start, end) in ranges {
            let Some(bytes) = image.bytes_from(start) else { continue };
            let bytes = &bytes[..((end - start) as usize).min(bytes.len())];
            let mut state = A::State::default();
            for decoded in A::decode(image, bytes, start) {
                let Some(insn) = std::hint::black_box(decoded).insn else { continue };
                instructions += 1;
                if level >= 1 {
                    found += u64::from(A::flow(&insn, &state, image).is_some());
                }
                if level >= 2 {
                    A::step(&mut state, &insn);
                }
                if level >= 3 {
                    found += u64::from(A::memory_reference(&insn, &state).is_some());
                    found += u64::from(A::address_taken(&insn, &state, image).is_some());
                    found += u64::from(A::based_data_address(&insn, &state).is_some());
                }
            }
        }
        std::hint::black_box(found);
        instructions
    }
    for (level, what) in ["decode", "and classify control flow", "and track registers", "and find the addresses referred to"].iter().enumerate() {
        let mut times = Vec::new();
        let mut instructions = 0;
        for _ in 0..runs {
            let start = Instant::now();
            instructions = match image.machine {
                Machine::X86_64 => walk::<recore::x86::X86<64, false>>(image, &ranges, level),
                Machine::X86 => walk::<recore::x86::X86<32, false>>(image, &ranges, level),
                Machine::Aarch64 => walk::<recore::arm64::Arm64>(image, &ranges, level),
                Machine::I8051 => walk::<recore::i8051::I8051>(image, &ranges, level),
                Machine::Thumb => walk::<recore::thumb::Thumb>(image, &ranges, level),
                Machine::Arm => walk::<recore::arm::Arm>(image, &ranges, level),
            };
            times.push(ms(start));
        }
        let time = Stat::of(times).min;
        println!("{time:>8.2} ms {:>6.1} ns per instruction  {what}  ({instructions} instructions)", time * 1e6 / instructions.max(1) as f64);
    }
    Ok(())
}
