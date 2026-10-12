//! The parent side of a corpus run: plans shards, supervises child processes, writes reports.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use recore_decomp::isolate::{FunctionRecord, Options, Status, Worker};

use crate::report::{BinaryReport, Slow, Summary};

pub struct Config {
    pub bin_dir: PathBuf,
    pub out_dir: PathBuf,
    pub jobs: usize,
    pub timeout: Duration,
    pub shard: usize,
    pub worker: Options,
}

/// One binary's functions and the results collected for it so far.
struct Binary {
    name: String,
    path: PathBuf,
    /// Entry points to decompile. Cold fragments are not among them: the decompiler reaches
    /// them from the function they belong to.
    functions: Vec<u64>,
    /// How many of recore's entries were left out as fragments.
    fragments: usize,
    /// Shards not yet finished; the reports are written when it reaches zero.
    pending: usize,
    records: Vec<FunctionRecord>,
    c_text: Vec<(u64, String)>,
}

/// Runs `work` on every item, on up to `jobs` threads.
fn for_each<T: Sync>(items: &[T], jobs: usize, work: impl Fn(&T) + Sync) {
    let next = AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for _ in 0..jobs.clamp(1, items.len().max(1)) {
            scope.spawn(|| {
                while let Some(item) = items.get(next.fetch_add(1, Ordering::Relaxed)) {
                    work(item);
                }
            });
        }
    });
}

pub fn corpus(config: &Config) -> Result<()> {
    std::fs::create_dir_all(&config.out_dir)?;
    let mut paths: Vec<PathBuf> = std::fs::read_dir(&config.bin_dir)?.map(|e| Ok(e?.path())).collect::<Result<_>>()?;
    paths.sort();
    let start = Instant::now();

    // The parent analyzes each binary only to learn which functions exist. Each child repeats
    // the analysis, which costs far less than shipping the result to it would save.
    let planned: Mutex<Vec<Binary>> = Mutex::new(Vec::new());
    for_each(&paths, config.jobs, |path| match plan(path) {
        Ok(binary) => planned.lock().unwrap().push(binary),
        Err(error) => eprintln!("{}: skipped: {error:#}", path.display()),
    });
    let mut binaries = planned.into_inner().unwrap();
    // Largest first, so the long ones do not all finish last on a few threads.
    binaries.sort_by_key(|b| std::cmp::Reverse(b.functions.len()));

    // Functions are dealt round-robin, because neighbours tend to be similar in size.
    let mut shards: Vec<(usize, Vec<u64>)> = Vec::new();
    for (index, binary) in binaries.iter_mut().enumerate() {
        let count = binary.functions.len().div_ceil(config.shard).max(1);
        binary.pending = count;
        shards.extend((0..count).map(|i| (index, binary.functions.iter().copied().skip(i).step_by(count).collect())));
    }
    eprintln!("{} binaries, {} functions, {} shards, {} jobs", binaries.len(), binaries.iter().map(|b| b.functions.len()).sum::<usize>(), shards.len(), config.jobs);

    let binaries: Vec<Mutex<Binary>> = binaries.into_iter().map(Mutex::new).collect();
    let fragments: usize = binaries.iter().map(|b| b.lock().unwrap().fragments).sum();
    let finished: Mutex<Vec<(String, Vec<FunctionRecord>)>> = Mutex::new(Vec::new());
    for_each(&shards, config.jobs, |(index, addrs)| {
        let path = binaries[*index].lock().unwrap().path.clone();
        let (records, c_text) = run_shard(&config.worker, config.timeout, &path, addrs);
        let mut binary = binaries[*index].lock().unwrap();
        binary.records.extend(records);
        binary.c_text.extend(c_text);
        binary.pending -= 1;
        if binary.pending == 0 {
            match finish(config, &mut binary) {
                Ok(records) => finished.lock().unwrap().push((binary.name.clone(), records)),
                Err(error) => eprintln!("{}: writing reports failed: {error:#}", binary.name),
            }
        }
    });

    let summary = summarize(config, &finished.into_inner().unwrap(), fragments, start.elapsed());
    std::fs::write(config.out_dir.join("summary.json"), serde_json::to_vec_pretty(&summary)?)?;
    print_summary(&summary);
    Ok(())
}

fn plan(path: &Path) -> Result<Binary> {
    let image = recore::Image::load(path)?;
    let analysis = recore::analyze(&image);
    let (fragments, functions): (Vec<_>, Vec<_>) = analysis.functions.iter().partition(|f| f.fragment_of.is_some());
    Ok(Binary {
        name: image.name.clone(),
        path: path.to_path_buf(),
        functions: functions.iter().map(|f| f.addr).collect(),
        fragments: fragments.len(),
        pending: 0,
        records: Vec::new(),
        c_text: Vec::new(),
    })
}

/// Writes the reports of a binary whose shards are all done, and returns its records.
fn finish(config: &Config, binary: &mut Binary) -> Result<Vec<FunctionRecord>> {
    let mut functions = std::mem::take(&mut binary.records);
    functions.sort_by_key(|r| r.addr);
    let report = BinaryReport { name: binary.name.clone(), fragments_skipped: binary.fragments, functions };
    std::fs::write(config.out_dir.join(format!("{}.json", binary.name)), serde_json::to_vec(&report)?)?;
    if config.worker.emit_c {
        let mut c_text = std::mem::take(&mut binary.c_text);
        c_text.sort_by_key(|c| c.0);
        let text: String = c_text.iter().map(|(addr, text)| format!("// {addr:#x}\n{text}\n")).collect();
        std::fs::write(config.out_dir.join(format!("{}.c", binary.name)), text)?;
    }
    let failed = report.functions.iter().filter(|r| r.status != Status::Ok).count();
    eprintln!("{}: {} functions, {failed} not ok", binary.name, report.functions.len());
    Ok(report.functions)
}

/// Decompiles `addrs` in worker processes. A worker that dies or stalls costs only the function
/// it was working on: that one is recorded as crashed or timed out, and a new worker takes over
/// the rest.
pub fn run_shard(options: &Options, timeout: Duration, binary: &Path, addrs: &[u64]) -> (Vec<FunctionRecord>, Vec<(u64, String)>) {
    let mut records = Vec::new();
    let mut c_texts = Vec::new();
    let mut worker: Option<Worker> = None;
    for (index, &addr) in addrs.iter().enumerate() {
        if worker.is_none() {
            let started = std::env::current_exe().map_err(anyhow::Error::from).and_then(|exe| {
                let mut command = Command::new(exe);
                command.arg("worker");
                Worker::spawn(command, binary, options)
            });
            match started {
                Ok(started) => worker = Some(started),
                Err(error) => {
                    // Setup failed, so a new worker would fail the same way.
                    let message = format!("{error:#}");
                    records.extend(addrs[index..].iter().map(|&addr| FunctionRecord::failed(addr, Status::Error, message.clone(), 0.0)));
                    break;
                }
            }
        }
        match worker.as_mut().expect("started above").decompile(addr, timeout) {
            Ok((record, c_text)) => {
                c_texts.extend(c_text.map(|text| (addr, text)));
                records.push(record);
            }
            Err(record) => {
                records.push(record);
                worker = None;
            }
        }
    }
    (records, c_texts)
}

fn summarize(config: &Config, binaries: &[(String, Vec<FunctionRecord>)], fragments_skipped: usize, wall: Duration) -> Summary {
    let all = || binaries.iter().flat_map(|(name, records)| records.iter().map(move |r| (name, r)));
    let count = |status| all().filter(|(_, r)| r.status == status).count();
    let mut times: Vec<f64> = all().map(|(_, r)| r.ms).collect();
    times.sort_by(f64::total_cmp);
    let at = |q: f64| times.get(((times.len().max(1) - 1) as f64 * q) as usize).copied().unwrap_or(0.0);
    let mut slowest: Vec<Slow> = all().map(|(name, r)| Slow { binary: name.clone(), addr: r.addr, ms: r.ms, status: r.status }).collect();
    slowest.sort_by(|a, b| b.ms.total_cmp(&a.ms));
    slowest.truncate(20);
    Summary {
        binaries: binaries.len(),
        functions: times.len(),
        fragments_skipped,
        ok: count(Status::Ok),
        error: count(Status::Error),
        timeout: count(Status::Timeout),
        crash: count(Status::Crash),
        jobs: config.jobs,
        wall_seconds: wall.as_secs_f64(),
        function_seconds: times.iter().sum::<f64>() / 1e3,
        median_ms: at(0.5),
        p90_ms: at(0.9),
        p99_ms: at(0.99),
        max_ms: at(1.0),
        slowest,
    }
}

fn print_summary(s: &Summary) {
    println!("{} binaries, {} functions ({} cold fragments not decompiled on their own)", s.binaries, s.functions, s.fragments_skipped);
    println!("ok {}, error {}, timeout {}, crash {}", s.ok, s.error, s.timeout, s.crash);
    println!("wall {:.1}s with {} jobs; {:.1}s summed over functions", s.wall_seconds, s.jobs, s.function_seconds);
    println!("per function: median {:.2}ms, p90 {:.2}ms, p99 {:.1}ms, max {:.0}ms", s.median_ms, s.p90_ms, s.p99_ms, s.max_ms);
    println!("slowest:");
    for slow in &s.slowest {
        println!("  {:>9.0}ms {:?} {} {:#x}", slow.ms, slow.status, slow.binary, slow.addr);
    }
}

/// Prints the C of chosen functions, or of all of them. Each argument is a hex address or a
/// name the image carries for a function, mangled or demangled.
pub fn functions(binary: &Path, wanted: &[String], all: bool, jobs: usize, timeout: Duration, worker: &Options) -> Result<()> {
    let worker = Options { emit_c: true, ..worker.clone() };
    let shards: Vec<Vec<u64>> = if all {
        // Listing every function means analyzing here as well as in the children.
        let functions = plan(binary)?.functions;
        let count = jobs.clamp(1, functions.len().max(1));
        (0..count).map(|i| functions.iter().copied().skip(i).step_by(count).collect()).collect()
    } else {
        // Loading without analyzing is enough to resolve names, and takes milliseconds.
        let image = recore::Image::load(binary)?;
        let resolve = |text: &String| {
            let by_name = || image.symbol_names.iter().find(|(_, name)| *name == text || recore::names::display_name(name) == *text).map(|(&addr, _)| addr);
            u64::from_str_radix(text.trim_start_matches("0x"), 16).ok().or_else(by_name).with_context(|| format!("{text} is neither a hex address nor a known name"))
        };
        vec![wanted.iter().map(resolve).collect::<Result<_>>()?]
    };

    let results: Mutex<Vec<(FunctionRecord, Option<String>)>> = Mutex::new(Vec::new());
    for_each(&shards, jobs, |addrs| {
        let (records, mut texts) = run_shard(&worker, timeout, binary, addrs);
        let with_text = records.into_iter().map(|record| {
            let text = texts.iter().position(|text| text.0 == record.addr).map(|index| texts.swap_remove(index).1);
            (record, text)
        });
        results.lock().unwrap().extend(with_text);
    });
    let mut results = results.into_inner().unwrap();
    // In the order asked for, or by address for a full dump.
    let order = |addr: u64| shards[0].iter().position(|&a| a == addr).filter(|_| !all).map_or(addr, |index| index as u64);
    results.sort_by_key(|(record, _)| order(record.addr));
    let mut out = std::io::stdout().lock();
    for (record, text) in &results {
        match text {
            Some(text) => writeln!(out, "// {:#x} ({:.0}ms){text}", record.addr, record.ms)?,
            None => writeln!(out, "// {:#x}: {:?}: {}\n", record.addr, record.status, record.message.as_deref().unwrap_or(""))?,
        }
    }
    Ok(())
}
