//! A sampling profile of one binary's analysis or decompilation, as tables of functions.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::ValueEnum;
use recore::program::Program;
use recore::image::Format;
use recore_decomp::{Facts, Session};

#[derive(ValueEnum, Clone, Copy)]
pub enum What {
    /// Loading and analyzing the binary.
    Analysis,
    /// Decompiling the chosen functions in this process, without the callees-first pass.
    Decompile,
}

/// Samples per second. High enough for a few seconds to give thousands of samples.
const FREQUENCY: i32 = 2000;

pub fn run(what: What, binary: &Path, functions: &[String], seconds: f64, top: usize, collapsed: Option<&Path>) -> Result<()> {
    let limit = Duration::from_secs_f64(seconds);
    // Set up before sampling starts, so that the profile is of the repeated work alone.
    let mut work: Box<dyn FnMut() -> Result<()>> = match what {
        What::Analysis => Box::new(|| {
            let image = recore::Image::load(binary)?;
            std::hint::black_box(recore::analyze(&image));
            Ok(())
        }),
        What::Decompile => {
            let program = Program::load(binary)?;
            let (image, analysis) = (&program.image, &program.analysis);
            let facts = Facts::derive(image, analysis);
            let mut session = Session::from_image(image, analysis)?;
            session.add_functions(&facts)?;
            session.add_strings(analysis)?;
            session.add_classes(analysis)?;
            if image.format == Format::Pe {
                session.override_jump_tables(analysis, &facts)?;
            }
            let chosen: Vec<u64> = if functions.is_empty() {
                crate::suites::sample(&program, 150)
            } else {
                functions.iter().map(|text| recore::program::parse_addr(text).with_context(|| format!("{text} is not an address"))).collect::<Result<_>>()?
            };
            Box::new(move || {
                for &function in &chosen {
                    // A function the engine gives up on still costs the time it took.
                    let _ = session.decompile(function);
                }
                Ok(())
            })
        }
    };

    // Sampling inside the C library's own unwinder can deadlock, so those are left out.
    let guard = pprof::ProfilerGuardBuilder::default().frequency(FREQUENCY).blocklist(&["libc", "libgcc", "pthread", "vdso"]).build()?;
    let start = Instant::now();
    let mut rounds = 0;
    while rounds == 0 || start.elapsed() < limit {
        work()?;
        rounds += 1;
    }
    let elapsed = start.elapsed();
    let report = guard.report().build()?;

    // Per function: samples with it on top of the stack, and samples with it anywhere.
    let mut own: HashMap<String, isize> = HashMap::new();
    let mut inclusive: HashMap<String, isize> = HashMap::new();
    let mut stacks: Vec<(String, isize)> = Vec::new();
    let mut total = 0;
    for (frames, &count) in &report.data {
        // Innermost first; an inlined call adds its own name before the function it is in.
        let names: Vec<String> = frames.frames.iter().flatten().map(|symbol| symbol.name()).collect();
        let Some(leaf) = names.first() else { continue };
        total += count;
        *own.entry(leaf.clone()).or_default() += count;
        for name in names.iter().collect::<HashSet<_>>() {
            *inclusive.entry(name.clone()).or_default() += count;
        }
        stacks.push((names.iter().rev().map(String::as_str).collect::<Vec<_>>().join(";"), count));
    }

    println!("{rounds} rounds in {:.2}s ({:.2} ms each), {total} samples", elapsed.as_secs_f64(), elapsed.as_secs_f64() * 1e3 / f64::from(rounds));
    for (title, counts) in [("own time", &own), ("time including what it calls", &inclusive)] {
        let mut rows: Vec<(&String, &isize)> = counts.iter().collect();
        rows.sort_by_key(|&(name, &count)| (-count, name));
        println!("\n{title}");
        for (name, &count) in rows.into_iter().take(top) {
            let name: String = name.chars().take(150).collect();
            println!("{:>6.2}%  {name}", count as f64 * 100.0 / total.max(1) as f64);
        }
    }
    if let Some(path) = collapsed {
        stacks.sort();
        let text: String = stacks.iter().map(|(stack, count)| format!("{stack} {count}\n")).collect();
        std::fs::write(path, text)?;
    }
    Ok(())
}
