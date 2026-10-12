//! Times session startup and per-function decompilation, then checks that sessions running on
//! several threads produce the same output as the same sessions running one after another.
//!
//! `cargo run --release -p recore-decomp --example bench -- corpus/bin/coreutils__install [threads] [--style=paramid|normalize] [--jump-tables]`

use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use recore::report::Analysis;
use recore_decomp::{Facts, Session, Style};

struct Setup<'a> {
    image: &'a recore::Image,
    analysis: &'a Analysis,
    style: Style,
    jump_tables: bool,
}

impl Setup<'_> {
    fn session(&self) -> Result<Session> {
        let mut session = Session::from_image(self.image, self.analysis)?;
        let facts = Facts::derive(self.image, self.analysis);
        session.add_functions(&facts)?;
        session.set_style(self.style)?;
        if self.jump_tables {
            session.override_jump_tables(self.analysis, &facts)?;
        }
        Ok(session)
    }

    /// Decompiles `functions` in order in a fresh session. Each outcome is the address, the time
    /// taken and everything the decompiler returned, rendered for comparison.
    fn run(&self, functions: &[u64]) -> Result<Vec<(u64, Duration, String)>> {
        let mut session = self.session()?;
        Ok(functions
            .iter()
            .map(|&addr| {
                let start = Instant::now();
                let result = session.decompile(addr);
                (addr, start.elapsed(), format!("{result:?}"))
            })
            .collect())
    }
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut positional = args.iter().filter(|a| !a.starts_with("--"));
    let binary = PathBuf::from(positional.next().context("usage: bench <binary> [threads] [--style=...] [--jump-tables]")?);
    let threads: usize = positional.next().map_or(Ok(6), |n| n.parse())?;
    let style = match args.iter().find_map(|a| a.strip_prefix("--style=")) {
        None | Some("decompile") => Style::Decompile,
        Some("normalize") => Style::Normalize,
        Some("paramid") => Style::ParamId,
        Some(other) => bail!("unknown style {other}"),
    };

    let image = recore::Image::load(&binary)?;
    let analysis = recore::analyze(&image);
    let setup = Setup { image: &image, analysis: &analysis, style, jump_tables: args.iter().any(|a| a == "--jump-tables") };
    let functions: Vec<u64> = analysis.functions.iter().filter(|f| f.fragment_of.is_none()).map(|f| f.addr).collect();
    // Functions are dealt round-robin so every shard sees a similar mix.
    let shards: Vec<Vec<u64>> = (0..threads).map(|i| functions.iter().copied().skip(i).step_by(threads).collect()).collect();

    let start = Instant::now();
    let first = Session::from_image(&image, &analysis)?;
    println!("first session (parses specs, loads .sla): {:.1?}", start.elapsed());
    let start = Instant::now();
    drop(Session::from_image(&image, &analysis)?);
    println!("second session: {:.1?}", start.elapsed());
    drop(first);
    let start = Instant::now();
    drop(setup.session()?);
    println!("session with {} declared functions: {:.1?}", functions.len(), start.elapsed());

    let start = Instant::now();
    let mut sequential = Vec::new();
    for shard in &shards {
        sequential.extend(setup.run(shard)?);
    }
    let wall = start.elapsed();
    sequential.sort_by_key(|o| o.0);
    let mut times: Vec<Duration> = sequential.iter().map(|o| o.1).collect();
    times.sort_unstable();
    let at = |q: f64| times[((times.len() - 1) as f64 * q) as usize];
    let failed = sequential.iter().filter(|o| o.2.starts_with("Err")).count();
    println!(
        "{style:?}, 1 thread: {} functions in {wall:.2?} ({:.0}/s), {failed} failed\n  median {:.2?}, mean {:.2?}, p90 {:.2?}, p99 {:.2?}, worst {:.2?} (at {:#x})",
        functions.len(),
        functions.len() as f64 / wall.as_secs_f64(),
        at(0.5),
        times.iter().sum::<Duration>() / times.len() as u32,
        at(0.9),
        at(0.99),
        at(1.0),
        sequential.iter().max_by_key(|o| o.1).context("no functions")?.0,
    );
    let mut slowest: Vec<&(u64, Duration, String)> = sequential.iter().collect();
    slowest.sort_by_key(|o| std::cmp::Reverse(o.1));
    let slowest: Vec<String> = slowest.iter().take(8).map(|o| format!("{:#x} {:.2?}", o.0, o.1)).collect();
    println!("  slowest: {}", slowest.join(", "));
    for (addr, _, error) in sequential.iter().filter(|o| o.2.starts_with("Err")).take(5) {
        println!("  {addr:#x}: {error}");
    }

    let start = Instant::now();
    let mut parallel: Vec<_> = std::thread::scope(|scope| {
        let workers: Vec<_> = shards.iter().map(|shard| scope.spawn(|| setup.run(shard))).collect();
        workers.into_iter().map(|w| w.join().expect("worker panicked")).collect::<Result<Vec<_>>>()
    })?
    .into_iter()
    .flatten()
    .collect();
    let wall = start.elapsed();
    parallel.sort_by_key(|o| o.0);
    let differing = sequential.iter().zip(&parallel).filter(|(a, b)| a.2 != b.2).count();
    println!(
        "{threads} threads, one session each: {wall:.2?} including session setup ({:.0}/s), {differing} results differ from the 1-thread run",
        functions.len() as f64 / wall.as_secs_f64(),
    );

    // Does a result depend on what the session decompiled before? Redo a sample in fresh sessions.
    let sample: Vec<usize> = (0..functions.len()).step_by((functions.len() / 40).max(1)).collect();
    let mut dependent = 0;
    for &index in &sample {
        let fresh = &setup.run(&functions[index..=index])?[0].2;
        let seasoned = &sequential[index].2;
        if fresh != seasoned {
            dependent += 1;
            // The results are single-line debug renderings; show where they part ways.
            let split = fresh.bytes().zip(seasoned.bytes()).take_while(|(a, b)| a == b).count().saturating_sub(60);
            let excerpt = |text: &str| text.chars().skip(split).take(160).collect::<String>();
            println!("  {:#x} fresh:    ...{}\n  {:#x} seasoned: ...{}", functions[index], excerpt(fresh), functions[index], excerpt(seasoned));
        }
    }
    println!("{dependent} of {} sampled results change when the function is decompiled in a fresh session", sample.len());
    Ok(())
}
