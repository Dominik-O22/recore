//! Timings to trust and compare: `recore-bench run` measures the benchmark set, `recore-bench
//! profile` says where the time of one binary goes, and `recore-bench ratchet` holds the
//! instructions executed to a budget that only tightens.
//!
//! Every number is the fastest of several runs, because noise on a quiet machine only ever adds
//! time. The median is kept beside it, and the gap between the two is reported as the noise.

mod profile;
mod ratchet;
mod suites;
mod work;

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};

/// The allocator `recore-mcp` runs on, which changes how many instructions the same work takes.
#[global_allocator]
static ALLOCATOR: recore_decomp::MiMalloc = recore_decomp::MiMalloc;

#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(ValueEnum, Clone, Copy, PartialEq, Eq)]
enum Suite {
    /// Loading and analyzing each binary in this process.
    Analysis,
    /// From a new process to the answer: `recore-mcp summary`, `xrefs` and `decompile`, and a new
    /// decompiler process to its first function, with the most memory it held.
    Cold,
    /// A sample of each binary's functions through the decompiler, one after another.
    Decompile,
    /// An agent's walk through each binary: decompilations with renames between them.
    Session,
}

#[derive(Subcommand)]
enum Command {
    /// Measures the benchmark set and prints one table per suite.
    Run {
        /// Suites to run; all of them by default.
        #[arg(value_enum)]
        suites: Vec<Suite>,
        /// The list of binaries, one path per line, relative to the corpora's directory.
        #[arg(long, default_value = "bench/set.txt")]
        set: PathBuf,
        /// Only binaries whose path contains this.
        #[arg(long)]
        only: Option<String>,
        /// Runs per measurement.
        #[arg(long, default_value_t = 7)]
        runs: usize,
        /// Functions sampled per binary in the decompile suite.
        #[arg(long, default_value_t = 150)]
        functions: usize,
        /// Functions per binary the session suite starts a walk from.
        #[arg(long, default_value_t = 12)]
        walks: usize,
        /// Writes the results to `target/bench/<NAME>.json`.
        #[arg(long)]
        save: Option<String>,
        /// Shows the change against `target/bench/<NAME>.json`.
        #[arg(long)]
        compare: Option<String>,
    },
    /// Prints the wall time of each phase of analyzing one binary, fastest of several runs.
    Phases {
        binary: PathBuf,
        #[arg(long, default_value_t = 7)]
        runs: usize,
    },
    /// Times decoding every instruction of one binary once, the floor under the analysis.
    DecodeFloor {
        binary: PathBuf,
        #[arg(long, default_value_t = 7)]
        runs: usize,
    },
    /// Samples the call stack while one binary is analyzed or decompiled over and over, and
    /// prints the functions the time goes to.
    Profile {
        #[arg(value_enum)]
        what: profile::What,
        binary: PathBuf,
        /// Functions to decompile, as hex addresses; a sample of all of them by default.
        functions: Vec<String>,
        /// How long to keep repeating the work.
        #[arg(long, default_value_t = 3.0)]
        seconds: f64,
        /// Rows per table.
        #[arg(long, default_value_t = 40)]
        top: usize,
        /// Writes the stacks in collapsed form, for a flame graph.
        #[arg(long)]
        collapsed: Option<PathBuf>,
    },
    /// Counts the instructions of what an agent waits for on each binary of the set, and fails
    /// where they grew past `bench/budget.json`. Lowers the budget where they shrank.
    Ratchet {
        /// The list of binaries, one path per line, relative to the corpora's directory.
        #[arg(long, default_value = "bench/set.txt")]
        set: PathBuf,
        #[arg(long, default_value = "bench/budget.json")]
        budget: PathBuf,
        /// Raises the budget to what grew, for a change worth what it costs.
        #[arg(long)]
        accept: bool,
    },
    /// Counts the instructions of one binary for `ratchet`, which runs each binary in a
    /// process of its own, and prints them as JSON.
    #[command(hide = true)]
    Count {
        binary: PathBuf,
        /// The functions to decompile; chosen here if there are none.
        functions: Vec<u64>,
    },
}

fn saved(name: &str) -> PathBuf {
    PathBuf::from("target/bench").join(format!("{name}.json"))
}

/// The directory the corpora are in: `RECORE_CORPORA`, else `~/recore-corpora`, as corpus/store.py says.
pub(crate) fn corpora() -> PathBuf {
    std::env::var_os("RECORE_CORPORA").map_or_else(|| PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join("recore-corpora"), PathBuf::from)
}

/// The binaries `set` lists, as paths into the corpora, those whose path contains `only` if
/// it is given.
fn binaries(set: &Path, only: Option<&str>) -> Result<Vec<PathBuf>> {
    let list = std::fs::read_to_string(set).with_context(|| format!("reading {}", set.display()))?;
    Ok(list
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter(|line| only.is_none_or(|only| line.contains(only)))
        .map(|line| corpora().join(line))
        .collect())
}

fn main() -> Result<()> {
    // Every suite starts from no edits, whatever names and types are saved for these binaries.
    // SAFETY: no other thread has started yet.
    unsafe { std::env::set_var(recore::edits::DIR_VAR, std::path::absolute("target/bench/edits")?) };
    match Args::parse().command {
        Command::Run { suites, set, only, runs, functions, walks, save, compare } => {
            let binaries = binaries(&set, only.as_deref())?;
            let wanted = |suite| suites.is_empty() || suites.contains(&suite);
            let before: Option<suites::Results> = match &compare {
                Some(name) => {
                    let path = saved(name);
                    Some(serde_json::from_slice(&std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?)?)
                }
                None => None,
            };
            // Saving under a name that exists replaces only the suites run now.
            let kept = save.as_deref().and_then(|name| serde_json::from_slice(&std::fs::read(saved(name)).ok()?).ok());
            let mut results: suites::Results = kept.unwrap_or_default();
            if wanted(Suite::Analysis) {
                results.analysis = suites::analysis(&binaries, runs)?;
                suites::print_analysis(&results.analysis, before.as_ref().map(|b| b.analysis.as_slice()));
            }
            if wanted(Suite::Cold) {
                results.cold = suites::cold(&binaries, runs)?;
                suites::print_cold(&results.cold, before.as_ref().map(|b| b.cold.as_slice()));
            }
            if wanted(Suite::Decompile) {
                results.decompile = suites::decompile(&binaries, runs.min(3), functions)?;
                suites::print_decompile(&results.decompile, before.as_ref().map(|b| b.decompile.as_slice()));
            }
            if wanted(Suite::Session) {
                results.session = suites::session(&binaries, runs.min(3), walks)?;
                suites::print_session(&results.session, before.as_ref().map(|b| b.session.as_slice()));
            }
            if let Some(name) = save {
                let path = saved(&name);
                std::fs::create_dir_all(path.parent().expect("has a directory"))?;
                std::fs::write(&path, serde_json::to_vec_pretty(&results)?)?;
                println!("saved {}", path.display());
            }
            Ok(())
        }
        Command::Phases { binary, runs } => suites::phases(&binary, runs),
        Command::DecodeFloor { binary, runs } => suites::decode_floor(&binary, runs),
        Command::Profile { what, binary, functions, seconds, top, collapsed } => profile::run(what, &binary, &functions, seconds, top, collapsed.as_deref()),
        Command::Ratchet { set, budget, accept } => ratchet::run(&binaries(&set, None)?, &budget, accept),
        Command::Count { binary, functions } => ratchet::count(&binary, functions),
    }
}
