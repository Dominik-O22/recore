//! Timings to trust and compare: `recore-bench run` measures the benchmark set, `recore-bench
//! profile` says where the time of one binary goes.
//!
//! Every number is the fastest of several runs, because noise on a quiet machine only ever adds
//! time. The median is kept beside it, and the gap between the two is reported as the noise.

mod profile;
mod suites;

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(ValueEnum, Clone, Copy, PartialEq, Eq)]
enum Suite {
    /// Loading and analyzing each binary in this process.
    Analysis,
    /// From a new process to the answer: `recore-mcp summary` and `recore-mcp decompile`.
    Cold,
    /// A sample of each binary's functions through the decompiler, one after another.
    Decompile,
}

#[derive(Subcommand)]
enum Command {
    /// Measures the benchmark set and prints one table per suite.
    Run {
        /// Suites to run; all of them by default.
        #[arg(value_enum)]
        suites: Vec<Suite>,
        /// The list of binaries, one path per line, relative to the working directory.
        #[arg(long, default_value = "bench/set.txt")]
        set: PathBuf,
        /// Only binaries whose path contains this.
        #[arg(long)]
        only: Option<String>,
        /// Runs per measurement.
        #[arg(long, default_value_t = 5)]
        runs: usize,
        /// Functions sampled per binary in the decompile suite.
        #[arg(long, default_value_t = 150)]
        functions: usize,
        /// Writes the results to `target/bench/<NAME>.json`.
        #[arg(long)]
        save: Option<String>,
        /// Shows the change against `target/bench/<NAME>.json`.
        #[arg(long)]
        compare: Option<String>,
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
}

fn saved(name: &str) -> PathBuf {
    PathBuf::from("target/bench").join(format!("{name}.json"))
}

fn main() -> Result<()> {
    match Args::parse().command {
        Command::Run { suites, set, only, runs, functions, save, compare } => {
            let list = std::fs::read_to_string(&set).with_context(|| format!("reading {}", set.display()))?;
            let binaries: Vec<PathBuf> = list
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty() && !line.starts_with('#'))
                .filter(|line| only.as_deref().is_none_or(|only| line.contains(only)))
                .map(PathBuf::from)
                .collect();
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
            if let Some(name) = save {
                let path = saved(&name);
                std::fs::create_dir_all(path.parent().expect("has a directory"))?;
                std::fs::write(&path, serde_json::to_vec_pretty(&results)?)?;
                println!("saved {}", path.display());
            }
            Ok(())
        }
        Command::Profile { what, binary, functions, seconds, top, collapsed } => profile::run(what, &binary, &functions, seconds, top, collapsed.as_deref()),
    }
}
