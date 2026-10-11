//! Decompiles whole corpora with Ghidra's engine, one disposable child process per shard.

mod params;
mod report;
mod run;
mod worker;

use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use recore_decomp::Style;

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

/// What every child process is told to do.
#[derive(clap::Args, Clone)]
struct WorkerOptions {
    #[arg(long, value_enum, default_value = "decompile")]
    style: StyleArg,
    /// Also write the C text to `<out-dir>/<name>.c`.
    #[arg(long)]
    emit_c: bool,
    /// Address-space limit per child process, in GiB. Past it the engine's allocations fail and
    /// the function is reported as an error.
    #[arg(long, default_value_t = 4)]
    memory_gb: u64,
}

#[derive(ValueEnum, Clone, Copy)]
enum StyleArg {
    Decompile,
    Normalize,
    Paramid,
}

impl From<StyleArg> for Style {
    fn from(style: StyleArg) -> Style {
        match style {
            StyleArg::Decompile => Style::Decompile,
            StyleArg::Normalize => Style::Normalize,
            StyleArg::Paramid => Style::ParamId,
        }
    }
}

#[derive(Subcommand)]
enum Command {
    /// Decompiles every function of every binary in a directory, writing `<out-dir>/<name>.json`
    /// and `<out-dir>/summary.json`.
    Corpus {
        bin_dir: PathBuf,
        out_dir: PathBuf,
        /// Child processes running at once.
        #[arg(long, default_value_t = std::thread::available_parallelism().map_or(1, usize::from))]
        jobs: usize,
        /// Wall-clock seconds one function may take before its child is killed.
        #[arg(long, default_value_t = 30.0)]
        timeout: f64,
        /// Functions per child process.
        #[arg(long, default_value_t = 1000)]
        shard: usize,
        #[command(flatten)]
        worker: WorkerOptions,
    },
    /// Compares the parameter counts of a `corpus` run with DWARF in `<debug-dir>/<name>.debug`.
    Params {
        out_dir: PathBuf,
        debug_dir: PathBuf,
        #[arg(long, default_value_t = std::thread::available_parallelism().map_or(1, usize::from))]
        jobs: usize,
        /// Mismatches to print.
        #[arg(long, default_value_t = 0)]
        list: usize,
    },
    /// Child process of `corpus`: decompiles the addresses read from stdin.
    #[command(hide = true)]
    Worker {
        binary: PathBuf,
        #[command(flatten)]
        options: WorkerOptions,
    },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Corpus { bin_dir, out_dir, jobs, timeout, shard, worker } => {
            run::corpus(&run::Config { bin_dir, out_dir, jobs, timeout: Duration::from_secs_f64(timeout), shard, worker })
        }
        Command::Params { out_dir, debug_dir, jobs, list } => params::compare(&out_dir, &debug_dir, jobs, list),
        Command::Worker { binary, options } => worker::run(&binary, &options),
    }
}
