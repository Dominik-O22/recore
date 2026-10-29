//! Decompiles whole corpora with Ghidra's engine, one disposable child process per shard.

mod imports;
mod noise;
mod params;
mod report;
mod run;
mod structs;

use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use recore_decomp::Style;
use recore_decomp::isolate::{self, JumpTables, Options};

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
    /// Where switch targets come from: recore's jump tables, the engine's own recovery, or
    /// recore's for PE images and raw firmware and the engine's otherwise.
    #[arg(long, value_enum, default_value = "auto")]
    jump_tables: JumpTablesArg,
    /// Address space per child process, in GiB, beyond what loading the binary took. Past it the
    /// engine's allocations fail and the function is reported as an error.
    #[arg(long, default_value_t = 4)]
    memory_gb: u64,
    /// Decompile the functions a function calls before the function itself, so that its calls
    /// pass the parameters they were found to take.
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    callees_first: bool,
}

#[derive(ValueEnum, Clone, Copy)]
enum JumpTablesArg {
    Auto,
    Recore,
    Engine,
}

#[derive(ValueEnum, Clone, Copy)]
enum StyleArg {
    Decompile,
    Normalize,
    Paramid,
}

impl From<&WorkerOptions> for Options {
    fn from(options: &WorkerOptions) -> Options {
        Options {
            style: match options.style {
                StyleArg::Decompile => Style::Decompile,
                StyleArg::Normalize => Style::Normalize,
                StyleArg::Paramid => Style::ParamId,
            },
            emit_c: options.emit_c,
            jump_tables: match options.jump_tables {
                JumpTablesArg::Auto => JumpTables::Auto,
                JumpTablesArg::Recore => JumpTables::Recore,
                JumpTablesArg::Engine => JumpTables::Engine,
            },
            memory_gb: options.memory_gb,
            callees_first: options.callees_first,
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
    /// Prints the decompiled C of chosen functions of one binary.
    Function {
        binary: PathBuf,
        /// Hex addresses, or names the image carries (exports and symbols).
        functions: Vec<String>,
        /// Decompile every function instead.
        #[arg(long)]
        all: bool,
        /// Child processes for `--all`.
        #[arg(long, default_value_t = std::thread::available_parallelism().map_or(1, usize::from))]
        jobs: usize,
        /// Wall-clock seconds one function may take.
        #[arg(long, default_value_t = 30.0)]
        timeout: f64,
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
    /// Scores the structs recovered for pointer parameters against the DWARF of each binary in
    /// `<corpus>/bin` that has `<corpus>/debug/<name>.debug`, decompiling a sample of its
    /// functions as the census does: every so many, the same each run, without debug
    /// information or edits.
    Structs {
        /// Corpus directories, each with `bin/` and `debug/`.
        corpora: Vec<PathBuf>,
        /// The binaries struct recovery was tuned on, one `<corpus>/bin/<name>` a line, as
        /// `bench/set.txt` lists them. Scored apart from the others.
        #[arg(long)]
        tuning: Option<PathBuf>,
        /// Functions per binary.
        #[arg(long, default_value_t = 200)]
        sample: usize,
        /// Binaries scored at once, each with its own decompiler process.
        #[arg(long, default_value_t = 6)]
        jobs: usize,
        /// Wall-clock seconds one function may take.
        #[arg(long, default_value_t = 20.0)]
        timeout: f64,
        /// Write each scored struct, and each parameter refused one, as a JSON line here.
        #[arg(long)]
        cases: Option<PathBuf>,
    },
    /// Prints how much of the C of a `corpus` run with `--emit-c` is hard to read: flags kept as
    /// bits of a status register, values seen only as their bytes, registers no convention
    /// accounts for.
    Noise {
        out_dir: PathBuf,
        /// Also list the functions that carry this mark, by the name the report gives it.
        #[arg(long)]
        list: Option<String>,
    },
    /// Prints how many calls to imported functions in a directory of binaries have a prototype,
    /// and from which table.
    Imports {
        bin_dir: PathBuf,
        /// Imports without a prototype to print, most-called first.
        #[arg(long, default_value_t = 0)]
        list: usize,
    },
    /// Reads a binary's debug information and gives its types to a decompiler session, printing
    /// what was found and how long each step took, and how long a child takes to be ready with
    /// the debug information and without.
    DebugInfo { binary: PathBuf },
    /// Child process of the other commands: see `recore_decomp::isolate`.
    #[command(hide = true)]
    Worker { binary: PathBuf, options: String },
}

#[global_allocator]
static ALLOCATOR: recore_decomp::MiMalloc = recore_decomp::MiMalloc;

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Corpus { bin_dir, out_dir, jobs, timeout, shard, worker } => {
            run::corpus(&run::Config { bin_dir, out_dir, jobs, timeout: Duration::from_secs_f64(timeout), shard, worker: (&worker).into() })
        }
        Command::Function { binary, functions, all, jobs, timeout, worker } => {
            run::functions(&binary, &functions, all, jobs, Duration::from_secs_f64(timeout), &(&worker).into())
        }
        Command::Params { out_dir, debug_dir, jobs, list } => params::compare(&out_dir, &debug_dir, jobs, list),
        Command::Structs { corpora, tuning, sample, jobs, timeout, cases } => {
            let tuning = match tuning {
                Some(list) => std::fs::read_to_string(list)?.lines().map(str::trim).filter(|line| !line.is_empty() && !line.starts_with('#')).map(String::from).collect(),
                None => Default::default(),
            };
            // Each package unpacked as `<corpus>/pkgs/<source>/x/<package>`.
            let mut roots = Vec::new();
            for sources in corpora.iter().filter_map(|corpus| std::fs::read_dir(corpus.join("pkgs")).ok()).flatten().flatten() {
                roots.extend(std::fs::read_dir(sources.path().join("x")).into_iter().flatten().flatten().map(|package| package.path()));
            }
            structs::score(&structs::Config { corpora, roots, tuning, sample, jobs, timeout: Duration::from_secs_f64(timeout), cases })
        }
        Command::Noise { out_dir, list } => noise::report(&out_dir, list.as_deref()),
        Command::Imports { bin_dir, list } => imports::coverage(&bin_dir, list),
        Command::DebugInfo { binary } => imports::debug_info(&binary),
        Command::Worker { binary, options } => isolate::serve(&binary, &options),
    }
}
