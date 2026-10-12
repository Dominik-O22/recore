//! Command line for the analysis core.

use std::path::PathBuf;
use std::time::Instant;

use anyhow::Result;
use clap::{Parser, Subcommand};
use rayon::prelude::*;
use recore::program::{Program, matches, parse_addr};
use recore::report::CallTarget;

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Analyzes one binary and prints the result as JSON.
    Analyze { binary: PathBuf },
    /// Prints what the binary is and how much was recovered.
    Summary { binary: PathBuf },
    /// Lists strings with the functions that refer to each. `pattern` filters by a
    /// case-insensitive substring.
    Strings { binary: PathBuf, pattern: Option<String> },
    /// Lists imported functions with the functions that call each.
    Imports { binary: PathBuf, pattern: Option<String> },
    /// Shows one function: its extent, what it calls, who calls it, and the strings it uses.
    /// `addr` is any address inside it, in hex.
    Function { binary: PathBuf, addr: String },
    /// Lists what refers to an address: callers if it is a function, otherwise the
    /// instructions that read, write or take the address of that data. `addr` is in hex.
    Xrefs { binary: PathBuf, addr: String },
    /// Analyzes every file in a directory, writing `<out>/<name>.json`.
    Corpus {
        bin_dir: PathBuf,
        out: PathBuf,
        /// Ignore `.eh_frame`, to measure how much recovery depends on it.
        #[arg(long)]
        no_frames: bool,
    },
}

/// Labels of the distinct functions containing the given instruction addresses.
fn users(program: &Program, sites: impl Iterator<Item = u64>) -> String {
    program.users(sites).iter().map(|&entry| program.label(entry)).collect::<Vec<_>>().join(" ")
}

/// Reads a hex address given on the command line.
fn address(text: &str) -> Result<u64> {
    parse_addr(text).ok_or_else(|| anyhow::anyhow!("`{text}` is not a hex address"))
}

fn main() -> Result<()> {
    // Output is often piped into `head` or `grep -m`; end quietly when the reader goes away.
    // SAFETY: restoring the default disposition for a signal before any thread starts.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
    match Cli::parse().command {
        Command::Summary { binary } => {
            let start = Instant::now();
            let Program { image, analysis, .. } = Program::load(&binary)?;
            println!("{}: {:?}, entry {:#x}", image.name, image.machine, image.entry);
            println!(
                "{} functions ({} never return), {} instructions, {} calls, {} imports, {} jump tables, {} strings",
                analysis.functions.iter().filter(|f| f.fragment_of.is_none()).count(),
                analysis.functions.iter().filter(|f| f.noreturn).count(),
                analysis.instructions,
                analysis.calls.len(),
                analysis.imports.len(),
                analysis.jump_tables.len(),
                analysis.strings.len(),
            );
            println!("analyzed in {:.0} ms", start.elapsed().as_secs_f64() * 1000.0);
        }
        Command::Strings { binary, pattern } => {
            let program = Program::load(&binary)?;
            for string in program.analysis.strings.iter().filter(|s| matches(&s.text, pattern.as_deref())) {
                let sites = program.refs_to(string.addr).map(|r| r.from);
                println!("{:#x} {:?} used by: {}", string.addr, string.text, users(&program, sites));
            }
        }
        Command::Imports { binary, pattern } => {
            let program = Program::load(&binary)?;
            for import in program.analysis.imports.iter().filter(|i| matches(&i.name, pattern.as_deref())) {
                let sites = program.calls_to(import.slot).map(|c| c.at);
                println!("{} called by: {}", import.name, users(&program, sites));
            }
        }
        Command::Xrefs { binary, addr } => {
            let program = Program::load(&binary)?;
            let addr = address(&addr)?;
            for call in program.calls_to(addr) {
                println!("{:#x} in {} {}", call.at, program.site_label(call.at), if call.tail { "tail-calls it" } else { "calls it" });
            }
            for reference in program.refs_to(addr) {
                println!("{:#x} in {} refers to it", reference.from, program.site_label(reference.from));
            }
        }
        Command::Function { binary, addr } => {
            let program = Program::load(&binary)?;
            let entry = program.function_at(address(&addr)?)?;
            let noreturn = program.function(entry).is_some_and(|f| f.noreturn);
            let body = program.body(entry);
            println!("function {}, extent {body:x?}{}", program.label(entry), if noreturn { ", never returns" } else { "" });

            println!("called by: {}", users(&program, program.calls_to(entry).map(|c| c.at)));
            for &(start, end) in &body {
                for call in program.calls_in(start, end) {
                    let target = match call.target {
                        CallTarget::Function(target) => program.label(target),
                        CallTarget::Import(slot) => program.import_name(slot).unwrap_or("?").to_string(),
                    };
                    println!("  {:#x} {} {target}", call.at, if call.tail { "tail-calls" } else { "calls" });
                }
                for reference in program.refs_in(start, end) {
                    if let Some(string) = program.string_at(reference.to) {
                        println!("  {:#x} uses string {:?}", reference.from, string.text);
                    }
                }
            }
        }
        Command::Analyze { binary } => {
            let image = recore::Image::load(&binary)?;
            println!("{}", serde_json::to_string(&recore::analyze(&image))?);
        }
        Command::Corpus { bin_dir, out, no_frames } => {
            std::fs::create_dir_all(&out)?;
            let mut paths: Vec<PathBuf> = std::fs::read_dir(&bin_dir)?.map(|e| Ok(e?.path())).collect::<Result<_>>()?;
            paths.sort();
            let start = Instant::now();
            let failures: Vec<String> = paths
                .par_iter()
                .filter_map(|path| {
                    let result = recore::Image::load(path).and_then(|mut image| {
                        if no_frames {
                            image.frames.clear();
                        }
                        let analysis = recore::analyze(&image);
                        std::fs::write(out.join(format!("{}.json", analysis.name)), serde_json::to_vec(&analysis)?)?;
                        Ok(())
                    });
                    result.err().map(|error| format!("{}: {error:#}", path.display()))
                })
                .collect();
            failures.iter().for_each(|failure| eprintln!("{failure}"));
            eprintln!("analyzed {} binaries in {:.2}s", paths.len() - failures.len(), start.elapsed().as_secs_f64());
        }
    }
    Ok(())
}
