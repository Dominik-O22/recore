//! Command line for the analysis core.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::Result;
use clap::{Parser, Subcommand};
use rayon::prelude::*;
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
    /// Analyzes every file in a directory, writing `<out>/<name>.json`.
    Corpus {
        bin_dir: PathBuf,
        out: PathBuf,
        /// Ignore `.eh_frame`, to measure how much recovery depends on it.
        #[arg(long)]
        no_frames: bool,
    },
}

/// An analysis with the lookups the query commands share.
struct Loaded {
    image: recore::Image,
    analysis: recore::report::Analysis,
}

impl Loaded {
    fn new(binary: &Path) -> Result<Self> {
        let image = recore::Image::load(binary)?;
        let analysis = recore::analyze(&image);
        Ok(Loaded { image, analysis })
    }

    /// Entry address of the function whose extent contains `addr`.
    fn function_containing(&self, addr: u64) -> Option<u64> {
        let functions = &self.analysis.functions;
        let index = functions.partition_point(|f| f.addr <= addr);
        let function = functions[..index].last()?;
        function.ranges.iter().any(|&(start, end)| addr >= start && addr < end).then_some(function.addr)
    }

    /// A function as `address` or `address(name)`.
    fn label(&self, entry: u64) -> String {
        let name = self.analysis.functions.binary_search_by_key(&entry, |f| f.addr).ok().and_then(|i| self.analysis.functions[i].name.as_ref());
        match name {
            Some(name) => format!("{entry:#x}({name})"),
            None => format!("{entry:#x}"),
        }
    }

    /// Distinct functions containing the given instruction addresses.
    fn users(&self, sites: impl Iterator<Item = u64>) -> String {
        let users: BTreeSet<u64> = sites.filter_map(|site| self.function_containing(site)).collect();
        users.iter().map(|&entry| self.label(entry)).collect::<Vec<_>>().join(" ")
    }

    fn import_name(&self, slot: u64) -> &str {
        self.analysis.imports.iter().find(|i| i.slot == slot).map_or("?", |i| i.name.as_str())
    }
}

fn matches(text: &str, pattern: &Option<String>) -> bool {
    pattern.as_ref().is_none_or(|p| text.to_lowercase().contains(&p.to_lowercase()))
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
            let Loaded { image, analysis } = Loaded::new(&binary)?;
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
            let loaded = Loaded::new(&binary)?;
            for string in loaded.analysis.strings.iter().filter(|s| matches(&s.text, &pattern)) {
                let sites = loaded.analysis.data_refs.iter().filter(|r| r.to == string.addr).map(|r| r.from);
                println!("{:#x} {:?} used by: {}", string.addr, string.text, loaded.users(sites));
            }
        }
        Command::Imports { binary, pattern } => {
            let loaded = Loaded::new(&binary)?;
            for import in loaded.analysis.imports.iter().filter(|i| matches(&i.name, &pattern)) {
                let sites = loaded.analysis.calls.iter().filter(|c| c.target == CallTarget::Import(import.slot)).map(|c| c.at);
                println!("{} called by: {}", import.name, loaded.users(sites));
            }
        }
        Command::Function { binary, addr } => {
            let loaded = Loaded::new(&binary)?;
            let addr = u64::from_str_radix(addr.trim_start_matches("0x"), 16)?;
            let entry = loaded.function_containing(addr).ok_or_else(|| anyhow::anyhow!("no function contains {addr:#x}"))?;
            let function = loaded.analysis.functions.iter().find(|f| f.addr == entry).unwrap();
            let inside = |at: u64| function.ranges.iter().any(|&(start, end)| at >= start && at < end);
            println!("function {}, extent {:x?}{}", loaded.label(entry), function.ranges, if function.noreturn { ", never returns" } else { "" });

            let callers = loaded.analysis.calls.iter().filter(|c| c.target == CallTarget::Function(entry)).map(|c| c.at);
            println!("called by: {}", loaded.users(callers));
            for call in loaded.analysis.calls.iter().filter(|c| inside(c.at)) {
                let target = match call.target {
                    CallTarget::Function(target) => loaded.label(target),
                    CallTarget::Import(slot) => loaded.import_name(slot).to_string(),
                };
                println!("  {:#x} {} {target}", call.at, if call.tail { "tail-calls" } else { "calls" });
            }
            for reference in loaded.analysis.data_refs.iter().filter(|r| inside(r.from)) {
                if let Some(string) = loaded.analysis.strings.iter().find(|s| s.addr == reference.to) {
                    println!("  {:#x} uses string {:?}", reference.from, string.text);
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
