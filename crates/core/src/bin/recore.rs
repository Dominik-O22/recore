//! Command line for developing the analysis core: analyze one binary or a corpus. Queries about
//! a binary and decompilation are in `recore-mcp`.

use std::path::PathBuf;
use std::time::Instant;

use anyhow::Result;
use clap::{Parser, Subcommand};
use rayon::prelude::*;
use recore::program::Program;

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
    /// Analyzes every file in a directory, writing `<out>/<name>.json`.
    Corpus {
        bin_dir: PathBuf,
        out: PathBuf,
        /// Ignore `.eh_frame`, to measure how much recovery depends on it.
        #[arg(long)]
        no_frames: bool,
    },
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
