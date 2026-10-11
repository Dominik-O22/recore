//! Command line for the analysis core.

use std::path::PathBuf;
use std::time::Instant;

use anyhow::Result;
use clap::{Parser, Subcommand};
use rayon::prelude::*;

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Analyzes one binary and prints the result as JSON.
    Analyze { binary: PathBuf },
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
    match Cli::parse().command {
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
