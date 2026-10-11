//! Corpus tooling: extracts ground truth from debug files and scores analyzer output against it.

mod jumptables;
mod score;
mod truth;

use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::{Parser, Subcommand};
use rayon::prelude::*;

#[derive(Parser)]
struct Cli {
    /// Corpus directory containing `bin/` and `debug/`.
    #[arg(long, default_value = "corpus")]
    corpus: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Writes `truth/<name>.json` for every binary that has a debug file.
    Truth,
    /// Writes `jumptables/<name>.json` for every binary whose debug file lists its jump tables.
    Jumptables,
    /// Scores one or more analyzer output directories against the truth.
    Score {
        /// Directories of `<name>.json` analysis files, e.g. `corpus/ghidra`.
        dirs: Vec<PathBuf>,
        /// Print one row per binary, worst function recall first.
        #[arg(long)]
        detail: bool,
    },
}

fn binaries(corpus: &Path) -> Result<Vec<PathBuf>> {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(corpus.join("bin"))?.map(|e| Ok(e?.path())).collect::<Result<_>>()?;
    paths.sort();
    Ok(paths)
}

fn run_truth(corpus: &Path) -> Result<()> {
    let out_dir = corpus.join("truth");
    std::fs::create_dir_all(&out_dir)?;
    let results: Vec<_> = binaries(corpus)?
        .par_iter()
        .map(|binary| {
            let name = binary.file_name().unwrap().to_string_lossy().into_owned();
            let debug = corpus.join("debug").join(format!("{name}.debug"));
            let truth = truth::extract(binary, &debug);
            (name, truth)
        })
        .collect();

    let (mut functions, mut instructions, mut noreturn_calls, mut written) = (0, 0, 0, 0);
    for (name, truth) in results {
        match truth {
            // Too few symbols means the debug file has no usable symbol table.
            Ok(truth) if truth.functions.iter().filter(|f| f.size > 0).count() >= 10 => {
                functions += truth.functions.len();
                instructions += truth.instructions;
                noreturn_calls += truth.noreturn_calls.len();
                written += 1;
                std::fs::write(out_dir.join(format!("{name}.json")), serde_json::to_vec(&truth)?)?;
            }
            Ok(truth) => eprintln!("skip {name}: only {} function symbols", truth.functions.len()),
            Err(error) => eprintln!("skip {name}: {error:#}"),
        }
    }
    println!("{written} binaries, {functions} functions, {instructions} instructions, {noreturn_calls} noreturn calls");
    Ok(())
}

fn run_jumptables(corpus: &Path) -> Result<()> {
    let out_dir = corpus.join("jumptables");
    std::fs::create_dir_all(&out_dir)?;
    let results: Vec<_> = binaries(corpus)?
        .par_iter()
        .map(|binary| {
            let name = binary.file_name().unwrap().to_string_lossy().into_owned();
            let debug = corpus.join("debug").join(format!("{name}.debug"));
            let extracted = jumptables::extract(binary, &debug);
            (name, extracted)
        })
        .collect();

    let (mut listed, mut jumps, mut targets, mut rejected, mut written) = (0, 0, 0, 0, 0);
    for (name, extracted) in results {
        match extracted {
            Ok(Some(extracted)) => {
                let tables = &extracted.truth.tables;
                let table_targets: usize = tables.iter().map(|table| table.targets.len()).sum();
                println!(
                    "{name:16} {:4} listed  {:4} jumps  {table_targets:5} targets  {:3} rejected",
                    extracted.listed,
                    tables.len(),
                    extracted.rejected.len()
                );
                extracted.rejected.iter().for_each(|r| eprintln!("reject {name} table {:#x}: {}", r.table, r.reason));
                listed += extracted.listed;
                jumps += tables.len();
                targets += table_targets;
                rejected += extracted.rejected.len();
                written += 1;
                std::fs::write(out_dir.join(format!("{name}.json")), serde_json::to_vec(&extracted.truth)?)?;
            }
            // Not built by corpus/jt, so the compiler left no jump-table metadata.
            Ok(None) => {}
            Err(error) => eprintln!("skip {name}: {error:#}"),
        }
    }
    println!("{written} binaries, {listed} tables listed, {jumps} jumps, {targets} targets, {rejected} tables rejected");
    Ok(())
}

fn run_score(corpus: &Path, dir: &Path, detail: bool) -> Result<()> {
    let mut names: Vec<String> = std::fs::read_dir(corpus.join("truth"))?
        .filter_map(|e| Some(e.ok()?.path().file_stem()?.to_string_lossy().into_owned()))
        .collect();
    names.sort();
    let mut rows: Vec<(String, score::Score)> = names
        .par_iter()
        .filter_map(|name| {
            let analysis = std::fs::read(dir.join(format!("{name}.json"))).ok()?;
            let truth = std::fs::read(corpus.join("truth").join(format!("{name}.json"))).ok()?;
            let analysis: score::Analysis = serde_json::from_slice(&analysis).ok()?;
            let truth: truth::Truth = serde_json::from_slice(&truth).ok()?;
            let jump_tables: Option<jumptables::JumpTables> = std::fs::read(corpus.join("jumptables").join(format!("{name}.json")))
                .ok()
                .and_then(|data| serde_json::from_slice(&data).ok());
            Some((name.clone(), score::score(&truth, jump_tables.as_ref(), &analysis)))
        })
        .collect();

    let mut total = score::Score::default();
    rows.iter().for_each(|(_, s)| total += *s);
    let line = |label: &str, s: &score::Score| {
        println!(
            "{label:28} starts {}/{} (+{} outside)  recall {:5.1}%  precision {:5.1}%  F1 {:5.1}%  mid-func {:5}  in-cold {:6}  run-on {:5}  noreturn {:5.1}% (+{} extra, {} corroborated)  coverage {:5.1}%  jump tables {}/{} exact (missing {}, extra {}, unresolved {})",
            s.found,
            s.truth_functions,
            s.outside,
            100.0 * s.recall(),
            100.0 * s.precision(),
            100.0 * s.f1(),
            s.mid_function,
            s.in_fragment,
            s.run_on,
            100.0 * s.noreturn_recall(),
            s.extra_noreturn_calls,
            s.extra_noreturn_at_end,
            100.0 * s.coverage(),
            s.exact_tables,
            s.truth_tables,
            s.tables_missing_targets,
            s.tables_extra_targets,
            s.unresolved_tables,
        );
    };
    if detail {
        rows.sort_by(|a, b| a.1.recall().total_cmp(&b.1.recall()));
        rows.iter().for_each(|(name, s)| line(name, s));
    }
    line(&format!("{} ({} of {})", dir.display(), rows.len(), names.len()), &total);
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Truth => run_truth(&cli.corpus),
        Command::Jumptables => run_jumptables(&cli.corpus),
        Command::Score { dirs, detail } => dirs.iter().try_for_each(|dir| run_score(&cli.corpus, dir, detail)),
    }
}
