//! Corpus tooling: extracts ground truth from debug files and scores analyzer output against it.

mod classes;
mod compare;
mod jumptables;
mod losses;
mod references;
mod rendered;
mod score;
mod signatures;
mod signatures_score;
mod truth;

use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::{Parser, Subcommand};
use rayon::prelude::*;

#[derive(Parser)]
struct Cli {
    /// The corpus, with `bin/` and `debug/`: a name in the corpora's directory, or an absolute path.
    #[arg(long, default_value = "corpus")]
    corpus: PathBuf,
    /// Where function signatures are kept, `<corpus>/signatures` unless given.
    #[arg(long)]
    signatures: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Writes `truth/<name>.json` for every binary that has a debug file.
    Truth,
    /// Writes `jumptables/<name>.json` for every binary whose debug file lists its jump tables.
    Jumptables,
    /// Prints measurements over a PE corpus: exception directory, imports, jump tables, padding.
    PeFacts {
        /// Print the counters of each binary as well as the totals.
        #[arg(long)]
        detail: bool,
    },
    /// Builds the library-function fingerprint database from the corpus and writes it to `out`.
    Signatures { out: PathBuf },
    /// Checks fingerprint naming by leaving each project out of the database in turn.
    SignatureCheck,
    /// Reads function signatures from the PDBs, or from SDCC's debug records, into the
    /// signatures directory.
    SignatureTruth,
    /// Scores decompiler corpus reports in `dirs` against those signatures.
    ScoreSignatures { dirs: Vec<PathBuf> },
    /// Compares recore's data references with Ghidra's in `<corpus>/ghidra-refs`, which
    /// `ghidra/run-refs.sh` writes.
    ScoreReferences {
        /// Print each reference of Ghidra's that recore lacks, as `<binary> <from> <to> <kind>` and
        /// how far it is past the nearest address recore refers to from the same function.
        #[arg(long)]
        misses: bool,
    },
    /// Scores the C++ classes recore recovers against the symbols and DWARF of each debug file.
    ScoreClasses {
        /// Print each class that is missing or differs.
        #[arg(long)]
        detail: bool,
    },
    /// Scores the instruction set recore gives each function of a 32-bit ARM binary against its
    /// symbol, which has the Thumb bit for Thumb code.
    ScoreInstructionSets {
        /// Print each function in the wrong set.
        #[arg(long)]
        detail: bool,
    },
    /// Scores one or more analyzer output directories against the truth.
    Score {
        /// Directories of `<name>.json` analysis files, e.g. `corpus/ghidra`.
        dirs: Vec<PathBuf>,
        /// Print one row per binary, worst function recall first.
        #[arg(long)]
        detail: bool,
    },
    /// Scores two analyzer output directories binary by binary and prints each count that moved,
    /// with the binaries it moved in. Fails when a binary lost its analysis, and otherwise with
    /// exit status 3 when a total got worse, each total printed as a `Worse:` line.
    Compare { base: PathBuf, head: PathBuf },
    /// Holds the `Worse:` lines of the comparisons of a run, in `found`, to the lines of `named`
    /// that start `Worse:`. Fails on a loss no line names with a reason, its count and at least
    /// how far it moved, and on a `Worse:` line out of that form. A line that names no loss of the
    /// run only prints.
    Losses { found: String, named: String },
    /// Prints the lines that start `Worse:` of a page GitHub rendered, read as HTML on stdin,
    /// such as a pull request's `body_html`: those of its paragraphs and list items, also in a
    /// quote or a `<details>` block, and none that the page does not show.
    WorseLines,
}

fn binaries(corpus: &Path) -> Result<Vec<PathBuf>> {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(corpus.join("bin"))?.map(|e| Ok(e?.path())).collect::<Result<_>>()?;
    paths.sort();
    Ok(paths)
}

/// The name of a binary: its file's name, or for a raw image the name of its layout.
fn name_of(binary: &Path) -> String {
    let name = if recore::layout::is_layout(binary) { binary.file_stem() } else { binary.file_name() };
    name.unwrap().to_string_lossy().into_owned()
}

/// The debug file of a binary: `<name>.pdb` for a PE image, `<name>.cdb` for an 8051 program
/// built with SDCC, `<name>.debug` otherwise.
fn debug_file(corpus: &Path, name: &str) -> PathBuf {
    let with = |extension: &str| corpus.join("debug").join(format!("{name}.{extension}"));
    [with("pdb"), with("cdb")].into_iter().find(|path| path.exists()).unwrap_or_else(|| with("debug"))
}

fn run_truth(corpus: &Path) -> Result<()> {
    let out_dir = corpus.join("truth");
    std::fs::create_dir_all(&out_dir)?;
    let results: Vec<_> = binaries(corpus)?
        .par_iter()
        .map(|binary| {
            let name = name_of(binary);
            let truth = truth::extract(binary, &debug_file(corpus, &name));
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

fn run_pe_facts(corpus: &Path, detail: bool) -> Result<()> {
    let results: Vec<_> = binaries(corpus)?
        .par_iter()
        .map(|binary| {
            let name = name_of(binary);
            let facts = truth::pe_facts::facts(binary, &debug_file(corpus, &name));
            (name, facts)
        })
        .collect();
    let mut total = truth::pe_facts::Facts::default();
    let print = |label: &str, facts: &truth::pe_facts::Facts| {
        println!("== {label}");
        facts.0.iter().for_each(|(key, n)| println!("{n:12}  {key}"));
    };
    for (name, facts) in results {
        match facts {
            Ok(facts) => {
                total.merge(&facts);
                if detail {
                    print(&name, &facts);
                }
            }
            Err(error) => eprintln!("skip {name}: {error:#}"),
        }
    }
    print(&corpus.display().to_string(), &total);
    Ok(())
}

fn run_jumptables(corpus: &Path) -> Result<()> {
    let out_dir = corpus.join("jumptables");
    std::fs::create_dir_all(&out_dir)?;
    let results: Vec<_> = binaries(corpus)?
        .par_iter()
        .map(|binary| {
            let name = name_of(binary);
            let extracted = jumptables::extract(binary, &debug_file(corpus, &name));
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
            // Nothing lists this binary's jump tables: no compiler metadata, no tables in `.text`.
            Ok(None) => {}
            Err(error) => eprintln!("skip {name}: {error:#}"),
        }
    }
    println!("{written} binaries, {listed} tables listed, {jumps} jumps, {targets} targets, {rejected} tables rejected");
    Ok(())
}

/// The score of each binary of `corpus` that `dir` has an analysis for, sorted by name.
fn score_dir(corpus: &Path, dir: &Path) -> Result<Vec<(String, score::Score)>> {
    let mut names: Vec<String> = std::fs::read_dir(corpus.join("truth"))?
        .filter_map(|e| Some(e.ok()?.path().file_stem()?.to_string_lossy().into_owned()))
        .collect();
    names.sort();
    Ok(names
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
        .collect())
}

/// The exit status of a comparison whose only failing is a total that got worse, which a
/// `Worse:` line may accept. check.sh tells it from a failing no such line accepts.
const LOSSES_ONLY: i32 = 3;

fn run_compare(corpus: &Path, base: &Path, head: &Path) -> Result<()> {
    let (changes, missing) = compare::compare(&score_dir(corpus, base)?, &score_dir(corpus, head)?);
    println!("{} against {}", head.display(), base.display());
    compare::print(&changes, &missing);
    let name = |path: &Path| path.file_name().map_or_else(String::new, |name| name.to_string_lossy().into_owned());
    let run = format!("{}/{}", name(corpus), name(head));
    let losses = compare::losses(&changes, &run);
    losses.iter().for_each(|loss| println!("{loss}"));
    anyhow::ensure!(missing.is_empty(), "{} is worse than its base: {} binaries have no analysis", head.display(), missing.len());
    if !losses.is_empty() {
        eprintln!("{} is worse than its base: {} counts fell", head.display(), losses.len());
        std::process::exit(LOSSES_ONLY);
    }
    Ok(())
}

/// Prints how each loss in `found` and each `Worse:` line in `named` stands, one line each that
/// starts with its standing, and under a loss what its run left out of the counts. Fails on a loss
/// no line names and on a line out of form.
fn run_losses(found: &str, named: &str) -> Result<()> {
    let judged = losses::judge(found, named);
    for judged in &judged {
        println!("{:9}  {}", judged.standing.label(), judged.line);
        if let Some(note) = judged.note {
            println!("{:9}  left out {note}", "");
        }
    }
    let failing = judged.iter().filter(|judged| judged.standing.fails()).count();
    anyhow::ensure!(failing == 0, "{failing} of the losses and the Worse: lines do not match");
    Ok(())
}

fn run_score(corpus: &Path, dir: &Path, detail: bool) -> Result<()> {
    let names = std::fs::read_dir(corpus.join("truth"))?.count();
    let mut rows = score_dir(corpus, dir)?;
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
    line(&format!("{} ({} of {names})", dir.display(), rows.len()), &total);
    Ok(())
}

/// The directory the corpora are in: `RECORE_CORPORA`, else `~/recore-corpora`, as corpus/store.py says.
fn corpora() -> PathBuf {
    std::env::var_os("RECORE_CORPORA").map_or_else(|| PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join("recore-corpora"), PathBuf::from)
}

fn main() -> Result<()> {
    let mut cli = Cli::parse();
    cli.corpus = corpora().join(&cli.corpus);
    let signatures = cli.signatures.clone().unwrap_or_else(|| cli.corpus.join("signatures"));
    match cli.command {
        Command::Truth => run_truth(&cli.corpus),
        Command::Signatures { out } => signatures::build(&cli.corpus, &out),
        Command::SignatureCheck => signatures::evaluate(&cli.corpus),
        Command::SignatureTruth => signatures_score::write_truth(&cli.corpus, &signatures),
        Command::ScoreSignatures { dirs } => signatures_score::score(&signatures, &dirs),
        Command::Jumptables => run_jumptables(&cli.corpus),
        Command::ScoreReferences { misses } => references::score(&cli.corpus, misses),
        Command::ScoreClasses { detail } => classes::score(&cli.corpus, detail),
        Command::PeFacts { detail } => run_pe_facts(&cli.corpus, detail),
        Command::ScoreInstructionSets { detail } => {
            let (right, all) = truth::arm::score_instruction_sets(&cli.corpus, detail)?;
            println!("{}: {right} of {all} functions in the right instruction set ({:.2}%)", cli.corpus.display(), 100.0 * right as f64 / all.max(1) as f64);
            Ok(())
        }
        Command::Compare { base, head } => run_compare(&cli.corpus, &base, &head),
        Command::Losses { found, named } => run_losses(&found, &named),
        Command::WorseLines => {
            let html = std::io::read_to_string(std::io::stdin())?;
            rendered::lines(&html).iter().filter(|line| line.starts_with("Worse:")).for_each(|line| println!("{line}"));
            Ok(())
        }
        Command::Score { dirs, detail } => dirs.iter().try_for_each(|dir| run_score(&cli.corpus, dir, detail)),
    }
}
