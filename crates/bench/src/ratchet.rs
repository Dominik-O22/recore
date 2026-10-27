//! A limit on the instructions recore executes that only tightens: `recore-bench ratchet`.
//!
//! `bench/budget.json` holds, for each binary of the set, the instructions that loading and
//! analyzing it executed, and those that `diff` of it against itself executed. A run fails when
//! a count grew past its budget by more than [`SLACK`], and lowers the budget where a count
//! shrank by as much, so the next change is held to the faster code. Counted instructions do
//! not move with the machine's load, but they do with the compiler and with the processor,
//! where a library picks its code by what the processor has: a budget is kept on one machine.
//! Each binary is counted in a process of its own, because in one process the allocator's
//! state after the binaries before it moved a count by up to 2%.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use recore::program::Program;
use serde::{Deserialize, Serialize};

/// How far a count may move and still be the same: between runs it moves by a few hundredths
/// of a percent.
const SLACK: f64 = 0.01;

/// Instructions executed for one binary, in the order they are printed.
#[derive(Serialize, Deserialize, Clone, Copy)]
struct Work {
    analysis: u64,
    diff: u64,
}

/// Measures the binaries against the budget at `path`, and writes the budget back with what
/// shrank lowered and what is new added. With `accept`, what grew is raised to what it is now
/// and nothing fails: for a change that is worth what it costs, which its description says.
pub fn run(binaries: &[PathBuf], path: &Path, accept: bool) -> Result<()> {
    let mut budget: BTreeMap<String, Work> = match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).with_context(|| format!("reading {}", path.display()))?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
        Err(error) => return Err(error).with_context(|| format!("reading {}", path.display())),
    };
    let (mut over, mut lowered, mut added) = (Vec::new(), 0, 0);
    // A store can hold some corpora and not others, but one that holds none of the set is a
    // wrong path, which must not pass for a check.
    let (present, missing): (Vec<&PathBuf>, Vec<&PathBuf>) = binaries.iter().partition(|binary| binary.exists());
    if present.is_empty() {
        bail!("none of the {} binaries of the set is in {}", binaries.len(), crate::corpora().display());
    }
    println!("{:<46} {:>10} {:>8} {:>10} {:>8}", "binary", "analysis M", "change", "diff M", "change");
    for binary in present {
        let name = crate::suites::name(binary);
        let counted = std::process::Command::new(std::env::current_exe()?).arg("count").arg(binary).output()?;
        if !counted.status.success() {
            bail!("counting {}: {}", binary.display(), String::from_utf8_lossy(&counted.stderr).trim());
        }
        let now: Work = serde_json::from_slice(&counted.stdout).with_context(|| format!("counting {}", binary.display()))?;
        let limit = budget.entry(name.clone()).or_insert_with(|| {
            added += 1;
            now
        });
        let mut shown = Vec::new();
        for (what, now, limit) in [("analysis", now.analysis, &mut limit.analysis), ("diff", now.diff, &mut limit.diff)] {
            let change = now as f64 / (*limit).max(1) as f64 - 1.0;
            shown.push(format!("{:>10.1} {:>+7.1}%", now as f64 / 1e6, change * 100.0));
            if change > SLACK {
                over.push(format!("{name}: {what} {:.1}M -> {:.1}M ({:+.1}%)", *limit as f64 / 1e6, now as f64 / 1e6, change * 100.0));
                if accept {
                    *limit = now;
                }
            } else if change < -SLACK {
                *limit = now;
                lowered += 1;
            }
        }
        println!("{:<46} {}", name, shown.join(" "));
    }
    if !over.is_empty() && !accept {
        bail!("instructions grew past the budget, which `--accept` raises if the change is worth it:\n{}", over.join("\n"));
    }
    std::fs::write(path, serde_json::to_string_pretty(&budget)? + "\n").with_context(|| format!("writing {}", path.display()))?;
    println!("{} raised, {lowered} lowered, {added} added in {}", if accept { over.len() } else { 0 }, path.display());
    if !missing.is_empty() {
        println!("{} binaries of the set are not in {} and were not counted", missing.len(), crate::corpora().display());
    }
    Ok(())
}

/// Counts the instructions that loading and analyzing `binary`, and `diff` of it against
/// itself, execute, and prints them as JSON for [`run`].
pub fn count(binary: &Path) -> Result<()> {
    let (loaded, analysis) = crate::work::instructions(|| -> Result<_> {
        let image = recore::Image::load(binary)?;
        let analysis = recore::analyze(&image);
        Ok((image, analysis))
    });
    let (image, found) = loaded?;
    let program = Program::new(image, found);
    let (_, diff) = crate::work::instructions(|| recore::diff::diff(&program, &program));
    let (Some(analysis), Some(diff)) = (analysis, diff) else {
        bail!("the kernel lets this process count no instructions; /proc/sys/kernel/perf_event_paranoid must be 2 or less");
    };
    println!("{}", serde_json::to_string(&Work { analysis, diff })?);
    Ok(())
}
