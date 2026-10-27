//! A limit on the instructions recore executes that only tightens: `recore-bench ratchet`.
//!
//! `bench/budget.json` holds, for each binary of the set, the instructions that loading and
//! analyzing it executed, and those that `diff` of it against itself executed. A run fails when
//! a count grew past its budget by more than [`SLACK`] percent, and lowers the budget where a
//! count shrank by as much, so the next change is held to the faster code. Counted instructions do
//! not move with the machine's load, but they do with the compiler and with the processor,
//! where a library picks its code by what the processor has: a budget is kept on one machine.
//! Each binary is counted in a process of its own, because in one process the allocator's
//! state after the binaries before it moved a count by up to 2%.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use recore::program::Program;
use serde::{Deserialize, Serialize};

/// How far a count may move, in percent of its budget, and still be the same: between runs it
/// moves by a few hundredths of a percent.
const SLACK: u128 = 1;

/// Instructions executed for one binary, in the order they are printed.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Debug)]
struct Work {
    analysis: u64,
    diff: u64,
}

/// One run's check of each binary's counts against the budget.
struct Ratchet {
    budget: BTreeMap<String, Work>,
    accept: bool,
    /// Each count that grew past its budget, described.
    over: Vec<String>,
    lowered: usize,
    added: usize,
}

impl Ratchet {
    fn new(budget: BTreeMap<String, Work>, accept: bool) -> Ratchet {
        Ratchet { budget, accept, over: Vec::new(), lowered: 0, added: 0 }
    }

    /// Holds what the binary `name` counted to its budget, which a binary new to it gets at
    /// that count, and returns the row that shows how the counts moved.
    fn hold(&mut self, name: &str, now: Work) -> String {
        let limit = self.budget.entry(name.to_string()).or_insert_with(|| {
            self.added += 1;
            now
        });
        let mut shown = Vec::new();
        for (what, now, limit) in [("analysis", now.analysis, &mut limit.analysis), ("diff", now.diff, &mut limit.diff)] {
            let change = now as f64 / (*limit).max(1) as f64 - 1.0;
            shown.push(format!("{:>10.1} {:>+7.1}%", now as f64 / 1e6, change * 100.0));
            // In whole numbers, which put a count exactly `SLACK` off still inside it.
            let (percent, budget) = (u128::from(now) * 100, u128::from((*limit).max(1)));
            if percent > budget * (100 + SLACK) {
                self.over.push(format!("{name}: {what} {:.1}M -> {:.1}M ({:+.1}%)", *limit as f64 / 1e6, now as f64 / 1e6, change * 100.0));
                if self.accept {
                    *limit = now;
                }
            } else if percent < budget * (100 - SLACK) {
                *limit = now;
                self.lowered += 1;
            }
        }
        format!("{:<46} {}", name, shown.join(" "))
    }

    /// The budget to write back and how it moved, or the error that names each count that grew
    /// past it, unless the run accepts them.
    fn finish(self) -> Result<(BTreeMap<String, Work>, String)> {
        if !self.over.is_empty() && !self.accept {
            bail!("instructions grew past the budget, which `--accept` raises if the change is worth it:\n{}", self.over.join("\n"));
        }
        let raised = if self.accept { self.over.len() } else { 0 };
        Ok((self.budget, format!("{raised} raised, {} lowered, {} added", self.lowered, self.added)))
    }
}

/// Measures the binaries against the budget at `path`, and writes the budget back with what
/// shrank lowered and what is new added. With `accept`, what grew is raised to what it is now
/// and nothing fails: for a change that is worth what it costs, which its description says.
pub fn run(binaries: &[PathBuf], path: &Path, accept: bool) -> Result<()> {
    let budget: BTreeMap<String, Work> = match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).with_context(|| format!("reading {}", path.display()))?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
        Err(error) => return Err(error).with_context(|| format!("reading {}", path.display())),
    };
    let mut ratchet = Ratchet::new(budget, accept);
    // A store can hold some corpora and not others, but one that holds none of the set is a
    // wrong path, which must not pass for a check.
    let (present, missing): (Vec<&PathBuf>, Vec<&PathBuf>) = binaries.iter().partition(|binary| binary.exists());
    if present.is_empty() {
        bail!("none of the {} binaries of the set is in {}", binaries.len(), crate::corpora().display());
    }
    println!("{:<46} {:>10} {:>8} {:>10} {:>8}", "binary", "analysis M", "change", "diff M", "change");
    for binary in present {
        let counted = std::process::Command::new(std::env::current_exe()?).arg("count").arg(binary).output()?;
        if !counted.status.success() {
            bail!("counting {}: {}", binary.display(), String::from_utf8_lossy(&counted.stderr).trim());
        }
        let now: Work = serde_json::from_slice(&counted.stdout).with_context(|| format!("counting {}", binary.display()))?;
        println!("{}", ratchet.hold(&crate::suites::name(binary), now));
    }
    let (budget, moved) = ratchet.finish()?;
    std::fs::write(path, serde_json::to_string_pretty(&budget)? + "\n").with_context(|| format!("writing {}", path.display()))?;
    println!("{moved} in {}", path.display());
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

#[cfg(test)]
mod tests {
    use super::*;

    const LIMIT: Work = Work { analysis: 1_000_000, diff: 1_000_000 };

    /// Holds one count of the binary `a`, whose budget is [`LIMIT`], and finishes.
    fn finish_with(analysis: u64, accept: bool) -> Result<(BTreeMap<String, Work>, String)> {
        let mut ratchet = Ratchet::new(BTreeMap::from([("a".to_string(), LIMIT)]), accept);
        ratchet.hold("a", Work { analysis, ..LIMIT });
        ratchet.finish()
    }

    #[test]
    fn a_count_that_grew_more_than_one_percent_fails_the_run_and_is_named() {
        let error = finish_with(1_010_100, false).unwrap_err().to_string();
        assert!(error.contains("a: analysis 1.0M -> 1.0M (+1.0%)"), "{error}");
    }

    #[test]
    fn accepting_a_count_that_grew_raises_its_budget_to_it() {
        let (budget, moved) = finish_with(1_010_100, true).unwrap();
        assert_eq!((budget["a"].analysis, moved.as_str()), (1_010_100, "1 raised, 0 lowered, 0 added"));
    }

    #[test]
    fn a_count_that_shrank_more_than_one_percent_lowers_its_budget() {
        let (budget, moved) = finish_with(989_900, false).unwrap();
        assert_eq!((budget["a"], moved.as_str()), (Work { analysis: 989_900, ..LIMIT }, "0 raised, 1 lowered, 0 added"));
    }

    #[test]
    fn a_count_within_one_percent_either_way_leaves_its_budget() {
        for analysis in [990_000, 1_000_000, 1_010_000] {
            let (budget, moved) = finish_with(analysis, false).unwrap();
            assert_eq!((budget["a"], moved.as_str()), (LIMIT, "0 raised, 0 lowered, 0 added"), "{analysis}");
        }
    }

    #[test]
    fn a_binary_new_to_the_budget_is_added_at_what_it_counted() {
        let mut ratchet = Ratchet::new(BTreeMap::new(), false);
        ratchet.hold("b", Work { analysis: 5, diff: 7 });
        let (budget, moved) = ratchet.finish().unwrap();
        assert_eq!((budget["b"], moved.as_str()), (Work { analysis: 5, diff: 7 }, "0 raised, 0 lowered, 1 added"));
    }
}
