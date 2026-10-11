//! Scores an analyzer's output against ground truth.
//!
//! Every analyzer, Ghidra included, is reduced to the same JSON shape (`Analysis`), so the same
//! scoring applies to all of them. Scoring is limited to `.text`.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::ops::AddAssign;

pub use recore::report::Analysis;

use crate::jumptables::JumpTables;
use crate::truth::Truth;

#[derive(Default, Debug, Clone, Copy)]
pub struct Score {
    /// True function starts.
    pub truth_functions: u64,
    /// Starts found that are true.
    pub found: u64,
    /// Starts reported inside a true function but not at its entry.
    pub mid_function: u64,
    /// Starts reported inside a compiler-split cold fragment, typically exception landing pads.
    /// Counted separately and left out of precision: a fragment has no agreed owner.
    pub in_fragment: u64,
    /// Starts reported outside every true function (padding, unlabelled code).
    pub outside: u64,
    /// Reported functions whose body swallows another true function's entry.
    pub run_on: u64,
    pub truth_noreturn_calls: u64,
    pub found_noreturn_calls: u64,
    /// Calls marked non-returning that truth does not list.
    pub extra_noreturn_calls: u64,
    /// The subset of those whose callee ends some function, which corroborates them.
    pub extra_noreturn_at_end: u64,
    pub truth_bytes: u64,
    /// True function bytes covered by any reported function body.
    pub covered_bytes: u64,
    /// Jump tables in truth. Zero for binaries without jump-table truth.
    pub truth_tables: u64,
    /// Tables resolved to exactly the true target set.
    pub exact_tables: u64,
    /// Tables resolved with at least one true target missing.
    pub tables_missing_targets: u64,
    /// Tables resolved with at least one target that is not true. A table can also be missing some.
    pub tables_extra_targets: u64,
    /// Tables the analyzer reported no targets for.
    pub unresolved_tables: u64,
}

impl AddAssign for Score {
    fn add_assign(&mut self, o: Self) {
        self.truth_functions += o.truth_functions;
        self.found += o.found;
        self.mid_function += o.mid_function;
        self.in_fragment += o.in_fragment;
        self.outside += o.outside;
        self.run_on += o.run_on;
        self.truth_noreturn_calls += o.truth_noreturn_calls;
        self.found_noreturn_calls += o.found_noreturn_calls;
        self.extra_noreturn_calls += o.extra_noreturn_calls;
        self.extra_noreturn_at_end += o.extra_noreturn_at_end;
        self.truth_bytes += o.truth_bytes;
        self.covered_bytes += o.covered_bytes;
        self.truth_tables += o.truth_tables;
        self.exact_tables += o.exact_tables;
        self.tables_missing_targets += o.tables_missing_targets;
        self.tables_extra_targets += o.tables_extra_targets;
        self.unresolved_tables += o.unresolved_tables;
    }
}

fn ratio(a: u64, b: u64) -> f64 {
    if b == 0 { 1.0 } else { a as f64 / b as f64 }
}

impl Score {
    pub fn recall(&self) -> f64 {
        ratio(self.found, self.truth_functions)
    }
    pub fn precision(&self) -> f64 {
        ratio(self.found, self.found + self.mid_function + self.outside)
    }
    pub fn f1(&self) -> f64 {
        let (p, r) = (self.precision(), self.recall());
        if p + r == 0.0 { 0.0 } else { 2.0 * p * r / (p + r) }
    }
    pub fn noreturn_recall(&self) -> f64 {
        ratio(self.found_noreturn_calls, self.truth_noreturn_calls)
    }
    pub fn coverage(&self) -> f64 {
        ratio(self.covered_bytes, self.truth_bytes)
    }
}

/// Total length of the intersection of two sorted, non-overlapping range lists.
fn intersection_len(a: &[(u64, u64)], b: &[(u64, u64)]) -> u64 {
    let (mut i, mut j, mut total) = (0, 0, 0);
    while i < a.len() && j < b.len() {
        let start = a[i].0.max(b[j].0);
        let end = a[i].1.min(b[j].1);
        if start < end {
            total += end - start;
        }
        if a[i].1 < b[j].1 { i += 1 } else { j += 1 }
    }
    total
}

/// Sorts and merges ranges so they are disjoint.
fn normalize(mut ranges: Vec<(u64, u64)>) -> Vec<(u64, u64)> {
    ranges.sort_unstable();
    let mut merged: Vec<(u64, u64)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        match merged.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => merged.push((start, end)),
        }
    }
    merged
}

/// Scores `analysis` against `truth`, and against `jump_tables` for binaries that have that truth.
pub fn score(truth: &Truth, jump_tables: Option<&JumpTables>, analysis: &Analysis) -> Score {
    let (text_start, text_end) = truth.text;
    let in_text = |addr: u64| addr >= text_start && addr < text_end;

    let truth_starts: BTreeSet<u64> = truth.functions.iter().filter(|f| !f.fragment && in_text(f.addr)).map(|f| f.addr).collect();
    let fragments: HashSet<u64> = truth.functions.iter().filter(|f| f.fragment).map(|f| f.addr).collect();
    let truth_ranges = normalize(truth.functions.iter().filter(|f| in_text(f.addr)).map(|f| (f.addr, f.addr + f.size)).collect());
    let fragment_ranges = normalize(truth.functions.iter().filter(|f| f.fragment).map(|f| (f.addr, f.addr + f.size)).collect());
    let inside = |ranges: &[(u64, u64)], addr: u64| {
        let index = ranges.partition_point(|&(start, _)| start <= addr);
        index > 0 && addr < ranges[index - 1].1
    };
    let inside_truth = |addr: u64| inside(&truth_ranges, addr);

    let mut s = Score { truth_functions: truth_starts.len() as u64, ..Score::default() };
    let mut reported: HashSet<u64> = HashSet::new();
    for function in &analysis.functions {
        if !in_text(function.addr) || fragments.contains(&function.addr) || !reported.insert(function.addr) {
            continue;
        }
        if truth_starts.contains(&function.addr) {
            s.found += 1;
        } else if inside(&fragment_ranges, function.addr) {
            s.in_fragment += 1;
        } else if inside_truth(function.addr) {
            s.mid_function += 1;
        } else {
            s.outside += 1;
        }
        let swallows = function
            .ranges
            .iter()
            .any(|&(start, end)| truth_starts.range(start..end).any(|&entry| entry != function.addr));
        if swallows {
            s.run_on += 1;
        }
    }

    let truth_calls: HashSet<u64> = truth.noreturn_calls.iter().copied().collect();
    let terminal_calls: HashSet<u64> = truth.terminal_calls.iter().copied().collect();
    s.truth_noreturn_calls = truth_calls.len() as u64;
    for call in analysis.noreturn_calls.iter().filter(|&&addr| in_text(addr)).collect::<HashSet<_>>() {
        if truth_calls.contains(call) {
            s.found_noreturn_calls += 1;
        } else if inside_truth(*call) {
            s.extra_noreturn_calls += 1;
            if terminal_calls.contains(call) {
                s.extra_noreturn_at_end += 1;
            }
        }
    }

    let bodies = normalize(analysis.functions.iter().flat_map(|f| f.ranges.iter().copied()).collect());
    s.truth_bytes = truth_ranges.iter().map(|&(start, end)| end - start).sum();
    s.covered_bytes = intersection_len(&truth_ranges, &bodies);

    let resolved: HashMap<u64, HashSet<u64>> =
        analysis.jump_tables.iter().map(|table| (table.jump, table.targets.iter().copied().collect())).collect();
    for table in jump_tables.iter().flat_map(|truth| &truth.tables) {
        s.truth_tables += 1;
        let Some(found) = resolved.get(&table.jump).filter(|found| !found.is_empty()) else {
            s.unresolved_tables += 1;
            continue;
        };
        let missing = table.targets.iter().any(|target| !found.contains(target));
        let extra = found.iter().any(|target| table.targets.binary_search(target).is_err() && table.unreachable != Some(*target));
        s.exact_tables += u64::from(!missing && !extra);
        s.tables_missing_targets += u64::from(missing);
        s.tables_extra_targets += u64::from(extra);
    }
    s
}
