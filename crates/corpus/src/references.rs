//! Compares the data references recore finds with Ghidra's.
//!
//! Ghidra's references are not ground truth, but they are what an analyst is used to finding,
//! and nothing in a binary records the true set. Two tools rarely attach a reference to the
//! same instruction: one marks the instruction that forms an address, the other every later
//! one that uses it. So a reference counts as found when recore has one to the same address
//! from anywhere in the same function.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{Context, Result};
use recore::Image;
use recore::program::Program;
use recore::report::CallTarget;

/// What a reference points at.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum Kind {
    /// Bytes of a data section.
    Data,
    /// Uninitialized globals.
    ZeroFilled,
    /// Code: a function pointer, or a table among the code.
    Code,
    /// Outside the image as recore maps it: Ghidra's made-up addresses for imported symbols.
    Elsewhere,
}

#[derive(Default, Clone, Copy)]
struct Tally {
    ghidra: usize,
    found: usize,
}

/// Scores every binary of `corpus` that has `ghidra-refs/<name>.refs`, as `ghidra/run-refs.sh`
/// writes them. With `misses`, each reference recore lacks is printed too.
pub fn score(corpus: &Path, misses: bool) -> Result<()> {
    let dir = corpus.join("ghidra-refs");
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .with_context(|| format!("no {}; run ghidra/run-refs.sh first", dir.display()))?
        .filter_map(|entry| Some(entry.ok()?.file_name().to_string_lossy().strip_suffix(".refs")?.to_string()))
        .collect();
    names.sort();
    let mut total: BTreeMap<Kind, Tally> = BTreeMap::new();
    for name in &names {
        let program = Program::load(&corpus.join("bin").join(name))?;
        let tallies = score_one(&program, &std::fs::read_to_string(dir.join(format!("{name}.refs")))?, misses.then_some(name.as_str()));
        for (kind, tally) in &tallies {
            let sum = total.entry(*kind).or_default();
            sum.ghidra += tally.ghidra;
            sum.found += tally.found;
        }
        print(name, &tallies);
    }
    print(&format!("{} ({} binaries)", corpus.display(), names.len()), &total);
    Ok(())
}

fn kind(image: &Image, addr: u64) -> Kind {
    match image.section_at(addr) {
        Some(section) if section.executable => Kind::Code,
        Some(_) => Kind::Data,
        None if image.is_zero_filled(addr) => Kind::ZeroFilled,
        None => Kind::Elsewhere,
    }
}

/// Tallies Ghidra's references by whether recore has them. Under `misses`, a binary's name,
/// those it lacks are printed with one of the instructions Ghidra puts them on.
fn score_one(program: &Program, ghidra: &str, misses: Option<&str>) -> BTreeMap<Kind, Tally> {
    let owner = |site: u64| program.owners(site).first().copied();
    // `(function, address referred to)`, for recore's references and the targets of its calls.
    let mut ours: BTreeSet<(u64, u64)> = program.analysis.data_refs.iter().filter_map(|reference| Some((owner(reference.from)?, reference.to))).collect();
    ours.extend(program.analysis.calls.iter().filter_map(|call| {
        let (CallTarget::Function(target) | CallTarget::Import(target)) = call.target;
        Some((owner(call.at)?, target))
    }));
    // `(function, address referred to)` to the first instruction Ghidra has the reference on.
    let mut theirs: BTreeMap<(u64, u64), u64> = BTreeMap::new();
    for line in ghidra.lines() {
        let mut fields = line.split(' ');
        let Some((from, to)) = fields.next().and_then(|from| Some((from.parse().ok()?, fields.next()?.parse().ok()?))) else { continue };
        // An instruction recore puts in no function cannot be matched by function.
        if let Some(function) = owner(from) {
            theirs.entry((function, to)).or_insert(from);
        }
    }
    let mut tallies: BTreeMap<Kind, Tally> = BTreeMap::new();
    for (pair, from) in &theirs {
        let kind = kind(&program.image, pair.1);
        let tally = tallies.entry(kind).or_default();
        tally.ghidra += 1;
        tally.found += usize::from(ours.contains(pair));
        if let Some(name) = misses.filter(|_| !ours.contains(pair)) {
            // How far past the nearest address recore does refer to from this function: a small
            // distance is a later element or field of an object recore has the start of.
            let before = ours.range((pair.0, 0)..*pair).next_back().map_or_else(|| "-".to_string(), |near| (pair.1 - near.1).to_string());
            println!("{name} {from:#x} {:#x} {kind:?} {before}", pair.1);
        }
    }
    tallies
}

fn print(label: &str, tallies: &BTreeMap<Kind, Tally>) {
    let cell = |kind: Kind| {
        let tally = tallies.get(&kind).copied().unwrap_or_default();
        format!("{:6}/{:<6} {:5.1}%", tally.found, tally.ghidra, 100.0 * tally.found as f64 / tally.ghidra.max(1) as f64)
    };
    // Imported symbols have no address of their own, so those references are left out of the sum.
    let real = [Kind::Data, Kind::ZeroFilled, Kind::Code];
    let (found, all) = real.iter().filter_map(|kind| tallies.get(kind)).fold((0, 0), |(found, all), tally| (found + tally.found, all + tally.ghidra));
    println!(
        "{label:40} data {}  uninitialized {}  code {}  all {:5.1}%  (to imported symbols: {})",
        cell(Kind::Data),
        cell(Kind::ZeroFilled),
        cell(Kind::Code),
        100.0 * found as f64 / all.max(1) as f64,
        tallies.get(&Kind::Elsewhere).map_or(0, |tally| tally.ghidra),
    );
}
