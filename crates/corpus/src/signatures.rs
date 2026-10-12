//! Builds and evaluates the library-function fingerprint database from a corpus with names.
//!
//! A fingerprint goes into the database when binaries from at least two unrelated projects
//! contain a function with that fingerprint and all of them agree on its name. That selects
//! code that came from a shared library, such as a statically linked C runtime, and leaves
//! application code out.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;

use anyhow::Result;
use rayon::prelude::*;
use recore::signature::{Signatures, fingerprint, outline};

use crate::truth::Truth;

/// One named function seen in a binary: its fingerprint, name, and the project it came from.
struct Sample {
    project: String,
    hash: u64,
    outline: u32,
    name: String,
    /// The binary itself names the function, as an export, so nothing has to recognise it.
    carried: bool,
}

/// The project a corpus binary belongs to: the part of its file name before `__`. A binary
/// fetched from a distribution has the distribution there and its package next. The package
/// loses its version and what the distribution appends, so `deb__sqlite3__sqlite3` and
/// `sqlite__shell` are one project.
fn project_of(name: &str) -> &str {
    let mut parts = name.split("__");
    let first = parts.next().unwrap_or(name);
    if !matches!(first, "deb" | "brew") {
        return first;
    }
    let package = parts.next().unwrap_or(first);
    let package = package.split(['-', '@']).next().unwrap_or(package);
    package.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.')
}

/// The name a function is listed under: demangled, and without what GCC appends to a copy it
/// specialised, since the number in `.isra.0` or `.constprop.1` differs from build to build.
fn listed_name(symbol: &str) -> String {
    let name = recore::names::display_name(symbol);
    let clone = [".constprop.", ".isra.", ".part.", ".lto_priv.", ".localalias", ".cold"].iter().filter_map(|marker| name.find(marker)).min();
    let name = &name[..clone.unwrap_or(name.len())];
    // A link-time optimiser tells same-named local functions apart with a number of its own.
    match name.rsplit_once('.') {
        Some((plain, number)) if !number.is_empty() && number.bytes().all(|b| b.is_ascii_digit()) => plain.to_string(),
        _ => name.to_string(),
    }
}

/// Fingerprints every named function of every binary in the corpus.
fn samples(corpus: &Path) -> Result<Vec<Sample>> {
    let names: Vec<String> = std::fs::read_dir(corpus.join("truth"))?
        .filter_map(|e| Some(e.ok()?.path().file_stem()?.to_string_lossy().into_owned()))
        .collect();
    let per_binary: Vec<Vec<Sample>> = names
        .par_iter()
        .filter_map(|name| {
            let truth: Truth = serde_json::from_slice(&std::fs::read(corpus.join("truth").join(format!("{name}.json"))).ok()?).ok()?;
            let image = recore::Image::load(&corpus.join("bin").join(name)).ok()?;
            let analysis = recore::analyze(&image);
            let slots: recore::FxHashMap<u64, u64> = image.relative_targets.iter().copied().collect();
            let named: HashMap<u64, &str> = truth
                .functions
                .iter()
                .filter(|f| !f.fragment && !f.name.is_empty())
                .map(|f| (f.addr, f.name.as_str()))
                .collect();
            let found = analysis
                .functions
                .iter()
                .filter_map(|function| {
                    let name = named.get(&function.addr)?;
                    let &(start, end) = function.ranges.first()?;
                    let hash = fingerprint(&image, &slots, start, end)?;
                    let outline = outline(&image, start, end)?;
                    Some(Sample {
                        project: project_of(&truth.name).to_string(),
                        hash,
                        outline,
                        name: listed_name(name),
                        carried: image.symbol_names.contains_key(&function.addr),
                    })
                })
                .collect();
            Some(found)
        })
        .collect();
    Ok(per_binary.into_iter().flatten().collect())
}

/// Fingerprints that at least two projects share under a single name, with one of the samples
/// that has each.
fn database<'a>(samples: impl Iterator<Item = &'a Sample>) -> BTreeMap<u64, &'a Sample> {
    let mut seen: HashMap<u64, (&Sample, bool, BTreeSet<&str>)> = HashMap::new();
    for sample in samples {
        let (first, one_name, projects) = seen.entry(sample.hash).or_insert((sample, true, BTreeSet::new()));
        *one_name &= first.name == sample.name;
        projects.insert(&sample.project);
    }
    seen.into_iter().filter(|(_, (_, one_name, projects))| *one_name && projects.len() >= 2).map(|(hash, (sample, ..))| (hash, sample)).collect()
}

/// Writes the database built from the whole corpus as the table `recore` reads.
pub fn build(corpus: &Path, out: &Path) -> Result<()> {
    let samples = samples(corpus)?;
    let database = database(samples.iter());
    let entries: Vec<(u64, u32, &str)> = database.values().map(|sample| (sample.hash, sample.outline, sample.name.as_str())).collect();
    std::fs::write(out, Signatures::write(&entries))?;
    println!("{} fingerprints from {} named functions", database.len(), samples.len());
    Ok(())
}

/// For each project in turn, builds the database from the other projects and checks the names
/// it gives that project's functions against the project's own debug info. The last line counts
/// only what an analysis gains: functions the stripped binary does not name itself.
pub fn evaluate(corpus: &Path) -> Result<()> {
    let samples = samples(corpus)?;
    let projects: BTreeSet<&str> = samples.iter().map(|s| s.project.as_str()).collect();
    let (mut right, mut wrong, mut total) = (0, 0, 0);
    let (mut gained, mut gained_right) = (0, 0);
    for &project in &projects {
        let database = database(samples.iter().filter(|s| s.project != project));
        let own: Vec<&Sample> = samples.iter().filter(|s| s.project == project).collect();
        let named: Vec<&&Sample> = own.iter().filter(|s| database.contains_key(&s.hash)).collect();
        let correct = named.iter().filter(|s| database[&s.hash].name == s.name).count();
        println!(
            "{project:10} {:7} functions, {:5} named from other projects, {:5} right, {:3} wrong",
            own.len(),
            named.len(),
            correct,
            named.len() - correct
        );
        for sample in named.iter().filter(|s| database[&s.hash].name != s.name) {
            println!("    {} named {}", sample.name, database[&sample.hash].name);
        }
        right += correct;
        wrong += named.len() - correct;
        total += own.len();
        gained += named.iter().filter(|s| !s.carried).count();
        gained_right += named.iter().filter(|s| !s.carried && database[&s.hash].name == s.name).count();
    }
    println!("total      {total:7} functions, {:5} named, {right:5} right, {wrong:3} wrong", right + wrong);

    let mut projects_of: HashMap<u64, BTreeSet<&str>> = HashMap::new();
    for sample in &samples {
        projects_of.entry(sample.hash).or_default().insert(&sample.project);
    }
    let nameable: Vec<&Sample> = samples.iter().filter(|s| !s.carried).collect();
    let copied = nameable.iter().filter(|s| projects_of[&s.hash].len() >= 2).count();
    let percent = |part: usize, whole: usize| 100.0 * part as f64 / whole.max(1) as f64;
    println!(
        "unnamed    {:7} functions, {copied} ({:.1}%) with a copy in another project, {gained} ({:.1}%) named, {:.2}% of those right",
        nameable.len(),
        percent(copied, nameable.len()),
        percent(gained, nameable.len()),
        percent(gained_right, gained)
    );
    Ok(())
}
