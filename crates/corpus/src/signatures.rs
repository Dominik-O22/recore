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
use recore::signature::fingerprint;

use crate::truth::Truth;

/// One named function seen in a binary: its fingerprint, name, and the project it came from.
struct Sample {
    project: String,
    hash: u64,
    name: String,
}

/// The project a corpus binary belongs to: the part of its file name before `__`.
fn project_of(name: &str) -> &str {
    name.split("__").next().unwrap_or(name)
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
                    Some(Sample { project: project_of(&truth.name).to_string(), hash, name: name.to_string() })
                })
                .collect();
            Some(found)
        })
        .collect();
    Ok(per_binary.into_iter().flatten().collect())
}

/// Fingerprints that at least two projects share under a single name.
fn database<'a>(samples: impl Iterator<Item = &'a Sample>) -> BTreeMap<u64, &'a str> {
    let mut seen: HashMap<u64, (BTreeSet<&str>, BTreeSet<&str>)> = HashMap::new();
    for sample in samples {
        let (names, projects) = seen.entry(sample.hash).or_default();
        names.insert(&sample.name);
        projects.insert(&sample.project);
    }
    seen.into_iter()
        .filter(|(_, (names, projects))| names.len() == 1 && projects.len() >= 2)
        .map(|(hash, (names, _))| (hash, *names.first().unwrap()))
        .collect()
}

/// Writes the database built from the whole corpus, one `hash name` pair per line.
pub fn build(corpus: &Path, out: &Path) -> Result<()> {
    let samples = samples(corpus)?;
    let database = database(samples.iter());
    let text: String = database.iter().map(|(hash, name)| format!("{hash:016x} {name}\n")).collect();
    std::fs::write(out, text)?;
    println!("{} fingerprints from {} named functions", database.len(), samples.len());
    Ok(())
}

/// For each project in turn, builds the database from the other projects and checks the names
/// it gives that project's functions against the project's own debug info.
pub fn evaluate(corpus: &Path) -> Result<()> {
    let samples = samples(corpus)?;
    let projects: BTreeSet<&str> = samples.iter().map(|s| s.project.as_str()).collect();
    let (mut right, mut wrong, mut total) = (0, 0, 0);
    for &project in &projects {
        let database = database(samples.iter().filter(|s| s.project != project));
        let own: Vec<&Sample> = samples.iter().filter(|s| s.project == project).collect();
        let named: Vec<&&Sample> = own.iter().filter(|s| database.contains_key(&s.hash)).collect();
        let correct = named.iter().filter(|s| database[&s.hash] == s.name).count();
        println!(
            "{project:10} {:7} functions, {:5} named from other projects, {:5} right, {:3} wrong",
            own.len(),
            named.len(),
            correct,
            named.len() - correct
        );
        for sample in named.iter().filter(|s| database[&s.hash] != s.name) {
            println!("    {} named {}", sample.name, database[&sample.hash]);
        }
        right += correct;
        wrong += named.len() - correct;
        total += own.len();
    }
    println!("total      {total:7} functions, {:5} named, {right:5} right, {wrong:3} wrong", right + wrong);
    Ok(())
}
