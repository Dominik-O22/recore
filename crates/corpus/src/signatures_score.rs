//! Scores decompiled function signatures against the ones in each binary's PDB.
//!
//! A decompiler's output is only as readable as the signatures it recovers: a wrong parameter
//! count shows up at every call site. The PDB records the source-level signature, so the count
//! and whether the function returns a value can be checked. The source and the machine code do
//! not always agree, since an optimizer may drop a parameter or return a struct through a hidden
//! pointer, so the scores are for comparing tools on the same functions, not absolute.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use anyhow::{Context, Result};
use object::Object;
use pdb2::{FallibleIterator, PrimitiveKind, SymbolData, TypeData, TypeFinder, TypeIndex};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

/// What the PDB says about one function.
#[derive(Serialize, Deserialize, Clone, Copy)]
pub struct Signature {
    /// Parameters as the machine code receives them: `this` counts.
    params: usize,
    returns_value: bool,
    variadic: bool,
}

/// One function in a decompiler's corpus report. Both `recore-decompile corpus` and
/// `ghidra/ExportSignatures.java` write these.
#[derive(Deserialize)]
struct Record {
    addr: u64,
    status: String,
    params: usize,
    returns_value: bool,
}

#[derive(Deserialize)]
struct Report {
    functions: Vec<Record>,
}

fn is_void(finder: &TypeFinder, index: TypeIndex) -> bool {
    matches!(finder.find(index).and_then(|item| item.parse()), Ok(TypeData::Primitive(primitive)) if primitive.kind == PrimitiveKind::Void && primitive.indirection.is_none())
}

/// The signature the type at `index` describes, if it is a function type.
fn signature(finder: &TypeFinder, index: TypeIndex) -> Option<Signature> {
    let (returns, arguments, has_this) = match finder.find(index).ok()?.parse().ok()? {
        TypeData::Procedure(procedure) => (procedure.return_type, procedure.argument_list, false),
        TypeData::MemberFunction(method) => (Some(method.return_type), method.argument_list, method.this_pointer_type.is_some()),
        _ => return None,
    };
    let TypeData::ArgumentList(list) = finder.find(arguments).ok()?.parse().ok()? else { return None };
    // A variable argument list ends in an argument of no type.
    let variadic = list.arguments.last().is_some_and(|last| last.0 == 0);
    Some(Signature {
        params: list.arguments.len() - usize::from(variadic) + usize::from(has_this),
        returns_value: returns.is_some_and(|index| !is_void(finder, index)),
        variadic,
    })
}

/// Signatures of the functions in `pdb_path`, by address in the image at `binary_path`.
fn extract(binary_path: &Path, pdb_path: &Path) -> Result<BTreeMap<u64, Signature>> {
    let data = std::fs::read(binary_path)?;
    let base = object::File::parse(&*data)?.relative_address_base();
    let mut pdb = pdb2::PDB::open(std::fs::File::open(pdb_path)?)?;
    let address_map = pdb.address_map()?;
    let types = pdb.type_information()?;
    let mut finder = types.finder();
    let mut walk = types.iter();
    while walk.next()?.is_some() {
        finder.update(&walk);
    }
    let mut signatures = BTreeMap::new();
    let debug_information = pdb.debug_information()?;
    let mut modules = debug_information.modules()?;
    while let Some(module) = modules.next()? {
        let Some(info) = pdb.module_info(&module)? else { continue };
        let mut symbols = info.symbols()?;
        while let Some(symbol) = symbols.next()? {
            let Ok(SymbolData::Procedure(procedure)) = symbol.parse() else { continue };
            let Some(rva) = procedure.offset.to_rva(&address_map) else { continue };
            if let Some(signature) = signature(&finder, procedure.type_index) {
                signatures.insert(base + u64::from(rva.0), signature);
            }
        }
    }
    Ok(signatures)
}

/// Writes `<corpus>/signatures/<name>.json` for every binary whose PDB carries function types.
pub fn write_truth(corpus: &Path) -> Result<()> {
    let out = corpus.join("signatures");
    std::fs::create_dir_all(&out)?;
    let binaries: Vec<_> = std::fs::read_dir(corpus.join("bin"))?.filter_map(|entry| Some(entry.ok()?.path())).collect();
    let written: usize = binaries
        .par_iter()
        .filter_map(|binary| {
            let name = binary.file_name()?.to_string_lossy().into_owned();
            let signatures = extract(binary, &corpus.join("debug").join(format!("{name}.pdb"))).ok().filter(|found| !found.is_empty())?;
            let list: Vec<(u64, Signature)> = signatures.into_iter().collect();
            std::fs::write(out.join(format!("{name}.json")), serde_json::to_vec(&list).ok()?).ok()?;
            Some(1)
        })
        .sum();
    println!("signatures for {written} of {} binaries", binaries.len());
    Ok(())
}

#[derive(Default)]
struct Tally {
    truth: usize,
    decompiled: usize,
    params_right: usize,
    returns_right: usize,
}

impl Tally {
    fn add(&mut self, signature: &Signature, record: Option<&Record>) {
        self.truth += 1;
        let Some(record) = record.filter(|record| record.status == "ok") else { return };
        self.decompiled += 1;
        self.params_right += usize::from(record.params == signature.params);
        self.returns_right += usize::from(record.returns_value == signature.returns_value);
    }

    fn print(&self, label: &str) {
        let percent = |part: usize, whole: usize| 100.0 * part as f64 / whole.max(1) as f64;
        println!(
            "{label:44} {:7} functions  decompiled {:5.1}%  params exact {:5.1}%  return kind {:5.1}%",
            self.truth,
            percent(self.decompiled, self.truth),
            percent(self.params_right, self.decompiled),
            percent(self.returns_right, self.decompiled),
        );
    }
}

/// Scores each directory of corpus reports, over the binaries every directory has a report for
/// and the non-variadic functions with a signature. With several directories, a second line per
/// directory covers only the functions all of them decompiled.
pub fn score(corpus: &Path, dirs: &[std::path::PathBuf]) -> Result<()> {
    let load = |dir: &Path, name: &str| -> Option<HashMap<u64, Record>> {
        let report: Report = serde_json::from_slice(&std::fs::read(dir.join(name)).ok()?).ok()?;
        Some(report.functions.into_iter().map(|record| (record.addr, record)).collect())
    };
    let mut names: Vec<String> = std::fs::read_dir(corpus.join("signatures"))
        .context("no signatures; run `signatures` first")?
        .filter_map(|entry| Some(entry.ok()?.file_name().to_string_lossy().into_owned()))
        .filter(|name| dirs.iter().all(|dir| dir.join(name).exists()))
        .collect();
    names.sort();
    let mut all: Vec<Tally> = dirs.iter().map(|_| Tally::default()).collect();
    let mut shared: Vec<Tally> = dirs.iter().map(|_| Tally::default()).collect();
    for name in &names {
        let truth: Vec<(u64, Signature)> = serde_json::from_slice(&std::fs::read(corpus.join("signatures").join(name))?)?;
        let reports: Vec<HashMap<u64, Record>> = dirs.iter().filter_map(|dir| load(dir, name)).collect();
        if reports.len() != dirs.len() {
            continue;
        }
        for (addr, signature) in truth.iter().filter(|(_, signature)| !signature.variadic) {
            let records: Vec<Option<&Record>> = reports.iter().map(|report| report.get(addr)).collect();
            let everyone = records.iter().all(|record| record.is_some_and(|record| record.status == "ok"));
            for (index, record) in records.iter().enumerate() {
                all[index].add(signature, *record);
                if everyone {
                    shared[index].add(signature, *record);
                }
            }
        }
    }
    println!("{} binaries", names.len());
    for (index, dir) in dirs.iter().enumerate() {
        all[index].print(&dir.display().to_string());
        if dirs.len() > 1 {
            shared[index].print("  on functions every tool decompiled");
        }
    }
    Ok(())
}
