//! Scores decompiled function signatures against the ones in each binary's PDB, or for an 8051
//! program built with SDCC in the linker's debug records.
//!
//! A decompiler's output is only as readable as the signatures it recovers: a wrong parameter
//! count shows up at every call site. The debug file records the source-level signature, so the
//! count and whether the function returns a value can be checked. The source and the machine code do
//! not always agree, since an optimizer may drop a parameter or return a struct through a hidden
//! pointer, so the scores are for comparing tools on the same functions, not absolute.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use anyhow::{Context, Result};
use object::Object;
use pdb2::{FallibleIterator, PrimitiveKind, SymbolData, TypeData, TypeFinder, TypeIndex};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

/// What the debug file says about one function.
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

/// How many parameters the function `name` is declared with in `source`, and whether they end
/// in `...`. `line`, counted from one, is the line the compiler gives as the function's first,
/// which has the name or follows it closely.
fn declared_parameters(source: &str, line: usize, name: &str) -> Option<(usize, bool)> {
    let lines: Vec<&str> = source.lines().collect();
    let word = |c: char| c.is_ascii_alphanumeric() || c == '_';
    // Where the parameter list of a declaration of `name` opens in a line.
    let opens = |text: &str| {
        text.match_indices(name).find_map(|(at, _)| {
            let after = text[at + name.len()..].trim_start();
            (!text[..at].ends_with(word) && after.starts_with('(')).then(|| text.len() - after.len() + 1)
        })
    };
    let (first, open) = (line.saturating_sub(8)..line).rev().find_map(|index| Some((index, opens(lines.get(index)?)?)))?;
    let mut text = lines[first][open..].to_string();
    for more in &lines[first + 1..] {
        text.push(' ');
        text.push_str(more);
    }
    let (mut depth, mut pieces, mut piece) = (0, Vec::new(), String::new());
    for c in text.chars() {
        match c {
            '(' | '[' => depth += 1,
            ')' | ']' if depth > 0 => depth -= 1,
            ')' => {
                pieces.push(piece);
                let pieces: Vec<&str> = pieces.iter().map(|piece| piece.trim()).collect();
                let variadic = pieces.last() == Some(&"...");
                let none = matches!(pieces[..], [""] | ["void"]);
                return Some((if none { 0 } else { pieces.len() - usize::from(variadic) }, variadic));
            }
            ',' if depth == 0 => {
                pieces.push(std::mem::take(&mut piece));
                continue;
            }
            _ => {}
        }
        piece.push(c);
    }
    None
}

/// Signatures of the C functions of an 8051 program, from SDCC's debug records, the listing of
/// its modules, and its sources.
///
/// `F:G$name$0_0$0({2}DF,SI:U),..` gives a function's type, `SV` for one that returns nothing,
/// and `L:G$name$0$0:ADDR` where it starts. The records do not say which of a function's
/// symbols are parameters, so those are counted in the source. The record of the source line
/// at the function's start, `L:C$file.c$107$1_0$72:ADDR`, has the line, and the listing, which
/// repeats that line after the path of its file, has where the file is. A function whose
/// source is not there, or does not declare it by name, is left out.
fn sdcc_signatures(cdb: &str, rst: &str) -> BTreeMap<u64, Signature> {
    let address = |text: &str| u64::from_str_radix(text, 16).ok();
    // By the symbol a function's records go under: whether it returns a value.
    let mut functions: HashMap<&str, bool> = HashMap::new();
    let mut starts: HashMap<&str, u64> = HashMap::new();
    // The file and line of the first source line at an address.
    let mut lines: HashMap<u64, (&str, &str)> = HashMap::new();
    for line in cdb.lines() {
        if let Some((symbol, kind)) = line.strip_prefix("F:").and_then(|record| record.split_once("$0_0$0(")) {
            functions.insert(symbol, kind.split_once("DF,").is_some_and(|(_, returned)| !returned.starts_with("SV")));
        } else if let Some(record) = line.strip_prefix("L:C$") {
            let mut fields = record.split('$');
            if let (Some(file), Some(number), Some(addr)) = (fields.next(), fields.next(), record.rsplit_once(':').and_then(|(_, addr)| address(addr))) {
                lines.entry(addr).or_insert((file, number));
            }
        } else if let Some((symbol, addr)) = line.strip_prefix("L:").and_then(|record| record.split_once("$0$0:")) {
            starts.extend(address(addr).map(|addr| (symbol, addr)));
        }
    }
    // The listing has `;<tab><path>:<line>: <text>` for each line of source that made code.
    let path_of = |file: &str, number: &str| {
        let line = format!("/{file}:{number}: ");
        rst.lines().find_map(|listed| Some(format!("{}/{file}", listed.split_once(&line)?.0.split_once(";\t")?.1)))
    };
    let mut sources: HashMap<String, Option<String>> = HashMap::new();
    let mut signatures = BTreeMap::new();
    for (symbol, returns_value) in functions {
        let Some((&addr, &(file, number))) = starts.get(symbol).and_then(|addr| lines.get_key_value(addr)) else { continue };
        let Some(path) = path_of(file, number) else { continue };
        let source = sources.entry(path).or_insert_with_key(|path| std::fs::read(path).ok().map(|bytes| String::from_utf8_lossy(&bytes).into_owned()));
        let name = symbol.rsplit_once('$').map_or(symbol, |(_, name)| name);
        let declared = source.as_deref().and_then(|source| declared_parameters(source, number.parse().ok()?, name));
        if let Some((params, variadic)) = declared {
            signatures.insert(addr, Signature { params, returns_value, variadic });
        }
    }
    signatures
}

/// Writes `<signatures>/<name>.json` for every binary whose PDB carries function types, or that
/// SDCC's debug records describe.
pub fn write_truth(corpus: &Path, signatures: &Path) -> Result<()> {
    let out = signatures;
    std::fs::create_dir_all(out)?;
    let binaries: Vec<_> = std::fs::read_dir(corpus.join("bin"))?.filter_map(|entry| Some(entry.ok()?.path())).collect();
    let written: usize = binaries
        .par_iter()
        .filter_map(|binary| {
            let name = crate::name_of(binary);
            let debug = |extension: &str| corpus.join("debug").join(format!("{name}.{extension}"));
            let signatures = if recore::layout::is_layout(binary) {
                Some(sdcc_signatures(&std::fs::read_to_string(debug("cdb")).ok()?, &std::fs::read_to_string(debug("rst")).ok()?))
            } else {
                extract(binary, &debug("pdb")).ok()
            };
            let signatures = signatures.filter(|found| !found.is_empty())?;
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
pub fn score(signatures: &Path, dirs: &[std::path::PathBuf]) -> Result<()> {
    let load = |dir: &Path, name: &str| -> Option<HashMap<u64, Record>> {
        let report: Report = serde_json::from_slice(&std::fs::read(dir.join(name)).ok()?).ok()?;
        Some(report.functions.into_iter().map(|record| (record.addr, record)).collect())
    };
    let mut names: Vec<String> = std::fs::read_dir(signatures)
        .context("no signatures; run `signatures` first")?
        .filter_map(|entry| Some(entry.ok()?.file_name().to_string_lossy().into_owned()))
        .filter(|name| dirs.iter().all(|dir| dir.join(name).exists()))
        .collect();
    names.sort();
    let mut all: Vec<Tally> = dirs.iter().map(|_| Tally::default()).collect();
    let mut shared: Vec<Tally> = dirs.iter().map(|_| Tally::default()).collect();
    for name in &names {
        let truth: Vec<(u64, Signature)> = serde_json::from_slice(&std::fs::read(signatures.join(name))?)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parameters_are_counted_where_the_function_is_declared() {
        let source = "static uint16_t\nupdate (uint16_t crc, void (*step)(int, int),\n        unsigned char table[2])\n{\n  return update(crc, 0, 0);\n}\n\
                      void init( void ) {\n}\nvoid log(const char *format, ...)\n{\n}\nint tick() { return 1; }\n";
        assert_eq!(declared_parameters(source, 2, "update"), Some((3, false)));
        // The compiler may count from the line of the brace.
        assert_eq!(declared_parameters(source, 4, "update"), Some((3, false)));
        assert_eq!(declared_parameters(source, 7, "init"), Some((0, false)));
        assert_eq!(declared_parameters(source, 9, "log"), Some((1, true)));
        assert_eq!(declared_parameters(source, 12, "tick"), Some((0, false)));
        assert_eq!(declared_parameters(source, 7, "missing"), None);
    }
}
