//! Scores the structs recovered for pointer parameters against DWARF.
//!
//! Each binary is decompiled stripped, in a worker set up as an agent's session is: no debug
//! information, no edits, callees first. For each struct the decompiler puts on a parameter,
//! the function's DWARF definition says which parameter arrives in that register or stack
//! slot and what its type is. The struct is then checked against the type it points to: is the
//! parameter a pointer, to what, do the fields start where members start and are they as wide,
//! is the struct no larger, and the same again for the structs its fields point to. Coverage
//! goes the other way: of the parameters DWARF says point to a struct and that the function
//! reads through, how many got one, and why the others did not.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::{Context, Result};
use recore::image::Machine;
use recore::structs::{FieldType, Layout, Slot};
use recore_decomp::dwarf::{self, Entry, Located};
use recore_decomp::isolate::{Options, Status, Worker};
use recore_decomp::types::{Base, Type, TypeId, Types};
use serde_json::json;

pub struct Config {
    pub corpora: Vec<PathBuf>,
    /// Where the corpora's packages are unpacked, `<corpus>/pkgs/*/x/<package>`: the
    /// supplementary debug files of Debian's packages are there.
    pub roots: Vec<PathBuf>,
    /// Binaries the policy was tuned on, as `<corpus>/bin/<name>` lines.
    pub tuning: HashSet<String>,
    pub sample: usize,
    pub jobs: usize,
    pub timeout: Duration,
    /// One JSON line per scored struct and per covered parameter, for reading the cases.
    pub cases: Option<PathBuf>,
}

/// Counts by metric, under keys that sort into the order the report prints them in.
type Tally = BTreeMap<String, u64>;

fn count(tally: &mut Tally, key: impl Into<String>) {
    *tally.entry(key.into()).or_default() += 1;
}

/// A binary's place in the tuning set, as `bench/set.txt` lists it: its corpus directory's
/// name, `bin` and its file name.
fn listed_as(path: &Path) -> String {
    let parts: Vec<_> = path.iter().rev().take(3).map(|part| part.to_string_lossy().into_owned()).collect();
    parts.into_iter().rev().collect::<Vec<_>>().join("/")
}

pub fn score(config: &Config) -> Result<()> {
    let mut binaries = Vec::new();
    for corpus in &config.corpora {
        let mut paths: Vec<PathBuf> = std::fs::read_dir(corpus.join("bin"))?.map(|entry| Ok(entry?.path())).collect::<Result<_>>()?;
        paths.sort();
        for path in paths {
            let debug = corpus.join("debug").join(format!("{}.debug", path.file_name().unwrap().to_string_lossy()));
            if debug.is_file() {
                binaries.push((path, debug));
            }
        }
    }
    // An empty edits directory: the census decompiles without the user's edits.
    let edits = std::env::temp_dir().join(format!("recore-struct-truth-{}", std::process::id()));
    std::fs::create_dir_all(&edits)?;
    let cases = match &config.cases {
        Some(path) => Some(Mutex::new(std::io::BufWriter::new(std::fs::File::create(path)?))),
        None => None,
    };
    let totals: Mutex<BTreeMap<(String, String), (usize, Tally)>> = Mutex::new(BTreeMap::new());
    let next = AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for _ in 0..config.jobs.clamp(1, binaries.len().max(1)) {
            scope.spawn(|| {
                while let Some((path, debug)) = binaries.get(next.fetch_add(1, Ordering::Relaxed)) {
                    let set = if config.tuning.contains(&listed_as(path)) { "tuning" } else { "held out" };
                    let mut lines = Vec::new();
                    match score_binary(config, path, debug, &edits, &mut lines) {
                        Ok((arch, tally)) => {
                            eprintln!("{}: {} roots, {} fields", path.display(), tally.get("2 root: on a parameter").unwrap_or(&0), tally.get("5 root field: scored").unwrap_or(&0));
                            let mut totals = totals.lock().unwrap();
                            let (binaries, total) = totals.entry((set.to_string(), arch)).or_default();
                            *binaries += 1;
                            for (key, value) in tally {
                                *total.entry(key).or_default() += value;
                            }
                        }
                        Err(error) => eprintln!("{}: skipped: {error:#}", path.display()),
                    }
                    if let Some(cases) = &cases {
                        let mut cases = cases.lock().unwrap();
                        for line in lines {
                            let _ = writeln!(cases, "{line}");
                        }
                    }
                }
            });
        }
    });
    let _ = std::fs::remove_dir_all(&edits);
    if let Some(cases) = cases {
        cases.into_inner().unwrap().flush()?;
    }
    print(&totals.into_inner().unwrap());
    Ok(())
}

/// The headline shares, each as a numerator and a denominator over a tally's keys.
fn headlines(tally: &Tally) -> Vec<(&'static str, u64, u64)> {
    let sum = |keep: &dyn Fn(&str) -> bool| tally.iter().filter(|(key, _)| keep(key)).map(|(_, value)| value).sum::<u64>();
    let root = |what: &str| sum(&|key: &str| key == format!("3 root DWARF: {what}"));
    let matched = sum(&|key: &str| key.starts_with("3 root DWARF slot: "));
    let no_pointer = sum(&|key: &str| key.starts_with("3 root DWARF: no pointer"));
    let field = |level: &str, keep: &dyn Fn(&str) -> bool| sum(&|key: &str| key.strip_prefix(&format!("5 {level} field start: ")).is_some_and(keep));
    let nested = |keep: &dyn Fn(&str) -> bool| sum(&|key: &str| key.strip_prefix("7 nested struct: ").is_some_and(keep));
    let refused = sum(&|key: &str| key.starts_with("8 coverage: refused"));
    vec![
        ("roots with their DWARF parameter found", matched, sum(&|key: &str| key == "2 root: on a parameter")),
        ("1 the parameter is a pointer", matched - no_pointer, matched),
        ("2 to a struct or union", root("struct") + root("union"), matched),
        ("2 to void or a struct only declared: not checkable", root("void") + root("declared only"), matched),
        ("2 to a number, char, pointer or array: false", root("number") + root("char") + root("pointer") + root("array"), matched),
        ("3 root fields at a member's start", field("root", &|start| start == "at a member's start"), field("root", &|_| true)),
        ("3 ... or at a member of a later element", field("root", &|start| start.starts_with("at a member") || start.ends_with("of a later element")), field("root", &|_| true)),
        ("4 root structs no larger than the true one", sum(&|key: &str| key == "4 root size: fits" || key == "4 root size: larger, true one ends in an open array"), sum(&|key: &str| key.starts_with("4 root size: "))),
        ("5 root fields as wide as the member", sum(&|key: &str| key == "6 root field width: same"), field("root", &|start| start == "at a member's start")),
        ("6 nested links to a pointer to a struct or union", nested(&|kind| kind == "struct" || kind == "union"), nested(&|_| true)),
        ("6 nested fields at a member's start", sum(&|key: &str| key.starts_with("5 nested") && key.ends_with("field start: at a member's start")), sum(&|key: &str| key.starts_with("5 nested") && key.contains(" field start: "))),
        ("7 coverage: struct pointers read through that got a struct", sum(&|key: &str| key == "8 coverage: got a struct"), sum(&|key: &str| key == "8 coverage: got a struct") + refused),
    ]
}

/// Every key of every group, one row each, with a column per set and architecture and one per
/// set, then the headline shares in the same columns.
fn print(totals: &BTreeMap<(String, String), (usize, Tally)>) {
    let mut columns: Vec<(String, usize, Tally)> = totals.iter().map(|((set, arch), (binaries, tally))| (format!("{set} {arch}"), *binaries, tally.clone())).collect();
    for set in ["tuning", "held out"] {
        let mut all = Tally::new();
        let mut binaries = 0;
        for (_, (count, tally)) in totals.iter().filter(|((group, _), _)| group == set) {
            binaries += count;
            for (key, value) in tally {
                *all.entry(key.clone()).or_default() += value;
            }
        }
        columns.push((format!("{set} all"), binaries, all));
    }
    let keys: std::collections::BTreeSet<&String> = columns.iter().flat_map(|(_, _, tally)| tally.keys()).collect();
    print!("{:<72}", "");
    columns.iter().for_each(|(label, _, _)| print!(" {label:>20}"));
    println!();
    print!("{:<72}", "binaries");
    columns.iter().for_each(|(_, binaries, _)| print!(" {binaries:>20}"));
    println!();
    for key in keys {
        print!("{key:<72}");
        columns.iter().for_each(|(_, _, tally)| print!(" {:>20}", tally.get(key).copied().unwrap_or(0)));
        println!();
    }
    println!();
    let shares: Vec<Vec<(&str, u64, u64)>> = columns.iter().map(|(_, _, tally)| headlines(tally)).collect();
    for row in 0..shares.first().map_or(0, Vec::len) {
        print!("{:<72}", shares[0][row].0);
        for column in &shares {
            let (_, part, whole) = column[row];
            print!(" {:>20}", format!("{:.1}% of {whole}", 100.0 * part as f64 / whole.max(1) as f64));
        }
        println!();
    }
}

/// The engine's name for the register of DWARF number `number`, as slots spell it.
fn register(machine: Machine, number: u16) -> Option<String> {
    const X86_64: [&str; 17] = ["RAX", "RDX", "RCX", "RBX", "RSI", "RDI", "RBP", "RSP", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15", "RIP"];
    match machine {
        Machine::X86_64 => X86_64.get(usize::from(number)).map(|name| name.to_string()),
        Machine::Aarch64 if number <= 30 => Some(format!("x{number}")),
        _ => None,
    }
}

/// Where the decompiler sees a parameter DWARF locates at `entry`, and whether the source
/// passes it by value and the machine by pointer.
fn slot(machine: Machine, entry: Entry) -> Option<(Slot, bool)> {
    match entry {
        Entry::Register(number) => Some((Slot::Register(register(machine, number)?), false)),
        Entry::Address(number) => Some((Slot::Register(register(machine, number)?), true)),
        // The canonical frame address is the stack pointer before the call: on x86-64 the return
        // address lies between it and the stack pointer on entry, which slots count from.
        Entry::Frame(offset) if offset >= 0 => {
            let below = if machine == Machine::X86_64 { 8 } else { 0 };
            Some((Slot::Stack(offset as u64 + below), false))
        }
        Entry::Frame(_) => None,
    }
}

/// A slot as a worker's record spells a parameter's storage: a register, or `stack:0x8`.
fn storage_slot(storage: &str) -> Slot {
    match storage.strip_prefix("stack:0x").and_then(|hex| u64::from_str_radix(hex, 16).ok()) {
        Some(offset) => Slot::Stack(offset),
        None => Slot::Register(storage.to_string()),
    }
}

/// The type each parameter has in the C, by position: the text before its name, without the
/// `*` that goes with the name. The parameters are the last parenthesis of the signature, which
/// ends before the line that opens the body; a name may hold parentheses of its own, as
/// `(anonymous namespace)` does.
fn signature_types(c_text: &str) -> Vec<String> {
    let lines: Vec<&str> = c_text.lines().collect();
    let Some(body) = lines.iter().position(|line| *line == "{") else { return Vec::new() };
    let last = lines[..body].iter().rposition(|line| !line.trim().is_empty()).map_or(0, |at| at + 1);
    let first = lines[..last].iter().rposition(|line| line.is_empty() || line.starts_with("/*") || line.starts_with("//")).map_or(0, |at| at + 1);
    let signature = lines[first..last].join(" ");
    let Some(close) = signature.rfind(')') else { return Vec::new() };
    let mut depth = 0;
    let Some(open) = signature[..close].char_indices().rev().find_map(|(at, c)| {
        depth += match c {
            ')' => 1,
            '(' => -1,
            _ => 0,
        };
        (depth < 0).then_some(at)
    }) else {
        return Vec::new();
    };
    signature[open + 1..close].split(',').map(|param| param.trim().rsplit_once(' ').map_or(param.trim(), |(kind, _)| kind.trim()).to_string()).collect()
}

/// The type behind typedefs.
fn underlying(types: &Types, mut id: TypeId) -> TypeId {
    for _ in 0..32 {
        match types.get(id) {
            Type::Typedef { target, .. } => id = *target,
            _ => return types.resolve(id),
        }
    }
    id
}

/// A short C-like spelling of a type, for the cases file.
fn spell(types: &Types, id: TypeId, depth: u32) -> String {
    match types.get(id) {
        _ if depth == 0 => "..".into(),
        Type::Void => "void".into(),
        Type::Base { base, size } => format!("{base:?}{size}"),
        Type::Pointer(target) => format!("{} *", spell(types, *target, depth - 1)),
        Type::Array { element, count } => format!("{}[{count}]", spell(types, *element, depth - 1)),
        Type::Composite { name, union, size, .. } => format!("{} {name} ({size:#x} bytes)", if *union { "union" } else { "struct" }),
        Type::Enum { name, .. } => format!("enum {name}"),
        Type::Typedef { name, .. } => name.clone(),
        Type::Function(_) => "code".into(),
        Type::Alias(_) => "alias".into(),
    }
}

/// How the scorer knows which parameter arrives in a slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum How {
    /// Its DWARF location says so.
    Located,
    /// Its place among the parameters says so, by the calling convention, which the
    /// parameters that are located agree with.
    Position,
    /// The function returns a struct in memory the caller passes a pointer to.
    Result,
}

/// What DWARF says arrives in one slot: a parameter's name and type, what it points to if the
/// machine passes a pointer, and how that was found.
struct Arrives<'a> {
    /// Its place among the definition's parameters; none for the pointer to the result.
    index: Option<usize>,
    name: &'a str,
    kind: TypeId,
    pointee: Option<TypeId>,
    /// The type is a struct or union of a pointer's size that holds a pointer at its start,
    /// as Rust's `Option<&T>` and C++'s iterators do, and `pointee` is what that points to.
    wrapped: bool,
    how: How,
}

/// The registers integers and pointers are passed in, in order.
fn argument_registers(machine: Machine) -> Vec<String> {
    match machine {
        Machine::X86_64 => ["RDI", "RSI", "RDX", "RCX", "R8", "R9"].map(String::from).to_vec(),
        Machine::Aarch64 => (0..8).map(|number| format!("x{number}")).collect(),
        _ => Vec::new(),
    }
}

/// Which parameter of the function `defined` arrives in which slot. Those DWARF locates, then
/// those it does not by their place among the integer registers if every located one is where
/// its place says, then the pointer to a returned struct. `by_reference` says the function
/// returns a class C++ hands back through memory whatever its size.
fn arrivals<'a>(types: &Types, machine: Machine, defined: &'a dwarf::Defined, by_reference: bool) -> HashMap<Slot, Arrives<'a>> {
    let pointee = |kind: TypeId, by_pointer: bool| match types.get(underlying(types, kind)) {
        _ if by_pointer => (Some(kind), false),
        Type::Pointer(target) => (Some(*target), false),
        Type::Composite { size, .. } if *size == types.pointer => {
            let mut found = Vec::new();
            leaves(types, kind, 0, 0, &mut found, 16);
            let inner = found.iter().find_map(|leaf| match types.get(underlying(types, leaf.kind)) {
                Type::Pointer(target) if leaf.start == 0 => Some(*target),
                _ => None,
            });
            (inner, inner.is_some())
        }
        _ => (None, false),
    };
    let mut at = HashMap::new();
    for (index, param) in defined.params.iter().enumerate() {
        if let Some((slot, by_pointer)) = param.entry.and_then(|entry| slot(machine, entry)) {
            at.insert(slot, Arrives { index: Some(index), name: &param.name, kind: param.kind, pointee: pointee(param.kind, by_pointer).0, wrapped: pointee(param.kind, by_pointer).1, how: How::Located });
        }
    }
    let returned = underlying(types, defined.returns);
    let in_memory = matches!(types.get(returned), Type::Composite { .. }) && (by_reference || types.size(returned) > 16);
    let registers = argument_registers(machine);
    // x86-64 passes where the result goes before the parameters, AArch64 in a register of its own.
    let mut next = usize::from(in_memory && machine == Machine::X86_64);
    let mut guessed = Vec::new();
    let consistent = defined.params.iter().enumerate().all(|(index, param)| {
        let by_pointer = matches!(param.entry, Some(Entry::Address(_)));
        let kind = types.get(underlying(types, param.kind));
        let integer = by_pointer || matches!(kind, Type::Pointer(_) | Type::Enum { .. }) || matches!(kind, Type::Base { base, size } if *base != Base::Float && *size <= 8);
        if matches!(kind, Type::Base { base: Base::Float, .. }) && !by_pointer {
            return true;
        }
        let Some(register) = registers.get(next).filter(|_| integer) else {
            // Past the registers, or a value that takes some other number of them: no more
            // places are known, though those found so far are.
            next = registers.len();
            return integer || param.entry.is_some();
        };
        next += 1;
        match param.entry.and_then(|entry| slot(machine, entry)) {
            Some((Slot::Register(located), _)) => located == *register,
            Some(_) => false,
            None => {
                guessed.push((Slot::Register(register.clone()), index, param));
                true
            }
        }
    });
    if consistent {
        for (slot, index, param) in guessed {
            at.entry(slot).or_insert(Arrives { index: Some(index), name: &param.name, kind: param.kind, pointee: pointee(param.kind, false).0, wrapped: pointee(param.kind, false).1, how: How::Position });
        }
    }
    if in_memory {
        let register = if machine == Machine::Aarch64 { Some("x8".to_string()) } else { registers.first().cloned() };
        if let Some(register) = register {
            at.entry(Slot::Register(register)).or_insert(Arrives { index: None, name: "result", kind: defined.returns, pointee: Some(defined.returns), wrapped: false, how: How::Result });
        }
    }
    at
}

/// What a pointer to `target` points to, as the report counts it, and the struct or union
/// whose members fields are checked against.
fn pointee(types: &Types, target: TypeId) -> (&'static str, Option<TypeId>) {
    let id = underlying(types, target);
    match types.get(id) {
        Type::Composite { size: 0, .. } => ("declared only", None),
        Type::Composite { union: false, .. } => ("struct", Some(id)),
        Type::Composite { union: true, .. } => ("union", Some(id)),
        Type::Array { .. } => ("array", None),
        Type::Base { base: Base::Char, .. } => ("char", None),
        Type::Base { .. } | Type::Enum { .. } => ("number", None),
        Type::Pointer(_) => ("pointer", None),
        Type::Void => ("void", None),
        Type::Function(_) => ("code", None),
        Type::Typedef { .. } | Type::Alias(_) => ("unknown", None),
    }
}

/// A member that holds no other members: where it starts in the outermost type, its size, its
/// type, whether it is the storage unit of a bitfield, and whether it is an element of an array.
#[derive(Debug, Clone, Copy)]
struct Leaf {
    start: u64,
    size: u64,
    kind: TypeId,
    bitfield: bool,
    element: bool,
}

/// The leaf members of the type `id` that hold the byte at `offset`, found from `base`. More
/// than one where unions overlap. A bitfield's leaf is the unit of its type it lies in, which
/// is what the code reads. An array of no count at the end of a struct holds every byte after.
fn leaves(types: &Types, id: TypeId, offset: u64, base: u64, out: &mut Vec<Leaf>, depth: u32) {
    leaves_in(types, id, offset, base, false, out, depth);
}

fn leaves_in(types: &Types, id: TypeId, offset: u64, base: u64, element: bool, out: &mut Vec<Leaf>, depth: u32) {
    if depth == 0 {
        return;
    }
    match types.get(id) {
        Type::Typedef { target, .. } => leaves_in(types, *target, offset, base, element, out, depth - 1),
        Type::Composite { fields, .. } => {
            for field in fields {
                let size = types.size(field.kind);
                if let Some((bit, _)) = field.bits {
                    let unit = size.max(1);
                    let start = (8 * field.offset + u64::from(bit)) / (8 * unit) * unit;
                    if (start..start + unit).contains(&offset) {
                        out.push(Leaf { start: base + start, size: unit, kind: field.kind, bitfield: true, element: false });
                    }
                    continue;
                }
                let open = matches!(types.get(underlying(types, field.kind)), Type::Array { count: 0, .. });
                if offset >= field.offset && (offset < field.offset + size || open) {
                    leaves_in(types, field.kind, offset - field.offset, base + field.offset, false, out, depth - 1);
                }
            }
        }
        Type::Array { element, count } => {
            let size = types.size(*element);
            if size > 0 && (*count == 0 || offset / size < *count) {
                leaves_in(types, *element, offset % size, base + offset / size * size, true, out, depth - 1);
            }
        }
        _ => out.push(Leaf { start: base, size: types.size(id), kind: id, bitfield: false, element }),
    }
}

/// Whether the struct `id` ends in an array of no count, which makes its size a minimum.
fn open_ended(types: &Types, id: TypeId, depth: u32) -> bool {
    match types.get(underlying(types, id)) {
        Type::Composite { fields, .. } if depth > 0 => fields.iter().max_by_key(|field| field.offset).is_some_and(|last| {
            matches!(types.get(underlying(types, last.kind)), Type::Array { count: 0, .. }) || open_ended(types, last.kind, depth - 1)
        }),
        _ => false,
    }
}

/// For each struct, the structs that begin with it: that hold it at offset 0, as a C++ class
/// holds its first base and C code that does objects by hand holds its `super`, directly or
/// through such a struct. Code passed a pointer to the one often reads it as the other.
fn extensions(types: &Types) -> HashMap<TypeId, Vec<TypeId>> {
    let mut found: HashMap<TypeId, Vec<TypeId>> = HashMap::new();
    for id in 0..types.types.len() as TypeId {
        let Type::Composite { union: false, size: 1.., .. } = &types.types[id as usize] else { continue };
        let mut at = vec![id];
        for _ in 0..8 {
            let mut next = Vec::new();
            for outer in at {
                let Type::Composite { fields, .. } = types.get(outer) else { continue };
                for field in fields.iter().filter(|field| field.offset == 0 && field.bits.is_none()) {
                    let inner = underlying(types, field.kind);
                    if matches!(types.get(inner), Type::Composite { union: false, size: 1.., .. }) && inner != id {
                        found.entry(inner).or_default().push(id);
                        next.push(inner);
                    }
                }
            }
            at = next;
        }
    }
    found
}

/// How many fields of `layout` start where a member of `target` does.
fn starting(types: &Types, layout: &Layout, target: TypeId) -> usize {
    layout
        .fields()
        .keys()
        .filter(|&&offset| {
            let mut found = Vec::new();
            leaves(types, target, offset, 0, &mut found, 64);
            found.iter().any(|leaf| leaf.start == offset)
        })
        .count()
}

/// Whether the class `id`, or one it holds, has a virtual base.
fn holds_virtual_base(types: &Types, virtual_bases: &HashSet<TypeId>, id: TypeId, depth: u32) -> bool {
    let id = underlying(types, id);
    virtual_bases.contains(&id)
        || depth > 0 && matches!(types.get(id), Type::Composite { fields, .. } if fields.iter().any(|field| holds_virtual_base(types, virtual_bases, field.kind, depth - 1)))
}

/// One function's view for the scorer: its recovered structs by name, and the DWARF.
struct Scoring<'a> {
    types: &'a Types,
    extensions: &'a HashMap<TypeId, Vec<TypeId>>,
    virtual_bases: &'a HashSet<TypeId>,
    structs: &'a HashMap<String, Layout>,
    tally: &'a mut Tally,
    /// The fields of the case being scored, for the cases file.
    fields: Vec<serde_json::Value>,
    seen: HashSet<(String, TypeId)>,
    /// The recovered structs whose fields are being scored, outermost first, with the types
    /// they are scored against.
    enclosing: Vec<(String, TypeId)>,
}

impl Scoring<'_> {
    /// Whether two structs are one, or one begins with the other, as a node of a tree begins
    /// with the base its links point to.
    fn alike(&self, one: TypeId, other: TypeId) -> bool {
        one == other || self.extensions.get(&one).is_some_and(|wider| wider.contains(&other)) || self.extensions.get(&other).is_some_and(|wider| wider.contains(&one))
    }

    /// Checks the recovered struct `name` against the struct or union `target` it stands for,
    /// at `level` 0 for a parameter's struct, then the structs its fields point to.
    fn layout(&mut self, name: &str, target: TypeId, level: &str) {
        if !self.seen.insert((name.to_string(), target)) {
            return;
        }
        let Some(layout) = self.structs.get(name) else { return };
        self.enclosing.push((name.to_string(), target));
        self.fields_of(layout, target, level);
        self.enclosing.pop();
    }

    fn fields_of(&mut self, layout: &Layout, target: TypeId, level: &str) {
        let types = self.types;
        // A struct that reaches past the end of the type DWARF declares may be one that begins
        // with it, which the code casts the pointer to. Scored against the one of those that
        // has the most fields at a member's start, if that is more than the declared type has.
        let mut target = target;
        if layout.fields().iter().next_back().is_some_and(|(&offset, field)| offset + u64::from(field.size) > types.size(target)) {
            let declared = starting(types, layout, target);
            let best = self.extensions.get(&target).into_iter().flatten().map(|&wider| (starting(types, layout, wider), std::cmp::Reverse(types.size(wider)), wider)).max();
            if let Some((right, _, wider)) = best.filter(|best| best.0 > declared) {
                count(self.tally, format!("4 {level} scored against a struct that begins with the declared one"));
                self.fields.push(json!({"level": level, "declared": spell(types, target, 1), "scored against": spell(types, wider, 1), "right before": declared, "right after": right}));
                target = wider;
            }
        }
        let true_size = types.size(target);
        let size = if layout.size() <= true_size {
            "fits"
        } else if open_ended(types, target, 8) {
            "larger, true one ends in an open array"
        } else {
            "larger"
        };
        count(self.tally, format!("4 {level} size: {size}"));
        for (&offset, field) in layout.fields() {
            let mut found = Vec::new();
            leaves(types, target, offset, 0, &mut found, 64);
            let starting: Vec<Leaf> = found.iter().copied().filter(|leaf| leaf.start == offset).collect();
            count(self.tally, format!("5 {level} field: scored"));
            let start = if !starting.is_empty() {
                "at a member's start"
            } else if found.iter().any(|leaf| leaf.bitfield) {
                "inside a bitfield's unit"
            } else if let Some(leaf) = found.first() {
                match types.get(underlying(types, leaf.kind)) {
                    Type::Pointer(_) => "inside a pointer",
                    Type::Base { base: Base::Float, .. } => "inside a float",
                    _ => "inside a number",
                }
            } else if holds_virtual_base(types, self.virtual_bases, target, 8) {
                // The members leave out where a virtual base lies.
                "outside the members of a class with a virtual base"
            } else if offset >= true_size && true_size > 0 && {
                let mut again = Vec::new();
                leaves(types, target, offset % true_size, 0, &mut again, 64);
                again.iter().any(|leaf| leaf.start == offset % true_size)
            } {
                // A pointer to the first of an array of them, read at a constant index.
                "past the end, at a member of a later element"
            } else if offset >= true_size {
                "past the end"
            } else {
                "in padding"
            };
            count(self.tally, format!("5 {level} field start: {start}"));
            let width = if starting.is_empty() {
                None
            } else if starting.iter().any(|leaf| leaf.size == u64::from(field.size)) {
                Some("same")
            } else if starting.iter().all(|leaf| leaf.size < u64::from(field.size)) {
                // Arrays of bytes or numbers read several elements at a time, as copies do.
                Some(if starting.iter().any(|leaf| leaf.element) { "wider, over elements of an array" } else { "wider than the member" })
            } else if starting.iter().all(|leaf| leaf.bitfield) {
                Some("narrower, part of a bitfield's unit")
            } else {
                Some("narrower than the member")
            };
            if let Some(width) = width {
                count(self.tally, format!("6 {level} field width: {width}"));
            }
            let truth: Vec<String> = found.iter().map(|leaf| format!("+{:#x} {} ({})", leaf.start, spell(types, leaf.kind, 3), leaf.size)).collect();
            self.fields.push(json!({"level": level, "offset": offset, "size": field.size, "type": format!("{:?}", field.ty), "start": start, "width": width, "truth": truth}));
            let FieldType::Struct(child) = &field.ty else { continue };
            let pointer = starting.iter().find_map(|leaf| match types.get(underlying(types, leaf.kind)) {
                Type::Pointer(target) => Some(*target),
                _ => None,
            });
            // A field typed as pointing to the struct it is in, or to one that holds it, when
            // DWARF says it points to something else, points into the middle of that struct.
            // Recovered as pointing back to an enclosing struct: right for a list or a tree, whose
            // DWARF member points to the same type or to one it begins with, and wrong when DWARF
            // says another type, as for a pointer into the middle of the enclosing struct.
            let enclosing = self.enclosing.iter().find(|(name, _)| name == child).map(|&(_, scored)| scored);
            let nested = match (starting.is_empty(), pointer) {
                (true, _) => "field not at a member's start",
                (false, None) => "member is no pointer",
                (false, Some(target)) => match pointee(types, target) {
                    (kind, Some(inner)) => {
                        let level = match enclosing {
                            None => "nested",
                            Some(scored) if self.alike(scored, inner) => "nested, back to an enclosing struct of the same type",
                            Some(_) => "nested, back to an enclosing struct of another type",
                        };
                        self.layout(child, inner, level);
                        kind
                    }
                    (kind, None) => kind,
                },
            };
            count(self.tally, format!("7 nested struct: {nested}"));
            if let Some(scored) = enclosing {
                let same = pointer.and_then(|target| pointee(types, target).1).is_some_and(|inner| self.alike(scored, inner));
                count(self.tally, format!("7 nested struct, back to an enclosing struct: {}", if same { "same type".to_string() } else { format!("{nested}, not the same type") }));
            }
        }
    }
}

/// Decompiles the sample of one binary and scores it. Returns the binary's architecture.
fn score_binary(config: &Config, path: &Path, debug: &Path, edits: &Path, cases: &mut Vec<String>) -> Result<(String, Tally)> {
    let image = recore::Image::load(path)?;
    let machine = image.machine;
    let arch = format!("{:?} {:?}", image.format, machine);
    let analysis = recore::analyze(&image);
    let functions: Vec<u64> = analysis.functions.iter().filter(|function| function.fragment_of.is_none()).map(|function| function.addr).collect();
    drop(analysis);
    let step = (functions.len() / config.sample.max(1)).max(1);
    let sample: Vec<u64> = functions.iter().copied().step_by(step).take(config.sample).collect();
    let Located { types, functions: described, virtual_bases } = dwarf::located(debug, machine, &config.roots).with_context(|| format!("reading {}", debug.display()))?;
    let name = path.file_name().unwrap().to_string_lossy().into_owned();
    let extensions = extensions(&types);

    let edits = edits.to_path_buf();
    let command = move || {
        let mut command = Command::new(std::env::current_exe().unwrap_or_default());
        command.arg("worker").env(recore_decomp::types::DEBUG_VAR, "off").env(recore::edits::DIR_VAR, &edits);
        command
    };
    let mut worker = Worker::new(command, path, &Options::default());
    let mut tally = Tally::new();
    for addr in sample {
        count(&mut tally, "0 functions: sampled");
        let (record, c_text) = worker.decompile(addr, config.timeout);
        if record.status != Status::Ok {
            count(&mut tally, "0 functions: failed");
            continue;
        }
        let Ok(report) = worker.structs(addr, config.timeout) else {
            count(&mut tally, "0 functions: no struct report");
            continue;
        };
        // What the census sees: the type the C gives each parameter, by where it is passed.
        let shown: HashMap<Slot, String> = record.storage.iter().map(|storage| storage_slot(storage)).zip(signature_types(c_text.as_deref().unwrap_or_default())).collect();
        let defined = described.get(&addr);
        if defined.is_some() {
            count(&mut tally, "0 functions: in DWARF");
        }
        // C++ hands back a class with a destructor through memory, which the prototype the
        // reader rewrote for the machine shows as a first parameter `result`.
        let by_reference = types.functions.binary_search_by_key(&addr, |function| function.addr).ok().is_some_and(|at| {
            matches!(types.get(types.functions[at].prototype), Type::Function(prototype) if prototype.params.first().is_some_and(|(name, _)| name == "result"))
        });
        let at: HashMap<Slot, Arrives> = defined.map(|defined| arrivals(&types, machine, defined, by_reference)).unwrap_or_default();
        if let Some(defined) = defined {
            for index in 0..defined.params.len() {
                let how = at.values().find(|arrives| arrives.index == Some(index)).map(|arrives| arrives.how);
                count(&mut tally, format!("1 DWARF parameters: {}", match how {
                    Some(How::Located) => "located",
                    Some(How::Position) => "placed by position",
                    _ => "in no slot",
                }));
            }
        }

        for object in &report.objects {
            let Ok(struct_name) = &object.decision else { continue };
            for root in &object.slots {
                count(&mut tally, "2 root: on a parameter");
                count(&mut tally, if shown.get(root) == Some(struct_name) { "2 root: the C shows it" } else { "2 root: the C shows another type" });
                let Some(param) = at.get(root) else {
                    count(&mut tally, if defined.is_some() { "3 root DWARF: no parameter there" } else { "3 root DWARF: function not described" });
                    let described: Vec<String> = defined.into_iter().flat_map(|defined| &defined.params).map(|param| format!("{} {} {:?}", spell(&types, param.kind, 2), param.name, param.entry)).collect();
                    cases.push(json!({"case": "unmatched", "binary": name, "path": path, "function": format!("{addr:#x}"), "slot": root.to_string(), "struct": struct_name, "params": described, "storage": record.storage}).to_string());
                    continue;
                };
                count(&mut tally, format!("3 root DWARF slot: {:?}", param.how));
                if param.wrapped {
                    count(&mut tally, "3 root DWARF: a pointer in a struct of its size");
                }
                let target = param.pointee;
                let (kind, inner) = match target {
                    Some(target) => pointee(&types, target),
                    None => (
                        match types.get(underlying(&types, param.kind)) {
                            Type::Composite { .. } => "no pointer: struct by value",
                            Type::Base { base: Base::Float, .. } => "no pointer: float",
                            Type::Base { .. } | Type::Enum { .. } => "no pointer: number",
                            _ => "no pointer: other",
                        },
                        None,
                    ),
                };
                count(&mut tally, format!("3 root DWARF: {kind}"));
                let recovered = match worker.recovered(struct_name, config.timeout) {
                    Ok(recovered) => recovered,
                    Err(_) => {
                        count(&mut tally, "3 root: no layout from the worker");
                        continue;
                    }
                };
                let structs: HashMap<String, Layout> = recovered.structs.into_iter().collect();
                let mut scoring = Scoring { types: &types, extensions: &extensions, virtual_bases: &virtual_bases, structs: &structs, tally: &mut tally, fields: Vec::new(), seen: HashSet::new(), enclosing: Vec::new() };
                if let Some(inner) = inner {
                    scoring.layout(struct_name, inner, "root");
                }
                let fields = std::mem::take(&mut scoring.fields);
                let layouts: BTreeMap<&String, String> = structs.iter().map(|(name, layout)| (name, format!("{layout:?}"))).collect();
                cases.push(
                    json!({
                        "case": "root", "binary": name, "path": path, "function": format!("{addr:#x}"), "slot": root.to_string(),
                        "struct": struct_name, "shown": shown.get(root), "param": param.name, "dwarf": spell(&types, param.kind, 4), "how": format!("{:?}", param.how),
                        "kind": kind, "wrapped": param.wrapped, "true_size": target.map(|target| types.size(target)), "fields": fields, "layouts": layouts, "accesses": object.accesses,
                    })
                    .to_string(),
                );
            }
        }

        // Coverage: the parameters DWARF says point to a struct, by what became of them.
        for (root, param) in &at {
            let Some(("struct", Some(_))) = param.pointee.map(|target| pointee(&types, target)) else { continue };
            let object = report.objects.iter().find(|object| object.slots.contains(root));
            let outcome = match object {
                None => "no object".to_string(),
                Some(object) if object.accesses.is_empty() => "nothing read through it".to_string(),
                Some(object) => match &object.decision {
                    Ok(_) => "got a struct".to_string(),
                    Err(refusal) => format!("refused: {refusal:?}"),
                },
            };
            count(&mut tally, format!("8 coverage: {outcome}"));
            if outcome.starts_with("refused") {
                cases.push(json!({"case": "coverage", "binary": name, "path": path, "function": format!("{addr:#x}"), "slot": root.to_string(), "param": param.name, "dwarf": spell(&types, param.kind, 4), "outcome": outcome, "accesses": object.map(|object| &object.accesses), "pointee": param.pointee}).to_string());
            }
        }
    }
    Ok((arch, tally))
}

#[cfg(test)]
mod tests {
    use super::signature_types;

    #[test]
    fn a_signature_is_read_past_parentheses_in_the_name_and_over_lines() {
        let c_text = "/* WARNING: something */\n\nundefined1 re2c::(anonymous namespace)::RenderArray::vfunc_4(S_32f10_RDI *param_1,\n    int4 param_2)\n\n{\n  return 0;\n}\n";
        assert_eq!(signature_types(c_text), ["S_32f10_RDI", "int4"]);
    }
}
