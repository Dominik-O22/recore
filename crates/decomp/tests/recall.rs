//! How much of what a function reads and writes through its pointer parameters struct recovery
//! sees. The decompiler's data flow, printed after the whole pipeline, is the reference: each
//! load and store whose address is a parameter as passed plus a constant. `gather` in the shim
//! models the engine's propagation of a pointer type, and an access it misses is one the
//! struct of that parameter would not cover.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;

use recore::structs::Slot;
use recore_decomp::{Flow, Session, Target};

/// Accesses in the data flow, and how many of those `gather` collected at the same offset and
/// size from the same parameter. Of the others: how many it collected at that offset with
/// another size, how many lie inside an access it collected (the engine splits a field it has
/// typed into pieces), and how many come through a parameter it collected nothing from.
#[derive(Debug, Default, Clone, Copy, PartialEq)]
struct Recall {
    flow: usize,
    gathered: usize,
    other_size: usize,
    inside: usize,
    no_object: usize,
}

/// The parameter and constant offset a load or store address is, if it is one: followed back
/// through copies, casts and additions of constants to a parameter as passed.
fn resolve(flow: &Flow, defs: &HashMap<u32, usize>, mut value: u32) -> Option<(usize, i64)> {
    let mut offset = 0i64;
    for _ in 0..16 {
        let Some(&at) = defs.get(&value) else {
            return match &flow.values.get(&value)?.kind {
                recore_decomp::flow::Kind::Param { index, .. } => Some((*index, offset)),
                _ => None,
            };
        };
        let op = &flow.ops[at];
        // Signed, at the constant's own size: 32-bit code subtracts by adding 0xffffffd8.
        let constant = |input: u32| match flow.values.get(&input) {
            Some(recore_decomp::flow::Value { size, kind: recore_decomp::flow::Kind::Const(constant) }) if (1..8).contains(size) => {
                let shift = 64 - 8 * size;
                Some(((*constant as i64) << shift) >> shift)
            }
            Some(recore_decomp::flow::Value { kind: recore_decomp::flow::Kind::Const(constant), .. }) => Some(*constant as i64),
            _ => None,
        };
        match (op.code.as_str(), op.inputs.as_slice()) {
            ("COPY" | "CAST", [input]) => value = *input,
            ("INT_ADD" | "PTRSUB", [base, added]) => {
                offset = offset.wrapping_add(constant(*added)?);
                value = *base;
            }
            ("PTRADD", [base, index, size]) => {
                offset = offset.wrapping_add(constant(*index)?.wrapping_mul(constant(*size)?));
                value = *base;
            }
            _ => return None,
        }
    }
    None
}

/// The recall over the functions of the binary at `path`, one decompilation each: every one,
/// or as many as `sample` spread over the binary.
fn recall(path: &Path, sample: Option<usize>) -> (Target, Recall) {
    let image = recore::Image::load(path).unwrap();
    let analysis = recore::analyze(&image);
    let mut session = Session::from_image(&image, &analysis).unwrap();
    session.keep_flow(true);
    let mut recall = Recall::default();
    let functions: Vec<u64> = analysis.functions.iter().filter(|function| function.fragment_of.is_none()).map(|function| function.addr).collect();
    let step = sample.map_or(1, |sample| (functions.len() / sample).max(1));
    for &addr in functions.iter().step_by(step).take(sample.unwrap_or(usize::MAX)) {
        let Ok(decompiled) = session.decompile(addr) else { continue };
        let Some(flow) = &decompiled.flow else { continue };
        let report = session.structs_of(addr).unwrap_or_default();

        // What gather collected through each parameter, by the slot the shim names it by. An
        // object several parameters point to is taken to start where each of them points.
        let mut gathered: HashMap<String, HashSet<(i64, u32)>> = HashMap::new();
        for object in &report.objects {
            for slot in &object.slots {
                let storage = match slot {
                    Slot::Register(name) => name.clone(),
                    Slot::Stack(offset) => format!("stack:{offset:#x}"),
                };
                gathered.entry(storage).or_default().extend(object.accesses.iter().copied());
            }
        }
        let defs: HashMap<u32, usize> = flow.ops.iter().enumerate().filter_map(|(at, op)| Some((op.output?, at))).collect();
        for op in &flow.ops {
            let (address, size) = match (op.code.as_str(), op.inputs.as_slice()) {
                ("LOAD", [address]) => (*address, op.output.and_then(|output| flow.values.get(&output)).map_or(0, |value| value.size)),
                ("STORE", [address, stored]) => (*address, flow.values.get(stored).map_or(0, |value| value.size)),
                _ => continue,
            };
            let Some((index, offset)) = resolve(flow, &defs, address) else { continue };
            let Some(param) = decompiled.params.get(index) else { continue };
            if param.size != session.target().pointer_bytes() as u32 {
                continue;
            }
            recall.flow += 1;
            match gathered.get(&param.storage) {
                Some(accesses) if accesses.contains(&(offset, size)) => recall.gathered += 1,
                Some(accesses) if accesses.iter().any(|&(at, _)| at == offset) => recall.other_size += 1,
                Some(accesses) if accesses.iter().any(|&(at, width)| at <= offset && offset + i64::from(size) <= at + i64::from(width)) => recall.inside += 1,
                Some(accesses) => {
                    if std::env::var_os("RECORE_RECALL_SHOW").is_some() {
                        let near: Vec<&(i64, u32)> = accesses.iter().filter(|(at, _)| (at - offset).abs() < 8).collect();
                        eprintln!("not gathered: {} {addr:#x} {} +{offset:#x} {size}, gathered near: {near:x?}", path.display(), param.storage);
                    }
                }
                None => {
                    recall.no_object += 1;
                    if std::env::var_os("RECORE_RECALL_SHOW").is_some() {
                        eprintln!("no object: {} {addr:#x} {} +{offset:#x}", path.display(), param.storage);
                    }
                }
            }
        }
    }
    (session.target(), recall)
}

/// The recall of each target over `binaries`, printed one line each.
fn by_target(binaries: impl IntoIterator<Item = std::path::PathBuf>, sample: Option<usize>) -> BTreeMap<String, Recall> {
    let mut by_target: BTreeMap<String, Recall> = BTreeMap::new();
    for path in binaries {
        let (target, recall) = self::recall(&path, sample);
        let total = by_target.entry(format!("{target:?}")).or_default();
        total.flow += recall.flow;
        total.gathered += recall.gathered;
        total.other_size += recall.other_size;
        total.inside += recall.inside;
        total.no_object += recall.no_object;
    }
    for (target, recall) in &by_target {
        let share = 100.0 * recall.gathered as f64 / recall.flow.max(1) as f64;
        eprintln!(
            "{target}: {} of {} accesses through parameters gathered ({share:.1}%); missed, {} at another size, {} inside one gathered, {} through a parameter with no object, {} elsewhere",
            recall.gathered,
            recall.flow,
            recall.other_size,
            recall.inside,
            recall.no_object,
            recall.flow - recall.gathered - recall.other_size - recall.inside - recall.no_object
        );
    }
    by_target
}

/// The fixtures by target: x86-64 ELF and PE, 32-bit x86 ELF and PE, and arm64 Mach-O. Few
/// accesses each, but every one gathered.
#[test]
fn gather_sees_what_the_data_flow_reads_through_parameters() {
    let data = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data");
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("../core/tests/fixtures");
    let binaries = ["structs.elf", "types.elf", "classes.elf", "tables.elf", "aggregate.elf", "format.elf", "types.exe", "structs.exe"].map(|name| data.join(name));
    let found = by_target(binaries.into_iter().chain(["classes-x86-static", "classes-x86_64-static", "shapes-arm64"].map(|name| fixtures.join(name))), None);
    let counts: Vec<(&str, usize, usize)> = found.iter().map(|(target, recall)| (target.as_str(), recall.gathered, recall.flow)).collect();
    assert_eq!(counts, [("Aarch64", 2, 2), ("X86Gcc", 17, 17), ("X86Windows", 8, 8), ("X86_64Gcc", 31, 31), ("X86_64Windows", 4, 4)]);
}

/// The same over binaries of a corpus, 200 functions each: `RECORE_RECALL` names a file that
/// lists them, one path a line, as `bench/set.txt` does, relative to the directory it is run in.
/// With `RECORE_RECALL_SHOW` set, each access missed is printed.
#[test]
#[ignore = "needs a corpus"]
fn gather_sees_what_the_data_flow_reads_through_parameters_in_a_corpus() {
    let list = std::fs::read_to_string(std::env::var("RECORE_RECALL").expect("RECORE_RECALL names a list of binaries")).unwrap();
    let binaries = list.lines().map(str::trim).filter(|line| !line.is_empty() && !line.starts_with('#')).map(std::path::PathBuf::from);
    by_target(binaries, Some(200));
}
