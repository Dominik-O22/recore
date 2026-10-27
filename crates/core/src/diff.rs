//! Which functions of one build of a program are which in another, and which of them changed.
//!
//! Functions are paired by what stays the same between two builds: a name, then a body that no
//! other function has, then a place among functions already paired, since a function is called
//! by the same callers and calls the same callees in the same order. A pair whose bodies differ
//! in more than the addresses they hold is a change. Code that cannot be hashed, as the 8051's,
//! is paired all the same, and says it was not compared.

use std::collections::BTreeMap;

use crate::program::Program;
use crate::report::CallTarget;
use crate::{FxHashMap, FxHashSet};

/// Why two functions are taken for the same one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Evidence {
    /// Both have the name, and no other function of either build does.
    Name,
    /// Both have the body, and no other function of either build does.
    Body,
    /// The same call, counted from the start, of two functions already paired goes to them.
    Callee,
    /// Each is the one function left unpaired that a set of paired functions calls.
    Callers,
    /// They are in the same place in a run of unpaired functions between the same two paired
    /// ones. Nothing else reaches a function that is only called through a table.
    Order,
}

/// A function of the old build and the function it is in the new one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pair {
    pub old: u64,
    pub new: u64,
    pub evidence: Evidence,
    /// How the code differs, beyond the addresses it holds.
    pub change: Change,
}

/// How the code of a function differs between two builds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    /// In nothing but the addresses it holds.
    Same,
    /// The instructions are the same and only numbers in them differ: a constant, or the
    /// offsets of fields, as in every function that uses a structure which gained one.
    Numbers,
    /// The instructions differ.
    Code,
    /// The code of one or both could not be compared, so whether it differs is not known:
    /// [`crate::signature::hashes`] does not hash the machine, or the image lacks the bytes.
    Unknown,
}

/// How two builds of a program differ, function by function.
#[derive(Debug, Default)]
pub struct Diff {
    /// Sorted by the old address.
    pub pairs: Vec<Pair>,
    /// Entries of the old build's functions that the new build has no counterpart for.
    pub removed: Vec<u64>,
    /// Entries of the new build's functions that the old build has no counterpart for.
    pub added: Vec<u64>,
}

/// What a call goes to, in terms two builds share.
#[derive(PartialEq, Eq)]
enum Callee<'a> {
    Function(u64),
    Import(&'a str),
}

/// One build, with what pairing asks of each function.
struct Side<'a> {
    program: &'a Program,
    /// The body and shape hashes of each function whose code could be hashed, fragments
    /// included: see [`crate::signature::hashes`].
    bodies: FxHashMap<u64, (u64, u64)>,
}

impl<'a> Side<'a> {
    fn new(program: &'a Program) -> Side<'a> {
        let slots: FxHashMap<u64, u64> = program.image.relative_targets.iter().copied().collect();
        let hashes = |entry: u64| Some((entry, crate::signature::hashes(&program.image, &slots, &program.body(entry))?));
        Side { program, bodies: program.functions().filter_map(|function| hashes(function.addr)).collect() }
    }

    fn entries(&self) -> impl Iterator<Item = u64> + '_ {
        self.program.functions().map(|function| function.addr)
    }

    /// What the function calls, in the order of the calls in its code.
    fn callees(&self, entry: u64) -> Vec<Callee<'a>> {
        let program = self.program;
        let callee = |target| match target {
            CallTarget::Function(callee) => Callee::Function(callee),
            CallTarget::Import(slot) => Callee::Import(program.import_name(slot).unwrap_or_default()),
        };
        program.body(entry).into_iter().flat_map(|(start, end)| program.calls_in(start, end)).map(|call| callee(call.target)).collect()
    }

    /// The functions that call the function.
    fn callers(&self, entry: u64) -> impl Iterator<Item = u64> + '_ {
        self.program.calls_to(entry).flat_map(|call| self.program.owners(call.at))
    }
}

/// The pairs so far, readable from either side.
#[derive(Default)]
struct Pairing {
    by_old: BTreeMap<u64, (u64, Evidence)>,
    new: FxHashSet<u64>,
}

impl Pairing {
    /// Pairs the two unless either is paired already. Says whether it did.
    fn pair(&mut self, old: u64, new: u64, evidence: Evidence) -> bool {
        if self.by_old.contains_key(&old) || self.new.contains(&new) {
            return false;
        }
        self.by_old.insert(old, (new, evidence));
        self.new.insert(new)
    }

    /// Pairs the functions of each side that alone on their side have a key, where the other
    /// side has one with the same key.
    fn pair_unique<K: std::hash::Hash + Eq>(&mut self, old: impl Iterator<Item = (K, u64)>, new: impl Iterator<Item = (K, u64)>, evidence: Evidence) -> bool {
        /// Each key to its one function, or to `None` when several have it.
        fn unique<K: std::hash::Hash + Eq>(keyed: impl Iterator<Item = (K, u64)>) -> FxHashMap<K, Option<u64>> {
            let mut by_key = FxHashMap::default();
            for (key, entry) in keyed {
                by_key.entry(key).and_modify(|seen| *seen = None).or_insert(Some(entry));
            }
            by_key
        }
        let (old, new) = (unique(old), unique(new));
        let mut found: Vec<(u64, u64)> = old.into_iter().filter_map(|(key, entry)| Some((entry?, (*new.get(&key)?)?))).collect();
        found.sort_unstable();
        found.into_iter().fold(false, |any, (old, new)| self.pair(old, new, evidence) | any)
    }
}

/// Pairs, in address order, the unpaired functions that lie between two neighbouring pairs on
/// both sides, where both sides have as many. Says whether it paired any.
fn pair_in_order(old: &Side, new: &Side, pairing: &mut Pairing) -> bool {
    let new_entries: Vec<u64> = new.entries().collect();
    let mut found = Vec::new();
    // The unpaired old functions since the last pair, and the new address of that pair.
    let (mut run, mut after) = (Vec::new(), 0);
    for entry in old.entries().map(Some).chain([None]) {
        let before = match entry.map(|entry| pairing.by_old.get(&entry).map(|paired| paired.0).ok_or(entry)) {
            Some(Err(unpaired)) => {
                run.push(unpaired);
                continue;
            }
            Some(Ok(paired)) => paired,
            None => u64::MAX,
        };
        let (first, end) = (new_entries.partition_point(|&entry| entry < after), new_entries.partition_point(|&entry| entry < before));
        let candidates: Vec<u64> = new_entries[first..end.max(first)].iter().filter(|entry| !pairing.new.contains(*entry)).copied().collect();
        if candidates.len() == run.len() {
            found.extend(run.iter().copied().zip(candidates));
        }
        run.clear();
        after = before;
    }
    found.into_iter().fold(false, |any, (old, new)| pairing.pair(old, new, Evidence::Order) | any)
}

/// Pairs the functions of `old` with those of `new`.
pub fn diff(old: &Program, new: &Program) -> Diff {
    let (old, new) = (Side::new(old), Side::new(new));
    let mut pairing = Pairing::default();
    let named = |side: &Side| -> Vec<(String, u64)> { side.program.functions().filter_map(|function| Some((function.name.clone()?, function.addr))).collect() };
    pairing.pair_unique(named(&old).into_iter(), named(&new).into_iter(), Evidence::Name);
    loop {
        let mut progress = false;
        let open_old = |pairing: &Pairing, entry: &u64| !pairing.by_old.contains_key(entry);
        let open_new = |pairing: &Pairing, entry: &u64| !pairing.new.contains(entry);
        let bodies = |side: &Side, open: Vec<u64>| -> Vec<(u64, u64)> { open.into_iter().filter_map(|entry| Some((side.bodies.get(&entry)?.0, entry))).collect() };
        let (left_old, left_new): (Vec<u64>, Vec<u64>) = (old.entries().filter(|entry| open_old(&pairing, entry)).collect(), new.entries().filter(|entry| open_new(&pairing, entry)).collect());
        progress |= pairing.pair_unique(bodies(&old, left_old).into_iter(), bodies(&new, left_new).into_iter(), Evidence::Body);

        // Two paired functions that make the same number of calls make them to the same
        // functions, unless a call that is already paired on both sides says otherwise.
        let pairs: Vec<(u64, u64)> = pairing.by_old.iter().map(|(&old, &(new, _))| (old, new)).collect();
        for (old_entry, new_entry) in pairs {
            let (old_calls, new_calls) = (old.callees(old_entry), new.callees(new_entry));
            let agree = |(from, to): (&Callee, &Callee)| match (from, to) {
                (Callee::Function(from), Callee::Function(to)) => match pairing.by_old.get(from) {
                    Some((paired, _)) => paired == to,
                    None => !pairing.new.contains(to),
                },
                (from, to) => from == to,
            };
            if old_calls.len() != new_calls.len() || !old_calls.iter().zip(&new_calls).all(agree) {
                continue;
            }
            for calls in old_calls.iter().zip(&new_calls) {
                if let (Callee::Function(from), Callee::Function(to)) = calls {
                    progress |= pairing.pair(*from, *to, Evidence::Callee);
                }
            }
        }

        // A function left over whose callers are all paired, and are the callers of one
        // function left over on the other side.
        let callers_of_old = |entry: u64| -> Option<Vec<u64>> {
            let mut callers: Vec<u64> = old.callers(entry).map(|caller| pairing.by_old.get(&caller).map(|paired| paired.0)).collect::<Option<_>>()?;
            callers.sort_unstable();
            callers.dedup();
            (!callers.is_empty()).then_some(callers)
        };
        let callers_of_new = |entry: u64| -> Option<Vec<u64>> {
            let mut callers: Vec<u64> = new.callers(entry).map(|caller| pairing.new.contains(&caller).then_some(caller)).collect::<Option<_>>()?;
            callers.sort_unstable();
            callers.dedup();
            (!callers.is_empty()).then_some(callers)
        };
        let by_callers_old: Vec<(Vec<u64>, u64)> = old.entries().filter(|entry| open_old(&pairing, entry)).filter_map(|entry| Some((callers_of_old(entry)?, entry))).collect();
        let by_callers_new: Vec<(Vec<u64>, u64)> = new.entries().filter(|entry| open_new(&pairing, entry)).filter_map(|entry| Some((callers_of_new(entry)?, entry))).collect();
        progress |= pairing.pair_unique(by_callers_old.into_iter(), by_callers_new.into_iter(), Evidence::Callers);
        // Last, since it is the weakest: the linker keeps functions in order, so what is
        // left between two pairs is the same functions if it is as many.
        if !progress {
            progress = pair_in_order(&old, &new, &mut pairing);
        }
        if !progress {
            break;
        }
    }

    let change = |from: u64, to: u64| match (old.bodies.get(&from), new.bodies.get(&to)) {
        (Some(before), Some(after)) if before.0 == after.0 => Change::Same,
        (Some(before), Some(after)) if before.1 == after.1 => Change::Numbers,
        (Some(_), Some(_)) => Change::Code,
        _ => Change::Unknown,
    };
    let pairs = pairing.by_old.iter().map(|(&from, &(to, evidence))| Pair { old: from, new: to, evidence, change: change(from, to) }).collect();
    Diff {
        pairs,
        removed: old.entries().filter(|entry| !pairing.by_old.contains_key(entry)).collect(),
        added: new.entries().filter(|entry| !pairing.new.contains(entry)).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image::{Format, Image, Machine, Section};
    use crate::report::{Analysis, AnalyzedFunction};

    /// A program of `code` at 0 that is one function, `main`.
    fn program(machine: Machine, code: Vec<u8>) -> Program {
        let end = code.len() as u64;
        let text = Section { name: ".text".into(), addr: 0, data: code, file_offset: None, executable: true, writable: false };
        let main = AnalyzedFunction { addr: 0, ranges: vec![(0, end)], noreturn: false, thunk: false, origin: Default::default(), name: Some("main".into()), fragment_of: None, runs_on: None };
        let analysis = Analysis { name: String::new(), functions: vec![main], noreturn_calls: vec![], instructions: 0, jump_tables: vec![], calls: vec![], imports: vec![], data_refs: vec![], strings: vec![], classes: vec![], sends: vec![], types: vec![] };
        Program::new(Image::bare(String::new(), Format::Raw, machine, 0, vec![text]), analysis)
    }

    #[test]
    fn a_pair_whose_code_cannot_be_hashed_is_not_called_the_same() {
        let change = |machine, before: &[u8], after: &[u8]| diff(&program(machine, before.to_vec()), &program(machine, after.to_vec())).pairs[0].change;
        // mov r0, #1; bx lr against mov r0, #2; bx lr.
        let (one, two) = ([1, 0, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1], [2, 0, 0xA0, 0xE3, 0x1E, 0xFF, 0x2F, 0xE1]);
        assert_eq!(change(Machine::Arm, &one, &one), Change::Same);
        assert_eq!(change(Machine::Arm, &one, &two), Change::Numbers);
        // The 8051 is not hashed: mov a, #1; ret, the same in both, is not known to be.
        assert_eq!(change(Machine::I8051, &[0x74, 1, 0x22], &[0x74, 1, 0x22]), Change::Unknown);
    }
}
