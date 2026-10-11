//! recore's analysis, rearranged into the per-function statements the decompiler takes.

use std::borrow::Cow;
use std::collections::HashMap;

use recore::Image;
use recore::report::{Analysis, CallTarget};

/// Control-flow facts for one binary. Each override is attributed to the function whose
/// decompilation it affects: the function containing the instruction and, when that is a cold
/// fragment, also the function the fragment belongs to, because the decompiler follows jumps
/// into fragments.
#[derive(Debug, Default)]
pub struct Facts {
    /// Entry points to declare, with whether the function never returns. Fragments are left
    /// out: they are reached by jumps, never called.
    pub functions: Vec<(u64, bool)>,
    /// `(function, end)`: the highest address of the function and its fragments. A lower bound
    /// would cut off fragments, which the compiler usually places before all functions.
    pub ends: Vec<(u64, u64)>,
    /// PLT stubs of non-returning imports. recore does not list stubs as functions.
    pub noreturn_stubs: Vec<u64>,
    /// `(function, jump)`: an unconditional jump that leaves the function for another one or
    /// for an import. Conditional tail calls are left out, so the decompiler still follows those
    /// into the callee.
    pub tail_calls: Vec<(u64, u64)>,
    /// `(function, call, slot)`: a `call [rip+slot]` through an import slot.
    pub import_calls: Vec<(u64, u64, u64)>,
}

impl Facts {
    pub fn derive(image: &Image, analysis: &Analysis) -> Facts {
        let mut facts = Facts {
            functions: analysis.functions.iter().filter(|f| f.fragment_of.is_none()).map(|f| (f.addr, f.noreturn)).collect(),
            ..Facts::default()
        };
        let mut ends: HashMap<u64, u64> = HashMap::new();
        for function in &analysis.functions {
            let end = function.ranges.iter().map(|range| range.1).max().unwrap_or(function.addr);
            let owned = ends.entry(function.fragment_of.unwrap_or(function.addr)).or_default();
            *owned = end.max(*owned);
        }
        facts.ends = ends.into_iter().collect();
        // Every range with the functions an instruction inside it affects.
        let mut ranges: Vec<(u64, u64, u64, Option<u64>)> = analysis
            .functions
            .iter()
            .flat_map(|f| f.ranges.iter().map(move |&(start, end)| (start, end, f.addr, f.fragment_of)))
            .collect();
        ranges.sort_unstable();

        for call in &analysis.calls {
            let index = ranges.partition_point(|range| range.0 <= call.at);
            let Some(&(_, _, function, owner)) = ranges[..index].last().filter(|range| call.at < range.1) else { continue };
            // recore resolves calls through PLT stubs to the import as well. Those are direct
            // calls to the stub, so the opcode tells the two apart.
            let opcode = image.bytes_from(call.at).and_then(|bytes| bytes.first_chunk::<5>());
            for function in std::iter::once(function).chain(owner) {
                match (call.tail, call.target) {
                    // recore also reports conditional jumps to other functions as tail calls.
                    // The engine can only turn an unconditional jump into a call and return.
                    (true, _) if opcode.is_some_and(|op| matches!(op[0], 0xe9 | 0xeb | 0xff)) => {
                        facts.tail_calls.push((function, call.at));
                    }
                    (false, CallTarget::Import(slot)) if opcode.is_some_and(|op| op[0] == 0xff) => {
                        facts.import_calls.push((function, call.at, slot));
                    }
                    _ => {}
                }
            }
            if let (false, CallTarget::Import(_), true, Some([0xe8, rel @ ..])) = (call.tail, call.target, call.noreturn, opcode) {
                facts.noreturn_stubs.push((call.at + 5).wrapping_add_signed(i32::from_le_bytes(*rel).into()));
            }
        }
        facts.noreturn_stubs.sort_unstable();
        facts.noreturn_stubs.dedup();
        facts
    }
}

/// A piece of the image as the program sees it once the loader is done.
pub struct Loaded<'a> {
    pub addr: u64,
    pub data: Cow<'a, [u8]>,
    /// The bytes cannot change at run time, so the decompiler may use them as constants.
    pub constant: bool,
    pub code: bool,
}

/// The image's sections after loading. Relative relocations are applied, so that pointer tables
/// and GOT entries for local functions hold their real targets; in the file they are zero or an
/// addend. Slots bound to imports get whatever address the other library ends up at, so each is
/// split off as a piece that is not constant.
pub fn loaded(image: &Image) -> Vec<Loaded<'_>> {
    let mut slots: Vec<u64> = image.import_slots.keys().copied().collect();
    slots.sort_unstable();
    let mut relocations = image.relative_targets.clone();
    relocations.sort_unstable();

    let mut pieces = Vec::new();
    for section in &image.sections {
        let inside = |addr: u64| addr >= section.addr && addr + 8 <= section.end();
        if section.writable {
            pieces.push(Loaded { addr: section.addr, data: Cow::Borrowed(&section.data[..]), constant: false, code: section.executable });
            continue;
        }
        let mut data = Cow::Borrowed(&section.data[..]);
        let first = relocations.partition_point(|r| r.0 < section.addr);
        for &(slot, target) in relocations[first..].iter().take_while(|r| inside(r.0)) {
            let offset = (slot - section.addr) as usize;
            data.to_mut()[offset..offset + 8].copy_from_slice(&target.to_le_bytes());
        }
        // Cut the section at every import slot it contains.
        let first = slots.partition_point(|&slot| slot < section.addr);
        let mut cuts = vec![0];
        for &slot in slots[first..].iter().take_while(|&&slot| inside(slot)) {
            let offset = (slot - section.addr) as usize;
            cuts.extend([offset, offset + 8]);
        }
        cuts.push(data.len());
        for (index, range) in cuts.windows(2).enumerate().filter(|(_, range)| range[0] < range[1]) {
            let piece = match &data {
                Cow::Borrowed(bytes) => Cow::Borrowed(&bytes[range[0]..range[1]]),
                Cow::Owned(bytes) => Cow::Owned(bytes[range[0]..range[1]].to_vec()),
            };
            // Even windows lie between slots, odd ones are the slots themselves.
            pieces.push(Loaded { addr: section.addr + range[0] as u64, data: piece, constant: index % 2 == 0, code: section.executable });
        }
    }
    pieces
}
