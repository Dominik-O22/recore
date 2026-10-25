//! Vtables that no type information describes.
//!
//! A constructor stores the address of its class's vtable at the start of the object:
//!
//! ```text
//! mov dword [esi], 0x402000   ; the constructor
//! ```
//!
//! An image without run-time type information still has the vtables: each is an address that
//! an instruction stores at the start of an object, where the words that follow are function
//! entries.

use rayon::prelude::*;
use rustc_hash::FxHashSet;

use crate::arch::{Arch, Effect, Operand, Place};
use crate::image::Image;
use crate::report::Class;

/// Most slots read from one vtable.
const LONGEST: u64 = 1024;

/// The vtables that an instruction stores at the start of an object, each as a class named after
/// its address, where no class in `known` has it. `refs` are `(instruction, data address,
/// reads or writes it)` for what code refers to for certain, and `uncertain` for what code
/// decoded on a guess does. A vtable ends at the first word that is not a function entry, as
/// `is_entry` says, or at the next address that code refers to for certain.
pub fn untyped<A: Arch>(image: &Image, known: &[Class], refs: &[(u64, u64, bool)], uncertain: &[(u64, u64, bool)], is_entry: impl Fn(u64) -> bool + Sync) -> Vec<Class> {
    if A::THIS.is_none() {
        return Vec::new();
    }
    let pointer = image.machine.pointer_size();
    let word = |slot: u64| Some(image.bytes_from(slot)?.get(..pointer as usize)?.iter().rev().fold(0, |value, &byte| value << 8 | u64::from(byte)));
    let stores = |from: u64, value: u64| {
        let insn = A::decode(image, image.bytes_from(from).unwrap_or(&[]), from).next().and_then(|decoded| decoded.insn);
        insn.is_some_and(|insn| matches!(A::object_effect(&insn), Effect::Store { to: Place::Field { offset: 0, .. }, from: Operand::Constant(stored) } if stored == value))
    };
    let mut stored: Vec<u64> = refs
        .par_iter()
        .chain(uncertain)
        .filter(|&&(_, to, access)| !access && to % pointer == 0 && image.section_at(to).is_some_and(|section| !section.executable) && word(to).is_some_and(&is_entry))
        .filter(|&&(from, to, _)| stores(from, to))
        .map(|&(_, to, _)| to)
        .collect();
    stored.sort_unstable();
    stored.dedup();
    let known: FxHashSet<u64> = known.iter().map(|class| class.vtable).collect();
    if stored.iter().all(|vtable| known.contains(vtable)) {
        return Vec::new();
    }
    let mut referenced: Vec<u64> = refs.par_iter().map(|&(_, to, _)| to).collect();
    referenced.par_sort_unstable();
    let mut vtables: Vec<u64> = stored.iter().chain(&known).copied().collect();
    vtables.sort_unstable();
    let after = |ends: &[u64], addr: u64| ends.get(ends.partition_point(|&end| end <= addr)).copied().unwrap_or(u64::MAX);
    stored
        .into_iter()
        .filter(|vtable| !known.contains(vtable))
        .filter_map(|vtable| {
            let next = after(&referenced, vtable).min(after(&vtables, vtable));
            let methods: Vec<u64> = (0..LONGEST)
                .map(|index| vtable + index * pointer)
                .take_while(|&slot| slot < next)
                .map_while(|slot| word(slot).filter(|&target| is_entry(target)))
                .collect();
            (!methods.is_empty()).then(|| Class { name: format!("vtable_{vtable:x}"), vtable, methods, bases: Vec::new(), objc: false })
        })
        .collect()
}
