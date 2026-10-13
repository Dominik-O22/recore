//! recore's analysis, rearranged into the per-function statements the decompiler takes.

use std::borrow::Cow;
use std::collections::HashMap;
use std::ffi::CStr;

use recore::Image;
use recore::image::Machine;
use recore::report::{Analysis, CallTarget};

use crate::Target;

/// Control-flow facts for one binary. Each is attributed to the function whose decompilation
/// it affects: every function that has the instruction in one of its ranges, or the owner
/// when that function is a cold fragment, because the decompiler follows jumps into those.
#[derive(Debug, Default)]
pub struct Facts {
    /// Entry points to declare, with whether the function never returns. Fragments are left
    /// out: they are reached by jumps, never called, and a declared entry stops flow from other
    /// functions.
    pub functions: Vec<(u64, bool)>,
    /// Names the image carries for functions, demangled. Naming declares, so fragments are left
    /// out here too.
    pub names: Vec<(u64, String)>,
    /// `(function, count)`: a function known to take exactly `count` pointer-sized parameters:
    /// a stub that sends one Objective-C message, to a receiver and one argument per colon of
    /// the selector.
    pub param_counts: Vec<(u64, usize)>,
    /// `(function, fixup)`: a compiler helper whose calls the compiler spec's call fixup of that
    /// name stands in for.
    pub call_fixups: Vec<(u64, String)>,
    /// `(address, slot)`: code that only forwards to the import behind `slot`. These are PLT
    /// stubs, which recore does not list as functions, and import thunks, which it does.
    pub import_aliases: Vec<(u64, u64)>,
    /// `(function, jump)`: an unconditional jump that leaves the function for another one or
    /// for an import. Conditional tail calls are left out, so the decompiler still follows those
    /// into the callee.
    pub tail_calls: Vec<(u64, u64)>,
    /// `(function, call, slot)`: a call through an import slot.
    pub import_calls: Vec<(u64, u64, u64)>,
    /// `(function, call, target)`: a call through a pointer slot that holds a local function.
    pub local_calls: Vec<(u64, u64, u64)>,
    /// `(function, entry)`: another declared function whose entry lies inside one of the
    /// function's ranges, so control flow may pass through it.
    pub own_entries: Vec<(u64, u64)>,
    /// `(function, index into Analysis::jump_tables)`: an indirect jump inside the function.
    pub jump_tables: Vec<(u64, usize)>,
    /// `(call, register)`: a call that is the indirect jump of a jump table. The routine it
    /// calls takes its return address as the address of a table that follows the call, and
    /// jumps to the entry the value in the register picks.
    pub switch_calls: Vec<(u64, &'static CStr)>,
    /// `(call, bytes)`: a call followed by that much data, which the routine it calls reads
    /// before it returns to the code after the data.
    pub data_after_calls: Vec<(u64, u64)>,
}

impl Facts {
    pub fn derive(image: &Image, analysis: &Analysis) -> Facts {
        let mut facts = Facts {
            functions: analysis.functions.iter().filter(|f| f.fragment_of.is_none()).map(|f| (f.addr, f.noreturn)).collect(),
            names: analysis.functions.iter().filter(|f| f.fragment_of.is_none()).filter_map(|f| Some((f.addr, f.name.clone()?))).collect(),
            ..Facts::default()
        };
        if image.machine == Machine::I8051 {
            // recore lists a call to one of Keil's library routines that read what follows the
            // call as a jump table at the call: the cases of a `switch`, or for a routine that
            // stores a four-byte constant the one place it returns to, past the constant.
            for table in &analysis.jump_tables {
                let length = match image.bytes_from(table.jump).and_then(|bytes| bytes.first()) {
                    Some(0x12) => 3,
                    Some(acall) if acall & 0x1f == 0x11 => 2,
                    _ => continue,
                };
                match table.targets[..] {
                    [after] if after == table.jump + length + 4 => facts.data_after_calls.push((table.jump, 4)),
                    _ => facts.switch_calls.push((table.jump, c"ACC")),
                }
            }
        }
        let fixups: HashMap<String, String> = Target::of(image).map(Target::call_fixups).unwrap_or_default().into_iter().collect();
        // 32-bit C names carry one more leading underscore in some symbol sources than others.
        let fixup_of = |name: &str| fixups.get(name).or_else(|| fixups.get(&format!("_{name}"))).cloned();
        facts.call_fixups = facts.names.iter().filter_map(|(function, name)| Some((*function, fixup_of(name)?))).collect();
        let mut entries: Vec<u64> = facts.functions.iter().map(|f| f.0).collect();
        entries.sort_unstable();
        let x86 = matches!(image.machine, Machine::X86 | Machine::X86_64);
        // A function owns every one of its ranges: the main extent, cold blocks, and exits it
        // shares with other functions. What happens in a range is a fact about each function
        // that has it, and about the owner if the function is itself a fragment.
        let mut stub_names: Vec<(u64, String)> = Vec::new();
        for function in &analysis.functions {
            let owner = function.fragment_of.unwrap_or(function.addr);
            for &(start, end) in &function.ranges {
                let first = entries.partition_point(|&entry| entry < start);
                facts.own_entries.extend(entries[first..].iter().take_while(|&&entry| entry < end).filter(|&&entry| entry != owner).map(|&entry| (owner, entry)));

                let first = analysis.calls.partition_point(|call| call.at < start);
                for call in analysis.calls[first..].iter().take_while(|call| call.at < end) {
                    // recore says where a call goes, not how. On x86 the opcode tells a call
                    // through a pointer slot (ff /2, possibly behind a `notrack` prefix) from a
                    // direct one (e8).
                    let bytes = image.bytes_from(call.at).filter(|_| x86).unwrap_or(&[]);
                    let bytes = bytes.strip_prefix(&[0x3e]).unwrap_or(bytes);
                    let through_slot = bytes.first() == Some(&0xff);
                    match (call.tail, call.target) {
                        // The engine can only turn an unconditional jump into a call and return.
                        (true, _) if !call.conditional => facts.tail_calls.push((owner, call.at)),
                        (false, CallTarget::Import(slot)) if through_slot => facts.import_calls.push((owner, call.at, slot)),
                        (false, CallTarget::Function(target)) if through_slot => facts.local_calls.push((owner, call.at, target)),
                        _ => {}
                    }
                    // A stub the linker made for one Objective-C selector passes that selector to
                    // the dispatcher. Under the linker's own name for it, `objc_msgSend$alloc`,
                    // a call to it reads as the message it sends.
                    let mut stub = |stub: u64, slot: u64| match recore::objc::send_at(analysis, call.at).filter(|_| image.section_at(stub).is_some_and(|section| section.name.ends_with("__objc_stubs"))) {
                        Some(send) => stub_names.push((stub, format!("objc_msgSend${}", send.selector))),
                        None => facts.import_aliases.push((stub, slot)),
                    };
                    if let (Machine::Aarch64, CallTarget::Import(slot)) = (image.machine, call.target) {
                        // `bl` to a PLT stub, or `b` to one as a tail call: the top six bits are
                        // the opcode, the rest a word offset.
                        let word = image.bytes_from(call.at).and_then(|b| b.first_chunk::<4>()).map(|b| u32::from_le_bytes(*b));
                        if let Some(word) = word.filter(|word| word >> 26 == if call.tail { 0b000101 } else { 0b100101 }) {
                            let offset = i64::from((word << 6) as i32 >> 6) * 4;
                            stub(call.at.wrapping_add_signed(offset), slot);
                        }
                    }
                    match (call.tail, call.target, bytes.first_chunk::<5>()) {
                        // A direct call that recore resolves to an import goes to a PLT stub.
                        (false, CallTarget::Import(slot), Some([0xe8, rel @ ..])) => {
                            stub((call.at + 5).wrapping_add_signed(i32::from_le_bytes(*rel).into()), slot);
                        }
                        // A function that starts by jumping through an import slot is a thunk for it.
                        (true, CallTarget::Import(slot), _) if call.at == function.addr && through_slot => {
                            facts.import_aliases.push((function.addr, slot));
                        }
                        _ => {}
                    }
                }

                let jumps = analysis.jump_tables.iter().enumerate().filter(|(_, table)| (start..end).contains(&table.jump));
                facts.jump_tables.extend(jumps.map(|(index, _)| (owner, index)));
            }
        }
        for list in [&mut facts.tail_calls, &mut facts.own_entries] {
            list.sort_unstable();
            list.dedup();
        }
        for list in [&mut facts.import_calls, &mut facts.local_calls] {
            list.sort_unstable();
            list.dedup();
        }
        // A function that only jumps to a helper stands in for it: incremental linking calls
        // `_chkstk` through such a thunk.
        let helpers: HashMap<u64, String> = facts.call_fixups.iter().cloned().collect();
        let thunks = analysis.functions.iter().filter(|f| f.thunk && !helpers.contains_key(&f.addr));
        facts.call_fixups.extend(thunks.filter_map(|thunk| {
            let jump = &analysis.calls[analysis.calls.binary_search_by_key(&thunk.addr, |call| call.at).ok()?];
            let CallTarget::Function(target) = jump.target else { return None };
            Some((thunk.addr, helpers.get(&target).filter(|_| jump.tail)?.clone()))
        }));
        facts.jump_tables.sort_unstable();
        facts.jump_tables.dedup();
        facts.import_aliases.sort_unstable();
        facts.import_aliases.dedup_by_key(|alias| alias.0);
        stub_names.sort_unstable();
        stub_names.dedup_by_key(|name| name.0);
        facts.param_counts = stub_names.iter().map(|(stub, name)| (*stub, 1 + name.matches(':').count())).collect();
        facts.names.extend(stub_names);
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

    let pointer = image.machine.pointer_size() as usize;
    let mut pieces = Vec::new();
    for section in &image.sections {
        let inside = |addr: u64| addr >= section.addr && addr + pointer as u64 <= section.end();
        if section.writable {
            pieces.push(Loaded { addr: section.addr, data: Cow::Borrowed(&section.data[..]), constant: false, code: section.executable });
            continue;
        }
        let mut data = Cow::Borrowed(&section.data[..]);
        let first = relocations.partition_point(|r| r.0 < section.addr);
        for &(slot, target) in relocations[first..].iter().take_while(|r| inside(r.0)) {
            let offset = (slot - section.addr) as usize;
            data.to_mut()[offset..offset + pointer].copy_from_slice(&target.to_le_bytes()[..pointer]);
        }
        // Cut the section at every import slot it contains.
        let first = slots.partition_point(|&slot| slot < section.addr);
        let mut cuts = vec![0];
        for &slot in slots[first..].iter().take_while(|&&slot| inside(slot)) {
            let offset = (slot - section.addr) as usize;
            cuts.extend([offset, offset + pointer]);
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
