//! recore's analysis, rearranged into the per-function statements the decompiler takes.

use std::borrow::Cow;
use std::collections::HashMap;
use std::ffi::CStr;

use recore::Image;
use recore::image::Machine;
use recore::library::Routine;
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
    /// `(function, index into Analysis::jump_tables)`: those of `jump_tables` that the engine is
    /// left to read itself, because it then knows the value of each case, and is given only
    /// if it reads them otherwise than recore did: an 8051 `JMP @A+DPTR` into a row of jumps.
    pub engine_tables: Vec<(u64, usize)>,
    /// `(caller, function)`: a function to read as part of each function that calls it: a few
    /// instructions without a branch that an 8051 `switch` calls to scale its index, and
    /// that the engine must see through to know the value of each case.
    pub inlined: Vec<(u64, u64)>,
    /// `(call, register)`: a call that is the indirect jump of a jump table. The routine it
    /// calls takes its return address as the address of a table that follows the call, and
    /// jumps to the entry the value in the register picks.
    pub switch_calls: Vec<SwitchCall>,
    /// `(call, bytes)`: a call followed by that much data, which the routine it calls reads
    /// before it returns to the code after the data.
    pub data_after_calls: Vec<(u64, u64)>,
    /// `(function, registers)`: a function and the registers, separated by commas, that it
    /// and what it calls leave as they were, though the calling convention lets a call change
    /// them.
    pub kept_registers: Vec<(u64, String)>,
    /// Functions of SDCC code that return nothing: SDCC returns a value in `DPL` and the
    /// registers after it, and these have not set `DPL` when they return. What a function
    /// last passed to a call would else pass for what it returns.
    pub returns_nothing: Vec<u64>,
    /// `(function, storage)`: where a function takes its arguments and leaves its result, as
    /// [`crate::Session::set_storage`] takes it: a library routine as [`recore::library::Routine::storage`] has it, and a
    /// function of C51 code as its use of the registers says.
    pub storage: Vec<(u64, String)>,
    /// `(function, jump)`: a branch through a register that returns, which recore reads from
    /// the stack it was popped off, and the engine would take for a jump it cannot follow.
    pub returns: Vec<(u64, u64)>,
}

/// A call to a library routine that jumps on to one of several places and does not return.
#[derive(Debug)]
pub struct SwitchCall {
    pub call: u64,
    /// The register that holds the value switched on.
    pub selector: &'static CStr,
    /// When the cases are listed after the call in a way the compiler spec has a jump assist
    /// for: the assist's name, the number of cases and the address of the list. The engine
    /// then finds the places itself, and the value of each case with them.
    pub cases: Option<(&'static CStr, u64, u64)>,
}

impl SwitchCall {
    fn at(image: &Image, library: &[Routine], call: u64) -> SwitchCall {
        let cases = (|| {
            let &[0x12, high, low, ref list @ ..] = image.bytes_from(call)? else { return None };
            // The library is in the memory all banks share.
            let routine = image.bytes_from(u64::from(u16::from_be_bytes([high, low])))?;
            let (assist, selector, entry) = match library.iter().find(|known| known.is_at(routine))?.name {
                "?C?CCASE" => (c"byteCases", c"ACC", 3),
                // The high byte of the value is in B.
                "?C?ICASE" => (c"wordCases", c"AB", 4),
                _ => return None,
            };
            let count = list.chunks(entry).position(|case| case.starts_with(&[0, 0]))?;
            Some((selector, (assist, count as u64, call + 3)))
        })();
        SwitchCall { call, selector: cases.map_or(c"ACC", |cases| cases.0), cases: cases.map(|cases| cases.1) }
    }
}

/// The names the analysis gives the functions in their own right.
pub fn function_names(analysis: &Analysis) -> Vec<(u64, String)> {
    analysis.functions.iter().filter(|f| f.fragment_of.is_none()).filter_map(|f| Some((f.addr, f.name.clone()?))).collect()
}

impl Facts {
    pub fn derive(image: &Image, analysis: &Analysis) -> Facts {
        let mut facts = Facts {
            functions: analysis.functions.iter().filter(|f| f.fragment_of.is_none()).map(|f| (f.addr, f.noreturn)).collect(),
            names: function_names(analysis),
            ..Facts::default()
        };
        let library = recore::library::routines(image.machine, image.compiler);
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
                    _ => facts.switch_calls.push(SwitchCall::at(image, library, table.jump)),
                }
            }
        }
        if image.machine == Machine::Thumb {
            // A `BL` that is a jump through a table calls one of libgcc's helpers for a Thumb-1
            // `switch`, which picks the case by R0.
            for table in &analysis.jump_tables {
                let bl = |bytes: &[u8]| matches!(bytes, &[_, high, _, low, ..] if high & 0xF8 == 0xF0 && low & 0xD0 == 0xD0);
                if image.bytes_from(table.jump).is_some_and(bl) {
                    facts.switch_calls.push(SwitchCall { call: table.jump, selector: c"r0", cases: None });
                }
            }
        }
        // `(routine, register)`: what a library routine brings back though its code writes it.
        let mut restored: Vec<(u64, &str)> = Vec::new();
        // The analysis names a routine of the compiler's library that the image has no name
        // for. Where such a routine takes its arguments is in the library's list.
        if !library.is_empty() {
            let named: HashMap<u64, &str> = facts.names.iter().map(|(function, name)| (*function, name.as_str())).collect();
            let functions: Vec<u64> = named.keys().copied().collect();
            let routines = recore::library::recognise(image, &functions, library).into_iter().filter(|(function, routine)| named[function] == routine.name);
            for (function, routine) in routines {
                facts.storage.extend(routine.storage.map(|storage| (function, storage.to_string())));
                restored.extend(routine.restores.iter().map(|&register| (function, register)));
            }
        }
        let fixups: HashMap<String, String> = Target::of(image).call_fixups().into_iter().collect();
        // 32-bit C names carry one more leading underscore in some symbol sources than others.
        let fixup_of = |name: &str| fixups.get(name).or_else(|| fixups.get(&format!("_{name}"))).cloned();
        facts.call_fixups = facts.names.iter().filter_map(|(function, name)| Some((*function, fixup_of(name)?))).collect();
        if image.machine == Machine::I8051 {
            // What the instructions say of each function's registers stands in for a calling
            // convention, which much of an 8051 program is not held to.
            let declared: std::collections::HashSet<u64> = facts.functions.iter().map(|function| function.0).collect();
            let described: std::collections::HashSet<u64> = facts.storage.iter().map(|storage| storage.0).chain(facts.call_fixups.iter().map(|fixup| fixup.0)).collect();
            let c51 = Target::of(image) == Target::I8051;
            let mut uses: Vec<_> = recore::i8051::registers::uses(image, analysis).into_iter().filter(|(function, _)| declared.contains(function)).collect();
            uses.sort_unstable_by_key(|&(function, _)| function);
            for (function, registers) in uses {
                // The engine takes `DPTR` whole or not at all.
                let mut kept: Vec<&str> = registers.changed.others().names().filter(|name| !matches!(*name, "DPL" | "DPH")).collect();
                for &(_, register) in restored.iter().filter(|restored| restored.0 == function) {
                    if !kept.contains(&register) {
                        kept.push(register);
                    }
                }
                if !kept.is_empty() {
                    facts.kept_registers.push((function, kept.join(",")));
                }
                if c51 && !described.contains(&function) {
                    facts.storage.push((function, c51_storage(registers)));
                } else if !c51 && !registers.set.has("DPL") && !registers.set.has("DPTR") && !described.contains(&function) {
                    facts.returns_nothing.push(function);
                }
            }
        }
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
                        // The engine can only turn an unconditional jump into a call and return,
                        // and a trampoline entry is listed at its first instruction, which loads
                        // what its jump goes by.
                        (true, _) if !call.conditional && !image.banking.trampolines.contains_key(&call.at) => facts.tail_calls.push((owner, call.at)),
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
                        // A direct call that recore resolves to an import goes to a PLT stub, and
                        // so does a direct jump, as a call that ends a function is compiled.
                        (_, CallTarget::Import(slot), Some([0xe8 | 0xe9, rel @ ..])) => {
                            stub((call.at + 5).wrapping_add_signed(i32::from_le_bytes(*rel).into()), slot);
                        }
                        (true, CallTarget::Import(slot), Some([0xeb, rel, ..])) => {
                            stub((call.at + 2).wrapping_add_signed((*rel as i8).into()), slot);
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
        if image.machine == Machine::Arm {
            // A32 and Thumb code reach an import by BL or BLX to its PLT stub.
            use recore::arch::Arch;
            let declared: recore::FxHashSet<u64> = analysis.imports.iter().map(|import| import.slot).collect();
            facts.import_aliases.extend(recore::arm::Arm::plt_stubs(image).into_iter().filter(|(_, slot)| declared.contains(slot)));
        }
        if image.machine == Machine::Thumb {
            for function in &analysis.functions {
                let owner = function.fragment_of.unwrap_or(function.addr);
                for &(start, end) in &function.ranges {
                    facts.returns.extend(recore::thumb::returns_through_register(image, start, end).into_iter().map(|jump| (owner, jump)));
                }
            }
        }
        for list in [&mut facts.tail_calls, &mut facts.own_entries, &mut facts.returns] {
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
        if image.machine == Machine::I8051 {
            let jumps_through_dptr = |index: usize| image.bytes_from(analysis.jump_tables[index].jump).is_some_and(|bytes| bytes.first() == Some(&0x73));
            facts.engine_tables = facts.jump_tables.iter().copied().filter(|&(_, index)| jumps_through_dptr(index)).collect();
            /// The most bytes of code that is read as part of its callers: the routine that
            /// triples an index, `triple_index` in Keil's list, is 11, and this leaves room for one
            /// that scales by another number.
            const SCALER: u64 = 16;
            let call_at = |at: u64| analysis.calls.binary_search_by_key(&at, |call| call.at).ok().map(|index| &analysis.calls[index]);
            // The call straight before the jump, which is two or three bytes long.
            let scalers = facts.engine_tables.iter().filter_map(|&(_, index)| {
                let jump = analysis.jump_tables[index].jump;
                let call = [3, 2].into_iter().find_map(|length| call_at(jump.checked_sub(length)?).filter(|call| !call.tail))?;
                let CallTarget::Function(scaler) = call.target else { return None };
                let function = analysis.functions.iter().find(|function| function.addr == scaler && function.fragment_of.is_none())?;
                let &[(start, end)] = &function.ranges[..] else { return None };
                let straight = end - start <= SCALER && image.bytes_from(end - 1)?.first() == Some(&0x22) && !analysis.calls.iter().any(|call| (start..end).contains(&call.at));
                straight.then_some(scaler)
            });
            let scalers: std::collections::BTreeSet<u64> = scalers.collect();
            let owner_at = |at: u64| analysis.functions.iter().find(|function| function.ranges.iter().any(|&(start, end)| (start..end).contains(&at))).map(|function| function.fragment_of.unwrap_or(function.addr));
            facts.inlined = analysis.calls.iter().filter_map(|call| match call.target {
                CallTarget::Function(scaler) if scalers.contains(&scaler) => Some((owner_at(call.at)?, scaler)),
                _ => None,
            }).collect();
            facts.inlined.sort_unstable();
            facts.inlined.dedup();
        }
        facts.import_aliases.sort_unstable();
        facts.import_aliases.dedup_by_key(|alias| alias.0);
        stub_names.sort_unstable();
        stub_names.dedup_by_key(|name| name.0);
        facts.param_counts = stub_names.iter().map(|(stub, name)| (*stub, 1 + name.matches(':').count())).collect();
        facts.names.extend(stub_names);
        facts
    }
}

/// Where a function of C51 code takes its arguments and leaves its result, as
/// [`crate::Session::set_storage`] takes it. C51 passes the first three arguments in `R7`,
/// `R5` and `R3`, each with the register below it for a second byte, and a pointer that says
/// what memory it points into in `R3`, `R2` and `R1`; it returns in `R7`, in `R6` and `R7`,
/// in `R4` to `R7`, or a pointer in `R3`, `R2` and `R1`. A library routine or a piece of code
/// the linker shares takes or returns a value in `A`, `DPTR`, `B`, `R0` or the carry flag.
fn c51_storage(registers: recore::i8051::registers::Use) -> String {
    let taken = registers.taken;
    let mut arguments: Vec<&str> = Vec::new();
    // Four bytes in R0 to R3 are the second operand of arithmetic on four, whose first is in
    // R4 to R7.
    let long = ["R0", "R1", "R2", "R3"].iter().all(|name| taken.has(name));
    let first_long = long && ["R4", "R5", "R6", "R7"].iter().all(|name| taken.has(name));
    arguments.extend(first_long.then_some("R4R5R6R7"));
    for (pair, high, low) in [("R6R7", "R6", "R7"), ("R4R5", "R4", "R5")] {
        arguments.extend(match (taken.has(high), taken.has(low)) {
            _ if first_long => None,
            (true, true) => Some(pair),
            (false, true) => Some(low),
            (true, false) => Some(high),
            (false, false) => None,
        });
    }
    match (taken.has("R3"), taken.has("R2"), taken.has("R1")) {
        _ if long => arguments.push("R0R1R2R3"),
        (true, true, true) => arguments.push("R3:R2:R1"),
        (third, second, first) => {
            arguments.extend(match (second, third) {
                (true, true) => Some("R2R3"),
                (false, true) => Some("R3"),
                (true, false) => Some("R2"),
                (false, false) => None,
            });
            arguments.extend(first.then_some("R1"));
        }
    }
    arguments.extend(["ACC", "B", "DPTR", "DPL", "DPH", "R0", "CY"].into_iter().filter(|name| taken.has(name) && !(long && *name == "R0")));
    let result = match registers.given {
        // Nothing is known to call it, so nothing says what a caller reads of it.
        None => "?",
        Some(given) => {
            let all = |names: &[&str]| names.iter().all(|name| given.has(name));
            if all(&["R0", "R1", "R2", "R3"]) {
                "R0R1R2R3"
            } else if all(&["R3", "R2", "R1"]) {
                "R3:R2:R1"
            } else if all(&["R4", "R5", "R6", "R7"]) {
                "R4R5R6R7"
            } else if all(&["R6", "R7"]) {
                "R6R7"
            } else {
                ["R7", "ACC", "DPTR", "CY", "B", "R6", "R5", "R4", "R3", "R2", "R1", "R0", "DPL", "DPH"].into_iter().find(|name| given.has(name)).unwrap_or("void")
            }
        }
    };
    format!("{result}({})", arguments.join(","))
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
