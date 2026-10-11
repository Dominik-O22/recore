//! Function recovery and non-returning call analysis for x86-64.
//!
//! Function starts come from `.eh_frame`, exports, the entry point, and then from the targets of
//! calls and tail jumps found while decoding. Each function is decoded linearly inside its range,
//! which is sound for compiler output because jump tables live in read-only data, not in code.

use std::collections::{HashMap, HashSet};

use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction};
use rayon::prelude::*;

use crate::discover::{discover, is_function_section, FUNCTION_ALIGN};
use crate::image::Image;
use crate::noreturn::is_noreturn_import;
use crate::report::{AnalyzedFunction, Analysis, CallSite, CallTarget, Import, Origin};
use crate::x86::{classify, is_endbr, is_padding, opens_landing_pad, Flow};

#[derive(Debug, Clone, Copy)]
struct Control {
    addr: u64,
    #[allow(dead_code)]
    next: u64,
    flow: Flow,
}

struct Function {
    start: u64,
    end: u64,
    /// Control-flow instructions in address order.
    controls: Vec<Control>,
    instructions: u64,
}

/// Decodes `[start, end)` linearly and keeps its control-flow instructions. With `trim`, `end` is
/// only an upper bound and the function ends before any trailing padding.
fn decode(image: &Image, start: u64, end: u64, trim: bool) -> Function {
    let mut function = Function { start, end, controls: Vec::new(), instructions: 0 };
    let Some(bytes) = image.bytes_from(start) else {
        return function;
    };
    let bytes = &bytes[..bytes.len().min((end - start) as usize)];
    let mut decoder = Decoder::with_ip(64, bytes, start, DecoderOptions::NONE);
    let mut instr = Instruction::default();
    let mut body_end = start;
    while decoder.can_decode() {
        decoder.decode_out(&mut instr);
        if instr.is_invalid() {
            continue;
        }
        function.instructions += 1;
        if !is_padding(&instr) {
            body_end = instr.next_ip();
        }
        if let Some(flow) = classify(&instr) {
            function.controls.push(Control { addr: instr.ip(), next: instr.next_ip(), flow });
        }
    }
    if trim {
        function.end = body_end;
        function.controls.retain(|c| c.addr < body_end);
    }
    function
}

/// Resolves what a call or jump target is, when it is not a local function.
struct Imports<'a> {
    image: &'a Image,
    /// PLT stub address to the slot it jumps through.
    stubs: HashMap<u64, u64>,
}

impl<'a> Imports<'a> {
    fn new(image: &'a Image) -> Self {
        let mut stubs = HashMap::new();
        for section in image.sections.iter().filter(|s| s.executable && s.name.starts_with(".plt")) {
            let mut decoder = Decoder::with_ip(64, &section.data, section.addr, DecoderOptions::NONE);
            let mut stub_start = section.addr;
            let mut instr = Instruction::default();
            while decoder.can_decode() {
                decoder.decode_out(&mut instr);
                if instr.flow_control() == FlowControl::IndirectBranch && instr.is_ip_rel_memory_operand() {
                    let slot = instr.ip_rel_memory_address();
                    if image.import_slots.contains_key(&slot) {
                        stubs.insert(stub_start, slot);
                    }
                }
                // Stubs are padded to 16 bytes; the next one starts at the next boundary.
                if instr.next_ip() % 16 == 0 {
                    stub_start = instr.next_ip();
                }
            }
        }
        Imports { image, stubs }
    }

    /// The import behind a slot address, if the slot is one.
    fn slot(&self, slot: Option<u64>) -> Option<&'a str> {
        self.image.import_slots.get(&slot?).map(String::as_str)
    }

    /// The slot a PLT stub at `addr` jumps through.
    fn stub_slot(&self, addr: u64) -> Option<u64> {
        self.stubs.get(&addr).copied()
    }

    /// The import a PLT stub at `addr` reaches.
    fn stub(&self, addr: u64) -> Option<&'a str> {
        self.slot(self.stub_slot(addr))
    }
}

/// What following control flow from a function's entry finds.
struct Walk {
    /// Some path returns to the caller.
    may_return: bool,
    /// End of the highest code reached. Code in the range above it was never reached.
    reach_end: u64,
    /// False when an indirect jump could not be followed, so more may be reachable.
    complete: bool,
    /// The straight-line stretches of code that were reached, as `[start, end)`, sorted. May
    /// extend outside the function's own extent.
    reached: Vec<(u64, u64)>,
}

/// The whole program's control-flow instructions and function entries, for following a
/// function's paths wherever they lead.
struct Program<'a> {
    /// Every function's control-flow instructions, sorted by address.
    controls: Vec<Control>,
    /// Function entry addresses, sorted.
    starts: &'a [u64],
    imports: &'a Imports<'a>,
    tables: &'a HashMap<u64, &'a [u64]>,
}

impl Program<'_> {
    fn is_start(&self, addr: u64) -> bool {
        self.starts.binary_search(&addr).is_ok()
    }

    /// The first function entry after `addr`.
    fn next_start(&self, addr: u64) -> u64 {
        self.starts.get(self.starts.partition_point(|&start| start <= addr)).copied().unwrap_or(u64::MAX)
    }
}

/// Follows every path from the function's entry until it returns, stops, or reaches another
/// function's entry. A jump to code that is not an entry is followed even outside the function's
/// own extent, which is how a function reaches its cold part when that sits elsewhere. An
/// unresolved indirect jump counts as possibly returning.
fn walk(function: &Function, noreturn: &HashSet<u64>, program: &Program) -> Walk {
    let controls = &program.controls;
    let imports = program.imports;
    let in_extent = |addr: u64| addr >= function.start && addr < function.end;
    let target_returns = |target: u64| match imports.stub(target) {
        Some(name) => !is_noreturn_import(name),
        None => !noreturn.contains(&target),
    };

    let mut result = Walk { may_return: false, reach_end: function.start, complete: true, reached: Vec::new() };
    let mut visited: HashSet<usize> = HashSet::new();
    let mut pending = vec![function.start];
    while let Some(addr) = pending.pop() {
        // Everything up to the next control instruction falls through, unless another
        // function's entry comes first.
        let mut index = controls.partition_point(|c| c.addr < addr);
        let boundary = program.next_start(addr);
        let mut run_start = addr;
        loop {
            let Some(control) = controls.get(index).filter(|c| c.addr < boundary) else {
                // Fell through to the next function's entry, or off the end of the code.
                if in_extent(run_start) {
                    result.reach_end = function.end;
                    result.reached.push((run_start, function.end));
                }
                break;
            };
            if !visited.insert(index) {
                result.reached.push((run_start, control.addr));
                break;
            }
            result.reached.push((run_start, control.next));
            run_start = control.next;
            if in_extent(control.addr) {
                result.reach_end = result.reach_end.max(control.next);
            }
            let mut leave = |target: u64, pending: &mut Vec<u64>| {
                // A PLT stub or another function's entry is a tail call. Anything else is more
                // of this function's own code.
                let is_tail_call = imports.stub(target).is_some() || (target != function.start && program.is_start(target));
                if !is_tail_call {
                    pending.push(target);
                } else if target_returns(target) {
                    result.may_return = true;
                }
            };
            match control.flow {
                Flow::Return => {
                    result.may_return = true;
                    break;
                }
                Flow::Halt => break,
                Flow::Jump(target) => {
                    leave(target, &mut pending);
                    break;
                }
                Flow::Branch(target) => leave(target, &mut pending),
                Flow::JumpIndirect(None) => {
                    match program.tables.get(&control.addr) {
                        Some(targets) => pending.extend(targets.iter().copied()),
                        None => {
                            result.may_return = true;
                            result.complete = false;
                        }
                    }
                    break;
                }
                Flow::JumpIndirect(slot) => {
                    if !imports.slot(slot).is_some_and(is_noreturn_import) {
                        result.may_return = true;
                    }
                    break;
                }
                Flow::Call(target) => {
                    if !target_returns(target) {
                        break;
                    }
                }
                Flow::CallIndirect(slot) => {
                    if imports.slot(slot).is_some_and(is_noreturn_import) {
                        break;
                    }
                }
            }
            index += 1;
        }
    }
    result.reached.sort_unstable();
    result
}

/// The first real instruction in `[from, end)` after any padding, unless it opens an exception
/// landing pad. Landing pads are reached by the unwinder, not by control flow, so unreached
/// code that starts with one still belongs to the function before it.
fn next_function_start(image: &Image, from: u64, end: u64) -> Option<u64> {
    let bytes = image.bytes_from(from)?;
    let bytes = &bytes[..bytes.len().min((end.checked_sub(from)?) as usize)];
    let mut decoder = Decoder::with_ip(64, bytes, from, DecoderOptions::NONE);
    let mut instr = Instruction::default();
    while decoder.can_decode() {
        decoder.decode_out(&mut instr);
        if instr.is_invalid() {
            return None;
        }
        if is_padding(&instr) {
            continue;
        }
        let start = instr.ip();
        let mut first = instr;
        if is_endbr(&first) && decoder.can_decode() {
            decoder.decode_out(&mut first);
        }
        // Landing pads sit at arbitrary offsets; a function that starts flush against the
        // previous one, with no padding to mark the boundary, still starts aligned.
        return (start % FUNCTION_ALIGN == 0 && !opens_landing_pad(&first)).then_some(start);
    }
    None
}

pub fn analyze(image: &Image) -> Analysis {
    let imports = Imports::new(image);
    let frames: Vec<(u64, u64)> = image
        .frames
        .iter()
        .copied()
        .filter(|&(start, _)| image.section_at(start).is_some_and(is_function_section))
        .collect();
    let frame_end: HashMap<u64, u64> = frames.iter().copied().collect();

    let mut discovery = discover(image, &frames);
    let tables: HashMap<u64, &[u64]> = discovery.jump_tables.iter().map(|t| (t.jump, t.targets.as_slice())).collect();

    let (starts, functions, noreturn) = loop {
        let starts: Vec<u64> = discovery.starts.keys().copied().collect();
        let functions: Vec<Function> = starts
            .par_iter()
            .enumerate()
            .map(|(index, &start)| match frame_end.get(&start) {
                Some(&end) => decode(image, start, end, false),
                None => {
                    let section_end = image.section_at(start).map_or(start, |s| s.end());
                    let bound = starts.get(index + 1).copied().unwrap_or(section_end).min(section_end);
                    decode(image, start, bound, true)
                }
            })
            .collect();

        let mut controls: Vec<Control> = functions.iter().flat_map(|f| f.controls.iter().copied()).collect();
        controls.sort_unstable_by_key(|c| c.addr);
        let program = Program { controls, starts: &starts, imports: &imports, tables: &tables };

        // Least fixpoint: a function joins the set once no path through it can return.
        let mut noreturn: HashSet<u64> = HashSet::new();
        loop {
            let added: Vec<u64> = functions
                .par_iter()
                .filter(|f| !noreturn.contains(&f.start) && !walk(f, &noreturn, &program).may_return)
                .map(|f| f.start)
                .collect();
            if added.is_empty() {
                break;
            }
            noreturn.extend(added);
        }

        // Code in a function's extent that no path from its entry reaches belongs to a
        // different function: it follows a call that never returns, and nothing else marked it
        // as an entry point. Functions with a frame are left alone, since the frame already
        // gives their extent.
        let splits: Vec<u64> = functions
            .par_iter()
            .filter(|f| !frame_end.contains_key(&f.start))
            .filter_map(|f| {
                let reached = walk(f, &noreturn, &program);
                (reached.complete && reached.reach_end < f.end)
                    .then(|| next_function_start(image, reached.reach_end, f.end))
                    .flatten()
            })
            .collect();
        if splits.is_empty() {
            break (starts, functions, noreturn);
        }
        for addr in splits {
            discovery.starts.entry(addr).or_insert(Origin::Unreachable);
        }
    };

    let is_start = |addr: u64| starts.binary_search(&addr).is_ok();
    let leaves = |function: &Function, target: u64| target < function.start || target >= function.end;

    // A frame nothing refers to as a function, entered only by jumps from one other function,
    // is a split-off piece of that function.
    let mut jumped_from: HashMap<u64, Vec<u64>> = HashMap::new();
    for function in &functions {
        for control in &function.controls {
            if let Flow::Jump(target) | Flow::Branch(target) = control.flow {
                if leaves(function, target) && is_start(target) {
                    jumped_from.entry(target).or_default().push(function.start);
                }
            }
        }
    }
    let by_start: HashMap<u64, &Function> = functions.iter().map(|f| (f.start, f)).collect();
    // A piece of another function either jumps back into the middle of its owner or never
    // returns. A real function that is only ever tail-called from one place does neither.
    let behaves_like_fragment = |piece: &Function, owner: &Function| {
        let rejoins_owner = piece.controls.iter().any(|control| match control.flow {
            Flow::Jump(target) | Flow::Branch(target) => target > owner.start && target < owner.end,
            _ => false,
        });
        rejoins_owner || !piece.controls.iter().any(|control| control.flow == Flow::Return)
    };
    let fragment_of: HashMap<u64, u64> = jumped_from
        .iter()
        .filter(|&(target, sources)| {
            !discovery.referenced.contains(target)
                && discovery.starts[target] == Origin::Frame
                && sources.iter().all(|&source| source == sources[0])
                && behaves_like_fragment(by_start[target], by_start[&sources[0]])
        })
        .map(|(&target, sources)| (target, sources[0]))
        .collect();

    let mut calls: Vec<CallSite> = functions
        .par_iter()
        .flat_map_iter(|function| {
            let fragment_of = &fragment_of;
            let noreturn = &noreturn;
            let imports = &imports;
            function.controls.iter().filter_map(move |control| {
                let local = |target: u64, tail: bool| {
                    // Moving between a function and its own fragment is ordinary control flow.
                    let same_function = fragment_of.get(&target) == Some(&function.start)
                        || fragment_of.get(&function.start) == Some(&target);
                    (is_start(target) && !same_function)
                        .then(|| (CallTarget::Function(target), noreturn.contains(&target), tail))
                };
                let import = |slot: u64, tail: bool| {
                    imports.slot(Some(slot)).map(|name| (CallTarget::Import(slot), is_noreturn_import(name), tail))
                };
                let (target, noreturn, tail) = match control.flow {
                    Flow::Call(target) => imports.stub_slot(target).and_then(|slot| import(slot, false)).or_else(|| local(target, false)),
                    Flow::CallIndirect(Some(slot)) => import(slot, false),
                    Flow::Jump(target) | Flow::Branch(target) if leaves(function, target) => {
                        imports.stub_slot(target).and_then(|slot| import(slot, true)).or_else(|| local(target, true))
                    }
                    Flow::JumpIndirect(Some(slot)) => import(slot, true),
                    _ => None,
                }?;
                Some(CallSite { at: control.addr, target, noreturn, tail })
            })
        })
        .collect();
    calls.sort_unstable_by_key(|call| call.at);

    let noreturn_calls: Vec<u64> = calls.iter().filter(|call| call.noreturn && !call.tail).map(|call| call.at).collect();
    let used_slots: HashSet<u64> = calls
        .iter()
        .filter_map(|call| match call.target {
            CallTarget::Import(slot) => Some(slot),
            CallTarget::Function(_) => None,
        })
        .collect();
    let mut import_list: Vec<Import> = used_slots
        .into_iter()
        .map(|slot| {
            let name = image.import_slots[&slot].clone();
            Import { slot, noreturn: is_noreturn_import(&name), name }
        })
        .collect();
    import_list.sort_unstable_by_key(|import| import.slot);

    Analysis {
        name: image.name.clone(),
        instructions: functions.iter().map(|f| f.instructions).sum(),
        functions: functions
            .iter()
            .map(|f| AnalyzedFunction {
                addr: f.start,
                ranges: vec![(f.start, f.end)],
                noreturn: noreturn.contains(&f.start),
                thunk: false,
                origin: discovery.starts[&f.start],
                fragment_of: fragment_of.get(&f.start).copied(),
            })
            .collect(),
        noreturn_calls,
        jump_tables: discovery.jump_tables.clone(),
        calls,
        imports: import_list,
    }
}
