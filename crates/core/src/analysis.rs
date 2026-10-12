//! Function recovery and non-returning call analysis for x86-64.
//!
//! Function starts come from `.eh_frame`, exports, the entry point, and then from the targets of
//! calls and tail jumps found while decoding. Each function is decoded linearly inside its range,
//! which is sound for compiler output because jump tables live in read-only data, not in code.

use rustc_hash::{FxHashMap, FxHashSet};

use rayon::prelude::*;

use crate::arch::{Arch, Flow};
use crate::discover::{discover, is_function_section};
use crate::image::{Format, Image, Machine};
use crate::noreturn::is_noreturn_import;
use crate::phase;
use crate::report::{AnalyzedFunction, Analysis, CallSite, CallTarget, DataRef, Import, Origin, StringLiteral};
use crate::signature::{Signatures, fingerprint};
use crate::strings::string_at;
use crate::x86::X86;

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
fn decode<A: Arch>(image: &Image, start: u64, end: u64, trim: bool) -> Function {
    let mut function = Function { start, end, controls: Vec::new(), instructions: 0 };
    let Some(bytes) = image.bytes_from(start) else {
        return function;
    };
    let bytes = &bytes[..bytes.len().min((end - start) as usize)];
    let mut state = A::State::default();
    let mut body_end = start;
    for decoded in A::decode(bytes, start) {
        let Some(insn) = decoded.insn else { continue };
        function.instructions += 1;
        if !A::is_padding(&insn) {
            body_end = decoded.next_addr();
        }
        match A::flow(&insn, &state) {
            Some(flow) => {
                function.controls.push(Control { addr: decoded.addr, next: decoded.next_addr(), flow });
                // The state only matters for resolving slots, so a fresh one after any control
                // transfer is enough for a linear pass.
                state = A::State::default();
            }
            None => A::step(&mut state, &insn),
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
    stubs: FxHashMap<u64, u64>,
}

impl<'a> Imports<'a> {
    fn new<A: Arch>(image: &'a Image) -> Self {
        Imports { image, stubs: A::plt_stubs(image) }
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
    /// Each function's `[start, end)`, in the same order as `starts`.
    extents: Vec<(u64, u64)>,
    imports: &'a Imports<'a>,
    tables: &'a FxHashMap<u64, &'a [u64]>,
    /// Slot address to target for pointers the loader relocates. A call through such a slot
    /// goes to a function in this image, not to an import.
    pointer_slots: &'a FxHashMap<u64, u64>,
}

impl Program<'_> {
    fn is_start(&self, addr: u64) -> bool {
        self.starts.binary_search(&addr).is_ok()
    }

    /// Whether `addr` lies inside some function's extent.
    fn is_covered(&self, addr: u64) -> bool {
        let index = self.extents.partition_point(|&(start, _)| start <= addr);
        index > 0 && addr < self.extents[index - 1].1
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
fn walk(function: &Function, noreturn: &FxHashSet<u64>, program: &Program) -> Walk {
    let controls = &program.controls;
    let imports = program.imports;
    let in_extent = |addr: u64| addr >= function.start && addr < function.end;
    let target_returns = |target: u64| match imports.stub(target) {
        Some(name) => !is_noreturn_import(name),
        None => !noreturn.contains(&target),
    };

    // What a call or jump through a slot reaches: an import, a local function through a
    // relocated pointer, or something unknown that is assumed to return.
    let slot_returns = |slot: Option<u64>| match (imports.slot(slot), slot.and_then(|s| program.pointer_slots.get(&s))) {
        (Some(name), _) => !is_noreturn_import(name),
        (None, Some(&target)) => !noreturn.contains(&target),
        (None, None) => true,
    };

    let mut result = Walk { may_return: false, reach_end: function.start, complete: true, reached: Vec::new() };
    let mut visited: FxHashSet<usize> = FxHashSet::default();
    let mut pending = vec![function.start];
    while let Some(addr) = pending.pop() {
        // Everything up to the next control instruction falls through, unless another
        // function's entry comes first.
        let mut index = controls.partition_point(|c| c.addr < addr);
        let boundary = program.next_start(addr);
        let mut run_start = addr;
        loop {
            let Some(control) = controls.get(index).filter(|c| c.addr < boundary) else {
                // Ran off the end of a function, which only code that never returns does, or
                // into code that no function's extent covers, such as a linker veneer. The
                // second kind carries on somewhere this walk cannot see, so it may return.
                if in_extent(run_start) {
                    result.reach_end = function.end;
                    result.reached.push((run_start, function.end));
                }
                // `run_start == addr` means nothing was decoded on the way: the jump itself
                // landed outside known code.
                if run_start == addr && !program.is_covered(addr) {
                    result.may_return = true;
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
                    if slot_returns(slot) {
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
                    if !slot_returns(slot) {
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

/// Where the code of a function without a frame ends, for images that keep data among the
/// code: the first unconditional terminator that no earlier forward branch jumps past. Decoding
/// up to the next function instead would read a trailing jump table as instructions.
fn code_end<A: Arch>(image: &Image, start: u64, bound: u64, tables: &FxHashMap<u64, &[u64]>) -> u64 {
    let Some(bytes) = image.bytes_from(start) else { return start };
    let bytes = &bytes[..bytes.len().min((bound - start) as usize)];
    let state = A::State::default();
    let mut furthest_target = start;
    for decoded in A::decode(bytes, start) {
        let Some(insn) = decoded.insn else { return decoded.addr };
        match A::flow(&insn, &state) {
            Some(Flow::Branch(target)) if target > decoded.addr && target < bound => {
                furthest_target = furthest_target.max(target);
            }
            Some(Flow::Jump(target)) if target > decoded.addr && target < bound && decoded.next_addr() <= furthest_target => {
                furthest_target = furthest_target.max(target);
            }
            // The cases of a resolved switch come after the jump that dispatches to them.
            Some(Flow::JumpIndirect(None)) if tables.contains_key(&decoded.addr) => {
                let cases = tables[&decoded.addr].iter().copied().filter(|&target| target > decoded.addr && target < bound);
                furthest_target = furthest_target.max(cases.max().unwrap_or(furthest_target));
                if decoded.next_addr() > furthest_target {
                    return decoded.next_addr();
                }
            }
            Some(Flow::Jump(_) | Flow::JumpIndirect(_) | Flow::Return | Flow::Halt) if decoded.next_addr() > furthest_target => {
                return decoded.next_addr();
            }
            _ => {}
        }
    }
    bound
}

/// Sorts ranges and joins the ones that touch or overlap.
fn merge(mut ranges: Vec<(u64, u64)>) -> Vec<(u64, u64)> {
    ranges.sort_unstable();
    let mut merged: Vec<(u64, u64)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        match merged.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => merged.push((start, end)),
        }
    }
    merged
}

/// The parts of sorted, disjoint `a` that also lie in sorted, disjoint `b`.
fn intersect(a: &[(u64, u64)], b: &[(u64, u64)]) -> Vec<(u64, u64)> {
    let (mut i, mut j, mut out) = (0, 0, Vec::new());
    while i < a.len() && j < b.len() {
        let (start, end) = (a[i].0.max(b[j].0), a[i].1.min(b[j].1));
        if start < end {
            out.push((start, end));
        }
        if a[i].1 < b[j].1 { i += 1 } else { j += 1 }
    }
    out
}

/// The parts of sorted, disjoint `code` that no range in `covered` contains.
fn uncovered(code: &[(u64, u64)], covered: &[(u64, u64)]) -> Vec<(u64, u64)> {
    let covered = merge(covered.to_vec());
    let mut out = Vec::new();
    let mut j = 0;
    for &(mut start, end) in code {
        while j < covered.len() && covered[j].1 <= start {
            j += 1;
        }
        let mut k = j;
        while start < end {
            match covered.get(k) {
                Some(&(c_start, c_end)) if c_start < end => {
                    if c_start > start {
                        out.push((start, c_start));
                    }
                    start = start.max(c_end);
                    k += 1;
                }
                _ => {
                    out.push((start, end));
                    break;
                }
            }
        }
    }
    out
}

/// The first real instruction in `[from, end)` after any padding, unless it opens an exception
/// landing pad. Landing pads are reached by the unwinder, not by control flow, so unreached
/// code that starts with one still belongs to the function before it.
fn next_function_start<A: Arch>(image: &Image, from: u64, end: u64) -> Option<u64> {
    let bytes = image.bytes_from(from)?;
    let bytes = &bytes[..bytes.len().min((end.checked_sub(from)?) as usize)];
    let mut decoder = A::decode(bytes, from).skip_while(|d| d.insn.as_ref().is_some_and(A::is_padding));
    let first = decoder.next()?;
    let mut insn = first.insn?;
    let marked = A::is_entry_marker(&insn);
    if marked {
        insn = decoder.next()?.insn?;
    }
    // Landing pads sit at arbitrary offsets and carry no entry marker. A function that starts
    // flush against the previous one, with no padding to mark the boundary, still starts
    // aligned, or with a marker where alignment says nothing.
    let looks_like_entry = if A::ALIGNMENT_IS_EVIDENCE { first.addr % A::FUNCTION_ALIGN == 0 } else { marked };
    (looks_like_entry && !A::opens_landing_pad(&insn)).then_some(first.addr)
}

/// Analyzes a loaded image with the support for its architecture.
pub fn analyze(image: &Image) -> Analysis {
    match image.machine {
        // PE images follow the Windows calling convention, everything else System V.
        Machine::X86_64 if image.data_in_code => analyze_with::<X86<64, true>>(image),
        Machine::X86_64 => analyze_with::<X86<64, false>>(image),
        Machine::X86 if image.data_in_code => analyze_with::<X86<32, true>>(image),
        Machine::X86 => analyze_with::<X86<32, false>>(image),
        Machine::Aarch64 => analyze_with::<crate::arm64::Arm64>(image),
    }
}

fn analyze_with<A: Arch>(image: &Image) -> Analysis {
    // Assigning starts the next phase and ends the one before.
    let mut _phase = phase::scope("setup");
    let imports = Imports::new::<A>(image);
    let frames: Vec<(u64, u64)> = image
        .frames
        .iter()
        .copied()
        .filter(|&(start, _)| image.section_at(start).is_some_and(is_function_section))
        .collect();
    let frame_end: FxHashMap<u64, u64> = frames.iter().copied().collect();

    drop(_phase);
    let mut discovery = discover::<A>(image, &frames);
    _phase = phase::scope("setup");
    let tables: FxHashMap<u64, &[u64]> = discovery.jump_tables.iter().map(|t| (t.jump, t.targets.as_slice())).collect();

    let pointer_slots: FxHashMap<u64, u64> = image.relative_targets.iter().copied().collect();

    let (starts, functions, chunks, noreturn, controls, extents) = loop {
        _phase = phase::scope("decode functions");
        let starts: Vec<u64> = discovery.starts.keys().copied().collect();
        let functions: Vec<Function> = starts
            .par_iter()
            .enumerate()
            .map(|(index, &start)| match frame_end.get(&start) {
                Some(&end) => decode::<A>(image, start, end, false),
                None => {
                    let section_end = image.section_at(start).map_or(start, |s| s.end());
                    let mut bound = starts.get(index + 1).copied().unwrap_or(section_end).min(section_end);
                    if image.data_in_code {
                        bound = code_end::<A>(image, start, bound, &tables);
                    }
                    decode::<A>(image, start, bound, true)
                }
            })
            .collect();

        // Where function extents are tight, code that a function reaches by a jump can lie
        // outside every extent: a cold block placed elsewhere, or a shared exit. Those chunks
        // are decoded too, so that a function can be followed into them.
        _phase = phase::scope("decode chunks");
        let chunks: Vec<Function> = if image.data_in_code {
            let covered: Vec<(u64, u64)> = functions.iter().map(|f| (f.start, f.end)).collect();
            uncovered(&discovery.code, &covered).into_iter().map(|(start, end)| decode::<A>(image, start, end, false)).collect()
        } else {
            Vec::new()
        };

        // A chunk that several functions jump to the top of is a function they all tail-call,
        // not a cold block of one of them, and so is one that opens like a function.
        // Only jumps to the top of a chunk matter, and most images have no chunks at all.
        let mut jumped_to: FxHashMap<u64, FxHashSet<u64>> = chunks.iter().map(|chunk| (chunk.start, FxHashSet::default())).collect();
        if !chunks.is_empty() {
            for function in &functions {
                for control in &function.controls {
                    if let Flow::Jump(target) | Flow::Branch(target) = control.flow
                        && let Some(sources) = jumped_to.get_mut(&target)
                    {
                        sources.insert(function.start);
                    }
                }
            }
        }
        let tail_called: Vec<u64> = chunks
            .iter()
            .map(|chunk| chunk.start)
            .filter(|start| {
                let sources = jumped_to.get(start).map_or(0, FxHashSet::len);
                let opens_function = || {
                    let mut decoder = A::decode(image.bytes_from(*start)?, *start);
                    let first = decoder.next()?.insn?;
                    Some(A::opens_function(&first, decoder.next().and_then(|d| d.insn).as_ref()))
                };
                sources >= 2 || (sources == 1 && opens_function() == Some(true))
            })
            .collect();
        if !tail_called.is_empty() {
            for addr in tail_called {
                discovery.starts.entry(addr).or_insert(Origin::TailCall);
            }
            continue;
        }

        _phase = phase::scope("noreturn");
        let mut controls: Vec<Control> = functions.iter().chain(&chunks).flat_map(|f| f.controls.iter().copied()).collect();
        controls.par_sort_unstable_by_key(|c| c.addr);
        let mut extents: Vec<(u64, u64)> = functions.iter().chain(&chunks).map(|f| (f.start, f.end)).collect();
        extents.sort_unstable();
        let program = Program { controls, starts: &starts, extents, imports: &imports, tables: &tables, pointer_slots: &pointer_slots };

        // A compiler emits nothing after a call it knows will not return: the call is followed
        // by a trap, or ends the function. Padding after a call proves nothing, since an
        // aligned loop head can follow a call that returns. One such call site settles it for the
        // callee, even when the callee's own code has a return in it, as some C runtime exit
        // functions do. Only an extent that unwind information vouches for counts as "ends
        // the function": an extent inferred from layout may stop short at a wrong boundary.
        let terminal_callees: FxHashSet<u64> = functions
            .par_iter()
            .chain(&chunks)
            .flat_map_iter(|f| {
                let has_frame = frame_end.contains_key(&f.start);
                f.controls.iter().filter_map(move |control| {
                    let Flow::Call(target) = control.flow else { return None };
                    let ends_function = control.next == f.end && has_frame;
                    // Read the bytes themselves: a trap that pads the end of a function has
                    // been trimmed from its extent.
                    let trap_follows = || {
                        let insn = A::decode(image.bytes_from(control.next)?, control.next).next()?.insn?;
                        Some(A::flow(&insn, &A::State::default()) == Some(Flow::Halt))
                    };
                    (ends_function || trap_follows() == Some(true)).then_some(target)
                })
            })
            .collect();

        // Least fixpoint: a function joins the set once no path through it can return.
        let mut noreturn: FxHashSet<u64> = terminal_callees.into_iter().filter(|target| starts.binary_search(target).is_ok()).collect();
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
        _phase = phase::scope("unreached splits");
        let splits: Vec<u64> = functions
            .par_iter()
            .filter(|f| !frame_end.contains_key(&f.start) && !image.data_in_code)
            .filter_map(|f| {
                let reached = walk(f, &noreturn, &program);
                (reached.complete && reached.reach_end < f.end)
                    .then(|| next_function_start::<A>(image, reached.reach_end, f.end))
                    .flatten()
            })
            .collect();
        if splits.is_empty() {
            let Program { controls, extents, .. } = program;
            break (starts, functions, chunks, noreturn, controls, extents);
        }
        for addr in splits {
            discovery.starts.entry(addr).or_insert(Origin::Unreachable);
        }
    };

    // The chunks each function reaches become further ranges of its body.
    _phase = phase::scope("chunk ranges");
    let chunk_ranges: Vec<(u64, u64)> = chunks.iter().map(|c| (c.start, c.end)).collect();
    let extra_ranges: FxHashMap<u64, Vec<(u64, u64)>> = if chunks.is_empty() {
        FxHashMap::default()
    } else {
        let program = Program { controls, starts: &starts, extents, imports: &imports, tables: &tables, pointer_slots: &pointer_slots };
        functions
            .par_iter()
            .filter_map(|f| {
                let reached = walk(f, &noreturn, &program);
                let outside: Vec<(u64, u64)> = reached.reached.iter().copied().filter(|&(start, end)| end > start && (start < f.start || start >= f.end)).collect();
                let extra = intersect(&merge(outside), &chunk_ranges);
                (!extra.is_empty()).then_some((f.start, extra))
            })
            .collect()
    };

    _phase = phase::scope("fragments");
    let is_start = |addr: u64| starts.binary_search(&addr).is_ok();
    let leaves = |function: &Function, target: u64| target < function.start || target >= function.end;

    // A frame nothing refers to as a function, entered only by jumps from one other function,
    // is a split-off piece of that function.
    let mut jumped_from: FxHashMap<u64, Vec<u64>> = FxHashMap::default();
    for function in &functions {
        for control in &function.controls {
            if let Flow::Jump(target) | Flow::Branch(target) = control.flow {
                if leaves(function, target) && is_start(target) {
                    jumped_from.entry(target).or_default().push(function.start);
                }
            }
        }
    }
    let by_start: FxHashMap<u64, &Function> = functions.iter().map(|f| (f.start, f)).collect();
    // A piece of another function either jumps back into the middle of its owner or never
    // returns. A real function that is only ever tail-called from one place does neither.
    let behaves_like_fragment = |piece: &Function, owner: &Function| {
        let rejoins_owner = piece.controls.iter().any(|control| match control.flow {
            Flow::Jump(target) | Flow::Branch(target) => target > owner.start && target < owner.end,
            _ => false,
        });
        rejoins_owner || !piece.controls.iter().any(|control| control.flow == Flow::Return)
    };
    let fragment_of: FxHashMap<u64, u64> = jumped_from
        .iter()
        .filter(|&(target, sources)| {
            !discovery.referenced.contains(target)
                // An entry point known only from layout or from the jump itself.
                && matches!(
                    discovery.starts[target],
                    Origin::Frame | Origin::TailCall | Origin::GapAligned | Origin::GapEndbr | Origin::Unreachable
                )
                && sources.iter().all(|&source| source == sources[0])
                && behaves_like_fragment(by_start[target], by_start[&sources[0]])
        })
        .map(|(&target, sources)| (target, sources[0]))
        .collect();

    _phase = phase::scope("calls");
    let pieces: Vec<&Function> = functions.iter().chain(&chunks).collect();
    let mut calls: Vec<CallSite> = pieces
        .par_iter()
        .copied()
        .flat_map_iter(|function| {
            let fragment_of = &fragment_of;
            let noreturn = &noreturn;
            let imports = &imports;
            let pointer_slots = &pointer_slots;
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
                // A slot holds either an import or a relocated pointer to a local function.
                let through_slot =
                    |slot: u64, tail: bool| import(slot, tail).or_else(|| local(*pointer_slots.get(&slot)?, tail));
                let (target, noreturn, tail) = match control.flow {
                    Flow::Call(target) => imports.stub_slot(target).and_then(|slot| import(slot, false)).or_else(|| local(target, false)),
                    Flow::CallIndirect(Some(slot)) => through_slot(slot, false),
                    Flow::Jump(target) | Flow::Branch(target) if leaves(function, target) => {
                        imports.stub_slot(target).and_then(|slot| import(slot, true)).or_else(|| local(target, true))
                    }
                    Flow::JumpIndirect(Some(slot)) => through_slot(slot, true),
                    _ => None,
                }?;
                let conditional = matches!(control.flow, Flow::Branch(_));
                Some(CallSite { at: control.addr, target, noreturn, tail, conditional })
            })
        })
        .collect();
    calls.sort_unstable_by_key(|call| call.at);

    let noreturn_calls: Vec<u64> = calls.iter().filter(|call| call.noreturn && !call.tail).map(|call| call.at).collect();
    let used_slots: FxHashSet<u64> = calls
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

    // Strings sit where code points, or where a pointer in data points.
    // A string is used by taking its address, so only those references count as evidence.
    _phase = phase::scope("strings");
    // Addresses code takes that are data: an address in code is a function pointer.
    let from_code: FxHashSet<u64> = discovery.data_refs.iter().filter(|r| !r.2 && !image.is_code(r.1)).map(|&(_, to, _)| to).collect();
    let mut candidates: Vec<u64> = from_code.iter().copied().chain(image.relative_targets.iter().map(|&(_, to)| to)).collect();
    // A Mach-O image keeps its string literals in a section of their own, back to back, so
    // each is known whether or not anything points at its first byte. Swift code points 32
    // bytes before a literal, which lands inside the one before.
    let literals = image.sections.iter().find(|section| image.format == Format::MachO && section.name == "__TEXT,__cstring");
    if let Some(section) = literals {
        candidates.retain(|&addr| !section.contains(addr));
        let ends = section.data.iter().enumerate().filter(|&(_, &byte)| byte == 0).map(|(offset, _)| offset as u64 + 1);
        candidates.extend(std::iter::once(0).chain(ends).map(|offset| section.addr + offset).filter(|&addr| section.contains(addr)));
    }
    candidates.sort_unstable();
    candidates.dedup();
    let is_literal = |addr: u64| from_code.contains(&addr) || literals.is_some_and(|section| section.contains(addr));
    let mut strings: Vec<StringLiteral> = candidates.par_iter().filter_map(|&addr| string_at(image, addr, is_literal(addr))).collect();
    // Class names in type information are strings too, though pointers go to the record
    // around them and not to the text.
    strings.extend(crate::rtti::type_names(image).into_iter().map(|(addr, text)| StringLiteral { addr, text, wide: false }));
    strings.sort_by_key(|string| string.addr);
    strings.dedup_by_key(|string| string.addr);
    // What is left in the data sections that reads as text, for the strings a program reaches
    // by an address it computes.
    strings.extend(crate::strings::unreferenced(image, &strings));
    strings.sort_by_key(|string| string.addr);

    // A function that is a single jump forwards to its target; an export name on such a thunk
    // is really the target's name.
    _phase = phase::scope("names");
    let thunk_target = |f: &Function| match f.controls.as_slice() {
        [Control { flow: Flow::Jump(target), .. }] if f.instructions == 1 => Some(*target),
        _ => None,
    };
    let mut names: FxHashMap<u64, String> =
        image.symbol_names.iter().map(|(&addr, symbol)| (addr, crate::names::display_name(symbol))).collect();
    for function in &functions {
        if let (Some(target), Some(name)) = (thunk_target(function), names.get(&function.start).cloned()) {
            names.entry(target).or_insert(name);
        }
    }

    // The stack-cookie check is too short to fingerprint and matters more than its size: the
    // decompiler has to know that a call to it changes nothing.
    if image.format == Format::Pe {
        for function in functions.iter().filter(|f| f.instructions <= 8) {
            let Some(bytes) = image.bytes_from(function.start) else { continue };
            let insns: Vec<A::Insn> = A::decode(bytes, function.start).take(2).map_while(|d| d.insn).collect();
            if A::checks_stack_cookie(&insns) {
                names.entry(function.start).or_insert_with(|| "__security_check_cookie".to_string());
            }
        }
    }

    // Statically linked library code carries no symbol, but its bytes are the same in every
    // program that links it. The built-in fingerprints come from Windows builds.
    _phase = phase::scope("fingerprints");
    if image.format == Format::Pe {
        let signatures = Signatures::builtin(image.machine);
        let recognised: Vec<(u64, &str)> = functions
            .par_iter()
            .filter(|f| !names.contains_key(&f.start))
            .filter_map(|f| Some((f.start, signatures.name(fingerprint(image, &pointer_slots, f.start, f.end)?)?)))
            .collect();
        names.extend(recognised.into_iter().map(|(addr, name)| (addr, name.to_string())));
    }

    // A virtual function nothing else names takes the name of its vtable slot, in the class
    // that has the fewest bases among those listing it: the one that introduced it.
    _phase = phase::scope("classes");
    let classes = crate::rtti::classes(image);
    let mut by_depth: Vec<&crate::report::Class> = classes.iter().collect();
    by_depth.sort_by_key(|class| class.bases.len());
    for class in by_depth {
        for (index, &method) in class.methods.iter().enumerate() {
            if starts.contains(&method) {
                names.entry(method).or_insert_with(|| format!("{}::vfunc_{index}", class.name));
            }
        }
    }

    // Objective-C methods are named by their class and selector, and message sends by the
    // selector they pass.
    _phase = phase::scope("objective-c");
    let mut classes = classes;
    let mut sends = Vec::new();
    if let Some(objc) = crate::objc::metadata(image) {
        for (method, name) in &objc.methods {
            names.entry(*method).or_insert_with(|| name.clone());
        }
        let ranges: Vec<(u64, u64)> = pieces.iter().map(|piece| (piece.start, piece.end)).collect();
        let case_targets: FxHashSet<u64> = discovery.jump_tables.iter().flat_map(|table| table.targets.iter().copied()).collect();
        sends = crate::objc::sends::<A>(image, &objc, &ranges, &calls, &case_targets);
        classes.extend(objc.classes);
    }

    _phase = phase::scope("report");
    // References seen in code that was decoded on a guess count now that the functions are
    // settled: those from inside a function, to data or to a function's entry.
    let mut extents: Vec<(u64, u64)> = pieces.iter().map(|piece| (piece.start, piece.end)).collect();
    extents.sort_unstable();
    let in_function = |addr: u64| extents[..extents.partition_point(|&(start, _)| start <= addr)].last().is_some_and(|&(_, end)| addr < end);
    let is_data = |addr: u64| image.section_at(addr).map_or_else(|| image.is_zero_filled(addr), |section| !section.executable);
    let mut data_refs = discovery.data_refs.clone();
    data_refs.extend(discovery.uncertain_refs.iter().copied().filter(|&(from, target, access)| {
        in_function(from) && (is_data(target) || (!access && extents.binary_search_by_key(&target, |&(start, _)| start).is_ok()))
    }));
    data_refs.sort_unstable();
    data_refs.dedup();
    Analysis {
        sends,
        data_refs: data_refs.into_iter().map(|(from, to, access)| DataRef { from, to, access }).collect(),
        classes,
        strings,
        name: image.name.clone(),
        instructions: functions.iter().chain(&chunks).map(|f| f.instructions).sum(),
        functions: functions
            .iter()
            .map(|f| AnalyzedFunction {
                addr: f.start,
                ranges: std::iter::once((f.start, f.end)).chain(extra_ranges.get(&f.start).into_iter().flatten().copied()).collect(),
                noreturn: noreturn.contains(&f.start),
                thunk: thunk_target(f).is_some(),
                origin: discovery.starts[&f.start],
                fragment_of: fragment_of.get(&f.start).copied(),
                name: names.get(&f.start).cloned(),
            })
            .collect(),
        noreturn_calls,
        jump_tables: discovery.jump_tables.clone(),
        calls,
        imports: import_list,
    }
}
