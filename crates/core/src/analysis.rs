//! Function recovery and non-returning call analysis for x86-64.
//!
//! Function starts come from `.eh_frame`, exports, the entry point, and then from the targets of
//! calls and tail jumps found while decoding. Each function is decoded linearly inside its range,
//! which is sound for compiler output because jump tables live in read-only data, not in code.

use rustc_hash::{FxHashMap, FxHashSet};

use rayon::prelude::*;

use crate::arch::{Arch, Flow, TextPointer};
use crate::discover::{discover, is_function_section};
use crate::image::{Format, Image, Machine};
use crate::noreturn::is_noreturn_import;
use crate::phase;
use crate::report::{AnalyzedFunction, Analysis, CallSite, CallTarget, DataRef, Import, Origin, StringLiteral};
use crate::signature::Signatures;
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

/// The parts of `[start, end)` that are code: all of it but the jump tables in `tables` that
/// lie among it. `tables` is sorted `[start, end)` ranges.
fn code_pieces(start: u64, end: u64, tables: &[(u64, u64)]) -> impl Iterator<Item = (u64, u64)> {
    let mut tables = tables[tables.partition_point(|&(table, _)| table < start)..].iter().take_while(move |&&(table, _)| table < end);
    let mut next = Some(start);
    std::iter::from_fn(move || {
        let from = next.filter(|&from| from < end || from == start)?;
        let (to, after) = tables.next().map_or((end, None), |&(table, after)| (table, Some(after)));
        next = after;
        Some((from, to))
    })
}

/// Decodes `[start, end)` linearly, stepping over `tables`, and keeps its control-flow
/// instructions. With `trim`, `end` is only an upper bound and the function ends before any
/// trailing padding. A call through a register goes where `register_calls` says, which
/// discovery learned on its way there.
fn decode<A: Arch>(image: &Image, start: u64, end: u64, trim: bool, tables: &[(u64, u64)], register_calls: &FxHashMap<u64, u64>) -> Function {
    let mut function = Function { start, end, controls: Vec::new(), instructions: 0 };
    let mut body_end = start;
    for (from, to) in code_pieces(start, end, tables) {
        let Some(bytes) = image.bytes_from(from) else {
            return function;
        };
        let bytes = &bytes[..bytes.len().min((to - from) as usize)];
        let mut state = A::State::default();
        for decoded in A::decode(image, bytes, from) {
            let Some(insn) = decoded.insn else { continue };
            function.instructions += 1;
            if !A::is_padding(&insn) {
                body_end = decoded.next_addr();
            }
            match A::flow(&insn, &state, image) {
                Some(flow) => {
                    let flow = match flow {
                        Flow::CallIndirect(None) => Flow::CallIndirect(register_calls.get(&decoded.addr).copied()),
                        flow => flow,
                    };
                    function.controls.push(Control { addr: decoded.addr, next: decoded.next_addr(), flow });
                    // The state only matters for resolving slots, so a fresh one after any control
                    // transfer is enough for a linear pass.
                    if A::FLOW_READS_STATE {
                        state = A::State::default();
                    }
                }
                None if A::FLOW_READS_STATE => A::step(&mut state, &insn),
                None => {}
            }
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
    /// Some path ran through code outside the function's own extent.
    left_extent: bool,
}

/// A function that may yet turn out never to return, while that is being worked out.
struct Open<'a> {
    function: &'a Function,
    /// Whether what its last walk found may no longer hold.
    due: bool,
    /// What its last walk found.
    may_return: bool,
    left_extent: bool,
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
    /// [`Arch::RUNS_ON`].
    runs_on: bool,
    /// [`Discovery::frame_ends`].
    frame_ends: &'a [u64],
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

    /// Whether the function at `entry` has a return in its extent. One that its compiler knew
    /// never returns has none.
    fn has_return(&self, entry: u64) -> bool {
        let Ok(index) = self.extents.binary_search_by_key(&entry, |&(start, _)| start) else { return false };
        let end = self.extents[index].1;
        self.controls[self.controls.partition_point(|c| c.addr < entry)..].iter().take_while(|c| c.addr < end).any(|c| c.flow == Flow::Return)
    }
}

/// Follows every path from the function's entry until it returns, stops, or reaches another
/// function's entry. A jump to code that is not an entry is followed even outside the function's
/// own extent, which is how a function reaches its cold part when that sits elsewhere. An
/// unresolved indirect jump counts as possibly returning.
///
/// `reached` is told each straight-line stretch of code that is reached, as `[start, end)`, in
/// no order. A stretch may lie outside the function's own extent.
fn walk(function: &Function, noreturn: &FxHashSet<u64>, program: &Program, mut reached: impl FnMut(u64, u64)) -> Walk {
    let controls = &program.controls;
    let imports = program.imports;
    let in_extent = |addr: u64| addr >= function.start && addr < function.end;
    // Nearly every path stays inside the extent, so what a path asks at each step is answered
    // from the function's own few controls where it can be: a search of the whole program's
    // misses the cache at every probe.
    let own = controls.partition_point(|c| c.addr < function.start)..controls.partition_point(|c| c.addr < function.end);
    let first_control_from = |addr: u64| match in_extent(addr) {
        true => own.start + controls[own.clone()].partition_point(|c| c.addr < addr),
        false => controls.partition_point(|c| c.addr < addr),
    };
    // The entry after the function's own is also the next one after any address in the extent
    // that it lies beyond.
    let following = program.next_start(function.start);
    let next_start = |addr: u64| if in_extent(addr) && following > addr { following } else { program.next_start(addr) };
    let mut seen = vec![false; own.len()];
    let mut seen_outside: FxHashSet<usize> = FxHashSet::default();
    let mut first_visit = |index: usize| match own.contains(&index) {
        true => !std::mem::replace(&mut seen[index - own.start], true),
        false => seen_outside.insert(index),
    };
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

    let mut result = Walk { may_return: false, reach_end: function.start, complete: true, left_extent: false };
    let mut pending = vec![function.start];
    while let Some(addr) = pending.pop() {
        // Everything up to the next control instruction falls through, unless another
        // function's entry comes first.
        let mut index = first_control_from(addr);
        let boundary = next_start(addr);
        let mut run_start = addr;
        // Whether the last control passed was a direct call to a function with a return in it.
        let mut called = false;
        loop {
            let Some(control) = controls.get(index).filter(|c| c.addr < boundary) else {
                // Ran off the end of a function, which only code that never returns does, or
                // into code that no function's extent covers, such as a linker veneer. The
                // second kind carries on somewhere this walk cannot see, so it may return.
                if in_extent(run_start) {
                    result.reach_end = function.end;
                    reached(run_start, function.end);
                } else if program.frame_ends.binary_search(&run_start).is_ok() {
                    // A block a call goes on into, which runs on into a routine it shares.
                    reached(run_start, boundary);
                }
                // `run_start == addr` means nothing was decoded on the way: the jump itself
                // landed outside known code.
                if run_start == addr && !program.is_covered(addr) {
                    result.may_return = true;
                }
                // Running on into the next function is a tail call of it, when code leads
                // right up to its entry. Elsewhere than where functions run on, only a call that
                // comes back right at the entry does so: hand-written code such as MSVC's `cos`
                // calls a loader and comes back into the routine it shares. A compiler emits
                // nothing after a call it knows never returns, so the callee must have a return.
                let came_back = called && run_start == boundary;
                if (program.runs_on || came_back) && program.is_start(boundary) && program.is_covered(boundary - 1) && target_returns(boundary) {
                    result.may_return = true;
                }
                break;
            };
            if !first_visit(index) {
                reached(run_start, control.addr);
                break;
            }
            reached(run_start, control.next);
            run_start = control.next;
            called = matches!(control.flow, Flow::Call(target) if program.has_return(target));
            if in_extent(control.addr) {
                result.reach_end = result.reach_end.max(control.next);
            } else {
                result.left_extent = true;
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
                    // A call to a block that gives back this function's frame, or works in it,
                    // goes on in more of its own code.
                    if program.frame_ends.binary_search(&target).is_ok() {
                        pending.push(target);
                    }
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
    result
}

/// Where the code of a function without a frame ends, for images that keep data among the
/// code: the first unconditional terminator that no earlier forward branch jumps past. Decoding
/// up to the next function instead would read a trailing jump table as instructions.
fn code_end<A: Arch>(image: &Image, start: u64, bound: u64, tables: &FxHashMap<u64, &[u64]>, inline_tables: &[(u64, u64)]) -> u64 {
    let state = A::State::default();
    let mut furthest_target = start;
    for (from, to) in code_pieces(start, bound, inline_tables) {
        let Some(bytes) = image.bytes_from(from) else { return from };
        let bytes = &bytes[..bytes.len().min((to - from) as usize)];
        for decoded in A::decode(image, bytes, from) {
            let Some(insn) = decoded.insn else { return decoded.addr };
            match A::flow(&insn, &state, image) {
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
    let mut decoder = A::decode(image, bytes, from).skip_while(|d| d.insn.as_ref().is_some_and(A::is_padding));
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
        Machine::I8051 => analyze_with::<crate::i8051::I8051>(image),
        Machine::Thumb => analyze_with::<crate::thumb::Thumb>(image),
        Machine::Arm => analyze_with::<crate::arm::Arm>(image),
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
    // A table of trampoline entries is code with a known extent, like a function with a frame.
    let frame_end: FxHashMap<u64, u64> = frames.iter().chain(&image.banking.tables).copied().collect();

    drop(_phase);
    let mut discovery = discover::<A>(image, &frames);
    _phase = phase::scope("setup");
    let tables: FxHashMap<u64, &[u64]> = discovery.jump_tables.iter().map(|t| (t.jump, t.targets.as_slice())).collect();

    let pointer_slots: FxHashMap<u64, u64> = image.relative_targets.iter().copied().collect();

    _phase = phase::scope("classes");
    let mut classes = crate::rtti::classes(image);
    if classes.is_empty() {
        classes = crate::itanium::classes(image, &pointer_slots);
        // A virtual function is called through its vtable, and in an image that relocates
        // nothing its vtable slot is all that says it is a function.
        let methods = classes.iter().flat_map(|class| class.methods.iter().copied());
        for method in methods.filter(|&method| image.section_at(method).is_some_and(is_function_section)) {
            discovery.starts.entry(method).or_insert(Origin::DataPointer);
            discovery.referenced.insert(method);
        }
    }

    // Nothing calls a table of trampoline entries: what calls an entry calls the function the
    // entry reaches. The table is listed as one function, so that its code is listed at all.
    for &(table, _) in &image.banking.tables {
        discovery.starts.entry(table).or_insert(Origin::Export);
    }

    let inline_tables = std::mem::take(&mut discovery.inline_tables);
    let inline_tables = inline_tables.as_slice();
    let after_calls = std::mem::take(&mut discovery.after_calls);
    let frame_ends = std::mem::take(&mut discovery.frame_ends);
    let register_calls = std::mem::take(&mut discovery.register_calls);
    let register_calls = &register_calls;

    // Functions by the entry and the bound they were decoded from. A round of the loop below
    // that adds entry points starts over, and all but the functions next to the new entry
    // points come out as they did before.
    let mut decoded: FxHashMap<(u64, u64), Function> = FxHashMap::default();
    let (starts, functions, chunks, noreturn, controls, extents) = loop {
        _phase = phase::scope("decode functions");
        let starts: Vec<u64> = discovery.starts.keys().copied().collect();
        // A frame gives a function's end; otherwise the next entry point bounds it.
        let spans: Vec<(u64, u64)> = starts
            .iter()
            .enumerate()
            .map(|(index, &start)| match frame_end.get(&start) {
                Some(&end) if image.frames_merge => (start, starts.get(index + 1).map_or(end, |&next| end.min(next))),
                Some(&end) => (start, end),
                None => {
                    let section_end = image.section_at(start).map_or(start, |s| s.end());
                    (start, starts.get(index + 1).copied().unwrap_or(section_end).min(section_end))
                }
            })
            .collect();
        let reused: Vec<Option<Function>> = spans.iter().map(|span| decoded.remove(span)).collect();
        let functions: Vec<Function> = spans
            .par_iter()
            .zip(reused)
            .map(|(&(start, bound), reused)| {
                reused.unwrap_or_else(|| match frame_end.contains_key(&start) {
                    true => decode::<A>(image, start, bound, false, inline_tables, register_calls),
                    false if image.data_in_code => decode::<A>(image, start, code_end::<A>(image, start, bound, &tables, inline_tables), true, inline_tables, register_calls),
                    false => decode::<A>(image, start, bound, true, inline_tables, register_calls),
                })
            })
            .collect();

        // Where function extents are tight, code that a function reaches by a jump can lie
        // outside every extent: a cold block placed elsewhere, or a shared exit. Those chunks
        // are decoded too, so that a function can be followed into them.
        _phase = phase::scope("decode chunks");
        let chunks: Vec<Function> = if image.data_in_code {
            let covered: Vec<(u64, u64)> = functions.iter().map(|f| (f.start, f.end)).collect();
            uncovered(&discovery.code, &covered).into_iter().map(|(start, end)| decode::<A>(image, start, end, false, inline_tables, register_calls)).collect()
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
                    let mut decoder = A::decode(image, image.bytes_from(*start)?, *start);
                    let first = decoder.next()?.insn?;
                    Some(A::opens_function(&first, decoder.next().and_then(|d| d.insn).as_ref()))
                };
                sources >= 2 || (sources == 1 && opens_function() == Some(true))
            })
            .collect();
        // Go round again only for a start that is new. A chunk can begin at a start already: a
        // function whose first instruction runs past the next start decodes to nothing and leaves
        // its bytes uncovered. Each further round adds a start, and a section holds finitely many.
        let before = discovery.starts.len();
        for addr in tail_called {
            discovery.starts.entry(addr).or_insert(Origin::TailCall);
        }
        if discovery.starts.len() > before {
            decoded = spans.into_iter().zip(functions).collect();
            continue;
        }

        _phase = phase::scope("noreturn");
        let mut controls: Vec<Control> = functions.iter().chain(&chunks).flat_map(|f| f.controls.iter().copied()).collect();
        controls.par_sort_unstable_by_key(|c| c.addr);
        let mut extents: Vec<(u64, u64)> = functions.iter().chain(&chunks).map(|f| (f.start, f.end)).collect();
        extents.sort_unstable();
        let program = Program { controls, starts: &starts, extents, imports: &imports, tables: &tables, pointer_slots: &pointer_slots, runs_on: A::RUNS_ON, frame_ends: &frame_ends };

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
                        let insn = A::decode(image, image.bytes_from(control.next)?, control.next).next()?.insn?;
                        Some(A::flow(&insn, &A::State::default(), image) == Some(Flow::Halt))
                    };
                    (ends_function || trap_follows() == Some(true)).then_some(target)
                })
            })
            .collect();

        // Least fixpoint: a function joins the set once no path through it can return. What a
        // walk finds changes only when a function it asked about joins the set, and it asks at
        // the calls and jumps it passes. So after the first round only the functions that can
        // pass a call or jump to one that has just joined are walked again: those with one in
        // their extent, and those that leave their extent, which may pass any.
        let mut noreturn: FxHashSet<u64> = terminal_callees.into_iter().filter(|target| starts.binary_search(target).is_ok()).collect();
        let mut open: Vec<Open> = functions
            .iter()
            .filter(|f| !noreturn.contains(&f.start))
            .map(|function| Open { function, due: true, may_return: true, left_extent: false })
            .collect();
        loop {
            open.par_iter_mut().filter(|open| open.due).for_each(|open| {
                let walk = walk(open.function, &noreturn, &program, |_, _| {});
                (open.may_return, open.left_extent) = (walk.may_return, walk.left_extent);
            });
            let added: FxHashSet<u64> = open.iter().filter(|open| !open.may_return).map(|open| open.function.start).collect();
            if added.is_empty() {
                break;
            }
            // In address order, as the controls are.
            let asking: Vec<u64> = program
                .controls
                .iter()
                .filter(|control| {
                    let target = match control.flow {
                        Flow::Call(target) | Flow::Jump(target) | Flow::Branch(target) => Some(target),
                        Flow::CallIndirect(Some(slot)) | Flow::JumpIndirect(Some(slot)) => pointer_slots.get(&slot).copied(),
                        _ => None,
                    };
                    target.is_some_and(|target| added.contains(&target))
                })
                .map(|control| control.addr)
                .collect();
            let passes = |f: &Function| asking.get(asking.partition_point(|&addr| addr < f.start)).is_some_and(|&addr| addr < f.end);
            open.retain(|open| open.may_return);
            for open in &mut open {
                open.due = open.left_extent || passes(open.function);
            }
            noreturn.extend(added);
        }

        // An entry point that discovery took away, as the code before it comes back from a call
        // and runs on into it, is one after all where the call never returns.
        let before = discovery.starts.len();
        for &(start, _) in after_calls.iter().filter(|(_, callee)| noreturn.contains(callee)) {
            discovery.starts.entry(start).or_insert(Origin::Unreachable);
        }
        if discovery.starts.len() > before {
            decoded = spans.into_iter().zip(functions).collect();
            continue;
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
                let reached = walk(f, &noreturn, &program, |_, _| {});
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
        decoded = spans.into_iter().zip(functions).collect();
    };

    // The chunks each function reaches become further ranges of its body.
    _phase = phase::scope("chunk ranges");
    let chunk_ranges: Vec<(u64, u64)> = chunks.iter().map(|c| (c.start, c.end)).collect();
    let extra_ranges: FxHashMap<u64, Vec<(u64, u64)>> = if chunks.is_empty() {
        FxHashMap::default()
    } else {
        let program = Program { controls, starts: &starts, extents, imports: &imports, tables: &tables, pointer_slots: &pointer_slots, runs_on: A::RUNS_ON, frame_ends: &frame_ends };
        functions
            .par_iter()
            .filter_map(|f| {
                let mut outside: Vec<(u64, u64)> = Vec::new();
                walk(f, &noreturn, &program, |start, end| {
                    if end > start && (start < f.start || start >= f.end) {
                        outside.push((start, end));
                    }
                });
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
    // A slot the loader relocates holds an address, whatever text its bytes spell: in a small
    // image an address such as 0x202f reads as "/ ".
    let relocated: FxHashSet<u64> = image.relative_targets.iter().map(|&(slot, _)| slot).collect();
    candidates.retain(|addr| !relocated.contains(addr));
    candidates.sort_unstable();
    candidates.dedup();
    let is_literal = |addr: u64| from_code.contains(&addr) || literals.is_some_and(|section| section.contains(addr));
    let mut strings: Vec<StringLiteral> = candidates.par_iter().filter_map(|&addr| string_at(image, addr, is_literal(addr))).collect();
    // Class names in type information are strings too, though pointers go to the record
    // around them and not to the text.
    strings.extend(crate::rtti::type_names(image).into_iter().map(|(addr, text)| StringLiteral { addr, text, wide: false }));
    strings.sort_by_key(|string| string.addr);
    strings.dedup_by_key(|string| string.addr);
    // A wide string that something points into is short narrow strings packed back to back:
    // "<", "!" and "(" each with its zero read as the UTF-16 text "<!(".
    strings.retain(|string| {
        let end = || string.addr + 2 * string.text.encode_utf16().count() as u64;
        !string.wide || candidates[candidates.partition_point(|&at| at <= string.addr)..].first().is_none_or(|&at| at >= end())
    });
    // What is left in the data sections that reads as text, for the strings a program reaches
    // by an address it computes.
    strings.extend(crate::strings::unreferenced(image, &strings));
    strings.sort_by_key(|string| string.addr);
    // Text among the code, and the instructions that form its address.
    let mut text_refs = Vec::new();
    if A::TEXT_IN_CODE {
        let pieces = functions.par_iter().chain(&chunks).flat_map_iter(|piece| code_pieces(piece.start, piece.end, inline_tables));
        let pointers: Vec<TextPointer> = pieces.flat_map_iter(|(start, end)| A::text_pointers(image, start, end)).collect();
        let (among_code, pointers) = crate::strings::among_code(image, &discovery.code, pointers);
        text_refs = pointers;
        strings.extend(among_code);
        strings.sort_by_key(|string| string.addr);
        strings.extend(crate::strings::unreferenced_among_code(image, &discovery.code, &strings));
        strings.sort_by_key(|string| string.addr);
    }

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
            let insns: Vec<A::Insn> = A::decode(image, bytes, function.start).take(2).map_while(|d| d.insn).collect();
            if A::checks_stack_cookie(&insns) {
                names.entry(function.start).or_insert_with(|| "__security_check_cookie".to_string());
            }
        }
    }

    // Statically linked library code carries no symbol, but its bytes are the same in every
    // program that links it.
    _phase = phase::scope("fingerprints");
    let signatures = Signatures::builtin(image.format, image.machine);
    if !signatures.is_empty() {
        let recognised: Vec<(u64, &str)> = functions
            .par_iter()
            .filter(|f| !names.contains_key(&f.start))
            .filter_map(|f| Some((f.start, signatures.recognise(image, &pointer_slots, f.start, f.end)?)))
            .collect();
        names.extend(recognised.into_iter().map(|(addr, name)| (addr, name.to_string())));
    }
    // A compiler's own library is known by its code too. A fragment is no routine.
    let library = crate::library::routines(image.machine, image.compiler);
    if !library.is_empty() {
        let unnamed: Vec<u64> = functions.iter().map(|f| f.start).filter(|start| !names.contains_key(start) && !fragment_of.contains_key(start)).collect();
        names.extend(crate::library::recognise(image, &unnamed, library).into_iter().map(|(addr, routine)| (addr, routine.name.to_string())));
    }

    // A virtual function nothing else names takes the name of its vtable slot, in the class
    // that has the fewest bases among those listing it: the one that introduced it. A class
    // with several vtables numbers the slots of each from zero, and the first to claim a name
    // keeps it.
    _phase = phase::scope("classes");
    // A class without type information is known by the vtable its constructor stores.
    classes.extend(crate::vtables::untyped::<A>(image, &classes, &discovery.data_refs, &discovery.uncertain_refs, |addr| is_start(addr) && !fragment_of.contains_key(&addr)));
    let mut by_depth: Vec<&crate::report::Class> = classes.iter().collect();
    by_depth.sort_by_key(|class| class.bases.len());
    let mut slot_names: FxHashSet<String> = FxHashSet::default();
    for class in by_depth {
        for (index, &method) in class.methods.iter().enumerate() {
            if is_start(method) && !names.contains_key(&method) {
                let name = format!("{}::vfunc_{index}", class.name);
                if slot_names.insert(name.clone()) {
                    names.insert(method, name);
                }
            }
        }
    }

    // Objective-C methods are named by their class and selector, and message sends by the
    // selector they pass and the receiver they can be seen to go to.
    _phase = phase::scope("objective-c");
    let mut sends = Vec::new();
    let swift = crate::swift::metadata(image).unwrap_or_default();
    if let Some(objc) = crate::objc::metadata(image) {
        for (method, name) in &objc.methods {
            names.entry(*method).or_insert_with(|| name.clone());
        }
        let ranges: Vec<(u64, u64)> = pieces.iter().map(|piece| (piece.start, piece.end)).collect();
        let case_targets: FxHashSet<u64> = discovery.jump_tables.iter().flat_map(|table| table.targets.iter().copied()).collect();
        let swift_methods: Vec<(u64, &str)> = swift.instance_methods.iter().map(|&(method, class)| (method, swift.types[class].name.as_str())).collect();
        sends = crate::objc::sends::<A>(image, &objc, &swift_methods, &ranges, &calls, &case_targets);
        classes.extend(objc.classes);
    }

    // What Swift's metadata calls the functions it refers to, for those nothing else names.
    for (function, name) in swift.names {
        names.entry(function).or_insert(name);
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
    data_refs.extend(text_refs.iter().map(|pointer| (pointer.from, pointer.to, false)));
    data_refs.sort_unstable();
    data_refs.dedup();
    // A body that ends where another function begins runs on into it, unless its last
    // instruction sends control elsewhere. Elsewhere than where functions run on, only one
    // whose last instruction is a call that returns, to a function with a return, does, as
    // `walk` has it.
    let has_return = |entry: u64| functions.binary_search_by_key(&entry, |f| f.start).is_ok_and(|index| functions[index].controls.iter().any(|c| c.flow == Flow::Return));
    let runs_on = |f: &Function| {
        let last = f.controls.last().filter(|control| control.next == f.end);
        let stops = last.is_some_and(|control| match control.flow {
            Flow::Jump(_) | Flow::JumpIndirect(_) | Flow::Return | Flow::Halt => true,
            Flow::Call(target) => noreturn.contains(&target),
            Flow::Branch(_) | Flow::CallIndirect(_) => false,
        });
        let comes_back = !stops && last.is_some_and(|control| matches!(control.flow, Flow::Call(target) if has_return(target)));
        let code_to_end = code_pieces(f.start, f.end, inline_tables).last().is_some_and(|(from, to)| from < to && to == f.end);
        ((A::RUNS_ON && !stops) || comes_back).then_some(f.end).filter(|&end| is_start(end) && code_to_end)
    };
    Analysis {
        sends,
        types: swift.types,
        data_refs: data_refs.into_iter().map(|(from, to, access)| DataRef { from, to, access }).collect(),
        classes,
        strings,
        name: image.name.clone(),
        instructions: functions.iter().chain(&chunks).map(|f| f.instructions).sum(),
        functions: functions
            .iter()
            .map(|f| AnalyzedFunction {
                addr: f.start,
                ranges: code_pieces(f.start, f.end, inline_tables).chain(extra_ranges.get(&f.start).into_iter().flatten().copied()).collect(),
                noreturn: noreturn.contains(&f.start),
                thunk: thunk_target(f).is_some(),
                origin: discovery.starts[&f.start],
                fragment_of: fragment_of.get(&f.start).copied(),
                runs_on: runs_on(f),
                name: names.get(&f.start).cloned(),
            })
            .collect(),
        noreturn_calls,
        jump_tables: discovery.jump_tables.clone(),
        calls,
        imports: import_list,
    }
}
