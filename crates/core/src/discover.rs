//! Code discovery: finds instructions and function entry points by following control flow.
//!
//! Starts from the entry point, exports, code pointers stored in data, and `.eh_frame` entries
//! when present. Follows calls and jumps, takes `lea`-computed code addresses as entry points,
//! then fills the gaps that nothing referenced.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use crate::arch::{Arch, Flow, Table};
use crate::image::{Image, Machine, Section};
use crate::noreturn::is_noreturn_import;
use crate::report::{JumpTable, Origin};

/// One executable section and which of its bytes begin a decoded instruction.
struct Region<'a> {
    section: &'a Section,
    is_instruction: Vec<bool>,
    /// Addresses that execution cannot fall into: the byte after a terminator or after padding.
    follows_break: Vec<bool>,
}

pub struct Discovery {
    /// Function entry points with the evidence that first identified each.
    pub starts: BTreeMap<u64, Origin>,
    /// Indirect jumps resolved through a jump table.
    pub jump_tables: Vec<JumpTable>,
    /// Addresses something calls, takes the address of, exports, or points to from data. A
    /// frame that none of these reach is a split-off piece of another function.
    pub referenced: HashSet<u64>,
    /// `(instruction, address, accessed)` for each data address an instruction refers to:
    /// `accessed` when it reads or writes there, otherwise it takes the address.
    pub data_refs: Vec<(u64, u64, bool)>,
    /// Every stretch of decoded instructions, as sorted `[start, end)` ranges.
    pub code: Vec<(u64, u64)>,
}

/// An address to decode from.
struct Pending<A: Arch> {
    addr: u64,
    /// Register state on arrival.
    state: A::State,
    /// False when the path here went through a jump table of unknown length, whose trailing
    /// entries may not be real. Such a path can decode code but must not be used as evidence.
    trusted: bool,
    /// The bytes here are only presumed to be code. What decoding them finds may resolve a
    /// jump table but creates no entry points.
    speculative: bool,
}

impl<A: Arch> Pending<A> {
    fn entry(addr: u64) -> Self {
        Pending { addr, state: A::State::default(), trusted: true, speculative: false }
    }
}

struct Explorer<'a, A: Arch> {
    image: &'a Image,
    regions: Vec<Region<'a>>,
    starts: BTreeMap<u64, Origin>,
    referenced: HashSet<u64>,
    /// Direct jumps as `(from, to)`, kept to recognise tail calls afterwards.
    jumps: Vec<(u64, u64)>,
    /// Addresses still to decode.
    pending: Vec<Pending<A>>,
    /// Untrusted addresses, decoded only once nothing trusted is left, so that a real path gets
    /// to shared code first and with the right state.
    deferred: Vec<Pending<A>>,
    /// Resolved tables with the jump that uses each.
    tables: Vec<(u64, Table)>,
    /// Indirect jumps decoded without enough known state to resolve them. A later path that
    /// arrives with more may still do so.
    unresolved: BTreeSet<u64>,
    /// Data addresses computed by `lea`. The next one after a table bounds its length.
    data_refs: BTreeSet<u64>,
    /// `(instruction, address, accessed)` for each data address an instruction refers to.
    data_ref_sites: Vec<(u64, u64, bool)>,
    /// Slot address to target for every pointer a relative relocation stores in data.
    pointer_slots: HashMap<u64, u64>,
    /// Every value a relocation stores, for telling addresses from look-alike constants.
    pointer_values: HashSet<u64>,
    /// Entry counts of tables that have no bounds check, learned from an earlier pass.
    known_lengths: HashMap<u64, usize>,
    /// `[start, end)` ranges from `.eh_frame`. Nothing strictly inside one becomes an entry point.
    frames: &'a [(u64, u64)],
}

impl<A: Arch> Explorer<'_, A> {
    fn region_index(&self, addr: u64) -> Option<usize> {
        self.regions.iter().position(|r| r.section.contains(addr))
    }

    fn inside_frame(&self, addr: u64) -> bool {
        let index = self.frames.partition_point(|&(start, _)| start <= addr);
        index > 0 && addr > self.frames[index - 1].0 && addr < self.frames[index - 1].1
    }

    fn add_start(&mut self, addr: u64, origin: Origin) {
        if matches!(origin, Origin::Call | Origin::AddressTaken | Origin::DataPointer | Origin::Export | Origin::Thunk) {
            self.referenced.insert(addr);
        }
        if self.region_index(addr).is_some() && !self.inside_frame(addr) && !self.starts.contains_key(&addr) {
            self.starts.insert(addr, origin);
            self.pending.push(Pending::entry(addr));
        }
    }

    fn queue(&mut self, pending: Pending<A>) {
        if pending.trusted { self.pending.push(pending) } else { self.deferred.push(pending) }
    }

    /// Whether a call lands on an import that never returns, directly or through a PLT stub.
    fn import_never_returns(&self, flow: Flow) -> bool {
        let slot = match flow {
            Flow::CallIndirect(slot) | Flow::JumpIndirect(slot) => slot,
            _ => None,
        };
        slot.and_then(|slot| self.image.import_slots.get(&slot)).is_some_and(|name| is_noreturn_import(name))
    }

    /// The frame containing `addr`, when unwind information covers it.
    fn frame_of(&self, addr: u64) -> Option<(u64, u64)> {
        let index = self.frames.partition_point(|&(start, _)| start <= addr);
        self.frames[..index].last().copied().filter(|&(_, end)| addr < end)
    }

    fn frame_end(&self, addr: u64) -> Option<u64> {
        self.frame_of(addr).map(|(_, end)| end)
    }

    /// Whether `target` can appear in the table of the switch at `jump`: it must be code, and
    /// inside the same frame when unwind information covers the jump. The frame's end address is
    /// allowed because compilers use it to fill cases they proved unreachable.
    fn is_case_target(&self, jump: u64, target: u64) -> bool {
        // Windows unwind entries describe pieces of functions, so a case in another entry is
        // normal there and the frame says nothing.
        if self.image.data_in_code {
            return self.is_case_code(target);
        }
        match self.frame_of(jump) {
            // The end address itself is not code, so it carries no marker.
            Some((_, end)) if target == end => true,
            Some((start, end)) => target >= start && target < end && A::marked_jump_target(self.image, target) != Some(false),
            None => self.region_index(target).is_some() && A::marked_jump_target(self.image, target) != Some(false),
        }
    }

    /// Whether `target` is code that an indirect jump may reach at all.
    fn is_case_code(&self, target: u64) -> bool {
        self.region_index(target).is_some() && A::marked_jump_target(self.image, target) != Some(false)
    }

    /// Decodes from every pending address until control flow ends or reaches known code.
    fn drain(&mut self) {
        while let Some(Pending { addr: start, mut state, trusted, speculative }) = self.pending.pop().or_else(|| self.deferred.pop()) {
            let Some(index) = self.region_index(start) else { continue };
            let section = self.regions[index].section;
            let mut after_call = false;
            for decoded in A::decode(&section.data[(start - section.addr) as usize..], start) {
                let offset = (decoded.addr - section.addr) as usize;
                if std::mem::replace(&mut self.regions[index].is_instruction[offset], true) {
                    if trusted {
                        self.retry_jump_ahead(index, decoded.addr, state);
                    }
                    break;
                }
                // Padding straight after a call means the call does not return: compilers pad
                // between functions, not after a call that falls through.
                let Some(insn) = decoded.insn.filter(|insn| !(after_call && A::is_padding(insn))) else {
                    self.regions[index].is_instruction[offset] = false;
                    break;
                };
                after_call = false;
                let Some(flow) = A::flow(&insn, &state) else {
                    if let Some((base, data)) = A::based_data_address(&insn, &state) {
                        if self.image.base != 0 && base == self.image.base {
                            self.data_refs.insert(data);
                        }
                    }
                    let accessed = A::memory_reference(&insn)
                        .filter(|_| !speculative)
                        .filter(|target| !A::ADDRESSES_ARE_RELOCATED || self.pointer_values.contains(target))
                        .filter(|&target| self.image.section_at(target).is_some_and(|s| !s.executable));
                    if let Some(target) = accessed {
                        self.data_ref_sites.push((decoded.addr, target, true));
                    }
                    let taken = A::address_taken(&insn, &state)
                        .filter(|_| !speculative)
                        .filter(|target| !A::ADDRESSES_ARE_RELOCATED || self.pointer_values.contains(target));
                    if let Some(target) = taken {
                        if self.region_index(target).is_some() {
                            self.add_start(target, Origin::AddressTaken);
                        } else {
                            self.data_refs.insert(target);
                            self.data_ref_sites.push((decoded.addr, target, false));
                        }
                    }
                    A::step(&mut state, &insn);
                    continue;
                };
                let ends_flow = match flow {
                    Flow::Call(target) => {
                        if !speculative {
                            self.add_start(target, Origin::Call);
                        }
                        false
                    }
                    Flow::CallIndirect(_) => self.import_never_returns(flow),
                    // A function that is nothing but a jump forwards to another function.
                    Flow::Jump(target) if decoded.addr == start && self.starts.contains_key(&start) => {
                        self.add_start(target, Origin::Thunk);
                        true
                    }
                    Flow::Jump(target) => {
                        if !speculative {
                            self.jumps.push((decoded.addr, target));
                        }
                        self.queue(Pending { addr: target, state, trusted, speculative });
                        true
                    }
                    Flow::Branch(target) => {
                        let (taken, fallthrough) = A::branch(state, &insn);
                        if !speculative {
                            self.jumps.push((decoded.addr, target));
                        }
                        self.queue(Pending { addr: target, state: taken, trusted, speculative });
                        state = fallthrough;
                        false
                    }
                    Flow::JumpIndirect(None) => {
                        let jump = decoded.addr;
                        let resolved = A::resolve_table(&state, self.image, &self.pointer_slots, &insn, &|target| {
                            self.is_case_target(jump, target)
                        }, &|target| self.is_case_code(target));
                        let resolved = resolved.map(|table| self.apply_known_length(table));
                        match resolved {
                            Some(table) => self.accept_table(jump, table, A::after_jump(state, &insn), trusted, speculative),
                            None => {
                                self.unresolved.insert(jump);
                            }
                        }
                        true
                    }
                    Flow::JumpIndirect(Some(_)) | Flow::Return | Flow::Halt => true,
                };
                if ends_flow {
                    if let Some(flag) = self.regions[index].follows_break.get_mut((decoded.next_addr() - section.addr) as usize) {
                        *flag = true;
                    }
                    break;
                }
                if matches!(flow, Flow::Call(_) | Flow::CallIndirect(_)) {
                    A::step(&mut state, &insn);
                    after_call = true;
                }
            }
        }
    }

    /// Cuts a table without a bounds check to the length an earlier pass worked out for it.
    fn apply_known_length(&self, mut table: Table) -> Table {
        if let (false, Some(&length)) = (table.bounded, self.known_lengths.get(&table.address)) {
            table.entries.truncate(length);
            table.bounded = true;
        }
        table
    }

    /// The length of each table that has no bounds check but is followed by another data
    /// address the code refers to. Tables are laid out back to back, so that address ends it.
    fn learned_lengths(&self) -> HashMap<u64, usize> {
        self.tables
            .iter()
            .filter(|(_, table)| !table.bounded)
            .filter_map(|(_, table)| {
                let next = self.data_refs.range(table.address + 1..).next()?;
                let length = ((next - table.address) / table.entry_size) as usize;
                (length <= table.entries.len()).then_some((table.address, length))
            })
            .collect()
    }

    /// Records a resolved table and queues its cases.
    fn accept_table(&mut self, jump: u64, table: Table, at_case: A::State, trusted: bool, speculative: bool) {
        let function_end = self.frame_end(jump);
        let trusted = trusted && table.bounded;
        // An entry equal to the function's end marks a case proven unreachable.
        let queue = if trusted { &mut self.pending } else { &mut self.deferred };
        queue.extend(
            table.entries.iter().filter(|&&target| Some(target) != function_end).map(|&addr| Pending { addr, state: at_case, trusted, speculative }),
        );
        self.unresolved.remove(&jump);
        // Tables sit back to back, so each table's address ends the one before it.
        self.data_refs.insert(table.address);
        self.tables.push((jump, table));
    }

    /// Called when a path runs into code that was already decoded. If an unresolved indirect
    /// jump follows in a straight line, replays the instructions up to it with this path's
    /// state, which may know the table that the first path to get there did not.
    fn retry_jump_ahead(&mut self, index: usize, addr: u64, mut state: A::State) {
        /// How far ahead a dispatch sequence can reasonably end.
        const REACH: u64 = 96;
        let Some(&jump) = self.unresolved.range(addr..addr + REACH).next() else { return };
        let section = self.regions[index].section;
        for decoded in A::decode(&section.data[(addr - section.addr) as usize..], addr) {
            let Some(insn) = decoded.insn else { return };
            match A::flow(&insn, &state) {
                None => A::step(&mut state, &insn),
                Some(Flow::JumpIndirect(None)) if decoded.addr == jump => {
                    let resolved = A::resolve_table(&state, self.image, &self.pointer_slots, &insn, &|target| {
                        self.is_case_target(jump, target)
                    }, &|target| self.is_case_code(target));
                    if let Some(table) = resolved {
                        let table = self.apply_known_length(table);
                        self.accept_table(jump, table, A::after_jump(state, &insn), true, false);
                    }
                    return;
                }
                // Any other control flow before the jump means it is not a straight line.
                Some(_) => return,
            }
        }
    }

    /// Final target sets. A table without a bounds check is cut at the next data address the
    /// code refers to, since tables are laid out back to back.
    fn jump_tables(&self) -> Vec<JumpTable> {
        let mut tables: Vec<JumpTable> = self
            .tables
            .iter()
            .map(|(jump, table)| {
                let mut count = table.entries.len();
                if !table.bounded {
                    if let Some(&next) = self.data_refs.range(table.address + 1..).next() {
                        count = count.min(((next - table.address) / table.entry_size) as usize);
                    }
                }
                let function_end = self.frame_end(*jump);
                let mut targets: Vec<u64> =
                    table.entries[..count].iter().copied().filter(|&target| Some(target) != function_end).collect();
                targets.sort_unstable();
                targets.dedup();
                JumpTable { jump: *jump, targets }
            })
            .collect();
        tables.sort_by_key(|t| t.jump);
        tables
    }

    /// Whether execution cannot fall into `addr`: it sits right after a terminator, or after a
    /// terminator followed only by padding.
    fn starts_after_break(&self, addr: u64) -> bool {
        let Some(index) = self.region_index(addr) else { return false };
        let region = &self.regions[index];
        let offset = (addr - region.section.addr) as usize;
        // Padding between functions is shorter than one alignment unit.
        let earliest = offset.saturating_sub(A::FUNCTION_ALIGN as usize - 1);
        let Some(break_at) = (earliest..=offset).rev().find(|&o| region.follows_break[o]) else {
            return false;
        };
        A::decode(&region.section.data[break_at..offset], 0).all(|decoded| decoded.insn.is_some_and(|insn| A::is_padding(&insn)))
    }

    /// Marks a jump target as an entry point when the jump is a tail call: it leaves the function
    /// containing it, and the target looks like the top of a function.
    ///
    /// "Leaves the function" means an entry point backed by strong evidence lies between the jump
    /// and its target. Entry points that were themselves inferred from jumps or gaps do not
    /// count, otherwise one wrong guess would promote every jump that crosses it.
    fn promote_tail_calls(&mut self) -> bool {
        let strong: BTreeSet<u64> = self
            .starts
            .iter()
            .filter(|(_, origin)| !matches!(origin, Origin::TailCall | Origin::GapAligned | Origin::GapEndbr))
            .map(|(&addr, _)| addr)
            .collect();
        let mut promoted = Vec::new();
        for &(from, to) in &self.jumps {
            if to == from || to % A::FUNCTION_ALIGN != 0 || self.starts.contains_key(&to) {
                continue;
            }
            let (low, high) = if to < from { (to, from) } else { (from, to) };
            if strong.range(low + 1..=high).next().is_some() && self.starts_after_break(to) {
                promoted.push(to);
            }
        }
        let before = self.starts.len();
        promoted.into_iter().for_each(|addr| self.add_start(addr, Origin::TailCall));
        self.starts.len() != before
    }

    /// Removes entry points that were inferred from layout alone when a jump shows they are
    /// part of a neighbouring function: a direct jump that crosses an entry point and lands on
    /// something that is not itself an entry point stays within one function, so every weak
    /// entry point it crosses is not real. Typical case: an aligned loop head that follows a call.
    fn demote_crossed_starts(&mut self) -> bool {
        // A code pointer in data may be a label and not a function: a computed-goto target, or
        // an exception filter or handler block, which Windows scope tables point at. A jump
        // across it within one function shows which.
        // Where the format is known to do that, any such pointer is weak evidence; elsewhere
        // only one that is not function-aligned.
        let labels_in_data = self.image.data_in_code;
        let is_weak = |addr: u64, origin: &Origin| match origin {
            Origin::TailCall | Origin::GapAligned | Origin::GapEndbr => true,
            Origin::DataPointer => labels_in_data || addr % A::FUNCTION_ALIGN != 0,
            _ => false,
        };
        let mut demoted = BTreeSet::new();
        for &(from, to) in &self.jumps {
            if from == to || self.starts.contains_key(&to) {
                continue;
            }
            // A jump into a different frame leaves the function, whatever lies between.
            if self.frame_of(to).is_some_and(|(start, end)| from < start || from >= end) {
                continue;
            }
            let (low, high) = if to < from { (to, from) } else { (from, to) };
            let mut crossed = self.starts.range(low + 1..=high);
            if crossed.clone().all(|(&addr, origin)| is_weak(addr, origin)) {
                demoted.extend(crossed.by_ref().map(|(&addr, _)| addr));
            }
        }
        demoted.iter().for_each(|addr| {
            self.starts.remove(addr);
        });
        !demoted.is_empty()
    }

    /// Removes entry points that are targets of a resolved jump table. A switch case or a
    /// computed-goto label is inside its function even when a pointer to it is stored in data.
    fn demote_case_targets(&mut self) {
        // Only tables of known length: an unbounded read may run into the next table.
        for (jump, table) in self.tables.iter().filter(|(_, table)| table.bounded) {
            for target in &table.entries {
                // A dispatch that jumps to its own function's entry is a loop, not a label.
                if self.starts.range(..=*jump).next_back().map(|(&start, _)| start) != Some(*target) {
                    if !matches!(self.starts.get(target), Some(Origin::Frame | Origin::Export | Origin::Call)) {
                        self.starts.remove(target);
                    }
                }
            }
        }
    }

    /// Removes entry points whose code runs in another function's stack frame. Windows scope
    /// tables point at exception filters and handlers, and functions call their own `finally`
    /// blocks; all of these sit inside the function they belong to.
    fn demote_frame_borrowers(&mut self) {
        /// How many instructions decide it. A function sets up its frame within the first few.
        const PROBE: usize = 4;
        if !self.image.data_in_code {
            return;
        }
        let borrowers: Vec<u64> = self
            .starts
            .iter()
            .filter(|(_, origin)| !matches!(origin, Origin::Frame | Origin::Export | Origin::Thunk))
            .map(|(&addr, _)| addr)
            .filter(|&addr| {
                let Some(bytes) = self.image.bytes_from(addr) else { return false };
                let insns: Vec<A::Insn> = A::decode(bytes, addr).take(PROBE).map_while(|d| d.insn).collect();
                A::borrows_frame(&insns)
            })
            .collect();
        for addr in borrowers {
            self.starts.remove(&addr);
        }
    }

    /// Whether `addr` lies in the entries of a resolved jump table.
    fn in_table(&self, addr: u64) -> bool {
        self.tables.iter().any(|(_, table)| addr >= table.address && addr < table.address + table.entry_size * table.entries.len() as u64)
    }

    /// Every stretch of decoded instructions, merged where one runs straight into the next.
    fn code_ranges(&self) -> Vec<(u64, u64)> {
        let mut ranges: Vec<(u64, u64)> = Vec::new();
        for region in &self.regions {
            let section = region.section;
            let mut offset = 0;
            while offset < section.data.len() {
                if !region.is_instruction[offset] {
                    offset += 1;
                    continue;
                }
                let addr = section.addr + offset as u64;
                let len = A::decode(&section.data[offset..], addr).next().map_or(1, |d| u64::from(d.len.max(1)));
                match ranges.last_mut() {
                    Some(last) if last.1 == addr => last.1 = addr + len,
                    _ => ranges.push((addr, addr + len)),
                }
                offset += len as usize;
            }
        }
        ranges
    }

    /// Finds code that nothing referenced. Code following padding at an aligned address, or
    /// opening with an entry marker, starts a function. Other unreached code continues the
    /// function before it, such as switch cases behind an unresolved indirect jump.
    fn fill_gaps(&mut self) -> bool {
        let mut found = false;
        for index in 0..self.regions.len() {
            let section = self.regions[index].section;
            let mut offset = 0;
            // Offset just past the last data seen, or the section start: code beginning
            // exactly there follows a break even without padding in between.
            let mut after_data = 0;
            while offset < section.data.len() {
                let addr = section.addr + offset as u64;
                if self.regions[index].is_instruction[offset] {
                    // Skip the whole instruction, not only its first byte.
                    offset += A::decode(&section.data[offset..], addr).next().map_or(1, |d| usize::from(d.len.max(1)));
                    continue;
                }
                // Relocated pointers in a code section are a jump table. Step over the whole
                // table; what follows it cannot be fallen into.
                if self.image.data_in_code && self.pointer_slots.contains_key(&addr) {
                    let pointer_size = if self.image.machine == Machine::X86 { 4 } else { 8 };
                    offset += pointer_size;
                    after_data = offset;
                    continue;
                }
                // An unreached stretch: step over padding to the first real instruction.
                let mut decoder = A::decode(&section.data[offset..], addr);
                let mut skipped_padding = false;
                let mut candidate = None;
                let mut scanned_to = addr;
                for decoded in decoder.by_ref() {
                    if self.regions[index].is_instruction[(decoded.addr - section.addr) as usize] {
                        break;
                    }
                    scanned_to = decoded.next_addr();
                    let Some(insn) = decoded.insn else { break };
                    if A::is_padding(&insn) {
                        skipped_padding = true;
                        continue;
                    }
                    candidate = Some((decoded.addr, insn));
                    break;
                }
                // Always make progress, even past bytes that do not decode.
                offset = ((scanned_to - section.addr) as usize).max(offset + 1);
                let Some((addr, insn)) = candidate else { continue };
                if skipped_padding {
                    self.regions[index].follows_break[(addr - section.addr) as usize] = true;
                }
                let aligned = addr % A::FUNCTION_ALIGN == 0;
                let marked = A::is_entry_marker(&insn);
                let next = decoder.next().and_then(|d| d.insn);
                // An entry marker right after other code may open a landing pad at the end of a
                // function.
                let landing_pad = marked && !skipped_padding && next.as_ref().is_some_and(A::opens_landing_pad);
                let mut is_start = aligned && (skipped_padding || marked) && !landing_pad && !self.inside_frame(addr);
                if self.image.data_in_code {
                    // Where data sits among the code, unreached bytes are only trusted to be
                    // instructions when they look like a function: aligned behind padding, or
                    // opening like one behind padding or a terminator. A relocated pointer
                    // here is a jump-table entry.
                    let offset = (addr - section.addr) as usize;
                    let after_break = skipped_padding || self.regions[index].follows_break[offset] || offset == after_data;
                    let opens = after_break && A::opens_function(&insn, next.as_ref());
                    // After a table, alignment alone proves little: a byte table or more of the
                    // same function may follow. The start of the section is different.
                    let aligned_after_break = aligned && (skipped_padding || offset == 0);
                    is_start = (aligned_after_break || opens) && !self.inside_frame(addr);
                    if self.pointer_slots.contains_key(&addr) {
                        continue;
                    }
                    if !is_start {
                        // Inside an unwind entry the bytes belong to a function, so they are
                        // worth decoding to resolve what they dispatch to, without taking
                        // anything they call or refer to as evidence.
                        if self.frame_of(addr).is_some() && !self.in_table(addr) {
                            self.deferred.push(Pending { addr, state: A::State::default(), trusted: false, speculative: true });
                            found = true;
                            self.drain();
                        }
                        continue;
                    }
                }
                if is_start {
                    self.add_start(addr, if marked { Origin::GapEndbr } else { Origin::GapAligned });
                } else {
                    self.pending.push(Pending::entry(addr));
                }
                found = true;
                self.drain();
            }
        }
        found
    }
}

/// Code sections that hold functions. PLT stubs are resolved to imports instead.
pub fn is_function_section(section: &Section) -> bool {
    section.executable && !section.name.starts_with(".plt")
}

pub fn discover<A: Arch>(image: &Image, frames: &[(u64, u64)]) -> Discovery {
    // A table with no bounds check is read until something implausible, which can run into the
    // next table and send decoding to addresses that are not code. The first pass learns where
    // such tables really end; the second starts clean with that knowledge.
    let first = explore::<A>(image, frames, HashMap::new());
    let lengths = first.learned_lengths();
    let mut explorer = if lengths.is_empty() { first } else { explore::<A>(image, frames, lengths) };

    // An entry point is only real if its first bytes decoded.
    let starts = explorer
        .starts
        .iter()
        .map(|(&addr, &origin)| (addr, origin))
        .filter(|&(addr, _)| {
            explorer
                .region_index(addr)
                .is_some_and(|i| explorer.regions[i].is_instruction[(addr - explorer.regions[i].section.addr) as usize])
        })
        .collect();
    let mut data_refs = std::mem::take(&mut explorer.data_ref_sites);
    data_refs.sort_unstable();
    data_refs.dedup();
    let code = explorer.code_ranges();
    Discovery { starts, jump_tables: explorer.jump_tables(), referenced: explorer.referenced, data_refs, code }
}

fn explore<'a, A: Arch>(image: &'a Image, frames: &'a [(u64, u64)], known_lengths: HashMap<u64, usize>) -> Explorer<'a, A> {
    let regions = image
        .sections
        .iter()
        .filter(|s| is_function_section(s))
        .map(|section| Region {
            section,
            is_instruction: vec![false; section.data.len()],
            follows_break: vec![false; section.data.len()],
        })
        .collect();
    let mut explorer: Explorer<A> = Explorer {
        image,
        regions,
        starts: BTreeMap::new(),
        referenced: HashSet::new(),
        jumps: Vec::new(),
        pending: Vec::new(),
        deferred: Vec::new(),
        tables: Vec::new(),
        unresolved: BTreeSet::new(),
        data_refs: BTreeSet::new(),
        data_ref_sites: Vec::new(),
        pointer_slots: image.relative_targets.iter().copied().collect(),
        pointer_values: image.relative_targets.iter().map(|&(_, value)| value).collect(),
        known_lengths,
        frames,
    };

    let seeds = frames
        .iter()
        .map(|&(start, _)| (start, Origin::Frame))
        .chain(image.exports.iter().chain([&image.entry]).map(|&addr| (addr, Origin::Export)))
        // A relocated pointer that itself sits in a code section is an operand of an
        // instruction, which decoding will find, or a jump-table entry, which is a label.
        .chain(
            image
                .relative_targets
                .iter()
                .filter(|&&(slot, _)| !image.is_code(slot))
                .map(|&(_, target)| (target, Origin::DataPointer)),
        );
    for (seed, origin) in seeds {
        explorer.add_start(seed, origin);
    }
    explorer.drain();

    loop {
        let promoted = explorer.promote_tail_calls();
        explorer.drain();
        let filled = explorer.fill_gaps();
        if !promoted && !filled {
            break;
        }
    }

    explorer.demote_case_targets();
    while explorer.demote_crossed_starts() {}
    explorer.demote_frame_borrowers();

    explorer
}
