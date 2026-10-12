//! Code discovery: finds instructions and function entry points by following control flow.
//!
//! Starts from the entry point, exports, code pointers stored in data, and `.eh_frame` entries
//! when present. Follows calls and jumps, takes `lea`-computed code addresses as entry points,
//! then fills the gaps that nothing referenced.

use std::collections::{BTreeMap, BTreeSet};
use rustc_hash::{FxHashMap, FxHashSet};

use crate::arch::{Arch, Flow, Table};
use crate::image::{Image, Machine, Section};
use crate::noreturn::is_noreturn_import;
use crate::phase;
use crate::report::{JumpTable, Origin};

/// One executable section and which of its bytes begin a decoded instruction.
struct Region<'a> {
    section: &'a Section,
    /// Per byte, the length of the decoded instruction that begins there, or zero.
    insn_len: Vec<u8>,
    /// Per byte, what is known about the address: [`FOLLOWS_BREAK`], [`ASKED_AS_START`] and
    /// [`REFERENCED`]. One array, so that looking up a call's target touches one place in memory.
    flags: Vec<u8>,
    /// Per page, the time `insn_len` or a [`FOLLOWS_BREAK`] flag last changed in it, on the
    /// explorer's clock.
    changed: Vec<u32>,
    /// Per page, what the last gap scan of it did.
    scans: Vec<Option<PageScan>>,
    /// One bit per byte: the byte is part of a decoded instruction.
    covered: Vec<u64>,
    /// One bit per byte: two decoded instructions share the byte, as happens when data is
    /// decoded as code or a jump lands behind a prefix.
    shared: Vec<u64>,
}

/// Execution cannot fall into the address: it is the byte after a terminator or after padding.
const FOLLOWS_BREAK: u8 = 1;
/// The address was put forward as an entry point, whether or not it became one.
const ASKED_AS_START: u8 = 2;
/// Something calls the address, takes it, exports it, or points to it from data.
const REFERENCED: u8 = 4;

/// The gap scan works through a section in pages of this many bytes.
const PAGE: usize = 4096;

/// How far past the place it stops a scan may have looked: the longest stretch that is tested
/// for being a whole function, and the instruction after it.
const SCAN_REACH: usize = 1024;

/// What scanning one page for gaps came to. Scanning it again from the same position finds the
/// same, as long as nothing the scan looked at has changed.
#[derive(Clone, Copy)]
struct PageScan {
    /// The explorer's clock when the scan began.
    time: u32,
    /// How many jump tables were known, which decides whether bytes are table entries.
    tables: usize,
    /// `(offset, after_data)` on entering the page and on leaving it.
    entry: (usize, usize),
    exit: (usize, usize),
    found: bool,
}

impl Region<'_> {
    /// Marks the bytes of a decoded instruction.
    fn cover(&mut self, offset: usize, len: usize) {
        let (word, bit) = (offset / 64, offset % 64);
        let mask = (1u64 << len) - 1;
        self.shared[word] |= self.covered[word] & mask << bit;
        self.covered[word] |= mask << bit;
        if bit + len > 64 {
            self.shared[word + 1] |= self.covered[word + 1] & mask >> (64 - bit);
            self.covered[word + 1] |= mask >> (64 - bit);
        }
    }

    /// Where the instructions that follow the one at `offset` without a gap end: the offset
    /// that stepping from instruction to instruction would arrive at, found a word of the bit
    /// sets at a time. Bytes that no two instructions share and that follow an instruction
    /// are whole instructions, so only a shared byte or an uncovered one stops the run.
    fn end_of_run(&self, offset: usize) -> usize {
        let len = self.insn_len.len();
        let mut word = offset / 64;
        // Bytes before `offset` do not stop anything.
        let mut stops = (!self.covered[word] | self.shared[word]) & u64::MAX << (offset % 64);
        while stops == 0 {
            word += 1;
            if word * 64 >= len {
                return len;
            }
            stops = !self.covered[word] | self.shared[word];
        }
        let stop = (word * 64 + stops.trailing_zeros() as usize).min(len);
        if stop == offset {
            return offset + usize::from(self.insn_len[offset]);
        }
        if stop == len || self.covered[stop / 64] >> (stop % 64) & 1 == 0 {
            return stop;
        }
        // A shared byte: the run's last instruction is the one that holds the byte before it.
        let last = (offset..stop).rev().find(|&start| self.insn_len[start] != 0).expect("the instruction at `offset` at least");
        last + usize::from(self.insn_len[last])
    }

    fn follows_break(&self, offset: usize) -> bool {
        self.flags[offset] & FOLLOWS_BREAK != 0
    }

    /// Notes that `insn_len` or a [`FOLLOWS_BREAK`] flag changed at `offset`.
    fn touch(&mut self, offset: usize, time: u32) {
        self.changed[offset / PAGE] = time;
    }

    /// The result of the last scan of the page at `offset`, if a scan entering it in the state
    /// `entry` would see what that one saw.
    fn rescan(&self, entry: (usize, usize), tables: usize) -> Option<PageScan> {
        let scan = self.scans[entry.0 / PAGE]?;
        let last = ((scan.exit.0 + SCAN_REACH) / PAGE).min(self.changed.len() - 1);
        // A change made during the scan itself counts: the scan may have looked there first.
        let unchanged = self.changed[entry.0 / PAGE..=last].iter().all(|&changed| changed < scan.time);
        (scan.entry == entry && scan.tables == tables && unchanged).then_some(scan)
    }
}

pub struct Discovery {
    /// Function entry points with the evidence that first identified each.
    pub starts: BTreeMap<u64, Origin>,
    /// Indirect jumps resolved through a jump table.
    pub jump_tables: Vec<JumpTable>,
    /// Addresses something calls, takes the address of, exports, or points to from data. A
    /// frame that none of these reach is a split-off piece of another function.
    pub referenced: FxHashSet<u64>,
    /// `(instruction, address, accessed)` for each data address an instruction refers to:
    /// `accessed` when it reads or writes there, otherwise it takes the address.
    pub data_refs: Vec<(u64, u64, bool)>,
    /// Every stretch of decoded instructions, as sorted `[start, end)` ranges.
    pub code: Vec<(u64, u64)>,
}

/// A set of addresses, for asking of very many ranges whether any member lies inside. Most
/// ranges asked about are a short jump's, and are answered from a word or two of a bit set.
struct AddrSet {
    base: u64,
    bits: Vec<u64>,
    sorted: Vec<u64>,
}

impl AddrSet {
    /// A range longer than this is looked up in the sorted list instead of scanned bit by bit.
    const SCAN: u64 = 4096;

    /// `addrs` in ascending order.
    fn new(addrs: impl Iterator<Item = u64>) -> AddrSet {
        let sorted: Vec<u64> = addrs.collect();
        let base = sorted.first().copied().unwrap_or(0);
        let span = sorted.last().map_or(0, |last| last - base + 1);
        let mut bits = vec![0u64; span.div_ceil(64) as usize];
        for addr in &sorted {
            bits[((addr - base) / 64) as usize] |= 1 << ((addr - base) % 64);
        }
        AddrSet { base, bits, sorted }
    }

    fn contains(&self, addr: u64) -> bool {
        addr >= self.base && self.bits.get(((addr - self.base) / 64) as usize).is_some_and(|word| word >> ((addr - self.base) % 64) & 1 != 0)
    }

    /// Whether a member lies in `low..=high`.
    fn any_in(&self, low: u64, high: u64) -> bool {
        let Some(&last) = self.sorted.last() else { return false };
        let (low, high) = (low.max(self.base), high.min(last));
        if low > high {
            return false;
        }
        if high - low > Self::SCAN {
            let index = self.sorted.partition_point(|&addr| addr < low);
            return self.sorted.get(index).is_some_and(|&addr| addr <= high);
        }
        let (first, end) = (low - self.base, high - self.base);
        let (first_word, end_word) = ((first / 64) as usize, (end / 64) as usize);
        // Bits from `first` up in the first word, bits up to `end` in the last.
        let from = u64::MAX << (first % 64);
        let upto = u64::MAX >> (63 - end % 64);
        if first_word == end_word {
            return self.bits[first_word] & from & upto != 0;
        }
        self.bits[first_word] & from != 0 || self.bits[end_word] & upto != 0 || self.bits[first_word + 1..end_word].iter().any(|&word| word != 0)
    }
}

/// How far ahead of a path that runs into decoded code an unresolved indirect jump is looked
/// for: about as far as a dispatch sequence can reasonably end.
const RETRY_REACH: u64 = 96;

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
    referenced: FxHashSet<u64>,
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
    data_refs: Vec<u64>,
    /// `(instruction, address, accessed)` for each data address an instruction refers to.
    data_ref_sites: Vec<(u64, u64, bool)>,
    /// Slot address to target for every pointer a relative relocation stores in data.
    pointer_slots: &'a FxHashMap<u64, u64>,
    /// Every value a relocation stores, for telling addresses from look-alike constants.
    pointer_values: &'a FxHashSet<u64>,
    /// Entry counts of tables that have no bounds check, learned from an earlier pass.
    known_lengths: FxHashMap<u64, usize>,
    /// `[start, end)` ranges from `.eh_frame`. Nothing strictly inside one becomes an entry point.
    frames: &'a [(u64, u64)],
    /// Counts the page scans of the gap search, and dates changes to what those scans read.
    clock: u32,
    /// `[start, end)` of every section that holds no code, sorted.
    data_sections: Vec<(u64, u64)>,
}

impl<A: Arch> Explorer<'_, A> {
    fn region_index(&self, addr: u64) -> Option<usize> {
        self.regions.iter().position(|r| r.section.contains(addr))
    }

    /// Whether `addr` is in a section that holds no code.
    /// Records that the instruction at `at` reads or writes the data at `target`. Reading a slot
    /// the loader fills with an address in this image also takes that address: a global or a
    /// function reached through the global offset table.
    fn note_access(&mut self, at: u64, target: u64) {
        self.data_ref_sites.push((at, target, true));
        if let Some(&pointee) = self.pointer_slots.get(&target) {
            self.data_ref_sites.push((at, pointee, false));
        }
    }

    fn is_data(&self, addr: u64) -> bool {
        let index = self.data_sections.partition_point(|&(start, _)| start <= addr);
        index > 0 && addr < self.data_sections[index - 1].1
    }

    fn inside_frame(&self, addr: u64) -> bool {
        let index = self.frames.partition_point(|&(start, _)| start <= addr);
        index > 0 && addr > self.frames[index - 1].0 && addr < self.frames[index - 1].1
    }

    fn add_start(&mut self, addr: u64, origin: Origin) {
        let referenced = matches!(origin, Origin::Call | Origin::AddressTaken | Origin::DataPointer | Origin::Export | Origin::Thunk);
        let Some(index) = self.region_index(addr) else {
            if referenced {
                self.referenced.insert(addr);
            }
            return;
        };
        let region = &mut self.regions[index];
        let flags = &mut region.flags[(addr - region.section.addr) as usize];
        if referenced && *flags & REFERENCED == 0 {
            *flags |= REFERENCED;
            self.referenced.insert(addr);
        }
        // Whether an address becomes an entry point depends neither on who asks nor on when,
        // and most addresses are asked about many times: once per call to them.
        if *flags & ASKED_AS_START != 0 {
            return;
        }
        *flags |= ASKED_AS_START;
        if !self.inside_frame(addr) && !self.starts.contains_key(&addr) {
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
        // One decoder per section, made when first needed.
        let mut decoders: Vec<Option<A::Decoder<'_>>> = self.regions.iter().map(|_| None).collect();
        loop {
            // Most branch targets have been decoded by the time their turn comes. Those are
            // looked at where they lie: taking one off the queue copies its whole state.
            let queue = if self.pending.is_empty() { &mut self.deferred } else { &mut self.pending };
            let Some(next) = queue.last() else { break };
            let region = self.regions.iter().position(|r| r.section.contains(next.addr));
            let decoded = region.is_some_and(|index| self.regions[index].insn_len[(next.addr - self.regions[index].section.addr) as usize] != 0);
            if region.is_none() || decoded && !(next.trusted && self.unresolved.range(next.addr..next.addr + RETRY_REACH).next().is_some()) {
                queue.pop();
                continue;
            }
            let Some(Pending { addr: start, mut state, trusted, speculative }) = queue.pop() else { break };
            let index = region.expect("checked above");
            let section = self.regions[index].section;
            if decoded {
                self.retry_jump_ahead(index, start, state);
                continue;
            }
            let mut after_call = false;
            let decoder = decoders[index].get_or_insert_with(|| A::decoder(&section.data, section.addr));
            for decoded in A::decode_from(decoder, (start - section.addr) as usize) {
                let offset = (decoded.addr - section.addr) as usize;
                if std::mem::replace(&mut self.regions[index].insn_len[offset], decoded.len.max(1)) != 0 {
                    // Decoded before, and to the same length.
                    if trusted {
                        self.retry_jump_ahead(index, decoded.addr, state);
                    }
                    break;
                }
                // Padding straight after a call means the call does not return: compilers pad
                // between functions, not after a call that falls through.
                let clock = self.clock;
                self.regions[index].touch(offset, clock);
                let Some(insn) = decoded.insn.filter(|insn| !(after_call && A::is_padding(insn))) else {
                    self.regions[index].insn_len[offset] = 0;
                    break;
                };
                after_call = false;
                self.regions[index].cover(offset, usize::from(decoded.len.max(1)));
                let Some(flow) = A::flow(&insn, &state) else {
                    if let Some((base, data)) = A::based_data_address(&insn, &state) {
                        if self.image.base != 0 && base == self.image.base {
                            self.data_refs.push(data);
                            if !speculative && self.is_data(data) {
                                self.data_ref_sites.push((decoded.addr, data, true));
                            }
                        }
                    }
                    let accessed = A::memory_reference(&insn, &state)
                        .filter(|_| !speculative)
                        .filter(|target| !A::ADDRESSES_ARE_RELOCATED || self.pointer_values.contains(target))
                        .filter(|&target| self.is_data(target));
                    if let Some(target) = accessed {
                        self.note_access(decoded.addr, target);
                    }
                    if let Some(target) = A::offset_address(&insn, &state).filter(|&target| !speculative && self.is_data(target)) {
                        self.data_ref_sites.push((decoded.addr, target, false));
                    }
                    /// Offsets from a pointer further than this are not fields of what it points to.
                    const FARTHEST_FIELD: u64 = 1 << 20;
                    let through = A::through_pointer(&insn, &state).filter(|&(_, offset, _)| !speculative && offset < FARTHEST_FIELD);
                    if let Some((pointee, offset, access)) = through.and_then(|(slot, offset, access)| Some((*self.pointer_slots.get(&slot)?, offset, access))) {
                        if self.is_data(pointee) && self.is_data(pointee + offset) {
                            if access {
                                self.note_access(decoded.addr, pointee + offset);
                            } else {
                                self.data_ref_sites.push((decoded.addr, pointee + offset, false));
                            }
                        }
                    }
                    let taken = A::address_taken(&insn, &state)
                        .filter(|_| !speculative)
                        .filter(|target| !A::ADDRESSES_ARE_RELOCATED || self.pointer_values.contains(target));
                    if let Some(target) = taken {
                        if self.region_index(target).is_some() {
                            self.add_start(target, Origin::AddressTaken);
                            // Code whose address is taken is a callback or a method table entry,
                            // and who takes it is worth as much as who calls it.
                            self.data_ref_sites.push((decoded.addr, target, false));
                        } else {
                            self.data_refs.push(target);
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
                        let taken = A::branch(&mut state, &insn);
                        if !speculative {
                            self.jumps.push((decoded.addr, target));
                        }
                        self.queue(Pending { addr: target, state: taken, trusted, speculative });
                        false
                    }
                    Flow::JumpIndirect(None) => {
                        let jump = decoded.addr;
                        let resolved = A::resolve_table(&state, self.image, self.pointer_slots, &insn, &|target| {
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
                    let after = (decoded.next_addr() - section.addr) as usize;
                    if after < section.data.len() && !self.regions[index].follows_break(after) {
                        self.regions[index].flags[after] |= FOLLOWS_BREAK;
                        self.regions[index].touch(after, clock);
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

    /// The data addresses the code refers to, in order. They are only asked about once
    /// exploring is over, so they are collected unsorted.
    fn sorted_data_refs(&self) -> Vec<u64> {
        let mut data_refs = self.data_refs.clone();
        data_refs.sort_unstable();
        data_refs.dedup();
        data_refs
    }

    /// The length of each table that has no bounds check but is followed by another data
    /// address the code refers to. Tables are laid out back to back, so that address ends it.
    fn learned_lengths(&self) -> FxHashMap<u64, usize> {
        let data_refs = self.sorted_data_refs();
        self.tables
            .iter()
            .filter(|(_, table)| !table.bounded)
            .filter_map(|(_, table)| {
                let next = data_refs.get(data_refs.partition_point(|&addr| addr <= table.address))?;
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
        self.data_refs.push(table.address);
        self.tables.push((jump, table));
    }

    /// Called when a path runs into code that was already decoded. If an unresolved indirect
    /// jump follows in a straight line, replays the instructions up to it with this path's
    /// state, which may know the table that the first path to get there did not.
    fn retry_jump_ahead(&mut self, index: usize, addr: u64, mut state: A::State) {
        let Some(&jump) = self.unresolved.range(addr..addr + RETRY_REACH).next() else { return };
        let section = self.regions[index].section;
        for decoded in A::decode(&section.data[(addr - section.addr) as usize..], addr) {
            let Some(insn) = decoded.insn else { return };
            match A::flow(&insn, &state) {
                None => A::step(&mut state, &insn),
                Some(Flow::JumpIndirect(None)) if decoded.addr == jump => {
                    let resolved = A::resolve_table(&state, self.image, self.pointer_slots, &insn, &|target| {
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
        let data_refs = self.sorted_data_refs();
        let mut tables: Vec<JumpTable> = self
            .tables
            .iter()
            .map(|(jump, table)| {
                let mut count = table.entries.len();
                if !table.bounded {
                    if let Some(&next) = data_refs.get(data_refs.partition_point(|&addr| addr <= table.address)) {
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

    /// Whether execution cannot fall into `addr`: it sits right after a terminator or a jump
    /// table, or after one of those followed only by padding.
    fn starts_after_break(&self, addr: u64) -> bool {
        let Some(index) = self.region_index(addr) else { return false };
        let region = &self.regions[index];
        let offset = (addr - region.section.addr) as usize;
        // Padding between functions is shorter than one alignment unit.
        let earliest = offset.saturating_sub(A::FUNCTION_ALIGN as usize - 1);
        let pointer_size = if self.image.machine == Machine::X86 { 4 } else { 8 };
        let after_table = |o: usize| {
            self.image.data_in_code && o >= pointer_size && self.pointer_slots.contains_key(&(region.section.addr + (o - pointer_size) as u64))
        };
        let Some(break_at) = (earliest..=offset).rev().find(|&o| region.follows_break(o) || after_table(o)) else {
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
        let strong = AddrSet::new(
            self.starts.iter().filter(|(_, origin)| !matches!(origin, Origin::TailCall | Origin::GapAligned | Origin::GapEndbr)).map(|(&addr, _)| addr),
        );
        let starts = AddrSet::new(self.starts.keys().copied());
        let mut promoted = Vec::new();
        for &(from, to) in &self.jumps {
            if to == from || to % A::FUNCTION_ALIGN != 0 || starts.contains(to) {
                continue;
            }
            let (low, high) = if to < from { (to, from) } else { (from, to) };
            if strong.any_in(low + 1, high) && self.starts_after_break(to) {
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
        let starts = AddrSet::new(self.starts.keys().copied());
        let mut demoted = BTreeSet::new();
        for &(from, to) in &self.jumps {
            let (low, high) = if to < from { (to, from) } else { (from, to) };
            // Nearly every jump stays inside its function and crosses nothing.
            if from == to || starts.contains(to) || !starts.any_in(low + 1, high) {
                continue;
            }
            // A jump into a different frame leaves the function, whatever lies between.
            if self.frame_of(to).is_some_and(|(start, end)| from < start || from >= end) {
                continue;
            }
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
    /// Removes entry points that are the address of a resolved jump table. Mach-O compilers put
    /// a function's tables after its code, and the dispatch takes a table's address just as
    /// other code takes a function's.
    fn demote_table_addresses(&mut self) {
        for (_, table) in &self.tables {
            if self.starts.get(&table.address) == Some(&Origin::AddressTaken) {
                self.starts.remove(&table.address);
            }
        }
    }

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
    /// Whether the unreached bytes at `addr` are a whole function nothing refers to: they decode
    /// without a gap to a return or a jump elsewhere, and padding or known code follows.
    /// `may_call` says whether calls are allowed in it; a function without an unwind entry, where
    /// others have one, is a leaf and makes none.
    fn is_whole_function(&self, index: usize, addr: u64, may_call: bool) -> bool {
        const LONGEST: usize = 48;
        let region = &self.regions[index];
        let section = region.section;
        let known = |at: u64| ((at - section.addr) as usize) < section.data.len() && region.insn_len[(at - section.addr) as usize] != 0;
        let state = A::State::default();
        let mut decoder = A::decode(&section.data[(addr - section.addr) as usize..], addr);
        for decoded in decoder.by_ref().take(LONGEST) {
            let Some(insn) = decoded.insn else { return false };
            let inside = (decoded.addr..decoded.next_addr()).any(|at| known(at) || self.pointer_slots.contains_key(&at));
            if inside || A::is_padding(&insn) || self.frame_of(decoded.addr).is_some() {
                return false;
            }
            match A::flow(&insn, &state) {
                Some(Flow::Call(target)) if !may_call || self.region_index(target).is_none() => return false,
                Some(Flow::CallIndirect(_)) if !may_call => return false,
                Some(Flow::Halt | Flow::JumpIndirect(None)) => return false,
                Some(Flow::Branch(target)) if target < addr || self.region_index(target).is_none() => return false,
                Some(Flow::Jump(target)) if self.region_index(target).is_none() => return false,
                Some(Flow::Return | Flow::Jump(_) | Flow::JumpIndirect(Some(_))) => {
                    let end = decoded.next_addr();
                    // A lone `ret` is more often the tail of the function before it.
                    if end - addr < 3 {
                        return false;
                    }
                    let padded = decoder.next().is_some_and(|next| next.insn.as_ref().is_some_and(A::is_padding));
                    return padded || known(end) || end == section.addr + section.data.len() as u64 || self.frame_of(end).is_some();
                }
                _ => {}
            }
        }
        false
    }

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
                let len = u64::from(region.insn_len[offset]);
                if len == 0 {
                    offset += 1;
                    continue;
                }
                let addr = section.addr + offset as u64;
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
                // A page that looks as it did the last time is not scanned again. After the
                // first scan that is nearly every page, and every scan but the last finds
                // something somewhere.
                if let Some(scan) = self.regions[index].rescan((offset, after_data), self.tables.len()) {
                    (offset, after_data) = scan.exit;
                    found |= scan.found;
                    continue;
                }
                self.clock += 1;
                let (time, entry) = (self.clock, (offset, after_data));
                let found_before = std::mem::replace(&mut found, false);
                let page_end = ((offset / PAGE + 1) * PAGE).min(section.data.len());
                while offset < page_end {
                    let addr = section.addr + offset as u64;
                    let known = usize::from(self.regions[index].insn_len[offset]);
                    if known != 0 {
                        // Skip the whole instruction, not only its first byte, and with it every
                        // instruction that follows without a gap.
                        offset = self.regions[index].end_of_run(offset);
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
                        if self.regions[index].insn_len[(decoded.addr - section.addr) as usize] != 0 {
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
                    let at = (addr - section.addr) as usize;
                    if skipped_padding && !self.regions[index].follows_break(at) {
                        self.regions[index].flags[at] |= FOLLOWS_BREAK;
                        let clock = self.clock;
                        self.regions[index].touch(at, clock);
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
                        let at = (addr - section.addr) as usize;
                        let after_break = skipped_padding || self.regions[index].follows_break(at) || at == after_data;
                        let opens = after_break && A::opens_function(&insn, next.as_ref());
                        // After a table, alignment alone proves little: a byte table or more of the
                        // same function may follow. The start of the section is different.
                        let aligned_after_break = aligned && (skipped_padding || at == 0);
                        if self.pointer_slots.contains_key(&addr) {
                            // The padding scan stopped on a table entry; resume after that entry.
                            let pointer_size = if self.image.machine == Machine::X86 { 4 } else { 8 };
                            offset = (addr - section.addr) as usize + pointer_size;
                            after_data = offset;
                            continue;
                        }
                        // A function with no unwind entry calls nothing; one that starts on an
                        // alignment boundary straight after a terminator may call.
                        let unwound_elsewhere = !self.frames.is_empty() && self.frame_of(addr).is_none();
                        let whole = after_break
                            && (unwound_elsewhere && self.is_whole_function(index, addr, false)
                                || aligned && self.is_whole_function(index, addr, true));
                        is_start = (aligned_after_break || opens || whole) && !self.inside_frame(addr);
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
                self.regions[index].scans[entry.0 / PAGE] = Some(PageScan { time, tables: self.tables.len(), entry, exit: (offset, after_data), found });
                found |= found_before;
            }
        }
        found
    }
}


/// Code sections that hold functions. PLT stubs are resolved to imports instead.
pub fn is_function_section(section: &Section) -> bool {
    section.executable && !section.is_stubs()
}

pub fn discover<A: Arch>(image: &Image, frames: &[(u64, u64)]) -> Discovery {
    // A table with no bounds check is read until something implausible, which can run into the
    // next table and send decoding to addresses that are not code. The first pass learns where
    // such tables really end; the second starts clean with that knowledge.
    let _phase = phase::scope("discover");
    let pointers = {
        let _phase = phase::scope("discover/pointers");
        Pointers::new(image)
    };
    let first = explore::<A>(image, frames, &pointers, FxHashMap::default());
    let lengths = first.learned_lengths();
    let mut explorer = if lengths.is_empty() { first } else { explore::<A>(image, frames, &pointers, lengths) };

    // An entry point is only real if its first bytes decoded.
    let starts = explorer
        .starts
        .iter()
        .map(|(&addr, &origin)| (addr, origin))
        .filter(|&(addr, _)| {
            explorer
                .region_index(addr)
                .is_some_and(|i| explorer.regions[i].insn_len[(addr - explorer.regions[i].section.addr) as usize] != 0)
        })
        .collect();
    let mut data_refs = std::mem::take(&mut explorer.data_ref_sites);
    data_refs.sort_unstable();
    data_refs.dedup();
    let _phase = phase::scope("discover/code ranges");
    let code = explorer.code_ranges();
    Discovery { starts, jump_tables: explorer.jump_tables(), referenced: explorer.referenced, data_refs, code }
}

/// What the image's relative relocations say, in the forms exploring looks them up.
struct Pointers {
    /// Slot address to target.
    slots: FxHashMap<u64, u64>,
    /// Every target.
    values: FxHashSet<u64>,
    /// Targets of the slots outside code sections, in slot order. A relocated pointer that
    /// itself sits in a code section is an operand of an instruction, which decoding will find,
    /// or a jump-table entry, which is a label.
    from_data: Vec<u64>,
}

impl Pointers {
    fn new(image: &Image) -> Pointers {
        let code: Vec<(u64, u64)> = image.sections.iter().filter(|s| s.executable).map(|s| (s.addr, s.end())).collect();
        let in_code = |slot: u64| code.iter().any(|&(start, end)| slot >= start && slot < end);
        Pointers {
            slots: image.relative_targets.iter().copied().collect(),
            values: image.relative_targets.iter().map(|&(_, value)| value).collect(),
            from_data: image.relative_targets.iter().filter(|&&(slot, _)| !in_code(slot)).map(|&(_, target)| target).collect(),
        }
    }
}

fn explore<'a, A: Arch>(image: &'a Image, frames: &'a [(u64, u64)], pointers: &'a Pointers, known_lengths: FxHashMap<u64, usize>) -> Explorer<'a, A> {
    let regions = image
        .sections
        .iter()
        .filter(|s| is_function_section(s))
        .map(|section| Region {
            section,
            insn_len: vec![0; section.data.len()],
            flags: vec![0; section.data.len()],
            changed: vec![0; section.data.len() / PAGE + 1],
            scans: vec![None; section.data.len() / PAGE + 1],
            covered: vec![0; section.data.len() / 64 + 2],
            shared: vec![0; section.data.len() / 64 + 2],
        })
        .collect();
    let _phase = phase::scope("discover/setup");
    let mut explorer: Explorer<A> = Explorer {
        image,
        regions,
        starts: BTreeMap::new(),
        referenced: FxHashSet::default(),
        jumps: Vec::new(),
        pending: Vec::new(),
        deferred: Vec::new(),
        tables: Vec::new(),
        unresolved: BTreeSet::new(),
        data_refs: Vec::new(),
        data_ref_sites: Vec::new(),
        pointer_slots: &pointers.slots,
        pointer_values: &pointers.values,
        known_lengths,
        frames,
        clock: 0,
        data_sections: {
            // Zero-filled memory is data as much as what the file stores.
            let mut ranges: Vec<(u64, u64)> = image.sections.iter().filter(|s| !s.executable).map(|s| (s.addr, s.end())).chain(image.zero_filled.iter().copied()).collect();
            ranges.sort_unstable();
            ranges
        },
    };

    drop(_phase);

    let seeds = frames
        .iter()
        .map(|&(start, _)| (start, Origin::Frame))
        .chain(image.exports.iter().chain([&image.entry]).map(|&addr| (addr, Origin::Export)))
        .chain(pointers.from_data.iter().map(|&target| (target, Origin::DataPointer)));
    {
        let _phase = phase::scope("discover/seeds");
        for (seed, origin) in seeds {
            explorer.add_start(seed, origin);
        }
    }
    {
        let _phase = phase::scope("discover/drain");
        explorer.drain();
    }

    loop {
        let promoted = {
            let _phase = phase::scope("discover/promote tail calls");
            explorer.promote_tail_calls()
        };
        {
            let _phase = phase::scope("discover/drain");
            explorer.drain();
        }
        let _phase = phase::scope("discover/fill gaps");
        let filled = explorer.fill_gaps();
        if !promoted && !filled {
            break;
        }
    }

    let _phase = phase::scope("discover/demote");
    explorer.demote_table_addresses();
    explorer.demote_case_targets();
    while explorer.demote_crossed_starts() {}
    explorer.demote_frame_borrowers();

    explorer
}
