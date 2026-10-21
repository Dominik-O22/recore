//! Code discovery: finds instructions and function entry points by following control flow.
//!
//! Starts from the entry point, exports, code pointers stored in data, and `.eh_frame` entries
//! when present. Follows calls and jumps, takes `lea`-computed code addresses as entry points,
//! then fills the gaps that nothing referenced.

use std::collections::{BTreeMap, BTreeSet};
use rustc_hash::{FxHashMap, FxHashSet};

use crate::arch::{Arch, Flow, Table};
use crate::image::{Image, Section};
use crate::noreturn::is_noreturn_import;
use crate::phase;
use crate::report::{JumpTable, Origin};

/// One executable section and which of its bytes begin a decoded instruction.
struct Region<'a> {
    section: &'a Section,
    /// Per byte, the length of the decoded instruction that begins there, or zero.
    insn_len: Vec<u8>,
    /// Per byte, what is known about the address: [`FOLLOWS_BREAK`], [`ASKED_AS_START`],
    /// [`REFERENCED`] and [`IN_TABLE`]. One array, so that looking up a call's target touches one place in memory.
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
/// The byte is part of a jump table that lies among the code, or of a literal pool.
const IN_TABLE: u8 = 8;

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

    /// Where the decoded instruction that ends at `end` begins.
    fn insn_ending_at(&self, end: usize) -> Option<usize> {
        (1..=end.min(LONGEST_INSN)).map(|len| end - len).find(|&at| usize::from(self.insn_len[at]) == end - at)
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
    /// The same for instructions decoded on a guess that they are code. They count once the
    /// instruction turns out to be part of a function.
    pub uncertain_refs: Vec<(u64, u64, bool)>,
    /// Every stretch of decoded instructions, as sorted `[start, end)` ranges.
    pub code: Vec<(u64, u64)>,
    /// `[start, end)` of every jump table that lies among the code, and of every literal pool,
    /// sorted and joined where they touch. A function's code goes on after either.
    pub inline_tables: Vec<(u64, u64)>,
    /// Entry points taken away because the code before them comes back from a call and runs on
    /// into them, as `(entry, callee)`: entry points after all if the callee never returns.
    pub after_calls: Vec<(u64, u64)>,
    /// Entry points taken away because the code there gives back a frame it did not set up,
    /// sorted: see [`Arch::gives_back_frame`]. A call there jumps into the end of the caller.
    /// So are blocks that one call reaches and that work in the caller's frame: a call there
    /// goes on in the caller's own code.
    pub frame_ends: Vec<u64>,
    /// Calls through a register that the code on the way to them loaded from a slot, as call
    /// address to slot. Decoding the call on its own cannot tell where it goes.
    pub register_calls: FxHashMap<u64, u64>,
}

/// A set of addresses, for asking of very many ranges whether any member lies inside. Most
/// ranges asked about are a short jump's, and are answered from a word or two of a bit set.
struct AddrSet {
    base: u64,
    bits: Vec<u64>,
    /// Per word of `bits`, the number of members in the words before it.
    before: Vec<u32>,
}

impl AddrSet {
    /// `addrs` in ascending order.
    fn new(addrs: impl Iterator<Item = u64>) -> AddrSet {
        let sorted: Vec<u64> = addrs.collect();
        let base = sorted.first().copied().unwrap_or(0);
        let span = sorted.last().map_or(0, |last| last - base + 1);
        let mut bits = vec![0u64; span.div_ceil(64) as usize];
        let mut before = vec![0u32; bits.len()];
        for addr in &sorted {
            let word = ((addr - base) / 64) as usize;
            bits[word] |= 1 << ((addr - base) % 64);
            if let Some(next) = before.get_mut(word + 1) {
                *next += 1;
            }
        }
        let mut count = 0;
        for word in &mut before {
            count += *word;
            *word = count;
        }
        AddrSet { base, bits, before }
    }

    fn contains(&self, addr: u64) -> bool {
        addr >= self.base && self.bits.get(((addr - self.base) / 64) as usize).is_some_and(|word| word >> ((addr - self.base) % 64) & 1 != 0)
    }

    /// Whether a member lies in `low..=high`.
    fn any_in(&self, low: u64, high: u64) -> bool {
        let Some(last) = (self.bits.len() as u64 * 64).checked_sub(1) else { return false };
        let low = low.max(self.base);
        if low > high || low - self.base > last {
            return false;
        }
        let (first, end) = (low - self.base, (high - self.base).min(last));
        let (first_word, end_word) = ((first / 64) as usize, (end / 64) as usize);
        // Bits from `first` up in the first word, bits up to `end` in the last.
        let from = u64::MAX << (first % 64);
        let upto = u64::MAX >> (63 - end % 64);
        if first_word == end_word {
            return self.bits[first_word] & from & upto != 0;
        }
        self.bits[first_word] & from != 0 || self.bits[end_word] & upto != 0 || self.before[end_word] != self.before[first_word + 1]
    }
}

/// The longest instruction of any machine, x86's.
const LONGEST_INSN: usize = 15;

/// How many functions after a whole one, none of them reached, are decoded to show that it ends
/// where the next begins, where nothing else between functions does.
const WHOLE_CHAIN: u8 = 8;

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

/// How strongly an origin says that a function starts at its address, weakest first. Each pass
/// that weighs entry points against the code around them reads it from [`Explorer::evidence`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Evidence {
    /// How the code is laid out: unreached code after padding, or where a jump lands.
    Layout,
    /// An address the code takes, or a word in data, where either may just be a number: see
    /// [`Arch::TAKEN_IS_WEAK`].
    MaybeNumber,
    /// A pointer in data that may be a label inside a function: a computed-goto target, or an
    /// exception filter or handler block. A jump across it within one function shows which.
    MaybeLabel,
    /// An address the code takes, or a pointer in data.
    Pointer,
    /// What only a function explains: an unwind entry, an export, a call, a thunk's target.
    Sure,
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
    /// References seen while decoding speculatively, which decide nothing during discovery.
    uncertain_ref_sites: Vec<(u64, u64, bool)>,
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
    /// Where each stretch begins of the last gap found to divide into functions, in order.
    /// The gap search comes to them one after the other, and each holds as the gap did, so
    /// the gap is decoded once and not once for each.
    tiled: Vec<u64>,
    /// Whether what this pass finds will be reported. A first pass that has learned a table's
    /// length is followed by a second, and only its lengths are read: from then on it stops
    /// recording references and what is referenced, which decide nothing while exploring.
    recording: bool,
    /// How many tables without a bounds check a first pass has resolved.
    unbounded: u32,
    /// `[start, end)` of the literals the code reads, in no order.
    literals: Vec<(u64, u64)>,
    /// See [`Discovery::register_calls`].
    register_calls: FxHashMap<u64, u64>,
    /// Direct calls as `(from, to)`: to count those that reach a block borrowing a frame, and,
    /// where a call may be a jump, to find the ones that are: see [`Arch::CALL_MAY_BE_FAR_JUMP`].
    calls: Vec<(u64, u64)>,
    /// Whether the code has an instruction that rules out a call being a jump: see
    /// [`Arch::branches_reach_far`].
    branches_reach_far: bool,
    /// See [`Discovery::after_calls`].
    after_calls: Vec<(u64, u64)>,
    /// See [`Discovery::frame_ends`].
    frame_ends: Vec<u64>,
    /// The addresses that code reached from an entry point reads or writes through a register:
    /// see [`Arch::data_address`].
    data_addresses: Vec<u64>,
    /// Addresses taken that an earlier pass found inside other code, which are no entry points
    /// on that evidence: see [`Arch::TAKEN_IS_WEAK`].
    rejected: FxHashSet<u64>,
    /// The entry points made on the strength of an address taken alone, where that is weak.
    weak_starts: Vec<u64>,
}

/// One decoder per section, made when first needed. Decoding starts in a new place for every
/// branch target and every gap, and moving a decoder is cheaper than making one.
type Decoders<'a, A> = Vec<Option<<A as Arch>::Decoder<'a>>>;

impl<'a, A: Arch> Explorer<'a, A> {
    fn region_index(&self, addr: u64) -> Option<usize> {
        self.regions.iter().position(|r| r.section.contains(addr))
    }

    /// Records that the instruction at `at` reads or writes the data at `target`. Reading a slot
    /// the loader fills with an address in this image also takes that address: a global or a
    /// function reached through the global offset table.
    fn note_access(&mut self, at: u64, target: u64) {
        self.data_ref_sites.push((at, target, true));
        if let Some(&pointee) = self.pointer_slots.get(&target) {
            self.data_ref_sites.push((at, pointee, false));
        }
    }

    /// Whether the instruction at `addr` is filler.
    fn is_padding_at(&self, addr: u64) -> bool {
        self.image.bytes_from(addr).and_then(|bytes| A::decode(self.image, bytes, addr).next()?.insn).is_some_and(|insn| A::is_padding(&insn))
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
        let weak = self.evidence(addr, origin) == Evidence::MaybeNumber;
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
            if self.recording {
                self.referenced.insert(addr);
            }
        }
        // Whether an address becomes an entry point depends neither on who asks nor on when,
        // and most addresses are asked about many times: once per call to them. So each is
        // decided once, and is no entry point yet when it is.
        if *flags & ASKED_AS_START != 0 {
            return;
        }
        if weak && self.rejected.contains(&addr) {
            return;
        }
        *flags |= ASKED_AS_START;
        // Code that only falls or jumps into the inside of a frame is its function's. In a frame
        // that may hold several functions, the gap search vouches for one that opens as one.
        if !self.inside_frame(addr) || self.image.frames_merge && (referenced || origin == Origin::GapAligned) {
            if weak {
                self.weak_starts.push(addr);
            }
            let before = self.starts.insert(addr, origin);
            debug_assert!(before.is_none());
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
    fn drain(&mut self, decoders: &mut Decoders<'a, A>) {
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
            let decoder = decoders[index].get_or_insert_with(|| A::decoder(self.image, &section.data, section.addr));
            A::seek(decoder, (start - section.addr) as usize);
            while let Some(decoded) = A::decode_next(decoder) {
                let offset = (decoded.addr - section.addr) as usize;
                // Code does not run on into its constants, nor into a table.
                if self.regions[index].flags[offset] & IN_TABLE != 0 {
                    break;
                }
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
                // Nor does a function save the return address after it called, which it saved
                // before: what does so after a call opens the next function, where code is not
                // tiled and no padding marks where it starts.
                if after_call && A::LITERAL_POOLS && !A::TILES_GAPS && decoded.insn.is_some_and(|insn| A::opens_function(insn, None)) {
                    self.regions[index].insn_len[offset] = 0;
                    self.regions[index].flags[offset] |= FOLLOWS_BREAK;
                    break;
                }
                let Some(insn) = decoded.insn.filter(|insn| !(after_call && A::ends_code(insn))) else {
                    self.regions[index].insn_len[offset] = 0;
                    break;
                };
                after_call = false;
                self.regions[index].cover(offset, usize::from(decoded.len.max(1)));
                if let Some((start, end)) = A::literal(insn, &state).filter(|_| !speculative) {
                    self.mark_literal(start, end);
                }
                if A::CALL_MAY_BE_FAR_JUMP && !speculative && trusted && A::branches_reach_far(insn) {
                    self.branches_reach_far = true;
                }
                let Some(flow) = A::flow(insn, &state, self.image) else {
                    if let Some((base, data)) = A::based_data_address(insn, &state) {
                        let from_image_base = self.image.base != 0 && base == self.image.base;
                        if from_image_base {
                            self.data_refs.push(data);
                        }
                        // Off the image base, or a field or an element of the global whose
                        // address the register holds.
                        if self.recording && !speculative && (from_image_base || self.is_data(base)) && self.is_data(data) {
                            self.data_ref_sites.push((decoded.addr, data, true));
                        }
                    }
                    if self.recording {
                        self.note_references(insn, &state, decoded.addr, speculative);
                    }
                    if let Some(data) = A::data_address(insn, &state).filter(|_| trusted && !speculative) {
                        self.data_addresses.push(data);
                    }
                    let mut taken = A::address_taken(insn, &state, self.image).filter(|&target| self.may_be_address(target));
                    let in_code = taken.is_some_and(|target| self.region_index(target).is_some());
                    if in_code && !A::code_pointer(self.image, taken.unwrap_or_default()) {
                        taken = None;
                    }
                    if let Some(target) = taken.filter(|_| !speculative) {
                        if in_code {
                            self.add_start(target, Origin::AddressTaken);
                        } else {
                            self.data_refs.push(target);
                        }
                    }
                    // Who takes an address is reported for code as for data: code whose address
                    // is taken is a callback or a method table entry, and who takes it is worth
                    // as much as who calls it.
                    match taken.filter(|_| self.recording) {
                        Some(target) if speculative => self.uncertain_ref_sites.push((decoded.addr, target, false)),
                        Some(target) => self.data_ref_sites.push((decoded.addr, target, false)),
                        None => {}
                    }
                    A::step(&mut state, insn);
                    continue;
                };
                // A call or jump through a variable reads it, as an instruction that loads it
                // does. An import's slot is reported with the call instead.
                if let Flow::CallIndirect(Some(slot)) | Flow::JumpIndirect(Some(slot)) = flow
                    && self.recording
                    && !speculative
                    && self.is_data(slot)
                    && !self.image.import_slots.contains_key(&slot)
                {
                    self.note_access(decoded.addr, slot);
                }
                let ends_flow = match flow {
                    Flow::Call(target) => {
                        if !speculative {
                            self.calls.push((decoded.addr, target));
                            self.add_start(target, Origin::Call);
                        }
                        false
                    }
                    Flow::CallIndirect(slot) => {
                        if let Some(slot) = slot.filter(|_| self.recording && A::flow(insn, &A::State::default(), self.image) == Some(Flow::CallIndirect(None))) {
                            self.register_calls.insert(decoded.addr, slot);
                        }
                        self.import_never_returns(flow)
                    }
                    // A function that is nothing but a jump forwards to another function.
                    // Not to padding: a jump the linker puts in to step over an area it keeps
                    // for patches lands on the filler after it.
                    Flow::Jump(target) if decoded.addr == start && self.starts.contains_key(&start) && !self.is_padding_at(target) => {
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
                        let taken = A::branch(&mut state, insn);
                        if !speculative {
                            self.jumps.push((decoded.addr, target));
                        }
                        self.queue(Pending { addr: target, state: taken, trusted, speculative });
                        false
                    }
                    Flow::JumpIndirect(None) => {
                        let jump = decoded.addr;
                        let resolved = A::resolve_table(&state, self.image, self.pointer_slots, insn, &|target| {
                            self.is_case_target(jump, target)
                        }, &|target| self.is_case_code(target));
                        let resolved = resolved.map(|table| self.apply_known_length(table));
                        match resolved {
                            Some(table) => self.accept_table(jump, table, A::after_jump(state, insn), trusted, speculative),
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
                    A::step(&mut state, insn);
                    after_call = true;
                }
            }
        }
    }

    /// Whether an address taken or a word in data is only weak evidence of a function: see
    /// [`Arch::TAKEN_IS_WEAK`]. So it is too where the relocations are stripped, as nothing
    /// tells those addresses from numbers.
    fn taken_is_weak(&self) -> bool {
        A::TAKEN_IS_WEAK || self.image.relocations_stripped
    }

    /// How strongly `origin` says that a function starts at `addr`.
    fn evidence(&self, addr: u64, origin: Origin) -> Evidence {
        match origin {
            Origin::TailCall | Origin::GapAligned | Origin::GapEndbr => Evidence::Layout,
            Origin::AddressTaken | Origin::DataPointer if self.taken_is_weak() => Evidence::MaybeNumber,
            // Where the format puts labels among the code, any pointer may be one. Elsewhere
            // only one off the alignment functions have.
            Origin::DataPointer if self.image.data_in_code || addr % A::FUNCTION_ALIGN != 0 => Evidence::MaybeLabel,
            Origin::AddressTaken | Origin::DataPointer => Evidence::Pointer,
            Origin::Unknown | Origin::Frame | Origin::Export | Origin::Call | Origin::Unreachable | Origin::Thunk => Evidence::Sure,
        }
    }

    /// Whether a value the code holds may be an address. Where the loader relocates the
    /// addresses in code, only a value some relocation carries is one. Where the relocations
    /// are stripped, nothing tells them apart, so any value the image maps may be one: not the
    /// `push 1` or the -1.0 of `push 0xbf800000`.
    fn may_be_address(&self, value: u64) -> bool {
        if self.image.relocations_stripped {
            return self.image.section_at(value).is_some() || self.image.is_zero_filled(value);
        }
        !A::ADDRESSES_ARE_RELOCATED || self.pointer_values.contains(&value)
    }

    /// Marks `[start, end)` as a literal the code reads, which is no instruction.
    fn mark_literal(&mut self, start: u64, end: u64) {
        let Some(index) = self.region_index(start) else { return };
        let clock = self.clock;
        let region = &mut self.regions[index];
        let (from, to) = ((start - region.section.addr) as usize, ((end - region.section.addr) as usize).min(region.flags.len()));
        if region.flags[from..to].iter().all(|flags| flags & IN_TABLE != 0) {
            return;
        }
        region.flags[from..to].iter_mut().for_each(|flags| *flags |= IN_TABLE);
        region.touch(from, clock);
        region.touch(to - 1, clock);
        self.literals.push((start, end));
    }

    /// Records the data that `insn`, at `at`, reads, writes or forms the address of, where
    /// that decides nothing while exploring.
    fn note_references(&mut self, insn: &A::Insn, state: &A::State, at: u64, speculative: bool) {
        let accessed = A::memory_reference(insn, state)
            .filter(|&target| self.may_be_address(target))
            .filter(|&target| self.is_data(target));
        match accessed {
            Some(target) if speculative => self.uncertain_ref_sites.push((at, target, true)),
            Some(target) => self.note_access(at, target),
            None => {}
        }
        if let Some(target) = A::offset_address(insn, state).filter(|&target| !speculative && self.is_data(target)) {
            self.data_ref_sites.push((at, target, false));
        }
        /// Offsets from a pointer further than this are not fields of what it points to.
        const FARTHEST_FIELD: u64 = 1 << 20;
        let through = A::through_pointer(insn, state).filter(|&(_, offset, _)| !speculative && offset < FARTHEST_FIELD);
        if let Some((pointee, offset, access)) = through.and_then(|(slot, offset, access)| Some((*self.pointer_slots.get(&slot)?, offset, access))) {
            if self.is_data(pointee) && self.is_data(pointee + offset) {
                if access {
                    self.note_access(at, pointee + offset);
                } else {
                    self.data_ref_sites.push((at, pointee + offset, false));
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
        // Nothing in a table among the code is an instruction, whatever its bytes look like.
        if let Some(end) = table.inline_end
            && let Some(index) = self.region_index(table.address)
        {
            let clock = self.clock;
            let region = &mut self.regions[index];
            let (start, end) = ((table.address - region.section.addr) as usize, ((end - region.section.addr) as usize).min(region.flags.len()));
            region.flags[start..end].iter_mut().for_each(|flags| *flags |= IN_TABLE);
            (start..end).step_by(PAGE).chain([end.saturating_sub(1)]).for_each(|offset| region.touch(offset, clock));
        }
        // Tables sit back to back, so each table's address ends the one before it.
        self.data_refs.push(table.address);
        if self.recording && !speculative {
            // The jump reads its table, wherever the compiler put it: MSVC keeps tables among
            // the code.
            self.data_ref_sites.push((jump, table.address, true));
        }
        let first_pass = self.known_lengths.is_empty();
        let unbounded = !table.bounded;
        self.tables.push((jump, table));
        // A length learned now is still learned when the pass ends: data addresses only get
        // closer to a table. Asking sorts all of them, so it is asked ever more rarely.
        if self.recording && first_pass && unbounded {
            self.unbounded += 1;
            if self.unbounded.is_power_of_two() && !self.learned_lengths().is_empty() {
                self.recording = false;
            }
        }
    }

    /// Called when a path runs into code that was already decoded. If an unresolved indirect
    /// jump follows in a straight line, replays the instructions up to it with this path's
    /// state, which may know the table that the first path to get there did not.
    fn retry_jump_ahead(&mut self, index: usize, addr: u64, mut state: A::State) {
        let Some(&jump) = self.unresolved.range(addr..addr + RETRY_REACH).next() else { return };
        let section = self.regions[index].section;
        for decoded in A::decode(self.image, &section.data[(addr - section.addr) as usize..], addr) {
            let Some(insn) = decoded.insn else { return };
            match A::flow(&insn, &state, self.image) {
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

    /// Whether execution cannot fall into `addr`: it sits right after a terminator, a jump
    /// table or a literal pool, or after one of those followed only by padding.
    fn starts_after_break(&self, addr: u64) -> bool {
        let Some(index) = self.region_index(addr) else { return false };
        let region = &self.regions[index];
        let offset = (addr - region.section.addr) as usize;
        let earliest = offset.saturating_sub(A::LONGEST_PADDING as usize);
        let pointer_size = self.image.machine.pointer_size() as usize;
        let after_table = |o: usize| {
            self.image.data_in_code && o >= pointer_size && self.pointer_slots.contains_key(&(region.section.addr + (o - pointer_size) as u64))
                || A::LITERAL_POOLS && o > 0 && region.flags[o - 1] & IN_TABLE != 0
        };
        let Some(break_at) = (earliest..=offset).rev().find(|&o| region.follows_break(o) || after_table(o)) else {
            return false;
        };
        A::decode(self.image, &region.section.data[break_at..offset], region.section.addr + break_at as u64).all(|decoded| decoded.insn.is_some_and(|insn| A::is_padding(&insn)))
    }

    /// Marks a jump target as an entry point when the jump is a tail call: it leaves the function
    /// containing it, and the target looks like the top of a function.
    ///
    /// "Leaves the function" means an entry point backed by strong evidence lies between the jump
    /// and its target. Entry points that were themselves inferred from jumps or gaps do not
    /// count, otherwise one wrong guess would promote every jump that crosses it.
    fn promote_tail_calls(&mut self) -> bool {
        let strong = AddrSet::new(self.starts.iter().filter(|&(&addr, &origin)| self.evidence(addr, origin) > Evidence::MaybeNumber).map(|(&addr, _)| addr));
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
            if crossed.clone().all(|(&addr, &origin)| self.evidence(addr, origin) < Evidence::Pointer) {
                demoted.extend(crossed.by_ref().map(|(&addr, _)| addr));
            }
        }
        demoted.iter().for_each(|addr| {
            self.starts.remove(addr);
        });
        !demoted.is_empty()
    }

    /// Takes each word among the code that is no instruction and holds the address of code with
    /// the Thumb bit for a function: a table of handlers or a structure of callbacks in the
    /// flash. Returns whether that found a new entry point.
    fn seed_marked_pointers(&mut self) -> bool {
        let before = self.starts.len();
        let mut found = Vec::new();
        for region in &self.regions {
            let section = region.section;
            let first = (section.addr.next_multiple_of(4) - section.addr) as usize;
            for offset in (first..section.data.len().saturating_sub(3)).step_by(4) {
                // Not code, nor a jump table, whose entries are labels, nor a literal, which the
                // code that loads it has taken already.
                let covered = (offset..offset + 4).any(|at| region.covered[at / 64] >> (at % 64) & 1 != 0 || region.flags[at] & IN_TABLE != 0);
                let word = u64::from(u32::from_le_bytes(section.data[offset..offset + 4].try_into().unwrap()));
                if !covered && word & 1 != 0 {
                    found.push(word & !1);
                }
            }
        }
        for target in found {
            if self.region_index(target).is_some() && A::code_pointer(self.image, target) {
                self.add_start(target, Origin::DataPointer);
            }
        }
        self.starts.len() != before
    }

    /// Whether the instruction before `addr` was decoded and runs on into it.
    fn falls_into(&self, addr: u64) -> bool {
        let Some(index) = self.region_index(addr) else { return false };
        let region = &self.regions[index];
        let offset = (addr - region.section.addr) as usize;
        offset > 0 && !region.follows_break(offset) && region.covered[(offset - 1) / 64] >> ((offset - 1) % 64) & 1 != 0
    }

    /// The function called by the call that ends where `addr` begins, past any padding: the call
    /// may be the last of a function that calls one that never returns, which while discovering
    /// only an import's name tells. The padding need not have been decoded: decoding stops at
    /// padding after a call.
    fn call_before(&self, addr: u64) -> Option<u64> {
        let region = &self.regions[self.region_index(addr)?];
        let offset = (addr - region.section.addr) as usize;
        let earliest = offset.saturating_sub(A::LONGEST_PADDING as usize);
        let padding_to = |from: usize| {
            A::decode(self.image, &region.section.data[from..offset], region.section.addr + from as u64).all(|decoded| decoded.insn.is_some_and(|insn| A::is_padding(&insn)))
        };
        // The last instruction before the padding, nearest first.
        let before = (earliest..=offset).rev().filter(|&end| padding_to(end)).find_map(|end| {
            let at = region.insn_ending_at(end)?;
            let insn = A::decode(self.image, &region.section.data[at..], region.section.addr + at as u64).next()?.insn?;
            (!A::is_padding(&insn)).then_some(insn)
        })?;
        match A::flow(&before, &A::State::default(), self.image) {
            Some(Flow::Call(callee)) => Some(callee),
            _ => None,
        }
    }

    /// Removes `addr` from the entry points, as code runs on into it. Where that code comes back
    /// from a call, the call is kept, to put the entry point back if it never returns.
    fn demote_run_into(&mut self, addr: u64) {
        self.starts.remove(&addr);
        if let Some(callee) = self.call_before(addr) {
            self.after_calls.push((addr, callee));
        }
    }

    /// Whether the instruction that ends where `addr` begins is padding.
    fn after_padding(&self, addr: u64) -> bool {
        let Some(index) = self.region_index(addr) else { return false };
        let region = &self.regions[index];
        let before = region.insn_ending_at((addr - region.section.addr) as usize);
        before.is_some_and(|before| self.is_padding_at(region.section.addr + before as u64))
    }

    /// Removes the entry points that only an address taken or a word in data speaks for, where
    /// that is weak evidence, when code runs on into them: a number that lands inside a
    /// function. Not where padding runs on into one: compilers pad between functions, and the
    /// code before the padding may be data decoded as code, or follow a call that never returns.
    /// Nor is a number that lands in the padding itself a function.
    fn demote_taken_inside_code(&mut self) {
        let weak: Vec<u64> = self.starts.iter().filter(|&(&addr, &origin)| self.evidence(addr, origin) == Evidence::MaybeNumber).map(|(&addr, _)| addr).collect();
        for addr in weak {
            if self.is_padding_at(addr) {
                self.starts.remove(&addr);
            } else if self.falls_into(addr) && !self.after_padding(addr) {
                self.demote_run_into(addr);
            }
        }
    }

    /// Removes the entry points that only the layout speaks for, after a call and padding, that
    /// code after them jumps back to: a loop head that the compiler aligned after a call that
    /// returns, as MSVC does. A jump across an entry point shows the same, but one back to the
    /// head itself crosses none.
    fn demote_loop_heads(&mut self) {
        let heads: Vec<u64> = self
            .jumps
            .iter()
            .filter(|&&(from, to)| from > to && self.starts.get(&to) == Some(&Origin::GapAligned))
            .map(|&(_, to)| to)
            .collect::<BTreeSet<u64>>()
            .into_iter()
            .filter(|&head| !self.is_referenced(head) && self.call_before(head).is_some())
            .collect();
        for head in heads {
            self.demote_run_into(head);
        }
    }

    /// Whether something calls `addr`, takes it, exports it or points to it from data.
    fn is_referenced(&self, addr: u64) -> bool {
        self.region_index(addr).is_some_and(|index| self.regions[index].flags[(addr - self.regions[index].section.addr) as usize] & REFERENCED != 0)
    }

    /// Removes the entry points that only calls reach which are jumps within a function: in code
    /// whose branches do not reach as far, no other entry point lies between each call and where
    /// it goes, and the code before the target runs on into it, as it does into a block and not
    /// into a function. A compiler jumps with a call even where a branch would reach, as it
    /// lays out the function after it chose. Code that runs on into a function from a call that
    /// never returns is put back by analysis.
    fn demote_far_jumps(&mut self) {
        if self.branches_reach_far {
            return;
        }
        let mut calls_to: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
        for &(from, to) in &self.calls {
            calls_to.entry(to).or_default().push(from);
        }
        calls_to.retain(|&to, _| self.starts.get(&to) == Some(&Origin::Call) && self.falls_into(to));
        // Far jumps within one function lead to each other, and a guessed entry point between
        // them may be a guess they led to.
        let starts = AddrSet::new(self.starts.iter().filter(|&(&start, &origin)| self.evidence(start, origin) == Evidence::Sure && !calls_to.contains_key(&start)).map(|(&start, _)| start));
        let jumps: Vec<u64> = calls_to
            .into_iter()
            .filter(|(to, sites)| sites.iter().all(|&from| if from < *to { !starts.any_in(from + 1, to - 1) } else { !starts.any_in(to + 1, from) }))
            .map(|(to, _)| to)
            .collect();
        for to in jumps {
            self.demote_run_into(to);
        }
    }

    /// Removes entry points that are the address of a resolved jump table. Mach-O compilers put
    /// a function's tables after its code, and the dispatch takes a table's address just as
    /// other code takes a function's. Removes too what only a pointer or the layout puts inside
    /// a table among the code, which may have been decoded before the table was found.
    fn demote_table_addresses(&mut self) {
        let mut inside = Vec::new();
        for (_, table) in &self.tables {
            if self.starts.get(&table.address) == Some(&Origin::AddressTaken) {
                inside.push(table.address);
            }
            if let Some(end) = table.inline_end {
                inside.extend(self.starts.range(table.address..end).filter(|&(&addr, &origin)| self.evidence(addr, origin) < Evidence::Sure).map(|(&addr, _)| addr));
            }
        }
        for addr in inside {
            self.starts.remove(&addr);
        }
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

    /// Whether the code at `addr` runs on into another entry point before any branch or return.
    fn runs_into_start(&self, addr: u64) -> bool {
        /// How many instructions decide it.
        const PROBE: usize = 64;
        let Some(bytes) = self.image.bytes_from(addr) else { return false };
        for decoded in A::decode(self.image, bytes, addr).take(PROBE) {
            let Some(insn) = decoded.insn else { return false };
            if decoded.addr != addr && self.starts.contains_key(&decoded.addr) {
                return true;
            }
            if !matches!(A::flow(&insn, &A::State::default(), self.image), None | Some(Flow::Call(_) | Flow::CallIndirect(_))) {
                return false;
            }
        }
        false
    }

    /// Removes entry points whose code runs in another function's stack frame. Windows scope
    /// tables point at exception filters and handlers, and functions call their own `finally`
    /// blocks; all of these sit inside the function they belong to. Hand-written routines jump
    /// or call into an end that gives back the frame they set up, which may be another routine's.
    fn demote_frame_borrowers(&mut self) {
        /// How many instructions decide it. A function sets up its frame within the first few.
        const PROBE: usize = 4;
        if !self.image.data_in_code {
            return;
        }
        let candidates: Vec<u64> = self.starts.iter().filter(|(_, origin)| !matches!(origin, Origin::Frame | Origin::Export | Origin::Thunk)).map(|(&addr, _)| addr).collect();
        let borrowers: Vec<u64> = candidates
            .iter()
            .copied()
            .filter(|&addr| {
                let Some(bytes) = self.image.bytes_from(addr) else { return false };
                let insns: Vec<A::Insn> = A::decode(self.image, bytes, addr).take(PROBE).map_while(|d| d.insn).collect();
                A::borrows_frame(&insns)
            })
            .collect();
        let past_calls = A::CALL_MAY_BE_FAR_JUMP && !self.branches_reach_far;
        let mut frame_ends: Vec<u64> = candidates.into_iter().filter(|&addr| A::gives_back_frame(self.image, addr, past_calls)).collect();
        // A block that one call reaches is its caller's own, as MSVC calls a `__finally` block
        // on the way out of its `__try`. One that several calls reach is a routine of its own
        // that works in whichever frame it is called in, such as the runtime's `__SEH_epilog`,
        // unless it runs on into another entry point, as labels of one hand-written routine do.
        let mut sites: FxHashMap<u64, usize> = FxHashMap::default();
        for &(_, to) in &self.calls {
            *sites.entry(to).or_default() += 1;
        }
        for &addr in &borrowers {
            match sites.get(&addr) {
                Some(&count) if count > 1 && !self.runs_into_start(addr) => continue,
                Some(_) => frame_ends.push(addr),
                None => {}
            }
            self.starts.remove(&addr);
        }
        for addr in &frame_ends {
            self.starts.remove(addr);
        }
        frame_ends.sort_unstable();
        self.frame_ends = frame_ends;
    }

    /// Whether the unreached bytes at `addr` are a whole function nothing refers to: they decode
    /// without a gap to a return or a jump elsewhere, and padding or known code follows.
    /// `may_call` says whether calls are allowed in it; a function without an unwind entry, where
    /// others have one, is a leaf and makes none.
    ///
    /// Where code keeps literal pools and unreached code is not tiled into functions, as on
    /// 32-bit ARM, more shows a function whole: it goes on past a return to where a branch before
    /// it goes and through a table of known length to its cases, a call that runs into literals
    /// ends it, its own literals follow its end, and so may another function, one that opens as
    /// one or up to `chain` more whole ones.
    fn is_whole_function(&self, index: usize, addr: u64, may_call: bool, chain: u8) -> bool {
        const LONGEST: usize = 48;
        let extended = A::LITERAL_POOLS && !A::TILES_GAPS;
        let region = &self.regions[index];
        let section = region.section;
        let known = |at: u64| ((at - section.addr) as usize) < section.data.len() && region.insn_len[(at - section.addr) as usize] != 0;
        let literal = |at: u64| A::LITERAL_POOLS && region.flags.get((at - section.addr) as usize).is_some_and(|flags| flags & IN_TABLE != 0);
        // Where the branches so far go past the code decoded, and the literals it reads.
        let (mut ahead, mut pools): (BTreeSet<u64>, Vec<(u64, u64)>) = (BTreeSet::new(), Vec::new());
        // Where a path through the code ends at `end`: decoding goes on at the nearest place a
        // branch goes past it, or the function ends there, and then what follows says whether
        // it is whole.
        let finish = |mut end: u64, ahead: &BTreeSet<u64>, pools: &[(u64, u64)]| -> Result<bool, u64> {
            if let Some(&next) = ahead.range(end..).next() {
                return Err(next);
            }
            // A lone `ret` is more often the tail of the function before it.
            if end - addr < 3 {
                return Ok(false);
            }
            while let Some(&(_, pool_end)) = pools.iter().find(|&&(start, pool_end)| start <= end.next_multiple_of(4) && start >= end && pool_end > end) {
                end = pool_end;
            }
            let Some(rest) = section.data.get((end - section.addr) as usize..) else { return Ok(false) };
            let mut after = A::decode(self.image, rest, end).map(|decoded| decoded.insn);
            let (next, second) = (after.next().flatten(), after.next().flatten());
            let padded = next.as_ref().is_some_and(A::is_padding);
            let opens = next.as_ref().is_some_and(|next| A::opens_function(next, second.as_ref()));
            let follows = || literal(end) || chain > 0 && self.is_whole_function(index, end, may_call, chain - 1);
            Ok(padded || opens || known(end) || end == section.end() || self.frame_of(end).is_some() || follows())
        };
        let (mut from, mut decoded_count) = (addr, 0);
        loop {
            let mut decoder = A::decode(self.image, &section.data[(from - section.addr) as usize..], from);
            let (mut after_call, mut state) = (false, A::State::default());
            let ended = loop {
                let Some(decoded) = decoder.next() else { return false };
                decoded_count += 1;
                if decoded_count > LONGEST {
                    return false;
                }
                let own_pool = pools.iter().any(|&(start, end)| start < decoded.next_addr() && decoded.addr < end);
                let inside = (decoded.addr..decoded.next_addr()).any(|at| known(at) || literal(at) || self.pointer_slots.contains_key(&at));
                // A call that runs into literals never returns.
                if after_call && (own_pool || literal(decoded.addr)) {
                    break finish(decoded.addr, &ahead, &pools);
                }
                let Some(insn) = decoded.insn else { return false };
                if inside || own_pool || A::is_padding(&insn) || self.frame_of(decoded.addr).is_some() {
                    return false;
                }
                if let Some(pool) = A::literal(&insn, &state).filter(|_| extended) {
                    pools.push(pool);
                }
                let flow = A::flow(&insn, &state, self.image);
                after_call = extended && matches!(flow, Some(Flow::Call(_)));
                // Where code is not tiled, a call or tail call may go to the PLT, which holds no
                // functions.
                let callable = |target: u64| if extended { self.image.is_code(target) } else { self.region_index(target).is_some() };
                match flow {
                    Some(Flow::Call(target)) if !may_call || !callable(target) => return false,
                    Some(Flow::CallIndirect(_)) if !may_call => return false,
                    Some(Flow::JumpIndirect(None)) if extended => {
                        let in_reach = |target: u64| target >= addr && self.region_index(target) == Some(index);
                        let Some(table) = A::resolve_table(&state, self.image, self.pointer_slots, &insn, &in_reach, &in_reach).filter(|table| table.bounded) else { return false };
                        ahead.extend(table.entries.iter().copied());
                        pools.extend(table.inline_end.map(|end| (table.address, end)));
                        break finish(table.inline_end.unwrap_or(decoded.next_addr()).max(decoded.next_addr()), &ahead, &pools);
                    }
                    Some(Flow::Halt | Flow::JumpIndirect(None)) => return false,
                    Some(Flow::Branch(target)) if target < addr || self.region_index(target).is_none() => return false,
                    // Decoding goes on at a branch's target, which must lie in these bytes.
                    Some(Flow::Branch(target)) if extended && self.region_index(target) != Some(index) => return false,
                    Some(Flow::Branch(target)) => {
                        if extended {
                            A::branch(&mut state, &insn);
                            ahead.insert(target);
                        }
                    }
                    Some(Flow::Jump(target)) if !callable(target) => return false,
                    Some(Flow::Return | Flow::Jump(_) | Flow::JumpIndirect(Some(_))) if extended => break finish(decoded.next_addr(), &ahead, &pools),
                    Some(Flow::Return | Flow::Jump(_) | Flow::JumpIndirect(Some(_))) => {
                        let end = decoded.next_addr();
                        // A lone `ret` is more often the tail of the function before it.
                        if end - addr < 3 {
                            return false;
                        }
                        let padded = decoder.next().is_some_and(|next| next.insn.as_ref().is_some_and(A::is_padding));
                        return padded || known(end) || end == section.end() || self.frame_of(end).is_some();
                    }
                    _ if extended => A::step(&mut state, &insn),
                    _ => {}
                }
            };
            match ended {
                Err(next) => from = next,
                Ok(whole) => return whole,
            }
        }
    }

    /// Whether the unreached bytes from `addr` to the next known code divide into functions with
    /// nothing left over: decoded one after the other they are all instructions, each stretch
    /// ends in a return or a jump, the last of them where the known code begins, every jump
    /// lands on one of the instructions or on code, and every call on a function or on code
    /// that nothing has reached yet, which may be a function of another such gap. A
    /// stretch of a single return has to be one the code before it jumps to. Bytes that are
    /// data seldom do all of that. Between stretches, padding and the literal pools that the
    /// stretches read are no stretch. Fill after the last stretch, one byte repeated to the end
    /// of the region, is left over as no function. Where 0x00 and 0xFF are instructions and
    /// not padding, fill that stops short of the end is not told from code.
    fn tiles_gap(&mut self, index: usize, addr: u64) -> bool {
        if self.tiled.binary_search(&addr).is_ok() {
            return true;
        }
        let region = &self.regions[index];
        let section = region.section;
        let known = |at: u64| self.region_index(at).is_some_and(|index| self.regions[index].insn_len[(at - self.regions[index].section.addr) as usize] != 0);
        // Erased flash reads 0xFF, and a linker pads a bank to its size with 0x00.
        let is_fill = |byte: &u8| matches!(byte, 0x00 | 0xFF);
        let state = A::State::default();
        // Where each instruction and each stretch begins, in order, and where the code goes.
        let (mut instructions, mut stretches, mut jumps, mut calls) = (Vec::new(), vec![addr], Vec::new(), Vec::new());
        // The stretches too short to be functions.
        let mut tails = Vec::new();
        // `[start, end)` of the literals the stretches read.
        let mut pools: Vec<(u64, u64)> = Vec::new();
        let mut ended = false;
        // Where decoding starts again past a literal pool, and where the gap's instructions end.
        let (mut resume, mut end) = (Some(addr), addr);
        'gap: while let Some(from) = resume.take() {
            for decoded in A::decode(self.image, &section.data[(from - section.addr) as usize..], from) {
                if known(decoded.addr) {
                    break 'gap;
                }
                let between = ended && decoded.addr == stretches[stretches.len() - 1];
                let pool = pools.iter().find(|&&(start, end)| start < decoded.next_addr() && decoded.addr < end).copied();
                if let Some((start, end)) = pool {
                    if !between || start > decoded.addr {
                        return false;
                    }
                    *stretches.last_mut().unwrap() = end;
                    resume = Some(end);
                    continue 'gap;
                }
                let Some(insn) = decoded.insn else { return false };
                let covers = (decoded.addr - section.addr) as usize..(decoded.next_addr() - section.addr) as usize;
                if (decoded.addr + 1..decoded.next_addr()).any(known) || region.flags[covers].iter().any(|flags| flags & IN_TABLE != 0) {
                    return false;
                }
                if between && A::is_padding(&insn) {
                    *stretches.last_mut().unwrap() = decoded.next_addr();
                    continue;
                }
                instructions.push(decoded.addr);
                end = decoded.next_addr();
                if let Some(literal) = A::literal(&insn, &state) {
                    pools.push(literal);
                }
                ended = match A::flow(&insn, &state, self.image) {
                    Some(Flow::Halt) => return false,
                    Some(Flow::Call(target)) => {
                        calls.push(target);
                        false
                    }
                    Some(Flow::Branch(target)) => {
                        jumps.push(target);
                        false
                    }
                    Some(Flow::Jump(target)) => {
                        jumps.push(target);
                        true
                    }
                    Some(Flow::Return | Flow::JumpIndirect(_)) => true,
                    Some(Flow::CallIndirect(_)) | None => false,
                };
                if ended {
                    if decoded.next_addr() - stretches[stretches.len() - 1] < A::SHORTEST_TILE {
                        tails.push(stretches[stretches.len() - 1]);
                    }
                    let next = decoded.next_addr();
                    let rest = &section.data[(next - section.addr) as usize..];
                    // Each fill byte is looked at here once: if the fill stops short, the stretch
                    // that follows is decoded past it.
                    let filled = rest.first().is_some_and(|&fill| is_fill(&fill) && rest.iter().all(|&byte| byte == fill) && (next..section.end()).all(|at| !known(at)));
                    if filled {
                        break 'gap;
                    }
                    stretches.push(next);
                }
            }
        }
        // Here it is that tail only if the code before it jumps to it.
        jumps.sort_unstable();
        // What nothing calls may call or jump to what nothing else calls either, in another gap
        // the search comes to later.
        let elsewhere = |at: u64| {
            !(addr..end).contains(&at)
                && self.region_index(at).is_some_and(|index| {
                    let offset = (at - self.regions[index].section.addr) as usize;
                    self.regions[index].insn_len[offset] == 0 && self.regions[index].flags[offset] & IN_TABLE == 0
                })
        };
        let tiles = ended
            && tails.iter().all(|tail| *tail != addr && jumps.binary_search(tail).is_ok())
            && jumps.iter().all(|target| instructions.binary_search(target).is_ok() || known(*target) || elsewhere(*target))
            && calls.iter().all(|target| self.starts.contains_key(target) || stretches.binary_search(target).is_ok() || elsewhere(*target));
        if tiles {
            self.tiled = stretches;
        }
        tiles
    }

    /// Marks as data, in each region, everything from the first address that the code reached
    /// reads or writes through a register past the end of that code and of its tables and
    /// pools: the constants and the initial values of variables that a firmware image keeps
    /// after its code. Nothing there is a function, however its bytes decode. The entry points
    /// there that only an address the code takes speaks for go, and the code decoded from them
    /// ends nothing, where a pointer to text reads as one to code.
    fn mark_trailing_data(&mut self) {
        self.data_addresses.sort_unstable();
        self.weak_starts.sort_unstable();
        for index in 0..self.regions.len() {
            let region = &self.regions[index];
            let section = region.section;
            let weak: Vec<(usize, usize)> = self
                .weak_starts
                .iter()
                .filter(|&&addr| section.contains(addr) && self.starts.get(&addr) == Some(&Origin::AddressTaken))
                .map(|&addr| (addr - section.addr) as usize)
                .map(|offset| (offset, region.end_of_run(offset)))
                .collect();
            let from_weak = |at: usize| weak.iter().any(|&(start, end)| (start..end).contains(&at));
            let known = |at: usize| (region.insn_len[at] != 0 || region.flags[at] & IN_TABLE != 0) && !from_weak(at);
            let Some(last) = (0..section.data.len()).rev().find(|&at| known(at)) else { continue };
            let known_end = section.addr + last as u64 + u64::from(region.insn_len[last].max(1));
            let Some(&start) = self.data_addresses.iter().find(|&&addr| addr >= known_end && addr < section.end()) else { continue };
            let (from, clock) = ((start - section.addr) as usize, self.clock);
            let region = &mut self.regions[index];
            region.flags[from..].iter_mut().for_each(|flags| *flags |= IN_TABLE);
            region.touch(from, clock);
            region.touch(section.data.len() - 1, clock);
            self.starts.retain(|&addr, origin| !(section.contains(addr) && addr >= start && *origin == Origin::AddressTaken));
        }
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
                if region.insn_len[offset] == 0 {
                    offset += 1;
                    continue;
                }
                // The instruction here and every one that follows it without a gap.
                let end = region.end_of_run(offset);
                let (addr, end_addr) = (section.addr + offset as u64, section.addr + end as u64);
                match ranges.last_mut() {
                    Some(last) if last.1 == addr => last.1 = end_addr,
                    _ => ranges.push((addr, end_addr)),
                }
                offset = end;
            }
        }
        ranges
    }

    /// Finds code that nothing referenced. Code following padding at an aligned address, or
    /// opening with an entry marker, starts a function. Other unreached code continues the
    /// function before it, such as switch cases behind an unresolved indirect jump.
    fn fill_gaps(&mut self, decoders: &mut Decoders<'a, A>) -> bool {
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
                    if self.regions[index].flags[offset] & IN_TABLE != 0 {
                        offset += 1;
                        // Nothing runs on out of a literal pool: it follows the end of its code.
                        if A::LITERAL_POOLS {
                            after_data = offset;
                        }
                        continue;
                    }
                    // Relocated pointers in a code section are a jump table. Step over the whole
                    // table; what follows it cannot be fallen into.
                    if self.image.data_in_code && self.pointer_slots.contains_key(&addr) {
                        let pointer_size = self.image.machine.pointer_size() as usize;
                        offset += pointer_size;
                        after_data = offset;
                        continue;
                    }
                    // An unreached stretch: step over padding to the first real instruction, and
                    // take the one after it too.
                    let mut skipped_padding = false;
                    let mut candidate = None;
                    let mut scanned_to = addr;
                    let mut next = None;
                    let decoder = decoders[index].get_or_insert_with(|| A::decoder(self.image, &section.data, section.addr));
                    A::seek(decoder, offset);
                    while let Some(decoded) = A::decode_next(decoder) {
                        let at = (decoded.addr - section.addr) as usize;
                        if self.regions[index].insn_len[at] != 0 || self.regions[index].flags[at] & IN_TABLE != 0 {
                            break;
                        }
                        scanned_to = decoded.next_addr();
                        let Some(insn) = decoded.insn else { break };
                        // What sits right before a table aligns it, as MSVC's `mov edi, edi` does:
                        // the code that jumps through the table was decoded from its function. Not
                        // so before a literal pool, which follows the end of a function's code.
                        let before_table = || {
                            !A::LITERAL_POOLS && self.regions[index].flags.get((scanned_to - section.addr) as usize).is_some_and(|flags| flags & IN_TABLE != 0)
                        };
                        if A::is_padding(insn) || before_table() {
                            skipped_padding = true;
                            continue;
                        }
                        candidate = Some((decoded.addr, *insn));
                        next = A::decode_next(decoder).and_then(|d| d.insn.copied());
                        break;
                    }
                    // Always make progress, even past bytes that do not decode.
                    offset = ((scanned_to - section.addr) as usize).max(offset + 1);
                    let Some((addr, insn)) = candidate else { continue };
                    // A trampoline entry is not a function: what it reaches is, and every jump
                    // or call to the entry already goes there.
                    if self.image.banking.trampolines.contains_key(&addr) {
                        continue;
                    }
                    let at = (addr - section.addr) as usize;
                    if skipped_padding && !self.regions[index].follows_break(at) {
                        self.regions[index].flags[at] |= FOLLOWS_BREAK;
                        let clock = self.clock;
                        self.regions[index].touch(at, clock);
                    }
                    let aligned = addr % A::FUNCTION_ALIGN == 0;
                    let marked = A::is_entry_marker(&insn);
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
                        // Where nothing aligns functions, no address is likelier to start one.
                        let aligned_after_break = A::FUNCTION_ALIGN > 1 && aligned && (skipped_padding || at == 0);
                        if self.pointer_slots.contains_key(&addr) {
                            // The padding scan stopped on a table entry; resume after that entry.
                            let pointer_size = self.image.machine.pointer_size() as usize;
                            offset = (addr - section.addr) as usize + pointer_size;
                            after_data = offset;
                            continue;
                        }
                        // A function with no unwind entry calls nothing; one that starts on an
                        // alignment boundary straight after a terminator may call.
                        let unwound_elsewhere = !self.frames.is_empty() && self.frame_of(addr).is_none();
                        let whole = after_break
                            && (unwound_elsewhere && self.is_whole_function(index, addr, false, WHOLE_CHAIN)
                                || aligned && self.is_whole_function(index, addr, true, WHOLE_CHAIN)
                                || A::TILES_GAPS && self.tiles_gap(index, addr));
                        // A whole function, or a gap that divides into functions, is code
                        // whatever its first instructions look like.
                        let in_frame = || self.inside_frame(addr) && !(self.image.frames_merge && opens);
                        is_start = (aligned_after_break || opens || whole) && !in_frame() && (A::TILES_GAPS && whole || A::code_pointer(self.image, addr));
                        if !is_start {
                            // Inside an unwind entry the bytes belong to a function, so they are
                            // worth decoding to resolve what they dispatch to, without taking
                            // anything they call or refer to as evidence.
                            if self.frame_of(addr).is_some() && !self.in_table(addr) {
                                self.deferred.push(Pending { addr, state: A::State::default(), trusted: false, speculative: true });
                                found = true;
                                self.drain(decoders);
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
                    self.drain(decoders);
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
    // A first pass that learns a length stops recording what only a last pass has to report.
    let run = |rejected: &FxHashSet<u64>| {
        let first = explore::<A>(image, frames, &pointers, FxHashMap::default(), rejected.clone());
        let lengths = first.learned_lengths();
        debug_assert!(first.recording || !lengths.is_empty());
        if lengths.is_empty() { first } else { explore::<A>(image, frames, &pointers, lengths, rejected.clone()) }
    };
    let mut explorer = run(&FxHashSet::default());
    // Where an address taken is weak evidence, one that turns out to lie inside other code was
    // decoded as a function all the same, and what that found stays found: literals in real
    // code, calls that are none, Thumb-2 where there is none. Passes that leave those addresses
    // out from the start follow until no more turn out so.
    if A::TAKEN_IS_WEAK || image.relocations_stripped {
        let mut rejected = FxHashSet::default();
        loop {
            let before = rejected.len();
            // Not one that analysis may put back, where the call before it never returns.
            let after_call = |addr: &u64| explorer.after_calls.iter().any(|(start, _)| start == addr);
            rejected.extend(explorer.weak_starts.iter().filter(|addr| !explorer.starts.contains_key(addr) && !after_call(addr)));
            if rejected.len() == before {
                break;
            }
            explorer = run(&rejected);
        }
    }

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
    let uncertain_refs = std::mem::take(&mut explorer.uncertain_ref_sites);
    let mut inline_tables: Vec<(u64, u64)> = explorer.tables.iter().filter_map(|(_, table)| Some((table.address, table.inline_end?))).collect();
    inline_tables.extend(explorer.literals.iter().copied());
    inline_tables.sort_unstable();
    // Literals back to back make one pool, and a table read without a bounds check may run on
    // into the next table.
    let inline_tables = merge_touching(inline_tables);
    let after_calls = std::mem::take(&mut explorer.after_calls);
    let frame_ends = std::mem::take(&mut explorer.frame_ends);
    let register_calls = std::mem::take(&mut explorer.register_calls);
    Discovery { starts, jump_tables: explorer.jump_tables(), referenced: explorer.referenced, data_refs, uncertain_refs, code, inline_tables, after_calls, frame_ends, register_calls }
}

/// Sorted ranges with those that overlap or touch joined.
fn merge_touching(ranges: Vec<(u64, u64)>) -> Vec<(u64, u64)> {
    let mut merged: Vec<(u64, u64)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        match merged.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => merged.push((start, end)),
        }
    }
    merged
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

fn explore<'a, A: Arch>(image: &'a Image, frames: &'a [(u64, u64)], pointers: &'a Pointers, known_lengths: FxHashMap<u64, usize>, rejected: FxHashSet<u64>) -> Explorer<'a, A> {
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
        uncertain_ref_sites: Vec::new(),
        pointer_slots: &pointers.slots,
        pointer_values: &pointers.values,
        known_lengths,
        frames,
        clock: 0,
        recording: true,
        unbounded: 0,
        literals: Vec::new(),
        register_calls: FxHashMap::default(),
        calls: Vec::new(),
        branches_reach_far: false,
        after_calls: Vec::new(),
        frame_ends: Vec::new(),
        data_addresses: Vec::new(),
        rejected,
        weak_starts: Vec::new(),
        data_sections: {
            // Zero-filled memory is data as much as what the file stores.
            let mut ranges: Vec<(u64, u64)> = image.sections.iter().filter(|s| !s.executable).map(|s| (s.addr, s.end())).chain(image.zero_filled.iter().copied()).collect();
            ranges.sort_unstable();
            ranges
        },
        tiled: Vec::new(),
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
    let mut decoders: Decoders<A> = explorer.regions.iter().map(|_| None).collect();
    {
        let _phase = phase::scope("discover/drain");
        explorer.drain(&mut decoders);
    }

    // Pointers in data are read once what the code reaches is decoded, so that it is not read
    // as one, and before the gaps are, which may hold the data.
    if A::MARKED_CODE_POINTERS && explorer.seed_marked_pointers() {
        let _phase = phase::scope("discover/drain");
        explorer.drain(&mut decoders);
    }
    explorer.mark_trailing_data();
    loop {
        let promoted = {
            let _phase = phase::scope("discover/promote tail calls");
            explorer.promote_tail_calls()
        };
        {
            let _phase = phase::scope("discover/drain");
            explorer.drain(&mut decoders);
        }
        let _phase = phase::scope("discover/fill gaps");
        let filled = explorer.fill_gaps(&mut decoders);
        if !promoted && !filled {
            break;
        }
    }

    // The entry points of a pass that only learns lengths are not read.
    if !explorer.recording {
        return explorer;
    }
    let _phase = phase::scope("discover/demote");
    explorer.demote_table_addresses();
    explorer.demote_case_targets();
    while explorer.demote_crossed_starts() {}
    explorer.demote_loop_heads();
    explorer.demote_frame_borrowers();
    // What these remove may have been all that kept a jump across an entry point from
    // showing it as a guess.
    if A::CALL_MAY_BE_FAR_JUMP || explorer.taken_is_weak() {
        if A::CALL_MAY_BE_FAR_JUMP {
            explorer.demote_far_jumps();
        }
        if explorer.taken_is_weak() {
            explorer.demote_taken_inside_code();
        }
        while explorer.demote_crossed_starts() {}
    }

    explorer
}
