//! Code discovery: finds instructions and function entry points by following control flow.
//!
//! Starts from the entry point, exports, code pointers stored in data, and `.eh_frame` entries
//! when present. Follows calls and jumps, takes `lea`-computed code addresses as entry points,
//! then fills the gaps that nothing referenced.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use iced_x86::{Decoder, DecoderOptions, Instruction};

use crate::image::{Image, Section};
use crate::noreturn::is_noreturn_import;
use crate::jumptable::{State, Table};
use crate::report::{JumpTable, Origin};
use crate::x86::{classify, is_endbr, is_padding, lea_target, opens_landing_pad, Flow};

/// Typical function alignment for GCC, Clang and rustc at `-O2`.
pub const FUNCTION_ALIGN: u64 = 16;

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
}

struct Explorer<'a> {
    image: &'a Image,
    regions: Vec<Region<'a>>,
    starts: BTreeMap<u64, Origin>,
    referenced: HashSet<u64>,
    /// Direct jumps as `(from, to)`, kept to recognise tail calls afterwards.
    jumps: Vec<(u64, u64)>,
    /// Addresses still to decode, each with the register state on arrival.
    pending: Vec<(u64, State)>,
    /// Resolved tables with the jump that uses each.
    tables: Vec<(u64, Table)>,
    /// Data addresses computed by `lea`. The next one after a table bounds its length.
    data_refs: BTreeSet<u64>,
    /// Slot address to target for every pointer a relative relocation stores in data.
    pointer_slots: HashMap<u64, u64>,
    /// `[start, end)` ranges from `.eh_frame`. Nothing strictly inside one becomes an entry point.
    frames: &'a [(u64, u64)],
}

impl<'a> Explorer<'a> {
    fn region_index(&self, addr: u64) -> Option<usize> {
        self.regions.iter().position(|r| r.section.contains(addr))
    }

    fn inside_frame(&self, addr: u64) -> bool {
        let index = self.frames.partition_point(|&(start, _)| start <= addr);
        index > 0 && addr > self.frames[index - 1].0 && addr < self.frames[index - 1].1
    }

    fn add_start(&mut self, addr: u64, origin: Origin) {
        if matches!(origin, Origin::Call | Origin::AddressTaken | Origin::DataPointer | Origin::Export) {
            self.referenced.insert(addr);
        }
        if self.region_index(addr).is_some() && !self.inside_frame(addr) && !self.starts.contains_key(&addr) {
            self.starts.insert(addr, origin);
            self.pending.push((addr, State::default()));
        }
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
        match self.frame_of(jump) {
            Some((start, end)) => target >= start && target <= end,
            None => self.region_index(target).is_some(),
        }
    }

    /// Decodes from every pending address until control flow ends or reaches known code.
    fn drain(&mut self) {
        let mut instr = Instruction::default();
        while let Some((start, mut state)) = self.pending.pop() {
            let Some(index) = self.region_index(start) else { continue };
            let section = self.regions[index].section;
            let mut decoder =
                Decoder::with_ip(64, &section.data[(start - section.addr) as usize..], start, DecoderOptions::NONE);
            let mut after_call = false;
            while decoder.can_decode() {
                let offset = (decoder.ip() - section.addr) as usize;
                if std::mem::replace(&mut self.regions[index].is_instruction[offset], true) {
                    break;
                }
                decoder.decode_out(&mut instr);
                // Padding straight after a call means the call does not return: compilers pad
                // between functions, not after a call that falls through.
                if instr.is_invalid() || (after_call && is_padding(&instr)) {
                    self.regions[index].is_instruction[offset] = false;
                    break;
                }
                after_call = false;
                let Some(flow) = classify(&instr) else {
                    if let Some(target) = lea_target(&instr) {
                        if self.region_index(target).is_some() {
                            self.add_start(target, Origin::AddressTaken);
                        } else {
                            self.data_refs.insert(target);
                        }
                    }
                    state.step(&instr);
                    continue;
                };
                let ends_flow = match flow {
                    Flow::Call(target) => {
                        self.add_start(target, Origin::Call);
                        false
                    }
                    Flow::CallIndirect(_) => self.import_never_returns(flow),
                    Flow::Jump(target) => {
                        self.jumps.push((instr.ip(), target));
                        self.pending.push((target, state));
                        true
                    }
                    Flow::Branch(target) => {
                        let (taken, fallthrough) = state.branch(&instr);
                        self.jumps.push((instr.ip(), target));
                        self.pending.push((target, taken));
                        state = fallthrough;
                        false
                    }
                    Flow::JumpIndirect(None) => {
                        let jump = instr.ip();
                        let resolved =
                            state.resolve(self.image, &self.pointer_slots, &instr, |target| self.is_case_target(jump, target));
                        if let Some(table) = resolved {
                            let at_case = state.after_jump(&instr);
                            let function_end = self.frame_end(jump);
                            // An entry equal to the function's end marks a case proven unreachable.
                            self.pending.extend(
                                table.entries.iter().filter(|&&target| Some(target) != function_end).map(|&target| (target, at_case)),
                            );
                            self.tables.push((jump, table));
                        }
                        true
                    }
                    Flow::JumpIndirect(Some(_)) | Flow::Return | Flow::Halt => true,
                };
                if ends_flow {
                    if let Some(flag) = self.regions[index].follows_break.get_mut((instr.next_ip() - section.addr) as usize) {
                        *flag = true;
                    }
                    break;
                }
                if matches!(flow, Flow::Call(_) | Flow::CallIndirect(_)) {
                    state.step(&instr);
                    after_call = true;
                }
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
                        count = count.min(((next - table.address) / 4) as usize);
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
        let earliest = offset.saturating_sub(FUNCTION_ALIGN as usize - 1);
        let Some(break_at) = (earliest..=offset).rev().find(|&o| region.follows_break[o]) else {
            return false;
        };
        let mut decoder = Decoder::with_ip(64, &region.section.data[break_at..offset], 0, DecoderOptions::NONE);
        let mut instr = Instruction::default();
        while decoder.can_decode() {
            decoder.decode_out(&mut instr);
            if instr.is_invalid() || !is_padding(&instr) {
                return false;
            }
        }
        true
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
            if to == from || to % FUNCTION_ALIGN != 0 || self.starts.contains_key(&to) {
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
        // A code pointer in data that is not function-aligned may be a label, as in a table of
        // computed-goto targets, so it is only weak evidence.
        let is_weak = |addr: u64, origin: &Origin| match origin {
            Origin::TailCall | Origin::GapAligned | Origin::GapEndbr => true,
            Origin::DataPointer => addr % FUNCTION_ALIGN != 0,
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

    /// Finds code that nothing referenced. Code following padding at an aligned address, or
    /// opening with `endbr64`, starts a function. Other unreached code continues the function
    /// before it, such as switch cases behind an unresolved indirect jump.
    fn fill_gaps(&mut self) -> bool {
        let mut found = false;
        let mut instr = Instruction::default();
        for index in 0..self.regions.len() {
            let section = self.regions[index].section;
            let mut offset = 0;
            while offset < section.data.len() {
                if self.regions[index].is_instruction[offset] {
                    // Skip the whole instruction, not only its first byte.
                    let mut decoder =
                        Decoder::with_ip(64, &section.data[offset..], section.addr + offset as u64, DecoderOptions::NONE);
                    decoder.decode_out(&mut instr);
                    offset += instr.len().max(1);
                    continue;
                }
                // An unreached stretch: step over padding to the first real instruction.
                let mut decoder =
                    Decoder::with_ip(64, &section.data[offset..], section.addr + offset as u64, DecoderOptions::NONE);
                let mut skipped_padding = false;
                let mut candidate = None;
                while decoder.can_decode() {
                    let at = (decoder.ip() - section.addr) as usize;
                    if self.regions[index].is_instruction[at] {
                        break;
                    }
                    decoder.decode_out(&mut instr);
                    if instr.is_invalid() {
                        break;
                    }
                    if is_padding(&instr) {
                        skipped_padding = true;
                        continue;
                    }
                    candidate = Some(instr.ip());
                    break;
                }
                offset = (decoder.ip() - section.addr) as usize;
                let Some(addr) = candidate else { continue };
                if skipped_padding {
                    self.regions[index].follows_break[(addr - section.addr) as usize] = true;
                }
                let aligned = addr % FUNCTION_ALIGN == 0;
                let endbr = is_endbr(&instr);
                // An `endbr64` right after other code may be a landing pad at the end of a function.
                let landing_pad = endbr && !skipped_padding && {
                    let mut next = Instruction::default();
                    decoder.decode_out(&mut next);
                    !next.is_invalid() && opens_landing_pad(&next)
                };
                if aligned && (skipped_padding || endbr) && !landing_pad && !self.inside_frame(addr) {
                    self.add_start(addr, if endbr { Origin::GapEndbr } else { Origin::GapAligned });
                } else {
                    self.pending.push((addr, State::default()));
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

pub fn discover(image: &Image, frames: &[(u64, u64)]) -> Discovery {
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
    let mut explorer = Explorer {
        image,
        regions,
        starts: BTreeMap::new(),
        referenced: HashSet::new(),
        jumps: Vec::new(),
        pending: Vec::new(),
        tables: Vec::new(),
        data_refs: BTreeSet::new(),
        pointer_slots: image.relative_targets.iter().copied().collect(),
        frames,
    };

    let seeds = frames
        .iter()
        .map(|&(start, _)| (start, Origin::Frame))
        .chain(image.exports.iter().chain([&image.entry]).map(|&addr| (addr, Origin::Export)))
        .chain(image.relative_targets.iter().map(|&(_, target)| (target, Origin::DataPointer)));
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
    Discovery { starts, jump_tables: explorer.jump_tables(), referenced: explorer.referenced }
}
