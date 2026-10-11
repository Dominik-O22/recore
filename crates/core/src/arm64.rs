//! AArch64 support, decoded directly from the fixed 32-bit instruction words.
//!
//! Only the instruction classes the analysis needs are recognised: control flow, address
//! formation (`adrp`/`add`/`adr`), loads that feed indirect branches and jump tables, and the
//! markers and padding compilers emit around functions. Everything else is treated as an
//! ordinary instruction that writes its destination register.

use std::collections::HashMap;

use crate::arch::{Arch, Decoded, Flow, Table};
use crate::image::Image;

/// How many spilled values are tracked per path.
const SPILL_SLOTS: usize = 4;

/// Upper bound on entries when no bounds check is found.
const MAX_ENTRIES: usize = 4096;

const NOP: u32 = 0xD503_201F;
const BTI_C: u32 = 0xD503_245F;
const BTI_J: u32 = 0xD503_249F;
const BTI_JC: u32 = 0xD503_24DF;
const PACIASP: u32 = 0xD503_233F;
const PACIBSP: u32 = 0xD503_237F;

/// One instruction word and where it sits, which PC-relative forms need.
#[derive(Clone, Copy)]
pub struct Insn {
    word: u32,
    addr: u64,
}

fn sign_extend(value: u32, bits: u32) -> i64 {
    let shift = 64 - bits;
    ((u64::from(value) << shift) as i64) >> shift
}

impl Insn {
    /// Register in bits 0..5: the destination of most instructions, the target of loads.
    fn rd(self) -> usize {
        (self.word & 31) as usize
    }
    fn rn(self) -> usize {
        (self.word >> 5 & 31) as usize
    }
    fn rm(self) -> usize {
        (self.word >> 16 & 31) as usize
    }

    /// Target of a branch whose offset is `bits` wide starting at bit `low`, counted in words.
    fn branch_target(self, low: u32, bits: u32) -> u64 {
        let field = self.word >> low & ((1 << bits) - 1);
        self.addr.wrapping_add_signed(sign_extend(field, bits) * 4)
    }

    /// `b` and `bl`: `(is_call, target)`.
    fn direct(self) -> Option<(bool, u64)> {
        (self.word & 0x7C00_0000 == 0x1400_0000).then(|| (self.word >> 31 == 1, self.branch_target(0, 26)))
    }

    /// `b.cond`, `cbz`/`cbnz`, `tbz`/`tbnz`.
    fn conditional(self) -> Option<u64> {
        if self.word & 0xFF00_0000 == 0x5400_0000 || self.word & 0x7E00_0000 == 0x3400_0000 {
            Some(self.branch_target(5, 19))
        } else if self.word & 0x7E00_0000 == 0x3600_0000 {
            Some(self.branch_target(5, 14))
        } else {
            None
        }
    }

    /// `br`, `blr`, `ret` and their pointer-authenticating forms: the operation number.
    fn register_branch(self) -> Option<u32> {
        (self.word & 0xFE00_0000 == 0xD600_0000).then(|| self.word >> 21 & 7)
    }

    /// `adr` and `adrp`: the address formed.
    fn pc_relative(self) -> Option<(bool, u64)> {
        if self.word & 0x1F00_0000 != 0x1000_0000 {
            return None;
        }
        let offset = sign_extend((self.word >> 5 & 0x7FFFF) << 2 | (self.word >> 29 & 3), 21);
        let is_page = self.word >> 31 == 1;
        Some(if is_page {
            (true, (self.addr & !0xFFF).wrapping_add_signed(offset << 12))
        } else {
            (false, self.addr.wrapping_add_signed(offset))
        })
    }

    /// 64-bit `add xd, xn, #imm`: the immediate.
    fn add_immediate(self) -> Option<u64> {
        (self.word & 0xFF00_0000 == 0x9100_0000).then(|| {
            let imm = u64::from(self.word >> 10 & 0xFFF);
            if self.word >> 22 & 1 == 1 { imm << 12 } else { imm }
        })
    }

    /// 64-bit `ldr xt, [xn, #imm]`: the byte offset.
    fn load_offset(self) -> Option<u64> {
        (self.word & 0xFFC0_0000 == 0xF940_0000).then(|| u64::from(self.word >> 10 & 0xFFF) * 8)
    }

    /// 64-bit `str xt, [sp, #imm]`: the byte offset.
    fn store_to_stack(self) -> Option<u64> {
        (self.word & 0xFFC0_0000 == 0xF900_0000 && self.rn() == 31).then(|| u64::from(self.word >> 10 & 0xFFF) * 8)
    }

    /// `add sp, sp, #imm` / `sub sp, sp, #imm`, or a load or store that updates `sp`.
    fn moves_stack_pointer(self) -> bool {
        let adjusts = self.word & 0x7F00_0000 == 0x1100_0000 && self.rd() == 31 && self.rn() == 31 && self.word >> 31 == 1;
        let is_memory = self.word >> 25 & 0b0101 == 0b0100;
        let is_pair = self.word & 0x3A00_0000 == 0x2800_0000;
        let writes_base = if is_pair { self.word >> 23 & 1 == 1 } else { self.word >> 24 & 1 == 0 && self.word >> 10 & 1 == 1 };
        adjusts || (is_memory && writes_base && self.rn() == 31)
    }

    /// `ldr`/`ldrb`/`ldrh`/`ldrsw`... `[xn, xm, extend]`: `(entry size, signed)`.
    fn indexed_load(self) -> Option<(u64, bool)> {
        // Load/store with register offset; the two `opc` bits select store, zero- or
        // sign-extending load.
        (self.word & 0x3F20_0C00 == 0x3820_0800).then(|| (1u64 << (self.word >> 30), self.word >> 23 & 1 == 1)).filter(|_| {
            self.word >> 22 & 3 != 0
        })
    }

    /// `cmp wn, #imm` / `cmp xn, #imm`: `(register, immediate)`.
    fn compare_immediate(self) -> Option<(usize, u64)> {
        (self.word & 0x7F80_001F == 0x7100_001F).then(|| (self.rn(), u64::from(self.word >> 10 & 0xFFF)))
    }

    /// `mov xd, xm`, encoded as `orr xd, xzr, xm`.
    fn register_move(self) -> Option<usize> {
        (self.word & 0x7FE0_FFE0 == 0x2A00_03E0).then(|| self.rm())
    }
}

/// What a register is known to hold.
#[derive(Clone, Copy, PartialEq, Default, Debug)]
enum Value {
    #[default]
    Unknown,
    /// A page address from `adrp`, awaiting its low bits.
    Page(u64),
    /// A complete address.
    Addr(u64),
    /// A pointer loaded from the slot at this address.
    Slot(u64),
    /// An index proven to be at most this value by an unsigned bounds check.
    Bounded(u64),
    /// An entry loaded from a jump table.
    Entry { table: u64, size: u64, signed: bool, max_index: Option<u64> },
    /// A jump target formed as `base + (entry << shift)`.
    Target { table: u64, size: u64, signed: bool, max_index: Option<u64>, base: u64, shift: u32 },
}

/// Register contents at one program point.
#[derive(Clone, Copy, Default)]
pub struct State {
    registers: [Value; 32],
    /// Values spilled to the stack, as `(offset from sp, value)`. GCC keeps a hoisted table
    /// address in a stack slot across a loop.
    spills: [(u64, Value); SPILL_SLOTS],
    /// Register and immediate of a `cmp` whose flags the next instruction may branch on.
    compare: Option<(usize, u64)>,
}

impl State {
    fn set(&mut self, register: usize, value: Value) {
        // Register 31 is the zero register or the stack pointer, never a tracked value.
        if register != 31 {
            self.registers[register] = value;
        }
    }

    fn step(&mut self, insn: Insn) {
        self.compare = None;
        if let Some(compare) = insn.compare_immediate() {
            self.compare = Some(compare);
            return;
        }
        if insn.direct().is_some_and(|(is_call, _)| is_call) || insn.register_branch() == Some(1) {
            // A call may change every caller-saved register.
            for register in (0..=18).chain([30]) {
                self.registers[register] = Value::Unknown;
            }
            return;
        }
        if let Some(offset) = insn.store_to_stack() {
            // Remember addresses only: that is all a later dispatch needs back.
            let value = self.registers[insn.rd()];
            let slot = self.spills.iter().position(|(at, _)| *at == offset);
            match (slot, matches!(value, Value::Addr(_))) {
                (Some(slot), _) => self.spills[slot] = (offset, value),
                (None, true) => {
                    self.spills.rotate_right(1);
                    self.spills[0] = (offset, value);
                }
                (None, false) => {}
            }
            return;
        }
        if insn.moves_stack_pointer() {
            self.spills = Default::default();
        }
        let value = if let Some((is_page, address)) = insn.pc_relative() {
            if is_page { Value::Page(address) } else { Value::Addr(address) }
        } else if let Some(immediate) = insn.add_immediate() {
            match self.registers[insn.rn()] {
                Value::Page(page) => Value::Addr(page + immediate),
                _ => Value::Unknown,
            }
        } else if let Some(offset) = insn.load_offset() {
            match self.registers[insn.rn()] {
                _ if insn.rn() == 31 => self.spills.iter().find(|(at, _)| *at == offset).map_or(Value::Unknown, |&(_, value)| value),
                Value::Page(base) | Value::Addr(base) => Value::Slot(base + offset),
                _ => Value::Unknown,
            }
        } else if let Some(source) = insn.register_move() {
            self.registers[source]
        } else if let Some((size, signed)) = insn.indexed_load() {
            match self.registers[insn.rn()] {
                Value::Addr(table) => {
                    let max_index = match self.registers[insn.rm()] {
                        Value::Bounded(max) => Some(max),
                        _ => None,
                    };
                    Value::Entry { table, size, signed, max_index }
                }
                _ => Value::Unknown,
            }
        } else if insn.word & 0xFFE0_0000 == 0x8B20_0000 {
            // `add xd, xn, wm, <extend> #shift`: base plus scaled entry, GCC's dispatch.
            let signed = insn.word >> 15 & 1 == 1;
            match (self.registers[insn.rn()], self.registers[insn.rm()]) {
                (Value::Addr(base), Value::Entry { table, size, signed: loaded_signed, max_index }) => {
                    Value::Target { table, size, signed: signed || loaded_signed, max_index, base, shift: insn.word >> 10 & 7 }
                }
                _ => Value::Unknown,
            }
        } else if insn.word & 0xFF20_0000 == 0x8B00_0000 {
            // `add xd, xn, xm, lsl #shift`: table address plus entry, Clang's dispatch.
            let shift = insn.word >> 10 & 63;
            match (self.registers[insn.rn()], self.registers[insn.rm()]) {
                (Value::Addr(base), Value::Entry { table, size, signed, max_index })
                | (Value::Entry { table, size, signed, max_index }, Value::Addr(base))
                    if shift <= 2 =>
                {
                    Value::Target { table, size, signed, max_index, base, shift }
                }
                _ => Value::Unknown,
            }
        } else if insn.word >> 25 & 0b0101 == 0b0100 {
            // Other loads and stores: the transfer registers, and the base when it is updated.
            self.set(insn.rd(), Value::Unknown);
            let is_pair = insn.word & 0x3A00_0000 == 0x2800_0000;
            if is_pair {
                self.set((insn.word >> 10 & 31) as usize, Value::Unknown);
            }
            let writes_base = if is_pair { insn.word >> 23 & 1 == 1 } else { insn.word >> 24 & 1 == 0 && insn.word >> 10 & 1 == 1 };
            if writes_base {
                self.set(insn.rn(), Value::Unknown);
            }
            return;
        } else {
            Value::Unknown
        };
        self.set(insn.rd(), value);
    }
}

fn read_entry(bytes: &[u8], size: u64, signed: bool) -> i64 {
    let mut raw = [0u8; 8];
    raw[..size as usize].copy_from_slice(&bytes[..size as usize]);
    let value = u64::from_le_bytes(raw);
    if signed { sign_extend_64(value, size as u32 * 8) } else { value as i64 }
}

fn sign_extend_64(value: u64, bits: u32) -> i64 {
    let shift = 64 - bits;
    ((value << shift) as i64) >> shift
}

pub struct Arm64;

impl Arch for Arm64 {
    type Insn = Insn;
    type State = State;

    /// GCC packs AArch64 functions back to back at instruction alignment unless tuned for a
    /// specific core, so alignment says nothing about where a function starts.
    const FUNCTION_ALIGN: u64 = 4;
    const ALIGNMENT_IS_EVIDENCE: bool = false;

    fn decode(bytes: &[u8], addr: u64) -> impl Iterator<Item = Decoded<Insn>> {
        bytes.chunks_exact(4).zip((addr..).step_by(4)).map(|(chunk, addr)| {
            let word = u32::from_le_bytes(chunk.try_into().unwrap());
            Decoded { addr, len: 4, insn: Some(Insn { word, addr }) }
        })
    }

    fn flow(insn: &Insn, state: &State) -> Option<Flow> {
        let slot = |register: usize| match state.registers[register] {
            Value::Slot(slot) => Some(slot),
            _ => None,
        };
        if let Some((is_call, target)) = insn.direct() {
            Some(if is_call { Flow::Call(target) } else { Flow::Jump(target) })
        } else if let Some(target) = insn.conditional() {
            Some(Flow::Branch(target))
        } else if let Some(operation) = insn.register_branch() {
            Some(match operation {
                0 => Flow::JumpIndirect(slot(insn.rn())),
                1 => Flow::CallIndirect(slot(insn.rn())),
                _ => Flow::Return,
            })
        } else {
            // `brk`, and `udf` with a non-zero immediate. An all-zero word is padding.
            let traps = insn.word & 0xFFE0_001F == 0xD420_0000 || (insn.word >> 16 == 0 && insn.word != 0);
            traps.then_some(Flow::Halt)
        }
    }

    fn address_taken(insn: &Insn, state: &State) -> Option<u64> {
        match insn.pc_relative() {
            Some((false, address)) => Some(address),
            Some((true, _)) => None,
            None => match (insn.add_immediate(), state.registers[insn.rn()]) {
                (Some(immediate), Value::Page(page)) => Some(page + immediate),
                _ => None,
            },
        }
    }

    fn is_padding(insn: &Insn) -> bool {
        insn.word == NOP || insn.word == 0
    }

    fn is_entry_marker(insn: &Insn) -> bool {
        matches!(insn.word, BTI_C | BTI_JC | PACIASP | PACIBSP)
    }

    /// The unwinder enters a landing pad with the exception object in `x0`, and with branch
    /// protection the pad opens with `bti j`. A function entry never does either first.
    fn opens_landing_pad(insn: &Insn) -> bool {
        insn.word == BTI_J || insn.register_move() == Some(0)
    }

    fn step(state: &mut State, insn: &Insn) {
        state.step(*insn);
    }

    fn branch(mut state: State, insn: &Insn) -> (State, State) {
        let compare = state.compare.take();
        let (mut taken, mut fallthrough) = (state, state);
        // Only `b.cond` reads the flags of the compare.
        if let (Some((register, immediate)), true) = (compare, insn.word & 0xFF00_0000 == 0x5400_0000) {
            match insn.word & 0xF {
                // hi: falling through means index <= immediate.
                8 => fallthrough.set(register, Value::Bounded(immediate)),
                // ls: taken means index <= immediate.
                9 => taken.set(register, Value::Bounded(immediate)),
                // hs / lo: the strict forms.
                2 if immediate > 0 => fallthrough.set(register, Value::Bounded(immediate - 1)),
                3 if immediate > 0 => taken.set(register, Value::Bounded(immediate - 1)),
                _ => {}
            }
        }
        (taken, fallthrough)
    }

    fn after_jump(mut state: State, jump: &Insn) -> State {
        state.compare = None;
        state.set(jump.rn(), Value::Unknown);
        state
    }

    fn resolve_table(
        state: &State,
        image: &Image,
        _pointer_slots: &HashMap<u64, u64>,
        jump: &Insn,
        is_target: &dyn Fn(u64) -> bool,
    ) -> Option<Table> {
        let Value::Target { table, size, signed, max_index, base, shift } = state.registers[jump.rn()] else {
            return None;
        };
        let bytes = image.bytes_from(table)?;
        let limit = max_index.map_or(MAX_ENTRIES, |max| (max as usize).saturating_add(1).min(MAX_ENTRIES));
        let mut entries = Vec::new();
        for entry in bytes.chunks_exact(size as usize).take(limit) {
            let target = base.wrapping_add_signed(read_entry(entry, size, signed) << shift);
            if !is_target(target) {
                // A bounded table with an impossible entry is a misread, not a short table.
                if max_index.is_some() {
                    return None;
                }
                break;
            }
            entries.push(target);
        }
        (!entries.is_empty()).then_some(Table { address: table, entry_size: size, entries, bounded: max_index.is_some() })
    }

    fn marked_jump_target(image: &Image, target: u64) -> Option<bool> {
        if !image.branch_targets_marked {
            return None;
        }
        let word = image.bytes_from(target)?.get(..4).map(|b| u32::from_le_bytes(b.try_into().unwrap()))?;
        Some(matches!(word, BTI_J | BTI_JC))
    }

    /// A PLT stub is `adrp x16, page; ldr x17, [x16, #offset]; add x16, ...; br x17`, optionally
    /// preceded by `bti c`.
    fn plt_stubs(image: &Image) -> HashMap<u64, u64> {
        let mut stubs = HashMap::new();
        for section in image.sections.iter().filter(|s| s.executable && s.name.starts_with(".plt")) {
            let mut stub_start = section.addr;
            let mut page = None;
            let mut previous = 0u32;
            for decoded in Self::decode(&section.data, section.addr) {
                let Some(insn) = decoded.insn else { continue };
                match (insn.pc_relative(), insn.load_offset()) {
                    (Some((true, address)), _) if insn.rd() == 16 => {
                        page = Some(address);
                        stub_start = if previous == BTI_C { decoded.addr - 4 } else { decoded.addr };
                    }
                    (_, Some(offset)) if insn.rd() == 17 && insn.rn() == 16 => {
                        if let Some(slot) = page.take().map(|page| page + offset) {
                            if image.import_slots.contains_key(&slot) {
                                stubs.insert(stub_start, slot);
                            }
                        }
                    }
                    _ => {}
                }
                previous = insn.word;
            }
        }
        stubs
    }
}
