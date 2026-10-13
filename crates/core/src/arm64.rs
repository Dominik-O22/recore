//! AArch64 support, decoded directly from the fixed 32-bit instruction words.
//!
//! Only the instruction classes the analysis needs are recognised: control flow, address
//! formation (`adrp`/`add`/`adr`), loads that feed indirect branches and jump tables, and the
//! markers and padding compilers emit around functions. Everything else is treated as an
//! ordinary instruction that writes its destination register.

use rustc_hash::FxHashMap;

use crate::arch::{Arch, Decoded, FieldUse, Flow, Limit, MAX_ENTRIES, Table};
use crate::image::Image;

/// How many spilled values are tracked per path.
const SPILL_SLOTS: usize = 4;

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

    /// 64-bit `ldr xt, [xn], #imm` or `ldr xt, [xn, #imm]!`, which load and move the base, as a
    /// loop over a table of pointers does: whether the base moves before the load, and by how
    /// much.
    fn load_moving_base(self) -> Option<(bool, u64)> {
        (self.word & 0xFFE0_0400 == 0xF840_0400).then(|| (self.word >> 11 & 1 == 1, sign_extend(self.word >> 12 & 0x1FF, 9) as u64))
    }

    /// A load or store of any width at `[xn, #imm]`, the form that reads and writes globals:
    /// the byte offset.
    fn access_offset(self) -> Option<u64> {
        // Bits 29..27 and 25..24 select the unsigned-offset form; the top two bits give the
        // width, which scales the offset. A 128-bit vector register is the one exception.
        let scale = if self.word >> 26 & 1 == 1 && self.word >> 23 & 1 == 1 { 4 } else { self.word >> 30 };
        if self.word & 0x3B00_0000 == 0x3900_0000 {
            return Some(u64::from(self.word >> 10 & 0xFFF) << scale);
        }
        // The forms with a signed nine-bit offset in bytes: unscaled (`ldur`), and the two
        // that also move the base, of which the one that moves it afterwards reads at the base.
        let signed_offset = sign_extend(self.word >> 12 & 0x1FF, 9) as u64;
        match (self.word & 0x3B20_0000 == 0x3800_0000, self.word >> 10 & 3) {
            (true, 0b00 | 0b11) => return Some(signed_offset),
            (true, 0b01) => return Some(0),
            _ => {}
        }
        // A pair of registers loaded or stored at once (`ldp`, `stp`): a signed seven-bit
        // offset scaled by the width of one register.
        let pair_scale = 2 + (self.word >> 30) - u32::from(self.word >> 26 & 1 == 0 && self.word >> 31 == 1);
        let pair_offset = (sign_extend(self.word >> 15 & 0x7F, 7) << pair_scale) as u64;
        match (self.word & 0x3A00_0000 == 0x2800_0000, self.word >> 23 & 3) {
            (true, 0b10 | 0b11) => Some(pair_offset),
            (true, 0b01) => Some(0),
            _ => None,
        }
    }

    /// 64-bit `ldr xt, label`: the address loaded from. Apple's linker rewrites `adrp` and `ldr`
    /// to this when the slot is near enough.
    fn load_literal(self) -> Option<u64> {
        (self.word & 0xFF00_0000 == 0x5800_0000).then(|| self.branch_target(5, 19))
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

    /// A vector operation on registers of one shape, such as `mov v0.16b, v11.16b`, or a move
    /// between floating-point registers, such as `fmov d0, d8`: how floating-point arguments
    /// are set up. Neither touches a general register.
    fn writes_vector_only(self) -> bool {
        self.word & 0x9F20_0400 == 0x0E20_0400 || self.word & 0xFF3F_FC00 == 0x1E20_4000
    }

    /// Whether this is a store, or a load into vector registers: a load or store that writes
    /// none of the general registers it names as transferred. The exclusive forms also write
    /// a status register, and do not count.
    fn transfers_without_writing(self) -> bool {
        let is_memory = self.word >> 25 & 0b0101 == 0b0100;
        let is_pair = self.word & 0x3A00_0000 == 0x2800_0000;
        let is_exclusive = self.word & 0x3F00_0000 == 0x0800_0000;
        let is_literal = self.word & 0x3B00_0000 == 0x1800_0000;
        let is_load = is_literal || if is_pair { self.word >> 22 & 1 == 1 } else { self.word >> 22 & 3 != 0 };
        is_memory && !is_exclusive && !(is_load && self.word >> 26 & 1 == 0)
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
    /// What another pass said the register holds, by a number of its choosing.
    Object(u32),
    /// An index proven to be at most this value by an unsigned bounds check.
    Bounded(u64),
    /// An entry loaded from a jump table.
    Entry { table: u64, size: u8, signed: bool, limit: Option<Limit> },
    /// A jump target formed as `base + (entry << shift)`.
    Target { table: u64, size: u8, signed: bool, limit: Option<Limit>, base: u64, shift: u8 },
}

// A state is copied at every branch that is followed, so its size is part of the analysis time.
const _: () = assert!(size_of::<Value>() == 24);

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
            // Remember addresses, which are all a later dispatch needs back, and what
            // another pass follows.
            let value = self.registers[insn.rd()];
            let slot = self.spills.iter().position(|(at, _)| *at == offset);
            match (slot, matches!(value, Value::Addr(_) | Value::Object(_))) {
                (Some(slot), _) => self.spills[slot] = (offset, value),
                (None, true) => {
                    self.spills.rotate_right(1);
                    self.spills[0] = (offset, value);
                }
                (None, false) => {}
            }
            return;
        }
        if insn.writes_vector_only() {
            return;
        }
        if insn.moves_stack_pointer() {
            self.spills = Default::default();
        }
        if let Some((before, by)) = insn.load_moving_base() {
            let (loaded, moved) = match self.registers[insn.rn()] {
                Value::Addr(base) if insn.rn() != 31 => {
                    let moved = base.wrapping_add(by);
                    (Value::Slot(if before { moved } else { base }), Value::Addr(moved))
                }
                _ => (Value::Unknown, Value::Unknown),
            };
            self.set(insn.rn(), moved);
            self.set(insn.rd(), loaded);
            return;
        }
        let value = if let Some((is_page, address)) = insn.pc_relative() {
            if is_page { Value::Page(address) } else { Value::Addr(address) }
        } else if let Some(immediate) = insn.add_immediate() {
            match self.registers[insn.rn()] {
                Value::Page(base) | Value::Addr(base) => Value::Addr(base + immediate),
                _ => Value::Unknown,
            }
        } else if let Some(offset) = insn.load_offset() {
            match self.registers[insn.rn()] {
                _ if insn.rn() == 31 => self.spills.iter().find(|(at, _)| *at == offset).map_or(Value::Unknown, |&(_, value)| value),
                Value::Page(base) | Value::Addr(base) => Value::Slot(base + offset),
                _ => Value::Unknown,
            }
        } else if let Some(slot) = insn.load_literal() {
            Value::Slot(slot)
        } else if let Some(source) = insn.register_move() {
            self.registers[source]
        } else if let Some((size, signed)) = insn.indexed_load() {
            match self.registers[insn.rn()] {
                Value::Addr(table) => {
                    let limit = match self.registers[insn.rm()] {
                        Value::Bounded(max) => Some(Limit::of(max)),
                        _ => None,
                    };
                    Value::Entry { table, size: size as u8, signed, limit }
                }
                _ => Value::Unknown,
            }
        } else if insn.word & 0xFFE0_0000 == 0x8B20_0000 {
            // `add xd, xn, wm, <extend> #shift`: base plus scaled entry, GCC's dispatch.
            let signed = insn.word >> 15 & 1 == 1;
            match (self.registers[insn.rn()], self.registers[insn.rm()]) {
                (Value::Addr(base), Value::Entry { table, size, signed: loaded_signed, limit }) => {
                    Value::Target { table, size, signed: signed || loaded_signed, limit, base, shift: (insn.word >> 10 & 7) as u8 }
                }
                _ => Value::Unknown,
            }
        } else if insn.word & 0xFF20_0000 == 0x8B00_0000 {
            // `add xd, xn, xm, lsl #shift`: table address plus entry, Clang's dispatch.
            let shift = (insn.word >> 10 & 63) as u8;
            match (self.registers[insn.rn()], self.registers[insn.rm()]) {
                (Value::Addr(base), Value::Entry { table, size, signed, limit })
                | (Value::Entry { table, size, signed, limit }, Value::Addr(base))
                    if shift <= 2 =>
                {
                    Value::Target { table, size, signed, limit, base, shift }
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

    type Decoder<'a> = (&'a [u8], u64);

    fn decoder(bytes: &[u8], addr: u64) -> Self::Decoder<'_> {
        (bytes, addr)
    }

    fn decode_from<'d>(&mut (bytes, base): &'d mut Self::Decoder<'_>, offset: usize) -> impl Iterator<Item = Decoded<Insn>> + 'd {
        Self::decode(&bytes[offset..], base + offset as u64)
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

    fn memory_reference(insn: &Insn, state: &State) -> Option<u64> {
        match (insn.access_offset(), state.registers[insn.rn()]) {
            (Some(offset), Value::Page(base) | Value::Addr(base)) if insn.rn() != 31 => Some(base.wrapping_add(offset)),
            _ => insn.load_literal(),
        }
    }

    fn offset_address(insn: &Insn, state: &State) -> Option<u64> {
        match (insn.add_immediate(), state.registers[insn.rn()]) {
            (Some(immediate), Value::Addr(base)) => Some(base + immediate),
            _ => None,
        }
    }

    fn through_pointer(insn: &Insn, state: &State) -> Option<(u64, u64, bool)> {
        let Value::Slot(slot) = state.registers[insn.rn()] else { return None };
        match (insn.access_offset(), insn.add_immediate()) {
            (Some(offset), _) if insn.rn() != 31 => Some((slot, offset, true)),
            (None, Some(offset)) => Some((slot, offset, false)),
            _ => None,
        }
    }

    fn argument_slot(state: &State, index: usize) -> Option<u64> {
        match state.registers[index] {
            Value::Slot(slot) => Some(slot),
            _ => None,
        }
    }

    fn argument_object(state: &State, index: usize) -> Option<u32> {
        match state.registers[index] {
            Value::Object(object) => Some(object),
            _ => None,
        }
    }

    fn set_argument_object(state: &mut State, index: usize, object: u32) {
        state.registers[index] = Value::Object(object);
    }

    /// The general step takes every load and store to write the registers it transfers. A
    /// store writes none, and a function opens by storing the very registers an object is
    /// kept in across calls.
    fn step_following(state: &mut State, insn: &Insn) {
        let transferred = [insn.rd(), (insn.word >> 10 & 31) as usize];
        let before = transferred.map(|register| state.registers[register]);
        state.step(*insn);
        if insn.transfers_without_writing() {
            for (register, value) in transferred.into_iter().zip(before) {
                if matches!(value, Value::Object(_)) {
                    state.registers[register] = value;
                }
            }
        }
    }

    /// Swift's calling convention keeps `self` in `x20`, which the callee saves for C.
    fn set_self_object(state: &mut State, object: u32) {
        state.registers[20] = Value::Object(object);
    }

    /// A result comes back in `x0`, which is also where the first argument goes.
    fn set_result_object(state: &mut State, object: u32) {
        state.registers[0] = Value::Object(object);
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

    fn takes_variable_arguments(insns: &[Insn]) -> bool {
        // The last vector register that carries an argument is stored to the stack, alone or
        // as the second of a pair, which nothing but saving the arguments does at an entry.
        let stores_q7 = |insn: &Insn| {
            let vector_to_stack = insn.word >> 26 & 1 == 1 && insn.rn() == 31 && insn.word >> 22 & 1 == 0;
            let single = insn.word & 0x3B00_0000 == 0x3900_0000 && insn.rd() == 7;
            let pair = insn.word & 0x3A00_0000 == 0x2800_0000 && (insn.word >> 10 & 31) == 7;
            vector_to_stack && (single || pair)
        };
        insns.iter().any(stores_q7)
    }

    fn field_use(insn: &Insn) -> Option<(u64, FieldUse)> {
        // Not from the stack pointer or the frame pointer, which reach the function's own variables.
        let offset = insn.access_offset().filter(|_| !matches!(insn.rn(), 29 | 31))?;
        // Bit 22 tells a load from a store, in the single and in the paired forms alike.
        Some((offset, if insn.word >> 22 & 1 == 1 { FieldUse::Read } else { FieldUse::Write }))
    }

    fn step(state: &mut State, insn: &Insn) {
        state.step(*insn);
    }

    fn branch(fallthrough: &mut State, insn: &Insn) -> State {
        let compare = fallthrough.compare.take();
        let mut taken = *fallthrough;
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
        taken
    }

    fn after_jump(mut state: State, jump: &Insn) -> State {
        state.compare = None;
        state.set(jump.rn(), Value::Unknown);
        state
    }

    fn resolve_table(
        state: &State,
        image: &Image,
        pointer_slots: &FxHashMap<u64, u64>,
        jump: &Insn,
        is_target: &dyn Fn(u64) -> bool,
        _is_code: &dyn Fn(u64) -> bool,
    ) -> Option<Table> {
        let (table, size, signed, limit, base, shift) = match state.registers[jump.rn()] {
            Value::Target { table, size, signed, limit, base, shift } => (table, u64::from(size), signed, limit, base, shift),
            // A 64-bit entry jumped to as it is: a table of absolute code pointers, as computed
            // goto uses. It runs for as long as consecutive slots hold relocated code pointers.
            Value::Entry { table, size: 8, .. } => {
                let entries: Vec<u64> = (0..MAX_ENTRIES as u64)
                    .map_while(|i| pointer_slots.get(&(table + 8 * i)).copied())
                    .take_while(|&target| is_target(target))
                    .collect();
                return (!entries.is_empty()).then_some(Table { address: table, entry_size: 8, entries, bounded: true });
            }
            _ => return None,
        };
        let bytes = image.bytes_from(table)?;
        let mut entries = Vec::new();
        for entry in bytes.chunks_exact(size as usize).take(Limit::entries(limit)) {
            let target = base.wrapping_add_signed(read_entry(entry, size, signed) << shift);
            if !is_target(target) {
                // A bounded table with an impossible entry is a misread, not a short table.
                if limit.is_some() {
                    return None;
                }
                break;
            }
            entries.push(target);
        }
        (!entries.is_empty()).then_some(Table { address: table, entry_size: size, entries, bounded: limit.is_some() })
    }

    fn marked_jump_target(image: &Image, target: u64) -> Option<bool> {
        if !image.branch_targets_marked {
            return None;
        }
        let word = image.bytes_from(target)?.get(..4).map(|b| u32::from_le_bytes(b.try_into().unwrap()))?;
        Some(matches!(word, BTI_J | BTI_JC))
    }

    /// A stub loads the address in an import slot and jumps to it. ELF's is `adrp x16, page;
    /// ldr x17, [x16, #offset]; add x16, ...; br x17`, optionally after `bti c`; Mach-O's is
    /// `adrp x16, page; ldr x16, [x16, #offset]; br x16`, with a pointer-authenticating form,
    /// and one that loads a selector first to send an Objective-C message.
    fn plt_stubs(image: &Image) -> FxHashMap<u64, u64> {
        let mut stubs = FxHashMap::default();
        for section in image.sections.iter().filter(|s| s.is_stubs()) {
            let mut state = State::default();
            let mut stub_start = None;
            for decoded in Self::decode(&section.data, section.addr) {
                let Some(insn) = decoded.insn else { continue };
                // Padding and traps separate stubs.
                if insn.word == NOP || Self::flow(&insn, &state) == Some(Flow::Halt) {
                    continue;
                }
                let start = *stub_start.get_or_insert(decoded.addr);
                if insn.register_branch().is_none() && insn.direct().is_none() {
                    state.step(insn);
                    continue;
                }
                if let (Some(0), Value::Slot(slot)) = (insn.register_branch(), state.registers[insn.rn()]) {
                    if image.import_slots.contains_key(&slot) {
                        stubs.insert(start, slot);
                    }
                }
                (state, stub_start) = (State::default(), None);
            }
        }
        stubs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_load_through_a_page_address_refers_to_the_global() {
        // 0x4000: adrp x0, 0x5000; ldr w1, [x0, #0x10]
        let code: Vec<u8> = [0xB000_0000u32, 0xB940_1001].iter().flat_map(|word| word.to_le_bytes()).collect();
        let mut state = State::default();
        let mut referred = Vec::new();
        for decoded in Arm64::decode(&code, 0x4000) {
            let insn = decoded.insn.unwrap();
            referred.push(Arm64::memory_reference(&insn, &state));
            Arm64::step(&mut state, &insn);
        }
        assert_eq!(referred, [None, Some(0x5010)]);
    }

    #[test]
    fn offsets_of_the_other_addressing_forms_are_read() {
        let offset = |word: u32| Insn { word, addr: 0 }.access_offset().map(|offset| offset as i64);
        // ldur x0, [x1, #-0x8]; ldr x0, [x1], #0x8; strb w1, [x3, #-0x1]!
        assert_eq!([offset(0xF85F_8020), offset(0xF840_8420), offset(0x381F_FC61)], [Some(-8), Some(0), Some(-1)]);
        // stp xzr, xzr, [x3, #0x10]; stp wzr, wzr, [x19, #0x4]; stp q21, q21, [x24, #0xc0]
        assert_eq!([offset(0xA901_7C7F), offset(0x2900_FE7F), offset(0xAD06_5715)], [Some(0x10), Some(4), Some(0xc0)]);
        // add x1, x1, #0x20 reads nothing.
        assert_eq!(offset(0x9100_8021), None);
    }
}
