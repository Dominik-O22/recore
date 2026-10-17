//! ARM Cortex-M support: Thumb code, the 16-bit instructions and the 32-bit ones of Thumb-2,
//! decoded directly from their halfwords.
//!
//! Only what the analysis needs is told apart: control flow, the `IT` blocks that make the
//! instructions after them conditional, the literal pools and `MOVW`/`MOVT` pairs that form
//! addresses, and the compare, scaling and loads that lead to a jump through a table. Everything
//! else is an instruction that writes the registers it may write.
//!
//! A code address is even. A pointer to code has bit 0 set, the mark of Thumb state, which is
//! the only state a Cortex-M runs in; recore drops the mark where it reads a pointer.

use rustc_hash::FxHashMap;

use crate::arch::{Arch, Decoded, Flow, Limit, Table, TextPointer};
use crate::image::{Image, Section};

const PC: usize = 15;
const LR: usize = 14;

/// One instruction and where it sits, which PC-relative forms need.
#[derive(Clone, Copy)]
pub struct Insn {
    pub(crate) addr: u64,
    pub(crate) hw1: u16,
    /// The second halfword of a 32-bit instruction, zero for a 16-bit one.
    pub(crate) hw2: u16,
    /// Inside an `IT` block: the instruction runs only when the block's condition holds.
    pub(crate) conditional: bool,
    /// The word a PC-relative `LDR` loads, when the decoded bytes hold it.
    pub(crate) literal: Option<u32>,
}

pub(crate) fn sign_extend(value: u32, bits: u32) -> i64 {
    let shift = 64 - bits;
    ((u64::from(value) << shift) as i64) >> shift
}

/// The 32-bit constant of a Thumb-2 modified immediate, `i:imm3:imm8`.
fn expand_immediate(imm12: u32) -> u32 {
    let imm8 = imm12 & 0xFF;
    if imm12 >> 10 == 0 {
        match imm12 >> 8 & 3 {
            0 => imm8,
            1 => imm8 << 16 | imm8,
            2 => imm8 << 24 | imm8 << 8,
            _ => imm8 * 0x0101_0101,
        }
    } else {
        (0x80 | imm12 & 0x7F).rotate_right(imm12 >> 7)
    }
}

/// Where a PC-relative operand counts from: the instruction's address plus 4, down to a word.
fn aligned_pc(addr: u64) -> u64 {
    (addr + 4) & !3
}

impl Insn {
    pub(crate) fn wide(self) -> bool {
        is_wide(self.hw1)
    }

    /// A low register in bits `low..low + 3` of the first halfword.
    pub(crate) fn low_register(self, low: u32) -> usize {
        usize::from(self.hw1 >> low & 7)
    }

    /// `Rd` of the 32-bit data-processing forms, and `RdHi` of the long multiplies.
    pub(crate) fn rd(self) -> usize {
        usize::from(self.hw2 >> 8 & 15)
    }

    /// `Rt` of the 32-bit loads and stores, and `RdLo` of the long multiplies.
    pub(crate) fn rt(self) -> usize {
        usize::from(self.hw2 >> 12)
    }

    /// `Rn` of the 32-bit forms.
    pub(crate) fn rn(self) -> usize {
        usize::from(self.hw1 & 15)
    }

    /// The target of a direct branch, and whether it calls: `B`, `B<c>`, `CBZ`, `CBNZ` and `BL`.
    pub(crate) fn direct(self) -> Option<(u64, Transfer)> {
        let next = self.addr + 4;
        let (hw1, hw2) = (u32::from(self.hw1), u32::from(self.hw2));
        if !self.wide() {
            return match hw1 >> 11 {
                // B<c>; condition 14 is UDF and 15 is SVC.
                0b11010 | 0b11011 if hw1 >> 9 & 7 != 7 => Some((next.wrapping_add_signed(sign_extend((hw1 & 0xFF) << 1, 9)), Transfer::Branch)),
                0b11100 => Some((next.wrapping_add_signed(sign_extend((hw1 & 0x7FF) << 1, 12)), Transfer::Jump)),
                // CBZ and CBNZ, forward only.
                0b10110 | 0b10111 if hw1 & 0x0500 == 0x0100 => Some((next + u64::from((hw1 >> 9 & 1) << 6 | (hw1 >> 3 & 0x1F) << 1), Transfer::Branch)),
                _ => None,
            };
        }
        if hw1 >> 11 != 0b11110 || hw2 & 0x8000 == 0 {
            return None;
        }
        let s = hw1 >> 10 & 1;
        let (j1, j2) = (hw2 >> 13 & 1, hw2 >> 11 & 1);
        match hw2 & 0x5000 {
            // B<c>.W; the conditions 14 and 15 are other control instructions.
            0x0000 if hw1 >> 6 & 0xE != 0xE => {
                let offset = s << 20 | j2 << 19 | j1 << 18 | (hw1 & 0x3F) << 12 | (hw2 & 0x7FF) << 1;
                Some((next.wrapping_add_signed(sign_extend(offset, 21)), Transfer::Branch))
            }
            // B.W and BL; BLX, which only code that may run A32 has, goes to A32 code at a word.
            0x1000 | 0x5000 | 0x4000 => {
                let (i1, i2) = (!(j1 ^ s) & 1, !(j2 ^ s) & 1);
                let offset = s << 24 | i1 << 23 | i2 << 22 | (hw1 & 0x3FF) << 12 | (hw2 & 0x7FF) << 1;
                let from = if hw2 & 0x5000 == 0x4000 { next & !3 } else { next };
                let target = from.wrapping_add_signed(sign_extend(offset, 25));
                Some((target, if hw2 & 0x4000 != 0 { Transfer::Call } else { Transfer::Jump }))
            }
            _ => None,
        }
    }

    /// `[start, end)` of the data a PC-relative load reads: a literal `LDR` of any width,
    /// `LDRD` or `VLDR`.
    pub(crate) fn literal_range(self) -> Option<(u64, u64)> {
        let (hw1, hw2) = (self.hw1, self.hw2);
        let pc = aligned_pc(self.addr);
        if !self.wide() {
            return (hw1 >> 11 == 0b01001).then(|| {
                let at = pc + u64::from(hw1 & 0xFF) * 4;
                (at, at + 4)
            });
        }
        let up = hw1 & 0x0080 != 0;
        let (offset, size) = match hw1 & 0xFF7F {
            // LDRB, LDRH, LDR, LDRSB, LDRSH; a byte or halfword one into PC is a preload.
            0xF81F | 0xF83F | 0xF91F | 0xF93F if self.rt() == PC => return None,
            0xF81F | 0xF91F => (u64::from(hw2 & 0xFFF), 1),
            0xF83F | 0xF93F => (u64::from(hw2 & 0xFFF), 2),
            0xF85F => (u64::from(hw2 & 0xFFF), 4),
            0xE95F => (u64::from(hw2 & 0xFF) * 4, 8),
            // VLDR of a single or a double register.
            0xED1F | 0xED5F if hw2 & 0x0E00 == 0x0A00 => (u64::from(hw2 & 0xFF) * 4, if hw2 & 0x0100 != 0 { 8 } else { 4 }),
            _ => return None,
        };
        let at = if up { pc + offset } else { pc.wrapping_sub(offset) };
        Some((at, at + size))
    }

    /// `[start, end)` of the doubleword an `LDRD` or `VLDR` reads at an offset from a register
    /// that holds an address past it, as near as `ADR.W` reaches: a literal pool, whose address
    /// GCC forms with `ADR` to load a 64-bit constant.
    #[inline]
    pub(crate) fn pool_load(self, state: &State) -> Option<(u64, u64)> {
        /// How far `ADR.W` reaches.
        const REACH: u64 = 4095;
        let (hw1, hw2) = (self.hw1, self.hw2);
        // LDRD Rt, Rt2, [Rn, #imm] without writeback, and VLDR of a double register: both are
        // 32-bit instructions.
        let loads = hw1 & 0xFF70 == 0xE950 || hw1 & 0xFF30 == 0xED10 && hw2 & 0x0F00 == 0x0B00;
        if !loads || usize::from(hw1 & 0xF) == PC {
            return None;
        }
        let (offset, size) = (u64::from(hw2 & 0xFF) * 4, 8);
        let Value::Const(base) = state.registers[usize::from(hw1 & 0xF)] else { return None };
        let at = if hw1 & 0x0080 != 0 { u64::from(base) + offset } else { u64::from(base).wrapping_sub(offset) };
        (at > self.addr && at - self.addr <= REACH && at % 4 == 0).then_some((at, at + size))
    }

    /// The register a literal `LDR` of a word loads.
    pub(crate) fn literal_word_register(self) -> Option<usize> {
        if !self.wide() {
            return (self.hw1 >> 11 == 0b01001).then(|| self.low_register(8));
        }
        (self.hw1 & 0xFF7F == 0xF85F).then(|| self.rt())
    }

    /// `ADR` and `ADR.W`: the register and the address it gets.
    pub(crate) fn adr(self) -> Option<(usize, u64)> {
        let pc = aligned_pc(self.addr);
        if !self.wide() {
            return (self.hw1 >> 11 == 0b10100).then(|| (self.low_register(8), pc + u64::from(self.hw1 & 0xFF) * 4));
        }
        let offset = u64::from((self.hw1 >> 10 & 1) << 11 | (self.hw2 >> 12 & 7) << 8 | self.hw2 & 0xFF);
        match (self.hw1 & 0xFBFF, self.hw2 & 0x8000) {
            (0xF20F, 0) => Some((self.rd(), pc + offset)),
            (0xF2AF, 0) => Some((self.rd(), pc.wrapping_sub(offset))),
            _ => None,
        }
    }

    /// `MOVW` and `MOVT`: the register, the 16 bits, and whether they are the top half.
    pub(crate) fn move_half(self) -> Option<(usize, u32, bool)> {
        if !self.wide() || self.hw2 & 0x8000 != 0 {
            return None;
        }
        let top = match self.hw1 & 0xFBF0 {
            0xF240 => false,
            0xF2C0 => true,
            _ => return None,
        };
        let (hw1, hw2) = (u32::from(self.hw1), u32::from(self.hw2));
        let value = (hw1 & 15) << 12 | (hw1 >> 10 & 1) << 11 | (hw2 >> 12 & 7) << 8 | hw2 & 0xFF;
        Some((self.rd(), value, top))
    }

    /// `TBB [Rn, Rm]` or `TBH [Rn, Rm, LSL #1]`: `(Rn, Rm, entry size)`.
    pub(crate) fn table_branch(self) -> Option<(usize, usize, u64)> {
        (self.wide() && self.hw1 & 0xFFF0 == 0xE8D0 && self.hw2 & 0xFFE0 == 0xF000).then(|| (self.rn(), usize::from(self.hw2 & 15), if self.hw2 & 0x10 != 0 { 2 } else { 1 }))
    }

    /// The 16-bit forms that name a high register: `ADD`, `CMP`, `MOV`, `BX` and `BLX`, as the
    /// operation (bits 9 and 8), the destination or first operand, and the second operand.
    pub(crate) fn high(self) -> Option<(u16, usize, usize)> {
        (!self.wide() && self.hw1 & 0xFC00 == 0x4400).then(|| (self.hw1 >> 8 & 3, usize::from(self.hw1 >> 4 & 8 | self.hw1 & 7), usize::from(self.hw1 >> 3 & 15)))
    }

    /// Whether this is `POP` or a load of several registers from the stack that includes PC.
    pub(crate) fn pops_pc(self) -> bool {
        if !self.wide() {
            return self.hw1 & 0xFF00 == 0xBD00;
        }
        // LDMIA SP!, and LDR PC, [SP], #4.
        self.hw1 == 0xE8BD && self.hw2 & 0x8000 != 0 || self.hw1 == 0xF85D && self.hw2 == 0xFB04
    }

    /// A 32-bit load into PC from somewhere other than the stack: through a pointer, or a table.
    pub(crate) fn loads_pc(self) -> bool {
        if !self.wide() {
            return false;
        }
        let multiple = matches!(self.hw1 & 0xFFD0, 0xE890 | 0xE910) && self.hw2 & 0x8000 != 0;
        let single = self.hw1 & 0xFFF0 == 0xF8D0 || self.hw1 & 0xFFF0 == 0xF850;
        multiple || single && self.rt() == PC
    }

    /// The 16-bit `CMP Rn, #imm8`, `CMP Rn, Rm`, and the 32-bit `CMP.W Rn, #const`.
    pub(crate) fn compare(self, state: &State) -> Option<(usize, u32)> {
        if !self.wide() {
            return match self.hw1 >> 11 {
                0b00101 => Some((self.low_register(8), u32::from(self.hw1 & 0xFF))),
                _ if self.hw1 & 0xFFC0 == 0x4280 => match state.registers[self.low_register(3)] {
                    Value::Const(bound) => Some((self.low_register(0), bound)),
                    _ => None,
                },
                _ => None,
            };
        }
        let imm12 = u32::from(self.hw1 >> 10 & 1) << 11 | u32::from(self.hw2 >> 12 & 7) << 8 | u32::from(self.hw2 & 0xFF);
        (self.hw1 & 0xFBF0 == 0xF1B0 && self.hw2 & 0x8F00 == 0x0F00).then(|| (self.rn(), expand_immediate(imm12)))
    }

    /// Whether the instruction may set the condition flags. Those that cannot are loads and
    /// stores, moves of addresses and between high registers, stack adjustments, and the
    /// 32-bit forms that leave their S bit clear.
    pub(crate) fn sets_flags(self) -> bool {
        let hw1 = self.hw1;
        if !self.wide() {
            return !(hw1 >> 11 == 0b01001
                || (0x5..=0x9).contains(&(hw1 >> 12))
                || matches!(hw1 >> 11, 0b10100 | 0b10101 | 0b11000 | 0b11001)
                || matches!(hw1 >> 8, 0xB0 | 0xB2 | 0xB4 | 0xB5 | 0xBA | 0xBC | 0xBD | 0xBF | 0x44 | 0x46));
        }
        match hw1 >> 9 {
            0b1110100 | 0b1111100 => false,
            // Of the operations on registers only the shifts have an S bit, and multiplies none.
            0b1111101 => hw1 & 0xFF80 == 0xFA00 && hw1 & 0x10 != 0,
            0b1110101 => hw1 & 0x10 != 0,
            0b1111000..=0b1111011 if self.hw2 & 0x8000 == 0 => hw1 & 0x0200 == 0 && hw1 & 0x10 != 0,
            0b1110110 | 0b1110111 | 0b1111110 | 0b1111111 => hw1 == 0xEEF1 && self.hw2 & 0xF000 == 0xF000,
            _ => true,
        }
    }
}

/// Whether a halfword begins a 32-bit instruction.
fn is_wide(hw1: u16) -> bool {
    hw1 >> 11 >= 0b11101
}

#[derive(Clone, Copy, PartialEq)]
pub(crate) enum Transfer {
    Call,
    Jump,
    Branch,
}

/// What a register is known to hold.
#[derive(Clone, Copy, Default, PartialEq)]
pub(crate) enum Value {
    #[default]
    Unknown,
    /// A number the code put there whole: an address, or not.
    Const(u32),
    /// An index proven to be at most so large.
    Bounded(Limit),
    /// An index shifted left, by a bounds check or not. Every `shift` here is under 32.
    Scaled { limit: Option<Limit>, shift: u8 },
    /// `base + (index << shift)`, where `base` is the PC an `ADD Rd, PC` read.
    PcIndexed { base: u32, limit: Option<Limit>, shift: u8 },
    /// An entry of a table, of `size` bytes, shifted left, and whether it was loaded as a
    /// signed number.
    Entry { table: u32, size: u8, limit: Option<Limit>, shift: u8, signed: bool },
    /// A word popped off the stack, which a branch through returns: code that saved registers
    /// beside the return address pops that into a low register when it cannot pop it into PC,
    /// as Thumb-1 code after a frame of variable arguments does.
    Popped,
}

// A state is copied at every branch that is followed, so its size is part of the analysis time.
const _: () = assert!(size_of::<Value>() <= 12);

impl Value {
    /// The value shifted left: an index on its way to a table, or an entry on its way to a case.
    /// `by` is under 32, as an instruction's shift is; shifted out of the word, it is no index.
    pub(crate) fn shifted(self, by: u8) -> Value {
        let total = |shift: u8| Some(shift + by).filter(|&total| total < 32);
        match self {
            _ if by == 0 => self,
            Value::Unknown => Value::Scaled { limit: None, shift: by },
            Value::Bounded(limit) => Value::Scaled { limit: Some(limit), shift: by },
            Value::Scaled { limit, shift } => total(shift).map_or(Value::Unknown, |shift| Value::Scaled { limit, shift }),
            Value::Entry { table, size, limit, shift, signed } => total(shift).map_or(Value::Unknown, |shift| Value::Entry { table, size, limit, shift, signed }),
            _ => Value::Unknown,
        }
    }

    /// An index and how far it is shifted left, as far as it is known.
    pub(crate) fn index(self) -> Option<(Option<Limit>, u8)> {
        match self {
            Value::Unknown => Some((None, 0)),
            Value::Bounded(limit) => Some((Some(limit), 0)),
            Value::Scaled { limit, shift } => Some((limit, shift)),
            _ => None,
        }
    }
}

/// Register contents at one program point.
#[derive(Clone, Copy, Default)]
pub struct State {
    pub(crate) registers: [Value; 16],
    /// Register and number of a compare whose flags a branch may test.
    pub(crate) compare: Option<(u8, u32)>,
    /// The registers the instruction being stepped over writes.
    pub(crate) written: u16,
}

impl State {
    pub(crate) fn set(&mut self, register: usize, value: Value) {
        self.registers[register] = value;
        self.written |= 1 << register;
    }

    pub(crate) fn clobber(&mut self, mask: u16) {
        self.written |= mask;
        for register in (0..16).filter(|register| mask >> register & 1 != 0) {
            self.registers[register] = Value::Unknown;
        }
    }

    /// A compare's flags stay for a branch after instructions that set none, as long as the
    /// register it compared keeps its value.
    pub(crate) fn step(&mut self, insn: Insn) {
        if let Some((register, bound)) = insn.compare(self) {
            self.compare = Some((register as u8, bound));
            return;
        }
        let kept = self.compare.filter(|_| !insn.sets_flags());
        self.written = 0;
        self.apply(insn);
        self.compare = kept.filter(|&(register, _)| self.written >> register & 1 == 0);
    }

    pub(crate) fn apply(&mut self, insn: Insn) {
        if let Some(register) = insn.literal_word_register() {
            self.set(register, insn.literal.map_or(Value::Unknown, Value::Const));
            return;
        }
        if let Some((register, address)) = insn.adr() {
            self.set(register, Value::Const(address as u32));
            return;
        }
        if let Some((register, half, top)) = insn.move_half() {
            let value = match (top, self.registers[register]) {
                (false, _) => Value::Const(half),
                (true, Value::Const(low)) => Value::Const(half << 16 | low & 0xFFFF),
                (true, _) => Value::Unknown,
            };
            self.set(register, value);
            return;
        }
        if let Some((_, Transfer::Call)) = insn.direct() {
            self.clobber(CALLER_SAVED);
            return;
        }
        if insn.wide() { self.step_wide(insn) } else { self.step_narrow(insn) }
    }

    fn step_narrow(&mut self, insn: Insn) {
        let hw1 = insn.hw1;
        let (rd, rn, rm) = (insn.low_register(0), insn.low_register(3), insn.low_register(6));
        match hw1 >> 11 {
            // LSL #imm, of which LSL #0 is MOVS Rd, Rm.
            0b00000 => {
                let value = self.registers[rn].shifted((hw1 >> 6 & 0x1F) as u8);
                self.set(rd, value);
            }
            0b00001..=0b00011 => self.set(rd, Value::Unknown),
            0b00100 => self.set(insn.low_register(8), Value::Const(u32::from(hw1 & 0xFF))),
            0b00110 | 0b00111 => self.set(insn.low_register(8), Value::Unknown),
            0b01000 => {
                if let Some((operation, rd, rm)) = insn.high() {
                    match operation {
                        // ADD Rd, PC: the PC plus an index, or plus an offset into a table.
                        0 if rm == PC => {
                            let value = match (self.registers[rd].index(), u32::try_from(insn.addr + 4)) {
                                (Some((limit, shift)), Ok(base)) => Value::PcIndexed { base, limit, shift },
                                _ => Value::Unknown,
                            };
                            self.set(rd, value);
                        }
                        0 if rd != PC => self.set(rd, Value::Unknown),
                        2 if rd != PC => self.set(rd, self.registers[rm]),
                        3 if hw1 & 0x80 != 0 => self.clobber(CALLER_SAVED),
                        _ => {}
                    }
                } else {
                    // Data processing on low registers. TST, CMP and CMN write none.
                    if !matches!(hw1 >> 6 & 15, 0b1000 | 0b1010 | 0b1011) {
                        self.set(rd, Value::Unknown);
                    }
                }
            }
            // Loads and stores with a register offset: STR, STRH, STRB, then the loads.
            0b01010 | 0b01011 => {
                let operation = hw1 >> 9 & 7;
                if operation < 3 {
                    return;
                }
                let size = match operation {
                    0b100 => 4,
                    0b101 => 2,
                    0b110 => 1,
                    _ => 0,
                };
                let value = self.indexed_entry(self.registers[rn], self.registers[rm], size, false);
                self.set(rd, value);
            }
            // LDR, LDRB and LDRH with an immediate offset.
            0b01101 | 0b01111 | 0b10001 => {
                let (size, scale) = match hw1 >> 11 {
                    0b01101 => (4, 4),
                    0b01111 => (1, 1),
                    _ => (2, 2),
                };
                let offset = u32::from(hw1 >> 6 & 0x1F) * scale;
                let value = match self.registers[rn] {
                    // The shift that made the index makes it count entries of this size, of a
                    // table that ends below 4 GB.
                    Value::PcIndexed { base, limit, shift } if 1 << shift == size => base.checked_add(offset).map_or(Value::Unknown, |table| Value::Entry { table, size: size as u8, limit, shift: 0, signed: false }),
                    _ => Value::Unknown,
                };
                self.set(rd, value);
            }
            // LDR from the stack, ADD Rd, SP, #imm.
            0b10011 | 0b10101 => self.set(insn.low_register(8), Value::Unknown),
            0b10110 | 0b10111 => {
                // POP; extend and reverse bytes.
                if hw1 & 0xFE00 == 0xBC00 {
                    self.clobber(hw1 & 0xFF);
                    for register in (0..8).filter(|register| hw1 >> register & 1 != 0) {
                        self.registers[register] = Value::Popped;
                    }
                } else if matches!(hw1 & 0xFF00, 0xB200 | 0xBA00) {
                    self.set(rd, Value::Unknown);
                }
            }
            // LDM Rn!, {...}.
            0b11001 => self.clobber(hw1 & 0xFF | 1 << insn.low_register(8)),
            // STM Rn!, {...}.
            0b11000 => self.set(insn.low_register(8), Value::Unknown),
            _ => {}
        }
    }

    fn step_wide(&mut self, insn: Insn) {
        let (hw1, hw2) = (insn.hw1, insn.hw2);
        let rn = insn.rn();
        match hw1 >> 9 {
            // Load and store multiple.
            0b1110100 if hw1 & 0x40 == 0 => {
                let writeback = if hw1 & 0x20 != 0 { 1 << rn } else { 0 };
                self.clobber(if hw1 & 0x10 != 0 { hw2 | writeback } else { writeback });
            }
            // Load and store two registers, exclusive, and table branches.
            0b1110100 => {
                if insn.table_branch().is_none() {
                    self.clobber(1 << insn.rt() | 1 << insn.rd() | 1 << (hw2 & 15) | 1 << rn);
                }
            }
            // Data processing with a shifted register. MOV.W and LSL.W are ORR with no Rn.
            0b1110101 => {
                let (operation, flags) = (hw1 >> 5 & 15, hw1 & 0x10 != 0);
                let compares = flags && insn.rd() == PC && matches!(operation, 0b0000 | 0b0100 | 0b1000 | 0b1101);
                if compares {
                    return;
                }
                let shift = (hw2 >> 10 & 0x1C | hw2 >> 6 & 3) as u8;
                let value = match (operation, rn, hw2 >> 4 & 3) {
                    (0b0010, PC, 0) => self.registers[usize::from(hw2 & 15)].shifted(shift),
                    _ => Value::Unknown,
                };
                self.set(insn.rd(), value);
            }
            // Coprocessor and floating point: a move to core registers, or a base written back.
            0b1110110 | 0b1110111 | 0b1111110 | 0b1111111 => self.clobber(1 << insn.rt() | 1 << rn),
            // Data processing with an immediate.
            0b1111000..=0b1111011 if hw2 & 0x8000 == 0 => {
                let modified = hw1 & 0x0200 == 0;
                let (operation, flags) = (hw1 >> 5 & 15, hw1 & 0x10 != 0);
                if modified && flags && insn.rd() == PC && matches!(operation, 0b0000 | 0b0100 | 0b1000 | 0b1101) {
                    return;
                }
                let imm12 = u32::from(hw1 >> 10 & 1) << 11 | u32::from(hw2 >> 12 & 7) << 8 | u32::from(hw2 & 0xFF);
                let value = if modified && operation == 0b0010 && rn == PC { Value::Const(expand_immediate(imm12)) } else { Value::Unknown };
                self.set(insn.rd(), value);
            }
            // Branches and other control: of these only MRS writes a register.
            0b1111000..=0b1111011 => {
                if hw1 & 0xFFE0 == 0xF3E0 && hw2 & 0xD000 == 0x8000 {
                    self.set(insn.rd(), Value::Unknown);
                }
            }
            // Loads and stores of one register.
            0b1111100 => {
                // Only the form with an 8-bit offset can write the base back.
                let writeback = rn != PC && hw1 & 0x80 == 0 && hw2 & 0x0900 == 0x0900;
                let loads = hw1 & 0x10 != 0 && insn.rt() != PC;
                self.clobber(if loads { 1 << insn.rt() } else { 0 } | if writeback { 1 << rn } else { 0 });
            }
            // Data processing on registers, and multiplies.
            0b1111101 => {
                let long = hw1 & 0xFF80 == 0xFB80 && !matches!(hw1 >> 4 & 7, 0b001 | 0b011);
                self.clobber(1 << insn.rd() | if long { 1 << insn.rt() } else { 0 });
            }
            _ => self.clobber(1 << insn.rd() | 1 << insn.rt()),
        }
    }

    /// Splits the state at a branch taken on `condition`: returns the state where it is taken
    /// and leaves this one as it is where it is not. A compare's bound holds on the side of the
    /// branch it proves.
    pub(crate) fn split(&mut self, condition: Option<u16>) -> State {
        let compare = self.compare.take();
        let mut taken = *self;
        if let (Some((register, bound)), Some(condition)) = (compare, condition) {
            let register = usize::from(register);
            let bounded = |bound: u32| Value::Bounded(Limit::of(u64::from(bound)));
            match condition {
                // HI: falling through means the index is at most the bound.
                8 => self.set(register, bounded(bound)),
                // LS: taken means it.
                9 => taken.set(register, bounded(bound)),
                // HS and LO: the strict forms.
                2 if bound > 0 => self.set(register, bounded(bound - 1)),
                3 if bound > 0 => taken.set(register, bounded(bound - 1)),
                _ => {}
            }
        }
        taken
    }

    /// What a load of `size` bytes from `[base, index]` gives: an entry when one of the two is a
    /// table's address and the other an index scaled to entries of that size.
    pub(crate) fn indexed_entry(&self, base: Value, index: Value, size: u32, signed: bool) -> Value {
        let entry = |table: Value, index: Value| match (table, index.index()) {
            (Value::Const(table), Some((limit, shift))) if size != 0 && 1 << shift == size => Some(Value::Entry { table, size: size as u8, limit, shift: 0, signed }),
            _ => None,
        };
        entry(base, index).or_else(|| entry(index, base)).unwrap_or(Value::Unknown)
    }
}

/// The registers a call may change: R0 to R3, R12 and LR.
pub(crate) const CALLER_SAVED: u16 = 0b0101_0000_0000_1111;

/// How a table's entry gives its case.
#[derive(Clone, Copy)]
pub(crate) enum Cases {
    /// `base + (entry << shift)`.
    Relative { base: u64, shift: u8 },
    /// The same with the entry signed, and without the Thumb bit the sum may have.
    Signed { base: u64, shift: u8 },
    /// The entry is the case's address, with the Thumb bit where `thumb` and without it
    /// elsewhere.
    Absolute { thumb: bool },
}

/// One of libgcc's helpers for a Thumb-1 `switch`, `__gnu_thumb1_case_*` of `lib1funcs.S`: called
/// with the index in R0, it reads the table that follows the call, at its return address, and
/// goes to the case the entry gives, so that the call never returns.
struct CaseHelper {
    /// The helper's code. GCC links it from the library as it is.
    code: &'static [u16],
    /// Bytes in an entry, and whether it is signed.
    size: u64,
    signed: bool,
}

impl CaseHelper {
    /// Written by hand from `lib1funcs.S`, as no GCC was at hand to build it. Each scales the
    /// index, reads the entry at the return address with the Thumb bit cleared, and adds the
    /// entry times two to the return address, but `_si`, whose table of words starts at the
    /// next multiple of 4, and whose entries count from there in bytes.
    const ALL: [CaseHelper; 6] = [
        // _uqi: PUSH {R1}; MOV R1, LR; LSRS R1, R1, #1; LSLS R1, R1, #1; LDRB R1, [R1, R0];
        // LSLS R1, R1, #1; ADD LR, R1; POP {R1}; BX LR. _sqi has LDRSB.
        CaseHelper { code: &[0xB402, 0x4671, 0x0849, 0x0049, 0x5C09, 0x0049, 0x448E, 0xBC02, 0x4770], size: 1, signed: false },
        CaseHelper { code: &[0xB402, 0x4671, 0x0849, 0x0049, 0x5609, 0x0049, 0x448E, 0xBC02, 0x4770], size: 1, signed: true },
        // _uhi: PUSH {R0, R1}; MOV R1, LR; LSRS R1, R1, #1; LSLS R0, R0, #1; LSLS R1, R1, #1;
        // LDRH R1, [R1, R0]; LSLS R1, R1, #1; ADD LR, R1; POP {R0, R1}; BX LR. _shi has LDRSH.
        CaseHelper { code: &[0xB403, 0x4671, 0x0849, 0x0040, 0x0049, 0x5A09, 0x0049, 0x448E, 0xBC03, 0x4770], size: 2, signed: false },
        CaseHelper { code: &[0xB403, 0x4671, 0x0849, 0x0040, 0x0049, 0x5E09, 0x0049, 0x448E, 0xBC03, 0x4770], size: 2, signed: true },
        // _si: PUSH {R0, R1}; MOV R1, LR; ADDS R1, R1, #2, in either encoding; LSRS R1, R1, #2;
        // LSLS R0, R0, #2; LSLS R1, R1, #2; LDR R0, [R1, R0]; ADDS R0, R0, R1; MOV LR, R0;
        // POP {R0, R1}; MOV PC, LR.
        CaseHelper { code: &[0xB403, 0x4671, 0x1C89, 0x0889, 0x0080, 0x0089, 0x5808, 0x1840, 0x4686, 0xBC03, 0x46F7], size: 4, signed: true },
        CaseHelper { code: &[0xB403, 0x4671, 0x3102, 0x0889, 0x0080, 0x0089, 0x5808, 0x1840, 0x4686, 0xBC03, 0x46F7], size: 4, signed: true },
    ];

    /// The helper whose code is at `addr`, if any.
    fn at(image: &Image, addr: u64) -> Option<&'static CaseHelper> {
        let bytes = image.bytes_from(addr)?;
        let is = |helper: &CaseHelper| bytes.len() >= 2 * helper.code.len() && helper.code.iter().zip(bytes.chunks_exact(2)).all(|(&half, bytes)| half.to_le_bytes() == bytes);
        Self::ALL.iter().find(|helper| is(helper))
    }

    /// The table of a call to the helper that returns to `next`, as `read_table` takes it.
    fn table(&self, next: u64) -> (u64, Cases) {
        match self.size {
            4 => (next.next_multiple_of(4), Cases::Signed { base: next.next_multiple_of(4), shift: 0 }),
            _ if self.signed => (next, Cases::Signed { base: next, shift: 1 }),
            _ => (next, Cases::Relative { base: next, shift: 1 }),
        }
    }
}

/// Reads the table of `size`-byte entries at `table`. Without a bound it ends at the first entry
/// that is not a plausible case, or where the lowest case after the table begins, since the
/// cases follow it.
pub(crate) fn read_table(image: &Image, table: u64, size: u64, limit: Option<Limit>, cases: Cases, is_target: &dyn Fn(u64) -> bool) -> Option<Table> {
    let bytes = image.bytes_from(table)?;
    let mut entries = Vec::new();
    let mut lowest = u64::MAX;
    for (index, entry) in bytes.chunks_exact(size as usize).take(Limit::entries(limit)).enumerate() {
        let at = table + index as u64 * size;
        if limit.is_none() && at >= lowest {
            break;
        }
        let value = entry.iter().rev().fold(0u64, |value, &byte| value << 8 | u64::from(byte));
        let target = match cases {
            Cases::Relative { base, shift } => Some(base + (value << shift)),
            Cases::Signed { base, shift } => {
                let unused = 64 - 8 * size as u32;
                base.checked_add_signed(((value << unused) as i64 >> unused) << shift).map(|target| target & !1)
            }
            Cases::Absolute { thumb } => (value & 1 == u64::from(thumb)).then_some(value & !1),
        };
        // A case is never the table itself, which a padding byte of zero would give.
        let Some(target) = target.filter(|&target| (target < table || target >= at + size) && is_target(target)) else {
            if limit.is_some() {
                return None;
            }
            break;
        };
        if target > table {
            lowest = lowest.min(target);
        }
        entries.push(target);
    }
    let end = table + (entries.len() as u64 * size).next_multiple_of(2);
    (!entries.is_empty()).then_some(Table { address: table, entry_size: size, entries, bounded: limit.is_some(), inline_end: Some(end) })
}

/// The parts of a Cortex-M's address space that the architecture sets aside for data, by
/// `[start, end)` and what each is for. Below them is the code, which the image holds.
pub const MEMORY: [(u64, u64, &str); 5] = [
    (0x2000_0000, 0x4000_0000, "SRAM"),
    (0x4000_0000, 0x6000_0000, "peripherals"),
    (0x6000_0000, 0xA000_0000, "external RAM"),
    (0xA000_0000, 0xE000_0000, "external devices"),
    (0xE000_0000, 0x1_0000_0000, "system"),
];

/// `[start, end)` of the memory a Cortex-M program has besides what `sections` load: what it
/// reaches by address, none of it in the image.
pub fn memory(sections: &[Section]) -> Vec<(u64, u64)> {
    let mut free = Vec::new();
    for &(start, end, _) in &MEMORY {
        let mut from = start;
        for section in sections.iter().filter(|section| section.addr < end && section.end() > start) {
            if from < section.addr {
                free.push((from, section.addr));
            }
            from = from.max(section.end());
        }
        if from < end {
            free.push((from, end));
        }
    }
    free
}

/// Whether the load or store that `bytes` begin with reads memory, and whether it writes:
/// `None` for an instruction that is neither.
pub fn access(bytes: &[u8]) -> Option<(bool, bool)> {
    let hw1 = u16::from_le_bytes(bytes.get(..2)?.try_into().unwrap());
    let loads = if is_wide(hw1) {
        // Loads and stores of one register, of two, and of several.
        match hw1 >> 9 {
            0b1111100 | 0b1110100 => hw1 & 0x10 != 0,
            _ => return None,
        }
    } else {
        match hw1 >> 12 {
            // With a register offset: STR, STRH and STRB, then the loads.
            0b0101 => hw1 >> 9 & 7 >= 3,
            0b0110 | 0b0111 | 0b1000 | 0b1001 | 0b1100 => hw1 & 0x0800 != 0,
            _ => return None,
        }
    };
    Some((loads, !loads))
}

/// The vector table at the start of `table`: the initial stack pointer, then the address of the
/// handler of each exception and interrupt, with the Thumb bit, or zero for a slot not in use.
/// Returns the table's length in bytes and the handlers in table order, reset first. The table
/// ends at the first word that is neither, which is code, and an address of code, as `is_code`
/// tells, is a word that code would hardly begin with. The slots ARMv7-M reserves, words 7 to 10
/// and 13, may hold anything, as NXP's checksum of the words before it in word 7: they are the
/// table's where a slot after them is.
pub fn vector_table(table: &[u8], is_code: impl Fn(u64) -> bool) -> (u64, Vec<u64>) {
    /// The architecture's 16 exceptions and at most 496 interrupts.
    const MOST: usize = 512;
    const RESERVED: [usize; 5] = [7, 8, 9, 10, 13];
    let words = table.chunks_exact(4).map(|word| u64::from(u32::from_le_bytes(word.try_into().unwrap())));
    let mut handlers = Vec::new();
    let mut length = 4;
    for (index, word) in words.enumerate().skip(1).take(MOST - 1) {
        if RESERVED.contains(&index) {
            continue;
        }
        let handler = word & !1;
        if word != 0 && (word & 1 == 0 || !is_code(handler)) {
            break;
        }
        if word != 0 {
            handlers.push(handler);
        }
        length = (index as u64 + 1) * 4;
    }
    // Slots not in use after the last that is.
    while length > 8 && table[length as usize - 4..length as usize] == [0; 4] {
        length -= 4;
    }
    (length, handlers)
}

/// The branches through a register in `[start, end)` that return, through the word the code
/// popped off the stack: where the engine sees an indirect jump it cannot follow.
pub fn returns_through_register(image: &Image, start: u64, end: u64) -> Vec<u64> {
    let mut found = Vec::new();
    scan(image, start, end, |insn, _, flow| {
        if let (Some(Flow::Return), Some((2 | 3, _, rm))) = (flow, insn.high())
            && rm != LR
        {
            found.push(insn.addr);
        }
    });
    found
}

/// Decodes `[start, end)` one instruction after the other and hands `visit` each, with the
/// state before it and where it sends control. The state goes on past a call, which changes
/// the registers a call may, and past a branch, as it does where the branch is not taken, as
/// discovery has it on that path. After any other transfer nothing is known.
fn scan(image: &Image, start: u64, end: u64, mut visit: impl FnMut(&Insn, &State, Option<Flow>)) {
    let Some(bytes) = image.bytes_from(start) else { return };
    let mut state = State::default();
    for insn in Thumb::decode(image, bytes, start).take_while(|decoded| decoded.addr < end).filter_map(|decoded| decoded.insn) {
        let flow = Thumb::flow(&insn, &state, image);
        visit(&insn, &state, flow);
        match flow {
            Some(Flow::Call(_) | Flow::CallIndirect(_)) => state.clobber(CALLER_SAVED),
            Some(Flow::Branch(_)) => {
                Thumb::branch(&mut state, &insn);
            }
            Some(_) => state = State::default(),
            None => state.step(insn),
        }
    }
}

/// Thumb code of a Cortex-M.
pub struct Thumb;

/// Decodes the instruction at `offset` into `bytes`, which are loaded at `base`. `it` counts the
/// instructions of an `IT` block still to come. `BLX` to A32 code is an instruction only where
/// the processor runs A32 as well.
pub(crate) fn decode_at(bytes: &[u8], base: u64, offset: usize, it: &mut u8, a32: bool) -> Option<Decoded<Insn>> {
    let hw1 = u16::from_le_bytes(bytes.get(offset..offset + 2)?.try_into().unwrap());
    let addr = base + offset as u64;
    let wide = is_wide(hw1);
    let hw2 = match bytes.get(offset + 2..offset + 4) {
        Some(half) if wide => u16::from_le_bytes(half.try_into().unwrap()),
        // A 32-bit instruction cut short by the end of the bytes.
        None if wide => return Some(Decoded { addr, len: 2, insn: None }),
        _ => 0,
    };
    let conditional = *it != 0;
    *it = it.saturating_sub(1);
    if !a32 && wide && hw1 >> 11 == 0b11110 && hw2 & 0xD000 == 0xC000 {
        return Some(Decoded { addr, len: 4, insn: None });
    }
    // IT with a mask: the instructions it makes conditional follow.
    if !wide && hw1 & 0xFF00 == 0xBF00 && hw1 & 15 != 0 {
        *it = 4 - (hw1 & 15).trailing_zeros() as u8;
    }
    let mut insn = Insn { addr, hw1, hw2, conditional, literal: None };
    if insn.literal_word_register().is_some() {
        let (at, _) = insn.literal_range()?;
        let at = at.checked_sub(base).map(|at| at as usize);
        insn.literal = at.and_then(|at| bytes.get(at..at + 4)).map(|word| u32::from_le_bytes(word.try_into().unwrap()));
    }
    Some(Decoded { addr, len: if wide { 4 } else { 2 }, insn: Some(insn) })
}

/// A decoder over a section, with the state of the `IT` block it is in.
pub struct Decoder<'a> {
    bytes: &'a [u8],
    base: u64,
    offset: usize,
    it: u8,
    insn: Insn,
}

impl Thumb {
    /// The address the instruction completes in a register, whatever it is: a literal, an
    /// `ADR`, or the top half of a `MOVW` and `MOVT` pair.
    pub(crate) fn completed_address(insn: &Insn, state: &State) -> Option<u32> {
        if insn.literal_word_register().is_some() {
            return insn.literal;
        }
        if let Some((_, address)) = insn.adr() {
            return Some(address as u32);
        }
        match (insn.move_half(), insn.move_half().map(|(register, _, _)| state.registers[register])) {
            (Some((_, half, true)), Some(Value::Const(low))) => Some(half << 16 | low & 0xFFFF),
            _ => None,
        }
    }
}

impl Arch for Thumb {
    type Insn = Insn;
    type State = State;

    /// Clang aligns functions to four bytes and packs them at two, a compiler for size at two.
    const FUNCTION_ALIGN: u64 = 2;
    /// What aligns a function to 16 bytes, as a linker may the first of a section.
    const LONGEST_PADDING: u64 = 14;
    const ALIGNMENT_IS_EVIDENCE: bool = false;
    const TEXT_IN_CODE: bool = true;
    const LITERAL_POOLS: bool = true;
    const TAKEN_IS_WEAK: bool = true;
    const CALL_MAY_BE_FAR_JUMP: bool = true;
    const TILES_GAPS: bool = true;
    /// A lone `BX LR` or `B` is a function: an empty one, or one that goes on in another.
    const SHORTEST_TILE: u64 = 2;
    const MARKED_CODE_POINTERS: bool = true;

    fn decode<'a>(_: &'a Image, bytes: &'a [u8], addr: u64) -> impl Iterator<Item = Decoded<Insn>> + 'a {
        let (mut offset, mut it) = (0, 0);
        std::iter::from_fn(move || {
            let decoded = decode_at(bytes, addr, offset, &mut it, false)?;
            offset += usize::from(decoded.len);
            Some(decoded)
        })
    }

    type Decoder<'a> = Decoder<'a>;

    fn decoder<'a>(_: &'a Image, bytes: &'a [u8], addr: u64) -> Decoder<'a> {
        Decoder { bytes, base: addr, offset: 0, it: 0, insn: Insn { addr, hw1: 0, hw2: 0, conditional: false, literal: None } }
    }

    /// Nothing branches into an `IT` block, so a new place to decode from is outside one.
    fn seek(decoder: &mut Decoder<'_>, offset: usize) {
        (decoder.offset, decoder.it) = (offset, 0);
    }

    fn decode_next<'d>(decoder: &'d mut Decoder<'_>) -> Option<Decoded<&'d Insn>> {
        let decoded = decode_at(decoder.bytes, decoder.base, decoder.offset, &mut decoder.it, false)?;
        decoder.offset += usize::from(decoded.len);
        let insn = &mut decoder.insn;
        Some(Decoded { addr: decoded.addr, len: decoded.len, insn: decoded.insn.map(|decoded| &*{ *insn = decoded; insn }) })
    }

    fn flow(insn: &Insn, state: &State, image: &Image) -> Option<Flow> {
        let constant = |register: usize| match state.registers[register] {
            Value::Const(value) if value & 1 != 0 => Some(u64::from(value & !1)),
            _ => None,
        };
        let popped = |register: usize| state.registers[register] == Value::Popped;
        if let Some((target, transfer)) = insn.direct() {
            // Unoptimised code jumps to the next instruction with the short `B`, which goes
            // nowhere a fall through would not. A tail call to the next function is a `B.W`.
            if transfer == Transfer::Jump && !insn.wide() && target == insn.addr + 2 {
                return None;
            }
            return Some(match transfer {
                // A call that hands its return address to a helper that switches comes back
                // nowhere: it is an indirect jump, and its table follows it.
                Transfer::Call if !insn.conditional && CaseHelper::at(image, target).is_some() => Flow::JumpIndirect(None),
                Transfer::Call => Flow::Call(target),
                Transfer::Jump if !insn.conditional => Flow::Jump(target),
                Transfer::Jump | Transfer::Branch => Flow::Branch(target),
            });
        }
        let hw1 = insn.hw1;
        // A trap: UDF and UDF.W. BKPT stops for a debugger, which may let the code go on.
        if !insn.wide() && hw1 & 0xFF00 == 0xDE00 || insn.wide() && hw1 & 0xFFF0 == 0xF7F0 && insn.hw2 & 0xF000 == 0xA000 {
            return Some(Flow::Halt);
        }
        // A call through a register goes on after it, condition or not.
        if let Some((3, _, rm)) = insn.high().filter(|&(operation, _, _)| operation == 3 && hw1 & 0x80 != 0) {
            return Some(constant(rm).map_or(Flow::CallIndirect(None), Flow::Call));
        }
        // What follows leaves the code here, unless an `IT` block makes it conditional, when the
        // code goes on after it as well.
        let leaves = if insn.pops_pc() {
            Flow::Return
        } else if let Some((operation, rd, rm)) = insn.high() {
            match (operation, rd, rm) {
                (3, _, LR) | (2, PC, LR) => Flow::Return,
                (3, _, rm) | (2, PC, rm) if popped(rm) => Flow::Return,
                (3, _, _) | (2, PC, _) => constant(rm).map_or(Flow::JumpIndirect(None), Flow::Jump),
                (0, PC, _) => Flow::JumpIndirect(None),
                _ => return None,
            }
        } else if insn.table_branch().is_some() {
            Flow::JumpIndirect(None)
        } else if insn.loads_pc() {
            // LDR PC, [PC, #imm] jumps to the literal.
            match (insn.hw1 & 0xFF7F, insn.literal) {
                (0xF85F, Some(target)) if target & 1 != 0 => Flow::Jump(u64::from(target & !1)),
                _ => Flow::JumpIndirect(None),
            }
        } else {
            return None;
        };
        (!insn.conditional).then_some(leaves)
    }

    /// A pointer to code: one with the Thumb bit.
    fn address_taken(insn: &Insn, state: &State, _: &Image) -> Option<u64> {
        Self::completed_address(insn, state).filter(|address| address & 1 != 0).map(|address| u64::from(address & !1))
    }

    /// An address without the Thumb bit.
    fn data_address(insn: &Insn, state: &State) -> Option<u64> {
        Self::completed_address(insn, state).filter(|address| address & 1 == 0).map(u64::from)
    }

    fn memory_reference(insn: &Insn, state: &State) -> Option<u64> {
        let base = |register: usize| match state.registers[register] {
            Value::Const(base) => Some(u64::from(base)),
            _ => None,
        };
        if !insn.wide() {
            let hw1 = insn.hw1;
            // STR, LDR, STRB, LDRB, STRH and LDRH with an immediate offset.
            let scale = match hw1 >> 12 {
                0b0110 => 4,
                0b0111 => 1,
                0b1000 => 2,
                _ => return None,
            };
            return base(insn.low_register(3)).map(|base| base + u64::from(hw1 >> 6 & 0x1F) * scale);
        }
        // The 32-bit loads and stores of one register with a 12-bit offset.
        (insn.hw1 & 0xFE80 == 0xF880 && insn.rn() != PC).then(|| base(insn.rn()).map(|base| base + u64::from(insn.hw2 & 0xFFF))).flatten()
    }

    #[inline]
    fn literal(insn: &Insn, state: &State) -> Option<(u64, u64)> {
        insn.literal_range().or_else(|| insn.pool_load(state))
    }

    /// Whether the code at `target`, whose address with the Thumb bit the code forms or which
    /// follows a gap, can be a function. An odd number is as often the address of text, which
    /// begins at any byte, or a number that is no address at all; and data follows the code.
    /// A function either sets up its frame first, or is short and comes to its end before
    /// anything that cannot be code.
    fn code_pointer(image: &Image, target: u64) -> bool {
        /// How many instructions a function that saves nothing may run to its end.
        const LONGEST_LEAF: usize = 24;
        let Some(bytes) = image.bytes_from(target) else { return false };
        let mut insns = Self::decode(image, bytes, target).map(|decoded| decoded.insn);
        let Some(Some(first)) = insns.next() else { return false };
        // PUSH, PUSH.W, SUB SP, #imm.
        if Self::opens_function(&first, None) || !first.wide() && first.hw1 & 0xFF80 == 0xB080 {
            return true;
        }
        if Self::is_padding(&first) {
            return false;
        }
        // Text from the odd address on is text, unless it is a short function that returns,
        // whose `BX LR` reads as "pG".
        let text = bytes[1..].iter().take_while(|&&byte| matches!(byte, 0x20..=0x7E | b'\t' | b'\n' | b'\r')).count();
        let is_text = text >= 2 && bytes.get(1 + text) == Some(&0);
        let state = State::default();
        let mut insn = Some(first);
        for _ in 0..LONGEST_LEAF {
            let Some(current) = insn.filter(|insn| !Self::ends_code(insn)) else { return false };
            if is_text && current.addr > target + text as u64 {
                return false;
            }
            match Self::flow(&current, &state, image) {
                Some(Flow::Return) => return true,
                Some(Flow::Jump(_) | Flow::JumpIndirect(_)) => return !is_text,
                Some(Flow::Halt) => return false,
                _ => {}
            }
            insn = insns.next().flatten();
        }
        false
    }

    /// The addresses code forms of data in the flash, from a literal, an `ADR` or a `MOVW` and
    /// `MOVT` pair: text, if text is there. Text may begin at an odd address, which is not
    /// one of code then.
    fn text_pointers(image: &Image, start: u64, end: u64) -> Vec<TextPointer> {
        let mut found = Vec::new();
        // The literals lie past the end of the code that loads them.
        scan(image, start, end, |insn, state, _| {
            if let Some(address) = Self::completed_address(insn, state) {
                found.push(TextPointer { from: insn.addr, to: u64::from(address), marked: true });
            }
        });
        found
    }

    /// `NOP`, `NOP.W`, `MOV R8, R8`, which pads code for Thumb-1, the halfword lld fills gaps in
    /// code with, and zeros, which GNU ld does.
    fn is_padding(insn: &Insn) -> bool {
        if insn.wide() {
            return insn.hw1 == 0xF3AF && insn.hw2 == 0x8000;
        }
        matches!(insn.hw1, 0xBF00 | 0x46C0 | 0xD4D4 | 0x0000)
    }

    /// What a linker fills a gap between functions with. `NOP` aligns a loop as well.
    fn ends_code(insn: &Insn) -> bool {
        !insn.wide() && matches!(insn.hw1, 0xD4D4 | 0x0000)
    }

    fn is_entry_marker(_: &Insn) -> bool {
        false
    }

    /// `PUSH {..., LR}`, or `PUSH.W` with LR, which save the return address.
    fn opens_function(first: &Insn, _: Option<&Insn>) -> bool {
        if first.wide() { first.hw1 == 0xE92D && first.hw2 & 0x4000 != 0 } else { first.hw1 & 0xFF00 == 0xB500 }
    }

    /// A load from far up the stack before anything is pushed: a block that reads its
    /// function's variables. At a function's entry SP points at its fifth argument, and only
    /// the thirteenth on would be that far from it.
    fn borrows_frame(insns: &[Insn]) -> bool {
        const ARGUMENTS: u64 = 0x20;
        for insn in insns {
            let offset = match (insn.wide(), insn.hw1 >> 11, insn.hw1) {
                (false, 0b10011, _) => u64::from(insn.hw1 & 0xFF) * 4,
                (true, _, 0xF8DD) => u64::from(insn.hw2 & 0xFFF),
                _ => {
                    // PUSH, SUB SP and PUSH.W set up a frame of the code's own.
                    let sets_up = !insn.wide() && (insn.hw1 & 0xFE00 == 0xB400 || insn.hw1 & 0xFF80 == 0xB080) || insn.hw1 == 0xE92D;
                    if sets_up {
                        return false;
                    }
                    continue;
                }
            };
            return offset >= ARGUMENTS;
        }
        false
    }

    /// A `POP`, `ADD SP` or `LDR Rt, [SP], #4` before a `PUSH`, `SUB SP` or `STR Rt, [SP, #-4]!`.
    fn gives_back_frame(image: &Image, addr: u64, past_calls: bool) -> bool {
        /// How many instructions it may take to come to either.
        const LONGEST: usize = 64;
        let decode = |at: u64| Some(Self::decode(image, image.bytes_from(at)?, at));
        let Some(mut insns) = decode(addr) else { return false };
        for _ in 0..LONGEST {
            let Some(Decoded { insn: Some(insn), .. }) = insns.next() else { return false };
            let (hw1, hw2) = (insn.hw1, insn.hw2);
            let sets_up = if insn.wide() { hw1 == 0xE92D || hw1 == 0xF84D && hw2 & 0x0FFF == 0x0D04 } else { hw1 & 0xFE00 == 0xB400 || hw1 & 0xFF80 == 0xB080 };
            let gives_back = if insn.wide() { hw1 == 0xE8BD || hw1 == 0xF85D && hw2 & 0x0FFF == 0x0B04 } else { hw1 & 0xFE00 == 0xBC00 || hw1 & 0xFF80 == 0xB000 };
            if sets_up || gives_back {
                return gives_back;
            }
            match Self::flow(&insn, &State::default(), image) {
                None | Some(Flow::Branch(_)) => {}
                Some(Flow::Call(_) | Flow::CallIndirect(_)) if past_calls => {}
                Some(Flow::Jump(target)) => match decode(target) {
                    Some(next) => insns = next,
                    None => return false,
                },
                Some(_) => return false,
            }
        }
        false
    }

    /// The argument register the instruction writes, the lowest of R0 to R3 it writes, and the
    /// address it completes there.
    fn argument_write(insn: &Insn, state: &State) -> Option<(usize, Option<u64>)> {
        let mut after = *state;
        after.written = 0;
        after.apply(*insn);
        let position = (after.written & 0xF).trailing_zeros() as usize;
        (position < 4).then(|| (position, Self::completed_address(insn, state).map(u64::from)))
    }

    /// R3, the last register that carries an argument, stored before anything writes it right
    /// below the arguments the caller left on the stack, so that all lie in a row for `va_arg`.
    /// A function of four arguments that keeps them on the stack stores R3 lower down.
    fn takes_variable_arguments(insns: &[Insn]) -> bool {
        const SP: usize = 13;
        // Where each register points, as an offset from the stack pointer at entry, if it does.
        let mut points: [Option<i64>; 16] = [None; 16];
        points[SP] = Some(0);
        // Whether R3 stored at `offset` from what `base` points to lands right below the entry's.
        let saves = |points: &[Option<i64>; 16], base: usize, offset: i64| points[base].is_some_and(|at| at + offset == -4);
        // The offset of R3 among the words that a store of `list` writes in ascending order.
        let place = |list: u16| (list & 8 != 0).then(|| i64::from((list & 7).count_ones()) * 4);
        for insn in insns {
            let (hw1, hw2) = (insn.hw1, insn.hw2);
            let saved = if !insn.wide() {
                match hw1 >> 11 {
                    // STR Rt, [Rn, #imm5]; STR Rt, [SP, #imm8].
                    0b01100 => (hw1 & 7 == 3).then(|| saves(&points, insn.low_register(3), i64::from(hw1 >> 6 & 0x1F) * 4)),
                    0b10010 => (insn.low_register(8) == 3).then(|| saves(&points, SP, i64::from(hw1 & 0xFF) * 4)),
                    // STM Rn!, {...}, which moves Rn past what it stores.
                    0b11000 => {
                        let (base, list) = (insn.low_register(8), hw1 & 0xFF);
                        let saved = place(list).map(|offset| saves(&points, base, offset));
                        points[base] = points[base].map(|at| at + i64::from(list.count_ones()) * 4);
                        saved
                    }
                    // ADD Rd, SP, #imm8.
                    0b10101 => {
                        points[insn.low_register(8)] = points[SP].map(|at| at + i64::from(hw1 & 0xFF) * 4);
                        None
                    }
                    // SUB SP, #imm7, and PUSH.
                    0b10110 if hw1 & 0xFF80 == 0xB080 => {
                        points[SP] = points[SP].map(|at| at - i64::from(hw1 & 0x7F) * 4);
                        None
                    }
                    0b10110 if hw1 & 0xFE00 == 0xB400 => {
                        let list = hw1 & 0xFF | (hw1 & 0x100) << 6;
                        points[SP] = points[SP].map(|at| at - i64::from(list.count_ones()) * 4);
                        place(list).map(|offset| saves(&points, SP, offset))
                    }
                    // MOV Rd, SP.
                    0b01000 if hw1 & 0xFF78 == 0x4668 => {
                        points[usize::from(hw1 >> 4 & 8 | hw1 & 7)] = points[SP];
                        None
                    }
                    _ => None,
                }
            } else {
                let imm12 = u32::from(hw1 >> 10 & 1) << 11 | u32::from(hw2 >> 12 & 7) << 8 | u32::from(hw2 & 0xFF);
                match hw1 {
                    // PUSH.W, and STMIA.W Rn{!}, {...}.
                    0xE92D => {
                        points[SP] = points[SP].map(|at| at - i64::from(hw2.count_ones()) * 4);
                        place(hw2).map(|offset| saves(&points, SP, offset))
                    }
                    _ if hw1 & 0xFFD0 == 0xE880 => place(hw2).map(|offset| saves(&points, insn.rn(), offset)),
                    // STR.W Rt, [Rn, #imm12].
                    _ if hw1 & 0xFFF0 == 0xF8C0 => (insn.rt() == 3).then(|| saves(&points, insn.rn(), i64::from(hw2 & 0xFFF))),
                    // STRD Rt, Rt2, [Rn, #+/-imm8].
                    _ if hw1 & 0xFF50 == 0xE940 => {
                        let offset = i64::from(hw2 & 0xFF) * 4 * if hw1 & 0x80 != 0 { 1 } else { -1 };
                        let second = usize::from(hw2 >> 8 & 15);
                        (insn.rt() == 3 || second == 3).then(|| saves(&points, insn.rn(), offset + if second == 3 { 4 } else { 0 }))
                    }
                    // ADD.W, ADDW, SUB.W and SUBW of SP and an immediate.
                    _ if hw2 & 0x8000 == 0 && (matches!(hw1 & 0xFBEF, 0xF10D | 0xF1AD) || matches!(hw1 & 0xFBFF, 0xF20D | 0xF2AD)) => {
                        let value = i64::from(if hw1 & 0x0200 == 0 { expand_immediate(imm12) } else { imm12 });
                        points[insn.rd()] = points[SP].map(|at| if hw1 & 0x00A0 == 0x00A0 { at - value } else { at + value });
                        None
                    }
                    _ => None,
                }
            };
            if let Some(saved) = saved {
                return saved;
            }
            let mut after = State::default();
            after.apply(*insn);
            if after.written & 8 != 0 {
                return false;
            }
        }
        false
    }

    /// A 32-bit instruction of Thumb-2, which Thumb-1 code does not have: Thumb-1's are `BL` and
    /// the system's `MSR`, `MRS`, barriers and `UDF.W`. Thumb-2 has `B.W`.
    fn branches_reach_far(insn: &Insn) -> bool {
        let (hw1, hw2) = (insn.hw1, insn.hw2);
        let thumb1 = hw2 & 0xD000 == 0xD000 && hw1 >> 11 == 0b11110
            || hw2 & 0x8000 != 0 && (hw1 & 0xFFE0 == 0xF380 || matches!(hw1, 0xF3EF | 0xF3BF) || hw1 & 0xFFF0 == 0xF7F0);
        insn.wide() && !thumb1
    }

    fn opens_landing_pad(_: &Insn) -> bool {
        false
    }

    fn step(state: &mut State, insn: &Insn) {
        state.step(*insn);
    }

    fn branch(fallthrough: &mut State, insn: &Insn) -> State {
        let condition = match (insn.wide(), insn.direct()) {
            (false, Some((_, Transfer::Branch))) if insn.hw1 >> 12 == 0xD => Some(insn.hw1 >> 8 & 15),
            (true, Some((_, Transfer::Branch))) => Some(insn.hw1 >> 6 & 15),
            _ => None,
        };
        fallthrough.split(condition)
    }

    fn after_jump(_: State, _: &Insn) -> State {
        State::default()
    }

    fn resolve_table(
        state: &State,
        image: &Image,
        _: &FxHashMap<u64, u64>,
        jump: &Insn,
        is_target: &dyn Fn(u64) -> bool,
        _: &dyn Fn(u64) -> bool,
    ) -> Option<Table> {
        let next = jump.addr + 4;
        if let Some((target, Transfer::Call)) = jump.direct() {
            let helper = CaseHelper::at(image, target)?;
            let (table, cases) = helper.table(next);
            let limit = match state.registers[0] {
                Value::Bounded(limit) => Some(limit),
                _ => None,
            };
            return read_table(image, table, helper.size, limit, cases, is_target);
        }
        // TBB and TBH: the table follows, and each entry is half the way from it to the case.
        if let Some((PC, rm, size)) = jump.table_branch() {
            let limit = match state.registers[rm] {
                Value::Bounded(limit) => Some(limit),
                _ => None,
            };
            return read_table(image, next, size, limit, Cases::Relative { base: next, shift: 1 }, is_target);
        }
        let (operation, rm) = jump.high().map(|(operation, _, rm)| (operation, rm))?;
        let Value::Entry { table, size, limit, shift, .. } = state.registers[rm] else { return None };
        match operation {
            // ADD PC, Rm: the entry, scaled, counts from the PC the ADD reads.
            0 => read_table(image, u64::from(table), u64::from(size), limit, Cases::Relative { base: next, shift }, is_target),
            // MOV PC, Rm: the entry is the case's address.
            2 if size == 4 && shift == 0 => read_table(image, u64::from(table), 4, limit, Cases::Absolute { thumb: true }, is_target),
            _ => None,
        }
    }

    fn plt_stubs(_: &Image) -> FxHashMap<u64, u64> {
        FxHashMap::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::Origin;

    /// An image with `code` at `addr`.
    fn image(code: &[u8], addr: u64) -> Image {
        let section = Section { name: String::new(), addr, data: code.to_vec(), file_offset: None, executable: true, writable: false };
        Image::bare(String::new(), crate::image::Format::Raw, crate::image::Machine::Thumb, addr, vec![section])
    }

    /// The length and the control flow of each instruction of `halfwords` at `addr`.
    fn flows(halfwords: &[u16], addr: u64) -> Vec<(u8, Option<Flow>)> {
        let bytes: Vec<u8> = halfwords.iter().flat_map(|half| half.to_le_bytes()).collect();
        let image = image(&bytes, addr);
        let mut state = State::default();
        Thumb::decode(&image, &bytes, addr)
            .map(|decoded| {
                let insn = decoded.insn.unwrap();
                let flow = Thumb::flow(&insn, &state, &image);
                Thumb::step(&mut state, &insn);
                (decoded.len, flow)
            })
            .collect()
    }

    #[test]
    fn every_kind_of_branch_goes_where_its_bits_say() {
        use Flow::*;
        let cases: &[(&[u16], u64, &[(u8, Option<Flow>)])] = &[
            // B<c> T1 back and forward; B T2; CBZ; CBNZ.
            (&[0xD1FE], 0x1000, &[(2, Some(Branch(0x1000)))]),
            (&[0xD836], 0x100C, &[(2, Some(Branch(0x107C)))]),
            (&[0xE7FE], 0x1000, &[(2, Some(Jump(0x1000)))]),
            (&[0xE022], 0x103C, &[(2, Some(Jump(0x1084)))]),
            // B to the next instruction, which unoptimised code has, goes nowhere.
            (&[0xE7FF], 0x1000, &[(2, None)]),
            (&[0xB170], 0x1000, &[(2, Some(Branch(0x1020)))]),
            (&[0xBB78], 0x1000, &[(2, Some(Branch(0x1062)))]),
            // BL back by 0x2D4 and forward by 0x1682; B.W; BHI.W; B<c>.W back.
            (&[0xF7FF, 0xFE96], 0x8000_0300, &[(4, Some(Call(0x8000_0030)))]),
            (&[0xF001, 0xFB41], 0x0800_010E, &[(4, Some(Call(0x0800_1794)))]),
            (&[0xF7FF, 0xBFFE], 0x0800_003E, &[(4, Some(Jump(0x0800_003E)))]),
            (&[0xF200, 0x81A6], 0x0800_000C, &[(4, Some(Branch(0x0800_035C)))]),
            (&[0xF47F, 0xAFFE], 0x0800_1000, &[(4, Some(Branch(0x0800_1000)))]),
            // BX LR; POP {R4, PC}; MOV PC, LR; POP.W {R4-R11, PC}; LDR PC, [SP], #4.
            (&[0x4770], 0, &[(2, Some(Return))]),
            (&[0xBD10], 0, &[(2, Some(Return))]),
            (&[0x46F7], 0, &[(2, Some(Return))]),
            (&[0xE8BD, 0x8FF0], 0, &[(4, Some(Return))]),
            (&[0xF85D, 0xFB04], 0, &[(4, Some(Return))]),
            // BX R3; BLX R3; ADD PC, R1; MOV PC, R0; TBB [PC, R1]; LDR.W PC, [R0, #4].
            (&[0x4718], 0, &[(2, Some(JumpIndirect(None)))]),
            (&[0x4798], 0, &[(2, Some(CallIndirect(None)))]),
            (&[0x448F], 0, &[(2, Some(JumpIndirect(None)))]),
            (&[0x4687], 0, &[(2, Some(JumpIndirect(None)))]),
            (&[0xE8DF, 0xF001], 0, &[(4, Some(JumpIndirect(None)))]),
            (&[0xF8D0, 0xF004], 0, &[(4, Some(JumpIndirect(None)))]),
            // UDF; BKPT; SVC, which returns; WFI; PUSH; DMB.
            (&[0xDEFE], 0, &[(2, Some(Halt))]),
            (&[0xBE00], 0, &[(2, None)]),
            (&[0xDF00], 0, &[(2, None)]),
            (&[0xBF30], 0, &[(2, None)]),
            (&[0xB510], 0, &[(2, None)]),
            (&[0xF3BF, 0x8F5F], 0, &[(4, None)]),
            // IT NE; BXNE LR, which may fall through; then B, unconditional again.
            (&[0xBF18, 0x4770, 0xE7FE], 0x1000, &[(2, None), (2, None), (2, Some(Jump(0x1004)))]),
            // ITT EQ; POPEQ {R4, PC}; BEQ by the unconditional encoding, which is conditional here.
            (&[0xBF04, 0xBD10, 0xE7FE], 0x1000, &[(2, None), (2, None), (2, Some(Branch(0x1004)))]),
            // LDR R3, [PC, #0]; BLX R3: a call of the function whose address is the literal.
            (&[0x4B00, 0x4798, 0x0035, 0x0000], 0x1000, &[(2, None), (2, Some(Call(0x0034))), (2, None), (2, None)]),
            // POP {R4}; POP {R1}; ADD SP, #12; BX R1: a return through the popped word.
            (&[0xBC10, 0xBC02, 0xB003, 0x4708], 0, &[(2, None), (2, None), (2, None), (2, Some(Return))]),
            // MOVW R0, #0x1235; MOVT R0, #0x0800; BX R0: a jump to 0x08001234.
            (&[0xF241, 0x2035, 0xF6C0, 0x0000, 0x4700], 0, &[(4, None), (4, None), (2, Some(Jump(0x0800_1234)))]),
        ];
        for &(halfwords, addr, expected) in cases {
            assert_eq!(flows(halfwords, addr), expected, "{halfwords:04x?} at {addr:#x}");
        }
    }

    #[test]
    fn a_literal_load_reads_the_word_of_its_pool() {
        // At 0x1002, LDR R0, [PC, #4] reads the word at 0x1008: (0x1002 + 4) & !3 is 0x1004.
        let bytes = [0x00, 0xBF, 0x01, 0x48, 0x70, 0x47, 0x00, 0xBF, 0x35, 0x12, 0x00, 0x08];
        let insn = Thumb::decode(&image(&bytes, 0x1000), &bytes, 0x1000).nth(1).unwrap().insn.unwrap();
        assert_eq!((Thumb::literal(&insn, &State::default()), insn.literal), (Some((0x1008, 0x100C)), Some(0x0800_1235)));
        assert_eq!(Thumb::address_taken(&insn, &State::default(), &image(&bytes, 0x1000)), Some(0x0800_1234));
    }

    #[test]
    fn loads_read_and_stores_write() {
        // LDR R1, [R0, #4]; STR R1, [R0]; STRB R1, [R0, R2]; LDRH R1, [R0, R2]; LDR.W R1, [R0, #0x100];
        // STR.W R1, [R0, #0x100]; LDM R0!, {R1, R2}; MOVS R0, #1.
        let halfwords: [&[u16]; 8] = [&[0x6841], &[0x6001], &[0x5481], &[0x5A81], &[0xF8D0, 0x1100], &[0xF8C0, 0x1100], &[0xC806], &[0x2001]];
        let accesses = halfwords.map(|halfwords| access(&halfwords.iter().flat_map(|half| half.to_le_bytes()).collect::<Vec<u8>>()));
        let (load, store) = (Some((true, false)), Some((false, true)));
        assert_eq!(accesses, [load, store, store, load, load, store, load, None]);
    }

    /// What R0 to R3 hold after `halfwords` at `addr`.
    fn registers_after(halfwords: &[u16], addr: u64) -> [Value; 4] {
        let bytes: Vec<u8> = halfwords.iter().flat_map(|half| half.to_le_bytes()).collect();
        let mut state = State::default();
        Thumb::decode(&image(&bytes, addr), &bytes, addr).for_each(|decoded| state.step(decoded.insn.unwrap()));
        state.registers[..4].try_into().unwrap()
    }

    #[test]
    fn an_index_or_a_table_out_of_32_bits_is_none() {
        // LSLS R1, R1, #31 twice shifts an index out of the word; LSLS R1, R1, #1 twice does not.
        assert!(registers_after(&[0x07C9, 0x07C9], 0)[1] == Value::Unknown);
        assert!(registers_after(&[0x0049, 0x0049], 0)[1] == Value::Scaled { limit: None, shift: 2 });
        // LSLS R0, R0, #2; ADD R0, PC; LDR R0, [R0, #4]: an entry of the table after the code,
        // unless that would lie past 4 GB.
        let entry = |addr: u64| registers_after(&[0x0080, 0x4478, 0x6840], addr)[0];
        assert!(entry(0x1000) == Value::Entry { table: 0x100A, size: 4, limit: None, shift: 0, signed: false });
        assert!(entry(0xFFFF_FFF8) == Value::Unknown);
        // ADD R0, PC at an address past 4 GB, which a layout refuses but a hand-made image may hold.
        assert!(registers_after(&[0x0080, 0x4478], 0x1_0000_0000)[0] == Value::Unknown);
    }

    #[test]
    fn a_variable_number_of_arguments_is_told_by_where_r3_is_saved() {
        let cases: [(&[u16], bool); 7] = [
            // clang: SUB SP, #12; PUSH {R7, LR}; SUB SP, #12; MOV R12, R0; ADD R0, SP, #20; STM R0!, {R1-R3}.
            (&[0xB083, 0xB580, 0xB083, 0x4684, 0xA805, 0xC00E], true),
            // clang: SUB SP, #8; PUSH {R7, LR}; SUB SP, #8; MOV R12, R1; STRD R2, R3, [SP, #16].
            (&[0xB082, 0xB580, 0xB082, 0x468C, 0xE9CD, 0x2304], true),
            // clang -O0: SUB SP, #12; PUSH {R7, LR}; SUB SP, #20; STR R3, [SP, #36].
            (&[0xB083, 0xB580, 0xB085, 0x9309], true),
            // GCC: PUSH {R1-R3}; PUSH {LR}.
            (&[0xB40E, 0xB500], true),
            // Four arguments kept on the stack: SUB SP, #16; STR R0, [SP, #12]; ...; STR R3, [SP].
            (&[0xB084, 0x9003, 0x9102, 0x9201, 0x9300], false),
            // A small local: SUB SP, #4; STR R0, [SP]; MOVS R3, #0; STR R3, [SP].
            (&[0xB081, 0x9000, 0x2300, 0x9300], false),
            // PUSH {R3, LR}, which keeps the stack aligned.
            (&[0xB508, 0xB081], false),
        ];
        for (halfwords, expected) in cases {
            let bytes: Vec<u8> = halfwords.iter().flat_map(|half| half.to_le_bytes()).collect();
            let insns: Vec<Insn> = Thumb::decode(&image(&bytes, 0), &bytes, 0).filter_map(|decoded| decoded.insn).collect();
            assert_eq!(Thumb::takes_variable_arguments(&insns), expected, "{halfwords:04x?}");
        }
    }

    /// `BL to` at `from`.
    fn bl(from: u64, to: u64) -> [u16; 2] {
        let offset = to.wrapping_sub(from + 4) as u32;
        let (s, i1, i2) = (offset >> 24 & 1, offset >> 23 & 1, offset >> 22 & 1);
        let (j1, j2) = (!(i1 ^ s) & 1, !(i2 ^ s) & 1);
        [(0xF000 | s << 10 | offset >> 12 & 0x3FF) as u16, (0xD000 | j1 << 13 | j2 << 11 | offset >> 1 & 0x7FF) as u16]
    }

    /// The functions that analysis finds in `halfwords` at 0.
    fn functions(halfwords: &[u16]) -> Vec<u64> {
        let bytes: Vec<u8> = halfwords.iter().flat_map(|half| half.to_le_bytes()).collect();
        crate::analysis::analyze(&image(&bytes, 0)).functions.iter().map(|function| function.addr).collect()
    }

    #[test]
    fn a_function_after_a_call_that_never_returns_is_one() {
        // 0x00: PUSH {R4, LR}; LDR R0, =0x17; BL 0x10; POP {R4, PC}; NOP; .word 0x17.
        // 0x10: PUSH {R4, LR}; BL 0x1A. 0x16: ADDS R0, #1; BX LR, only its address taken.
        // 0x1A: B . or BX LR.
        let code = |last: u16| [&[0xB510, 0x4802][..], &bl(0x04, 0x10), &[0xBD10, 0xBF00, 0x0017, 0x0000, 0xB510], &bl(0x12, 0x1A), &[0x3001, 0x4770, last]].concat();
        // The function at 0x10 runs on into 0x16, which is a function where 0x1A never returns.
        assert_eq!(functions(&code(0xE7FE)), [0x00, 0x10, 0x16, 0x1A]);
        assert_eq!(functions(&code(0x4770)), [0x00, 0x10, 0x1A]);
    }

    #[test]
    fn an_end_that_gives_back_the_frame_of_whoever_jumps_there_is_no_function() {
        // 0x00: PUSH {R4, LR}; BL 0x0C; CMP R0, #0; BEQ 0x16; POP {R4, PC}. 0x0C: PUSH {R4, LR};
        // CMP R0, #1; BEQ 0x16; MOVS R0, #0; POP {R4, PC}. 0x16: MOVS R0, #1; POP {R4, PC}, or
        // with PUSH {R4, LR} first, which sets up a frame of its own.
        let code = |first: &[u16]| [&[0xB510][..], &bl(0x02, 0x0C), &[0x2800, 0xD005, 0xBD10, 0xB510, 0x2801, 0xD001, 0x2000, 0xBD10], first, &[0x2001, 0xBD10]].concat();
        assert_eq!(functions(&code(&[])), [0x00, 0x0C]);
        assert_eq!(functions(&code(&[0xB510])), [0x00, 0x0C, 0x16]);
    }

    #[test]
    fn a_doubleword_loaded_through_an_adr_is_data() {
        // 0x00: PUSH {LR}; ADR R3, 0x10; LDRD R2, R3, [R3], or MOVS R3, #0; MOVS R2, #0; NOP;
        // BL 0x18; POP {PC}; NOP. At 0x10 the constant, whose words read as MOVS R0, #1; BX LR
        // and MOVS R0, #2; BX LR. At 0x18 BX LR.
        let code = |load: [u16; 3]| [&[0xB500][..], &load, &bl(0x08, 0x18), &[0xBD00, 0xBF00, 0x2001, 0x4770, 0x2002, 0x4770, 0x4770]].concat();
        assert_eq!(functions(&code([0xA303, 0xE9D3, 0x2300])), [0x00, 0x18]);
        assert_eq!(functions(&code([0x2300, 0x2200, 0xBF00])), [0x00, 0x10, 0x14, 0x18]);
    }

    #[test]
    fn what_follows_the_code_from_an_address_it_loads_of_data_is_data() {
        // 0x00: LDR R0, =0x10 or =0; BX LR; padding; the literal. At 0x10 MOVS R0, #1; BX LR;
        // MOVS R0, #2; BX LR, which follow the code as constants do.
        let code = |literal: u16| [0x4801, 0x4770, 0xBF00, 0xBF00, literal, 0x0000, 0x0000, 0x0000, 0x2001, 0x4770, 0x2002, 0x4770];
        assert_eq!(functions(&code(0x10)), [0x00]);
        assert_eq!(functions(&code(0x00)), [0x00, 0x10, 0x14]);
    }

    #[test]
    fn a_block_that_calls_before_it_gives_back_the_frame_is_no_function_in_thumb_1() {
        // 0x00: PUSH {R4, LR}; BL 0x0C, a jump; MOVS R0, #1; POP {R4, PC}; NOP. 0x0C: MOVS R0,
        // #2; BL 0x14; POP {R4, PC}, or PUSH {R4, LR} first. 0x14: BX LR.
        let code = |first: &[u16]| [&[0xB510][..], &bl(0x02, 0x0C), &[0x2001, 0xBD10, 0xBF00], first, &[0x2002], &bl(0x0E + 2 * first.len() as u64, 0x14 + 2 * first.len() as u64), &[0xBD10, 0x4770]].concat();
        assert_eq!(functions(&code(&[])), [0x00, 0x14]);
        assert_eq!(functions(&code(&[0xB510])), [0x00, 0x0C, 0x16]);
    }

    #[test]
    fn a_call_may_be_a_jump_only_in_thumb_1() {
        // 0x00: PUSH {LR}; BL to; MOVS R0, #0 or MOVW R0, #0, then MOVS R0, #0 up to `to`: BX
        // LR. Code that has Thumb-2 has `B.W` to jump as far as it calls.
        let code = |to: usize, first: &[u16]| [&[0xB500][..], &bl(0x02, to as u64), first, &vec![0x2000; (to - 6 - 2 * first.len()) / 2], &[0x4770]].concat();
        assert_eq!(functions(&code(0x100, &[0x2000])), [0x00]);
        assert_eq!(functions(&code(0x100, &[0xF240, 0x0000])), [0x00, 0x100]);
        // A word after the code that points into the BL at 0x04, where its second halfword reads
        // as the first of a Thumb-2 store, is no evidence of Thumb-2.
        assert_eq!(functions(&[code(0x10, &[0x2000]), vec![0x0000, 0x0005, 0x0000]].concat()), [0x00]);
    }

    #[test]
    fn unreached_code_that_divides_into_functions_is_functions() {
        // 0x00: PUSH {R4, LR}; BL 0x1C; POP {R4, PC}. 0x08: ADDS R0, #1; BX LR. 0x0C: LDR R0,
        // =0x12345678; BX LR; the literal. 0x14: PUSH {R4, LR}; BL 0x08; `last`. 0x1C: MOVS R0, #0;
        // BX LR.
        let code = |last: u16| [&[0xB510][..], &bl(0x02, 0x1C), &[0xBD10, 0x3001, 0x4770, 0x4800, 0x4770, 0x5678, 0x1234, 0xB510], &bl(0x16, 0x08), &[last, 0x2000, 0x4770]].concat();
        // POP {R4, PC}: nothing reaches 0x08 to 0x1B, which divide into three functions all the same.
        assert_eq!(functions(&code(0xBD10)), [0x00, 0x08, 0x0C, 0x14, 0x1C]);
        // ADDS R0, #2, which runs on into the function at 0x1C: the bytes are no functions.
        assert_eq!(functions(&code(0x3002)), [0x00, 0x1C]);
    }

    #[test]
    fn a_call_to_a_gcc_switch_helper_jumps_through_the_table_after_it() {
        let helper = |kind: usize| CaseHelper::ALL[kind].code.to_vec();
        let tables = |halfwords: &[u16]| {
            let bytes: Vec<u8> = halfwords.iter().flat_map(|half| half.to_le_bytes()).collect();
            let analysis = crate::analysis::analyze(&image(&bytes, 0));
            let tables: Vec<(u64, Vec<u64>)> = analysis.jump_tables.iter().map(|table| (table.jump, table.targets.clone())).collect();
            (tables, analysis.functions.into_iter().map(|function| (function.addr, function.ranges)).collect::<Vec<_>>())
        };
        // CMP R0, #2; BHI 0x14; BL __gnu_thumb1_case_uqi; the bytes 2, 4, 6 and padding; at 0x0C,
        // 0x10 and 0x14 MOVS R0, #n; BX LR. The helper at 0x18.
        let code = [&[0x2802, 0xD807][..], &bl(0x04, 0x18), &[0x0402, 0x0006, 0x200A, 0x4770, 0x200B, 0x4770, 0x2000, 0x4770], &helper(0)].concat();
        let expected = vec![(0x00, vec![(0x00, 0x08), (0x0C, 0x18)]), (0x18, vec![(0x18, 0x2A)])];
        assert_eq!(tables(&code), (vec![(0x04, vec![0x0C, 0x10, 0x14])], expected));
        // B 0x06; a case at 0x02; CMP R0, #1; BHI 0x14; BL __gnu_thumb1_case_sqi; the bytes -6 and
        // 1; cases at 0x10 and 0x14. The helper at 0x18.
        let code = [&[0xE001, 0x200A, 0x4770, 0x2801, 0xD804][..], &bl(0x0A, 0x18), &[0x01FA, 0x200B, 0x4770, 0x2000, 0x4770], &helper(1)].concat();
        assert_eq!(tables(&code).0, [(0x0A, vec![0x02, 0x10])]);
        // ADDS R0, #0; CMP R0, #1; BHI 0x1C; BL __gnu_thumb1_case_si; padding to the words 8 and 12
        // at 0x0C, which count from there; cases at 0x14, 0x18 and 0x1C. The helper at 0x20.
        let code = [&[0x3000, 0x2801, 0xD80A][..], &bl(0x06, 0x20), &[0x0000, 0x0008, 0x0000, 0x000C, 0x0000, 0x2014, 0x4770, 0x2015, 0x4770, 0x2000, 0x4770], &helper(4)].concat();
        assert_eq!(tables(&code).0, [(0x06, vec![0x14, 0x18])]);
    }

    #[test]
    fn a_branch_through_the_popped_word_returns_past_a_branch_not_taken() {
        // POP {R1}; CMP R0, #0; BEQ 0x08; BX R1; at 0x08 BX LR.
        let bytes: Vec<u8> = [0xBC02u16, 0x2800, 0xD000, 0x4708, 0x4770].iter().flat_map(|half| half.to_le_bytes()).collect();
        assert_eq!(returns_through_register(&image(&bytes, 0), 0, 10), [0x06]);
    }

    #[test]
    fn a_compare_bounds_the_index_on_the_side_of_the_branch_it_proves() {
        // What R0 holds where `halfwords` fall through their last instruction, a branch, and
        // where the branch is taken.
        let bounds = |halfwords: &[u16]| {
            let bytes: Vec<u8> = halfwords.iter().flat_map(|half| half.to_le_bytes()).collect();
            let insns: Vec<Insn> = Thumb::decode(&image(&bytes, 0), &bytes, 0).filter_map(|decoded| decoded.insn).collect();
            let (branch, before) = insns.split_last().unwrap();
            let mut state = State::default();
            before.iter().for_each(|insn| state.step(*insn));
            let taken = Thumb::branch(&mut state, branch);
            (state.registers[0], taken.registers[0])
        };
        let bounded = |limit: u64| Value::Bounded(Limit::of(limit));
        let unknown = Value::Unknown;
        // CMP R0, #5, then BHI, BLS, BHS and BLO.
        assert!(bounds(&[0x2805, 0xD800]) == (bounded(5), unknown));
        assert!(bounds(&[0x2805, 0xD900]) == (unknown, bounded(5)));
        assert!(bounds(&[0x2805, 0xD200]) == (bounded(4), unknown));
        assert!(bounds(&[0x2805, 0xD300]) == (unknown, bounded(4)));
        // CMP R0, #0; BHS: no index is below 0.
        assert!(bounds(&[0x2800, 0xD200]) == (unknown, unknown));
        // MOVS R1, #7; CMP R0, R1; BHI. CMP.W R0, #255; BHI.W.
        assert!(bounds(&[0x2107, 0x4288, 0xD800]) == (bounded(7), unknown));
        assert!(bounds(&[0xF1B0, 0x0FFF, 0xF200, 0x8000]) == (bounded(255), unknown));
        // ADDS R1, #1 between sets the flags anew; LDR R1, [R2] does not.
        assert!(bounds(&[0x2805, 0x3101, 0xD800]) == (unknown, unknown));
        assert!(bounds(&[0x2805, 0x6811, 0xD800]) == (bounded(5), unknown));
    }

    #[test]
    fn a_jump_through_pc_reads_the_table_its_index_picks_from() {
        let tables = |halfwords: &[u16]| {
            let bytes: Vec<u8> = halfwords.iter().flat_map(|half| half.to_le_bytes()).collect();
            crate::analysis::analyze(&image(&bytes, 0)).jump_tables.iter().map(|table| (table.jump, table.targets.clone())).collect::<Vec<_>>()
        };
        // CMP R0, #2; BHI 0x1C; ADD R0, PC; LDRB R0, [R0, #4]; LSLS R0, R0, #1; ADD PC, R0; the
        // bytes 1, 3, 5 counting halfwords from 0x0E; three cases and the default.
        let cases = [0x200A, 0x4770, 0x200B, 0x4770, 0x200C, 0x4770, 0x2000, 0x4770];
        let code = [&[0x2802, 0xD80B, 0x4478, 0x7900, 0x0040, 0x4487, 0x0301, 0x0005][..], &cases].concat();
        assert_eq!(tables(&code), [(0x0A, vec![0x10, 0x14, 0x18])]);
        // CMP R0, #1; BHI 0x1C; ADR R1, 0x0C; LSLS R0, R0, #2; LDR R0, [R1, R0]; MOV PC, R0; the
        // addresses 0x14 and 0x18 with the Thumb bit; two cases and the default.
        let code = [&[0x2801, 0xD80B, 0xA101, 0x0080, 0x5808, 0x4687, 0x0015, 0x0000, 0x0019, 0x0000][..], &cases[2..]].concat();
        assert_eq!(tables(&code), [(0x0A, vec![0x14, 0x18])]);
    }

    #[test]
    fn code_is_a_function_where_it_sets_up_a_frame_or_soon_returns() {
        let is_function = |bytes: &[u8]| Thumb::code_pointer(&image(bytes, 0), 0);
        let halfwords = |halfwords: &[u16]| halfwords.iter().flat_map(|half| half.to_le_bytes()).collect::<Vec<u8>>();
        // PUSH {R4, LR}; SUB SP, #8; MOVS R0, #0; BX LR.
        assert!(is_function(&halfwords(&[0xB510, 0x2000])));
        assert!(is_function(&halfwords(&[0xB082, 0x2000])));
        assert!(is_function(&halfwords(&[0x2000, 0x4770])));
        // NOP first; zeros before the return; text.
        assert!(!is_function(&halfwords(&[0xBF00, 0x4770])));
        assert!(!is_function(&halfwords(&[0x2000, 0x0000, 0x4770])));
        assert!(!is_function(b"Hello, world\0\0\0\0"));
    }

    #[test]
    fn a_word_of_data_among_the_code_with_the_thumb_bit_points_at_a_function() {
        // BX LR; padding; a word; MOVS R0, #1; BX LR at 0x08.
        let origins = |word: u16| {
            let bytes: Vec<u8> = [0x4770, 0x0000, word, 0x0000, 0x2001, 0x4770].iter().flat_map(|half| half.to_le_bytes()).collect();
            crate::analysis::analyze(&image(&bytes, 0)).functions.iter().map(|function| (function.addr, function.origin)).collect::<Vec<_>>()
        };
        assert_eq!(origins(0x0009), [(0x00, Origin::Export), (0x08, Origin::DataPointer)]);
        assert!(origins(0x0008).iter().all(|&(_, origin)| origin != Origin::DataPointer));
    }

    #[test]
    fn the_memory_beyond_the_image_is_what_the_regions_leave() {
        let section = |addr: u64, len: usize| Section { name: String::new(), addr, data: vec![0; len], file_offset: None, executable: false, writable: true };
        let free = memory(&[section(0, 0x1000), section(0x2000_0000, 0x1000)]);
        assert_eq!(free, [(0x2000_1000, 0x4000_0000), (0x4000_0000, 0x6000_0000), (0x6000_0000, 0xA000_0000), (0xA000_0000, 0xE000_0000), (0xE000_0000, 0x1_0000_0000)]);
    }

    #[test]
    fn the_vector_table_ends_at_the_first_word_that_is_no_handler() {
        let table = |words: &[u32]| vector_table(&words.iter().flat_map(|word| word.to_le_bytes()).collect::<Vec<u8>>(), |addr| addr < 0x100);
        // SP, reset, NMI, two unused slots, a handler, then code: PUSH {R4, LR}; SUB SP, #0x28.
        assert_eq!(table(&[0x2002_0000, 0x21, 0x25, 0, 0, 0x25, 0xB08A_B510, 0, 0]), (24, vec![0x20, 0x24, 0x24]));
        // A checksum in reserved word 7 and code in reserved word 13 are the table's only where
        // a slot after them is: here SVCall in word 11 is, then code in word 13 and 14.
        let mut words = [0x2002_0000, 0x21, 0x25, 0x25, 0, 0, 0, 0xEFFF_5A3C, 0, 0, 0, 0x29, 0, 0xB08A_B510, 0xB08A_B510];
        assert_eq!(table(&words), (48, vec![0x20, 0x24, 0x24, 0x28]));
        // And here PendSV in word 14 is.
        words[14] = 0x2D;
        assert_eq!(table(&words), (60, vec![0x20, 0x24, 0x24, 0x28, 0x2C]));
        // A handler past the code is no handler.
        assert_eq!(table(&[0x2002_0000, 0x21, 0x101]), (8, vec![0x20]));
    }
}
