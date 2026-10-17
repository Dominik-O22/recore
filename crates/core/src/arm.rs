//! 32-bit ARM application code, as Linux runs it on ARMv5 to ARMv7: A32 instructions of four
//! bytes and Thumb ones of two or four, in functions side by side.
//!
//! Which of the two the bytes at an address are is no property of the bytes. ARM marks it on
//! every pointer to code instead: bit 0 is set on a pointer to Thumb code, which a `BX` or `BLX`
//! through it switches to, and a `BLX` to a label switches from one set to the other. The image
//! keeps where the sets change, which an unstripped ELF lists as `$a` and `$t` mapping symbols
//! and [`load`] otherwise works out from the pointers the loader sees and the calls and branches
//! of the code they lead to. The decoder decodes what that map says.
//!
//! Thumb code is decoded and tracked as on a Cortex-M, see [`crate::thumb`]. What differs here is
//! that a `BX` or `BLX` may go to A32 code, and that position-independent code forms addresses
//! by adding PC to a literal. A32 code shares the register state and its jump tables.

use rustc_hash::FxHashMap;

use crate::arch::{Arch, Decoded, Flow, Limit, Table};
use crate::image::{Image, InstructionSet, Section};
use crate::thumb::{self, CALLER_SAVED, Cases, State, Thumb, Transfer, Value, read_table, sign_extend};

const SP: usize = 13;
const LR: usize = 14;
const PC: usize = 15;

/// An A32 instruction and where it sits, which PC-relative forms need.
#[derive(Clone, Copy)]
pub struct A32 {
    addr: u64,
    word: u32,
    /// The word a PC-relative `LDR` loads, when the decoded bytes hold it.
    literal: Option<u32>,
}

/// The second operand of an A32 data-processing instruction.
#[derive(Clone, Copy, PartialEq)]
enum Operand {
    Immediate(u32),
    /// `Rm`, shifted left by a number of bits.
    Shifted { rm: usize, left: u8 },
    /// Any other shift: right, a rotation, or by a register.
    Other { rm: usize },
}

/// A load or store of one register: `[Rn, offset]`.
#[derive(Clone, Copy)]
struct Access {
    load: bool,
    /// Bytes moved: 1, 2, 4, or 8 for a pair.
    size: u8,
    signed: bool,
    rn: usize,
    rt: usize,
    offset: Offset,
    /// The address is `Rn` plus the offset; otherwise `Rn` itself, after which it moves on.
    pre: bool,
    up: bool,
    writeback: bool,
}

#[derive(Clone, Copy, PartialEq)]
enum Offset {
    Immediate(u32),
    /// `Rm` shifted left.
    Register { rm: usize, left: u8 },
    Other,
}

/// The constant of an A32 data-processing immediate: eight bits rotated right by twice four.
fn rotated(word: u32) -> u32 {
    (word & 0xFF).rotate_right(2 * (word >> 8 & 15))
}

impl A32 {
    fn condition(self) -> u32 {
        self.word >> 28
    }

    /// Runs only when its condition holds. The unconditional space, condition 15, is not.
    fn conditional(self) -> bool {
        self.condition() < 14
    }

    fn rd(self) -> usize {
        (self.word >> 12 & 15) as usize
    }

    fn rn(self) -> usize {
        (self.word >> 16 & 15) as usize
    }

    fn pc(self) -> u64 {
        self.addr + 8
    }

    /// `B`, `BL` and `BLX` to a label, which goes to Thumb code at a halfword.
    fn direct(self) -> Option<(u64, Transfer)> {
        if self.word >> 25 & 7 != 0b101 {
            return None;
        }
        let offset = sign_extend((self.word & 0xFF_FFFF) << 2, 26);
        if self.condition() == 15 {
            let halfword = u64::from(self.word >> 24 & 1) << 1;
            return Some((self.pc().wrapping_add_signed(offset) + halfword, Transfer::Call));
        }
        let transfer = if self.word >> 24 & 1 != 0 {
            Transfer::Call
        } else if self.conditional() {
            Transfer::Branch
        } else {
            Transfer::Jump
        };
        Some((self.pc().wrapping_add_signed(offset), transfer))
    }

    /// `(opcode, sets flags, Rn, Rd, operand)` of a data-processing instruction.
    fn data_processing(self) -> Option<(u32, bool, usize, usize, Operand)> {
        let word = self.word;
        if self.condition() == 15 || word >> 26 & 3 != 0 {
            return None;
        }
        let immediate = word >> 25 & 1 != 0;
        let (opcode, flags) = (word >> 21 & 15, word >> 20 & 1 != 0);
        // Multiplies and the extra loads and stores; then the forms of TST to CMN that set no
        // flags, which are other instructions: MRS, MSR, BX, CLZ, MOVW and MOVT.
        if !immediate && word & 0x90 == 0x90 || (8..=11).contains(&opcode) && !flags {
            return None;
        }
        let operand = if immediate {
            Operand::Immediate(rotated(word))
        } else {
            let rm = (word & 15) as usize;
            match (word >> 4 & 1, word >> 5 & 3) {
                (0, 0) => Operand::Shifted { rm, left: (word >> 7 & 31) as u8 },
                _ => Operand::Other { rm },
            }
        };
        Some((opcode, flags, self.rn(), self.rd(), operand))
    }

    /// `MOVW` and `MOVT`: the register, the 16 bits, and whether they are the top half.
    fn move_half(self) -> Option<(usize, u32, bool)> {
        let top = match self.word & 0x0FF0_0000 {
            0x0300_0000 => false,
            0x0340_0000 => true,
            _ => return None,
        };
        (self.condition() != 15).then(|| (self.rd(), self.word >> 4 & 0xF000 | self.word & 0xFFF, top))
    }

    /// A load or store of one register, of a byte, a halfword, a word or two words.
    fn transfer(self) -> Option<Access> {
        let word = self.word;
        if self.condition() == 15 {
            return None;
        }
        let (pre, up, writeback_bit, load) = (word >> 24 & 1 != 0, word >> 23 & 1 != 0, word >> 21 & 1 != 0, word >> 20 & 1 != 0);
        let (rn, rt) = (self.rn(), self.rd());
        // A post-indexed access always writes its base back.
        let writeback = !pre || writeback_bit;
        match word >> 25 & 7 {
            // LDR, STR, LDRB and STRB, with an immediate offset or a shifted register. A
            // register form with bit 4 set is a media instruction.
            0b010 | 0b011 => {
                let offset = if word >> 25 & 1 == 0 {
                    Offset::Immediate(word & 0xFFF)
                } else if word & 0x10 != 0 {
                    return None;
                } else if word >> 5 & 3 == 0 {
                    Offset::Register { rm: (word & 15) as usize, left: (word >> 7 & 31) as u8 }
                } else {
                    Offset::Other
                };
                let size = if word >> 22 & 1 != 0 { 1 } else { 4 };
                Some(Access { load, size, signed: false, rn, rt, offset, pre, up, writeback })
            }
            // The halfword, signed and doubleword forms.
            0b000 if word & 0x90 == 0x90 && word >> 5 & 3 != 0 => {
                let offset = if word >> 22 & 1 != 0 { Offset::Immediate(word >> 4 & 0xF0 | word & 15) } else { Offset::Register { rm: (word & 15) as usize, left: 0 } };
                let (size, signed, load) = match (load, word >> 5 & 3) {
                    (true, 1) => (2, false, true),
                    (true, 2) => (1, true, true),
                    (true, _) => (2, true, true),
                    (false, 1) => (2, false, false),
                    // LDRD and STRD.
                    (false, 2) => (8, false, true),
                    (false, _) => (8, false, false),
                };
                // With the doubleword forms the bits after a halfword are not checked further.
                (size != 8 || rt % 2 == 0).then_some(Access { load, size, signed, rn, rt, offset, pre, up, writeback })
            }
            _ => None,
        }
    }

    /// `[start, end)` of the data a PC-relative load reads: `LDR`, `LDRB`, the halfword and
    /// doubleword forms, and `VLDR`.
    fn literal_range(self) -> Option<(u64, u64)> {
        let address = |offset: u32, up: bool| if up { self.pc() + u64::from(offset) } else { self.pc().wrapping_sub(u64::from(offset)) };
        if let Some(transfer) = self.transfer() {
            let Offset::Immediate(offset) = transfer.offset else { return None };
            if !transfer.load || transfer.rn != PC || !transfer.pre || transfer.writeback || transfer.rt == PC {
                return None;
            }
            let at = address(offset, transfer.up);
            return Some((at, at + u64::from(transfer.size)));
        }
        // VLDR of a single or a double register.
        (self.word & 0x0F3F_0E00 == 0x0D1F_0A00 && self.condition() != 15).then(|| {
            let at = address((self.word & 0xFF) * 4, self.word >> 23 & 1 != 0);
            (at, at + if self.word & 0x100 != 0 { 8 } else { 4 })
        })
    }

    /// The register a literal `LDR` of a word loads.
    fn literal_word_register(self) -> Option<usize> {
        let transfer = self.transfer()?;
        (self.literal_range().is_some() && transfer.size == 4 && !transfer.signed).then_some(transfer.rt)
    }

    /// `ADR`, `ADD Rd, PC, #imm` or `SUB Rd, PC, #imm`: the register and the address it gets.
    fn adr(self) -> Option<(usize, u64)> {
        match self.data_processing()? {
            (4, false, PC, rd, Operand::Immediate(offset)) if rd != PC => Some((rd, self.pc() + u64::from(offset))),
            (2, false, PC, rd, Operand::Immediate(offset)) if rd != PC => Some((rd, self.pc().wrapping_sub(u64::from(offset)))),
            _ => None,
        }
    }

    /// `ADD Rd, PC, Rm` or `ADD Rd, Rm, PC`: how position-independent code adds the PC to an
    /// offset a literal holds. The register `Rm`.
    fn adds_pc(self) -> Option<(usize, usize)> {
        let (opcode, _, rn, rd, operand) = self.data_processing()?;
        let Operand::Shifted { rm, left: 0 } = operand else { return None };
        match (opcode, rn, rm) {
            (4, PC, other) | (4, other, PC) if rd != PC && other != PC => Some((rd, other)),
            _ => None,
        }
    }

    /// `LDM` or `STM`: `(load, Rn, writeback, registers)`.
    fn multiple(self) -> Option<(bool, usize, bool, u16)> {
        (self.condition() != 15 && self.word >> 25 & 7 == 0b100).then(|| (self.word >> 20 & 1 != 0, self.rn(), self.word >> 21 & 1 != 0, self.word as u16))
    }

    /// `BX Rm` or `BLX Rm`: the register and whether it calls.
    fn exchange(self) -> Option<(usize, bool)> {
        (self.word & 0x0FFF_FFD0 == 0x012F_FF10 && self.condition() != 15).then(|| ((self.word & 15) as usize, self.word & 0x20 != 0))
    }

    /// `CMP Rn, #imm` and `CMP Rn, Rm` where `Rm` holds a number.
    fn compare(self, state: &State) -> Option<(usize, u32)> {
        match self.data_processing()? {
            (10, true, rn, _, Operand::Immediate(bound)) => Some((rn, bound)),
            (10, true, rn, _, Operand::Shifted { rm, left: 0 }) => match state.registers[rm] {
                Value::Const(bound) => Some((rn, bound)),
                _ => None,
            },
            _ => None,
        }
    }

    /// Whether the instruction may set the condition flags.
    fn sets_flags(self) -> bool {
        let word = self.word;
        if let Some((_, flags, ..)) = self.data_processing() {
            return flags;
        }
        // Multiplies with S, MSR, and VMRS APSR_nzcv, FPSCR.
        word & 0x0F00_00F0 == 0x0000_0090 && word >> 20 & 1 != 0
            || word & 0x0FB0_F000 == 0x0320_F000 && word >> 18 & 3 != 0
            || word & 0x0DB0_F000 == 0x0120_F000
            || word & 0x0FFF_FFFF == 0x0EF1_FA10
    }

    /// `PUSH {..., LR}` or `STR LR, [SP, #-4]!`, which save the return address.
    fn saves_return(self) -> bool {
        self.word & 0xFFFF_4000 == 0xE92D_4000 || self.word == 0xE52D_E004
    }

    /// `MOV IP, #4096`, with which code that probes its stack against a clash opens, before it
    /// saves anything.
    fn probes_stack(self) -> bool {
        self.word == 0xE3A0_CA01
    }
}

/// One 32-bit ARM instruction, of either set.
#[derive(Clone, Copy)]
pub enum Insn {
    A32(A32),
    Thumb(thumb::Insn),
}

/// Decodes the A32 word at `offset` into `bytes`, which are loaded at `base`.
fn decode_a32(bytes: &[u8], base: u64, offset: usize) -> Option<Decoded<Insn>> {
    let addr = base + offset as u64;
    let rest = bytes.get(offset..).filter(|rest| !rest.is_empty())?;
    // Off the word, or cut short by the end of the bytes: no instruction, and on to the next
    // halfword, which may be one in the other set.
    if addr % 4 != 0 || rest.len() < 4 {
        return Some(Decoded { addr, len: 2.min(rest.len() as u8), insn: None });
    }
    let word = u32::from_le_bytes(rest[..4].try_into().unwrap());
    let mut insn = A32 { addr, word, literal: None };
    if insn.literal_word_register().is_some() {
        let (at, _) = insn.literal_range()?;
        let at = at.checked_sub(base).map(|at| at as usize);
        insn.literal = at.and_then(|at| bytes.get(at..at + 4)).map(|word| u32::from_le_bytes(word.try_into().unwrap()));
    }
    Some(Decoded { addr, len: 4, insn: Some(Insn::A32(insn)) })
}

/// A decoder over a section that decodes each instruction in the set the image says it is in.
pub struct Decoder<'a> {
    image: &'a Image,
    bytes: &'a [u8],
    base: u64,
    offset: usize,
    /// The instructions of an `IT` block still to come.
    it: u8,
    /// The set the bytes are in from `run.start` up to `run.end`.
    set: InstructionSet,
    run: std::ops::Range<u64>,
    insn: Insn,
}

impl Decoder<'_> {
    fn next(&mut self) -> Option<Decoded<Insn>> {
        let addr = self.base + self.offset as u64;
        if !self.run.contains(&addr) {
            (self.set, self.run) = self.image.instruction_set(addr);
            self.it = 0;
        }
        let decoded = match self.set {
            InstructionSet::A32 => decode_a32(self.bytes, self.base, self.offset)?,
            InstructionSet::Thumb => {
                let decoded = thumb::decode_at(self.bytes, self.base, self.offset, &mut self.it, true)?;
                Decoded { addr: decoded.addr, len: decoded.len, insn: decoded.insn.map(Insn::Thumb) }
            }
        };
        self.offset += usize::from(decoded.len);
        Some(decoded)
    }
}

/// The address the instruction completes in a register, whatever it is: a literal, the top
/// half of a `MOVW` and `MOVT` pair, or the sum of PC and an offset. Not an `ADR`, which only
/// names tables and literals among the code. Code that the loader relocates holds no address
/// in a literal: it holds the offset from the PC it is added to.
fn completed_address(insn: &Insn, state: &State, image: &Image) -> Option<u32> {
    let constant = |register: usize| match state.registers[register] {
        Value::Const(value) => Some(value),
        _ => None,
    };
    let literals = image.relative_targets.is_empty();
    match insn {
        Insn::Thumb(insn) => match pc_sum_thumb(insn) {
            Some(rd) => constant(rd).map(|offset| offset.wrapping_add(insn.addr as u32 + 4)),
            None if insn.adr().is_some() || !literals && insn.literal_word_register().is_some() => None,
            None => Thumb::completed_address(insn, state),
        },
        Insn::A32(insn) => {
            if insn.literal_word_register().is_some() {
                return insn.literal.filter(|_| literals);
            }
            if let Some((_, other)) = insn.adds_pc() {
                return constant(other).map(|offset| offset.wrapping_add(insn.pc() as u32));
            }
            match insn.move_half() {
                Some((register, half, true)) => constant(register).map(|low| half << 16 | low & 0xFFFF),
                _ => None,
            }
        }
    }
}

/// `ADD Rd, PC` of Thumb: the register it adds the PC to.
fn pc_sum_thumb(insn: &thumb::Insn) -> Option<usize> {
    insn.high().filter(|&(operation, rd, rm)| operation == 0 && rm == PC && rd != PC).map(|(_, rd, _)| rd)
}

/// Updates `state` for an A32 instruction. A conditional one may leave a register as it was,
/// so what it writes is unknown after it.
fn step_a32(state: &mut State, insn: A32) {
    if let Some((register, bound)) = insn.compare(state).filter(|_| !insn.conditional()) {
        state.compare = Some((register as u8, bound));
        return;
    }
    let kept = state.compare.filter(|_| !insn.sets_flags());
    state.written = 0;
    let before = state.registers;
    apply_a32(state, insn);
    if insn.conditional() {
        for register in (0..16).filter(|register| state.written >> register & 1 != 0) {
            if state.registers[register] != before[register] {
                state.registers[register] = Value::Unknown;
            }
        }
    }
    state.compare = kept.filter(|&(register, _)| state.written >> register & 1 == 0);
}

fn apply_a32(state: &mut State, insn: A32) {
    let word = insn.word;
    if let Some(register) = insn.literal_word_register() {
        state.set(register, insn.literal.map_or(Value::Unknown, Value::Const));
        return;
    }
    if let Some((register, address)) = insn.adr() {
        state.set(register, Value::Const(address as u32));
        return;
    }
    if let Some((register, other)) = insn.adds_pc() {
        let value = match state.registers[other] {
            Value::Const(offset) => Value::Const(offset.wrapping_add(insn.pc() as u32)),
            _ => Value::Unknown,
        };
        state.set(register, value);
        return;
    }
    if let Some((register, half, top)) = insn.move_half() {
        let value = match (top, state.registers[register]) {
            (false, _) => Value::Const(half),
            (true, Value::Const(low)) => Value::Const(half << 16 | low & 0xFFFF),
            (true, _) => Value::Unknown,
        };
        state.set(register, value);
        return;
    }
    if let Some((_, Transfer::Call)) = insn.direct() {
        state.clobber(CALLER_SAVED);
        return;
    }
    if let Some((_, true)) = insn.exchange() {
        state.clobber(CALLER_SAVED);
        return;
    }
    if let Some((opcode, _, rn, rd, operand)) = insn.data_processing() {
        // TST, TEQ, CMP and CMN write nothing.
        if (8..=11).contains(&opcode) || rd == PC {
            return;
        }
        let value = match (opcode, operand) {
            // MOV and MVN of a number, MOV of a register and LSL.
            (13, Operand::Immediate(value)) => Value::Const(value),
            (15, Operand::Immediate(value)) => Value::Const(!value),
            (13, Operand::Shifted { rm, left }) => state.registers[rm].shifted(left),
            // ADD Rd, Rn, Rn: the index doubled, on its way to a table of halfwords.
            (4, Operand::Shifted { rm, left: 0 }) if rm == rn => state.registers[rn].shifted(1),
            _ => Value::Unknown,
        };
        state.set(rd, value);
        return;
    }
    if let Some(transfer) = insn.transfer() {
        let mut written = 0u16;
        if transfer.writeback {
            written |= 1 << transfer.rn;
        }
        if transfer.load && transfer.rt != PC {
            written |= if transfer.size == 8 { 3 << transfer.rt } else { 1 << transfer.rt };
        }
        // A load from a table at `[Rn, Rm, LSL #shift]`, of an entry the index picks.
        let entry = match (transfer.load, transfer.offset, transfer.pre && !transfer.writeback && transfer.up) {
            (true, Offset::Register { rm, left }, true) if transfer.size <= 4 => {
                let index = state.registers[rm].shifted(left);
                state.indexed_entry(state.registers[transfer.rn], index, u32::from(transfer.size), transfer.signed)
            }
            _ => Value::Unknown,
        };
        state.clobber(written);
        if transfer.load && transfer.rt != PC && transfer.size <= 4 {
            state.set(transfer.rt, entry);
        }
        return;
    }
    if let Some((load, rn, writeback, registers)) = insn.multiple() {
        let base = if writeback { 1 << rn } else { 0 };
        if load {
            state.clobber(registers & !(1 << PC) | base);
            // A word popped off the stack, as a return address saved beside others is.
            if rn == SP {
                for register in (0..15).filter(|register| registers >> register & 1 != 0) {
                    state.registers[register] = Value::Popped;
                }
            }
        } else {
            state.clobber(base);
        }
        return;
    }
    match word >> 24 & 15 {
        // SVC: the kernel returns its result in R0.
        0xF if insn.condition() != 15 => state.clobber(1),
        // Coprocessor and floating point: a move to one or two core registers, or a base
        // written back. A move to R15 sets the flags instead.
        0xC..=0xE if insn.condition() != 15 => {
            let to_core = word & 0x0F10_0010 == 0x0E10_0010;
            let pair = word & 0x0FE0_0000 == 0x0C40_0000 && word >> 20 & 1 != 0;
            let writeback = word >> 25 & 7 == 0b110 && word >> 21 & 1 != 0;
            let mut mask = 0u16;
            if (to_core || pair) && insn.rd() != PC {
                mask |= 1 << insn.rd();
            }
            if pair || writeback {
                mask |= 1 << insn.rn();
            }
            state.clobber(mask);
        }
        // The unconditional space writes no core register but a NEON load or store's base.
        _ if insn.condition() == 15 => {
            if word >> 24 == 0xF4 && word & 15 != 15 {
                state.clobber(1 << insn.rn());
            }
        }
        // Multiplies, media instructions, MRS, CLZ and the rest: Rd in either place.
        _ => state.clobber(1 << insn.rd() | 1 << insn.rn()),
    }
}

/// The control flow of an A32 instruction.
fn flow_a32(insn: A32, state: &State) -> Option<Flow> {
    let target = |register: usize| match state.registers[register] {
        Value::Const(value) => Some(u64::from(value & !1)),
        _ => None,
    };
    let popped = |register: usize| state.registers[register] == Value::Popped;
    if let Some((to, transfer)) = insn.direct() {
        return Some(match transfer {
            Transfer::Call => Flow::Call(to),
            Transfer::Jump => Flow::Jump(to),
            Transfer::Branch => Flow::Branch(to),
        });
    }
    let word = insn.word;
    if insn.condition() == 15 {
        return None;
    }
    // UDF, which traps.
    if word & 0x0FF0_00F0 == 0x07F0_00F0 {
        return (!insn.conditional()).then_some(Flow::Halt);
    }
    // A call through a register goes on after it, condition or not.
    if let Some((rm, true)) = insn.exchange() {
        return Some(target(rm).map_or(Flow::CallIndirect(None), Flow::Call));
    }
    let leaves = if let Some((rm, false)) = insn.exchange() {
        match rm {
            LR => Flow::Return,
            _ if popped(rm) => Flow::Return,
            _ => target(rm).map_or(Flow::JumpIndirect(None), Flow::Jump),
        }
    } else if let Some((opcode, flags, _, PC, operand)) = insn.data_processing() {
        match (opcode, operand) {
            // MOVS PC, LR and SUBS PC, LR, #4 return from an exception.
            _ if flags => Flow::Return,
            (13, Operand::Shifted { rm: LR, left: 0 }) => Flow::Return,
            (13, Operand::Shifted { rm, left: 0 }) if popped(rm) => Flow::Return,
            (13, Operand::Shifted { rm, left: 0 }) => target(rm).map_or(Flow::JumpIndirect(None), Flow::Jump),
            // ADD PC, PC, Rm, LSL #2 and ADD PC, Rt, Re, which jump through a table.
            _ => Flow::JumpIndirect(None),
        }
    } else if let Some(transfer) = insn.transfer().filter(|transfer| transfer.load && transfer.rt == PC) {
        match (transfer.rn, transfer.offset, transfer.pre) {
            // LDR PC, [SP], #4.
            (SP, Offset::Immediate(4), false) => Flow::Return,
            // LDR PC, [PC, #imm]: a jump to the address the literal holds, as a linker's long
            // branch makes it.
            (PC, Offset::Immediate(offset), true) => {
                let at = if transfer.up { insn.pc() + u64::from(offset) } else { insn.pc().wrapping_sub(u64::from(offset)) };
                Flow::JumpIndirect(Some(at))
            }
            _ => Flow::JumpIndirect(None),
        }
    } else if let Some((true, rn, _, _)) = insn.multiple().filter(|&(_, _, _, registers)| registers >> PC & 1 != 0) {
        if rn == SP { Flow::Return } else { Flow::JumpIndirect(None) }
    } else {
        return None;
    };
    // A conditional jump through a table is how GCC dispatches a switch without PIC: it falls
    // through to the default when the index is out of range. Other conditional jumps through PC,
    // as into libgcc's unrolled division, fall through as far as the analysis goes.
    let dispatches = matches!(leaves, Flow::JumpIndirect(None)) && dispatch_a32(insn).is_some_and(|dispatch| index_a32(insn, state, dispatch).is_some());
    (!insn.conditional() || dispatches).then_some(leaves)
}

/// The index register of `dispatch` and what it holds where the jump is taken: a jump that runs
/// only when the index is at most the bound of the compare before it knows that bound.
fn index_a32(insn: A32, state: &State, dispatch: Dispatch) -> Option<Value> {
    let rm = match dispatch {
        Dispatch::AddPc { rm } | Dispatch::LoadPc { rm } => rm,
        Dispatch::AddTable { .. } => return None,
    };
    let bounded = |bound: u32| Value::Bounded(Limit::of(u64::from(bound)));
    match (insn.condition(), state.compare) {
        (9, Some((register, bound))) if usize::from(register) == rm => Some(bounded(bound)),
        (3, Some((register, bound))) if usize::from(register) == rm && bound > 0 => Some(bounded(bound - 1)),
        _ => match state.registers[rm] {
            value @ (Value::Bounded(_) | Value::Entry { .. }) => Some(value),
            _ => None,
        },
    }
}

/// The forms of an A32 jump through a table: `ADD PC, PC, Rm, LSL #2`, `LDR PC, [PC, Rm, LSL
/// #2]` and `ADD PC, Rt, Re`.
#[derive(Clone, Copy)]
enum Dispatch {
    /// PC plus four times what `Rm` holds: an entry, or the index into a row of branches.
    AddPc { rm: usize },
    /// The word of the table after the jump that `Rm` picks.
    LoadPc { rm: usize },
    /// A table's address plus an entry of it.
    AddTable { rt: usize, re: usize },
}

fn dispatch_a32(insn: A32) -> Option<Dispatch> {
    if let Some((4, false, rn, PC, operand)) = insn.data_processing() {
        return match (rn, operand) {
            (PC, Operand::Shifted { rm, left: 2 }) => Some(Dispatch::AddPc { rm }),
            (rt, Operand::Shifted { rm: re, left: 0 }) if rt != PC && re != PC => Some(Dispatch::AddTable { rt, re }),
            _ => None,
        };
    }
    let transfer = insn.transfer()?;
    match (transfer.load, transfer.rt, transfer.rn, transfer.offset, transfer.size) {
        (true, PC, PC, Offset::Register { rm, left: 2 }, 4) if transfer.pre && transfer.up && !transfer.writeback => Some(Dispatch::LoadPc { rm }),
        _ => None,
    }
}

/// The table behind an A32 jump. One that may fall through has the instruction after it as a
/// case as well.
fn resolve_a32(state: &State, image: &Image, jump: A32, is_target: &dyn Fn(u64) -> bool) -> Option<Table> {
    let limit = |value: Value| match value {
        Value::Bounded(limit) => Some(limit),
        Value::Scaled { limit, .. } => limit,
        _ => None,
    };
    let dispatch = dispatch_a32(jump)?;
    let index = |rm: usize| if jump.conditional() { index_a32(jump, state, dispatch).unwrap_or_default() } else { state.registers[rm] };
    let mut table = match dispatch {
        Dispatch::AddPc { rm } => match index(rm) {
            Value::Entry { table, size, limit, shift: 0, signed } => {
                let cases = if signed { Cases::Signed { base: jump.pc(), shift: 2 } } else { Cases::Relative { base: jump.pc(), shift: 2 } };
                let mut table = read_table(image, u64::from(table), u64::from(size), limit, cases, is_target)?;
                // A table in read-only data, not among the code.
                table.inline_end = None;
                table
            }
            // A row of branches, one per case, which are code.
            Value::Bounded(limit) => {
                let entries = (0..Limit::entries(Some(limit)) as u64).map(|case| jump.pc() + 4 * case).collect();
                Table { address: jump.pc(), entry_size: 4, entries, bounded: true, inline_end: None }
            }
            _ => return None,
        },
        Dispatch::LoadPc { rm } => read_table(image, jump.pc(), 4, limit(index(rm)), Cases::Absolute { thumb: false }, is_target)?,
        Dispatch::AddTable { rt, re } => {
            let entry = |base: usize, entry: usize| match (state.registers[base], state.registers[entry]) {
                (Value::Const(table), Value::Entry { table: read, size: 4, limit, shift: 0, .. }) if table == read => Some((table, limit)),
                _ => None,
            };
            let (address, limit) = entry(rt, re).or_else(|| entry(re, rt))?;
            read_table(image, u64::from(address), 4, limit, Cases::Signed { base: u64::from(address), shift: 0 }, is_target)?
        }
    };
    if jump.conditional() {
        table.entries.push(jump.addr + 4);
    }
    Some(table)
}

/// 32-bit ARM code, A32 and Thumb.
pub struct Arm;

impl Arch for Arm {
    type Insn = Insn;
    type State = State;

    /// A32 functions sit at a word and Thumb ones at a halfword.
    const FUNCTION_ALIGN: u64 = 2;
    const LONGEST_PADDING: u64 = 14;
    const ALIGNMENT_IS_EVIDENCE: bool = false;
    const LITERAL_POOLS: bool = true;
    const TAKEN_IS_WEAK: bool = true;

    fn decode<'a>(image: &'a Image, bytes: &'a [u8], addr: u64) -> impl Iterator<Item = Decoded<Insn>> + 'a {
        let mut decoder = Self::decoder(image, bytes, addr);
        std::iter::from_fn(move || decoder.next())
    }

    type Decoder<'a> = Decoder<'a>;

    fn decoder<'a>(image: &'a Image, bytes: &'a [u8], addr: u64) -> Decoder<'a> {
        let insn = Insn::A32(A32 { addr, word: 0, literal: None });
        Decoder { image, bytes, base: addr, offset: 0, it: 0, set: InstructionSet::A32, run: 0..0, insn }
    }

    /// Nothing branches into an `IT` block, so a new place to decode from is outside one.
    fn seek(decoder: &mut Decoder<'_>, offset: usize) {
        (decoder.offset, decoder.it, decoder.run) = (offset, 0, 0..0);
    }

    fn decode_next<'d>(decoder: &'d mut Decoder<'_>) -> Option<Decoded<&'d Insn>> {
        let decoded = decoder.next()?;
        let insn = &mut decoder.insn;
        Some(Decoded { addr: decoded.addr, len: decoded.len, insn: decoded.insn.map(|decoded| &*{ *insn = decoded; insn }) })
    }

    fn flow(insn: &Insn, state: &State, image: &Image) -> Option<Flow> {
        let insn = match insn {
            Insn::A32(insn) => return flow_a32(*insn, state),
            Insn::Thumb(insn) => insn,
        };
        // BX and BLX of an address that has no Thumb bit go to A32 code, which a Cortex-M has
        // not.
        if let (Some((3, _, rm)), Value::Const(value)) = (insn.high(), state.registers[insn.high().map_or(0, |(_, _, rm)| rm)]) {
            if value & 1 == 0 && rm != LR {
                let target = u64::from(value);
                return match insn.hw1 & 0x80 != 0 {
                    true => Some(Flow::Call(target)),
                    false => (!insn.conditional).then_some(Flow::Jump(target)),
                };
            }
        }
        Thumb::flow(insn, state, image)
    }

    /// A pointer to code: to Thumb code with the Thumb bit, to A32 code at a word without it.
    fn address_taken(insn: &Insn, state: &State, image: &Image) -> Option<u64> {
        let address = completed_address(insn, state, image)?;
        match address & 3 {
            0 => Some(u64::from(address)),
            1 | 3 => Some(u64::from(address & !1)),
            _ => None,
        }
    }

    fn memory_reference(insn: &Insn, state: &State) -> Option<u64> {
        let insn = match insn {
            Insn::Thumb(insn) => return Thumb::memory_reference(insn, state),
            Insn::A32(insn) => insn,
        };
        let transfer = insn.transfer().filter(|transfer| transfer.rn != PC && transfer.pre)?;
        let (Value::Const(base), Offset::Immediate(offset)) = (state.registers[transfer.rn], transfer.offset) else { return None };
        Some(if transfer.up { u64::from(base) + u64::from(offset) } else { u64::from(base).wrapping_sub(u64::from(offset)) })
    }

    fn literal(insn: &Insn) -> Option<(u64, u64)> {
        match insn {
            Insn::A32(insn) => insn.literal_range(),
            Insn::Thumb(insn) => insn.literal_range(),
        }
    }

    /// `NOP` and the moves of a register to itself that compilers pad with, and zeros, which
    /// GNU ld pads with.
    fn is_padding(insn: &Insn) -> bool {
        match insn {
            Insn::A32(insn) => matches!(insn.word, 0xE1A0_0000 | 0xE320_F000 | 0),
            Insn::Thumb(insn) => Thumb::is_padding(insn),
        }
    }

    /// Zeros, and in Thumb code the `NOP` that aligns the next function to a word: GCC puts
    /// neither after a call that returns.
    fn ends_code(insn: &Insn) -> bool {
        match insn {
            Insn::A32(insn) => insn.word == 0,
            Insn::Thumb(insn) => Thumb::ends_code(insn) || !insn.wide() && insn.hw1 == 0xBF00,
        }
    }

    fn is_entry_marker(_: &Insn) -> bool {
        false
    }

    fn opens_function(first: &Insn, second: Option<&Insn>) -> bool {
        match (first, second) {
            // GCC may put an instruction of the body first, as the compare of an argument, or
            // the probe of a stack that must not clash.
            (Insn::A32(insn), Some(Insn::A32(second))) if !insn.saves_return() => {
                let body = insn.data_processing().is_some_and(|(.., rd, _)| rd != PC);
                (insn.probes_stack() || body) && second.saves_return()
            }
            (Insn::A32(insn), _) => insn.saves_return(),
            (Insn::Thumb(insn), Some(Insn::Thumb(second))) => Thumb::opens_function(insn, Some(second)),
            (Insn::Thumb(insn), _) => Thumb::opens_function(insn, None),
        }
    }

    /// A Thumb block that reads its function's variables before setting up a frame.
    fn borrows_frame(insns: &[Insn]) -> bool {
        let thumb: Vec<thumb::Insn> = insns.iter().map_while(|insn| match insn {
            Insn::Thumb(insn) => Some(*insn),
            Insn::A32(_) => None,
        }).collect();
        thumb.len() == insns.len() && Thumb::borrows_frame(&thumb)
    }

    fn takes_variable_arguments(insns: &[Insn]) -> bool {
        let thumb: Vec<thumb::Insn> = insns.iter().map_while(|insn| match insn {
            Insn::Thumb(insn) => Some(*insn),
            Insn::A32(_) => None,
        }).collect();
        !thumb.is_empty() && Thumb::takes_variable_arguments(&thumb)
    }

    fn opens_landing_pad(_: &Insn) -> bool {
        false
    }

    fn step(state: &mut State, insn: &Insn) {
        match insn {
            Insn::A32(insn) => step_a32(state, *insn),
            // ADD Rd, PC of an offset a literal holds: the address of what the offset names.
            Insn::Thumb(insn) => match (pc_sum_thumb(insn), pc_sum_thumb(insn).map(|rd| state.registers[rd])) {
                (Some(rd), Some(Value::Const(offset))) => {
                    let kept = state.compare.filter(|&(register, _)| usize::from(register) != rd);
                    state.set(rd, Value::Const(offset.wrapping_add(insn.addr as u32 + 4)));
                    state.compare = kept;
                }
                _ => state.step(*insn),
            },
        }
    }

    fn branch(fallthrough: &mut State, insn: &Insn) -> State {
        match insn {
            Insn::Thumb(insn) => Thumb::branch(fallthrough, insn),
            Insn::A32(insn) => {
                let condition = matches!(insn.direct(), Some((_, Transfer::Branch))).then_some(insn.condition() as u16);
                fallthrough.split(condition)
            }
        }
    }

    fn after_jump(_: State, _: &Insn) -> State {
        State::default()
    }

    fn resolve_table(
        state: &State,
        image: &Image,
        pointer_slots: &FxHashMap<u64, u64>,
        jump: &Insn,
        is_target: &dyn Fn(u64) -> bool,
        is_code: &dyn Fn(u64) -> bool,
    ) -> Option<Table> {
        match jump {
            Insn::A32(jump) => resolve_a32(state, image, *jump, is_target),
            Insn::Thumb(jump) => Thumb::resolve_table(state, image, pointer_slots, jump, is_target, is_code),
        }
    }

    fn plt_stubs(image: &Image) -> FxHashMap<u64, u64> {
        image.sections.iter().filter(|section| section.is_stubs()).flat_map(plt_stubs).collect()
    }
}

/// Each PLT stub of `section` with the slot it jumps through. GNU ld's stub is A32: `ADD IP, PC,
/// #a; ADD IP, IP, #b; LDR PC, [IP, #c]!`. A Thumb caller that cannot `BLX` reaches it through
/// `BX PC; NOP` right before it.
fn plt_stubs(section: &Section) -> Vec<(u64, u64)> {
    let words: Vec<u32> = section.data.chunks_exact(4).map(|word| u32::from_le_bytes(word.try_into().unwrap())).collect();
    let mut stubs = Vec::new();
    for (index, window) in words.windows(3).enumerate() {
        let is = |word: u32, pattern: u32| word & 0xFFFF_F000 == pattern;
        if !(is(window[0], 0xE28F_C000) && is(window[1], 0xE28C_C000) && is(window[2], 0xE5BC_F000)) {
            continue;
        }
        let at = section.addr + 4 * index as u64;
        let slot = at + 8 + u64::from(rotated(window[0])) + u64::from(rotated(window[1])) + u64::from(window[2] & 0xFFF);
        stubs.push((at, slot));
        if index > 0 && words[index - 1] == 0x46C0_4778 {
            stubs.push((at - 4, slot));
        }
    }
    stubs
}

/// What is known of an instruction set at the address of a pointer to code, from its Thumb bit.
fn marked(pointer: u64) -> (u64, InstructionSet) {
    if pointer & 1 != 0 { (pointer & !1, InstructionSet::Thumb) } else { (pointer, InstructionSet::A32) }
}

/// Finishes loading a 32-bit ARM ELF: takes the Thumb bit off the addresses of code that the
/// file gives with it, and makes the map of instruction sets.
pub(crate) fn load(file: &object::File, image: &mut Image) {
    use object::{Object, ObjectSection, ObjectSymbol};
    let is_code = |image: &Image, addr: u64| image.is_code(addr);
    // Where the set is known for sure: the entry point, the exports and the pointers that the
    // loader relocates into code, each with the Thumb bit or without it, and the PLT, which
    // GNU ld writes in A32.
    let mut seeds = vec![marked(image.entry)];
    seeds.extend(file.dynamic_symbols().filter(|symbol| symbol.kind() == object::SymbolKind::Text && symbol.is_definition()).map(|symbol| marked(symbol.address())));
    // A pointer without the Thumb bit may be a label in Thumb code, as a table of them for a
    // computed goto holds, and not A32 code: it counts where what it points at reads as A32.
    seeds.extend(
        image
            .relative_targets
            .iter()
            .filter(|&&(_, target)| is_code(image, target & !1) && (target & 1 != 0 || target % 4 == 0 && image.bytes_from(target).is_some_and(|bytes| reads_as_a32(&bytes[..bytes.len().min(48)]))))
            .map(|&(_, target)| marked(target)),
    );
    seeds.extend(dynamic_code_pointers(file).into_iter().map(marked));
    seeds.extend(image.sections.iter().filter(|section| section.is_stubs()).map(|section| (section.addr, InstructionSet::A32)));

    image.entry &= !1;
    for export in &mut image.exports {
        *export &= !1;
    }
    image.symbol_names = std::mem::take(&mut image.symbol_names).into_iter().map(|(addr, name)| (if is_code(image, addr & !1) { addr & !1 } else { addr }, name)).collect();
    let code_targets: Vec<usize> = (0..image.relative_targets.len()).filter(|&index| is_code(image, image.relative_targets[index].1 & !1)).collect();
    for index in code_targets {
        image.relative_targets[index].1 &= !1;
    }

    image.frames = exception_index(file);
    image.frames_merge = true;

    // An unstripped file says where the sets change itself.
    let mut mapping: Vec<(u64, InstructionSet)> = file
        .symbols()
        .filter(|symbol| symbol.section_index().and_then(|index| file.section_by_index(index).ok()).is_some_and(|section| section.kind() == object::SectionKind::Text))
        .filter_map(|symbol| match symbol.name().ok()?.split('.').next()? {
            "$a" => Some((symbol.address(), InstructionSet::A32)),
            "$t" => Some((symbol.address(), InstructionSet::Thumb)),
            _ => None,
        })
        .collect();
    image.instruction_sets = if mapping.is_empty() {
        instruction_sets(image, &seeds)
    } else {
        mapping.sort_unstable_by_key(|&(addr, _)| addr);
        mapping
    };
}

/// The functions that `.ARM.exidx`, ARM's table for unwinding, lists, each from where its entry
/// says up to the next. An entry may hold several functions that the linker merged, see
/// [`Image::frames_merge`]. One that says the code cannot be unwound is left out: the linker
/// also writes those to cover code that has no entry of its own, any number of functions. So
/// is the last, whose end nothing says.
fn exception_index(file: &object::File) -> Vec<(u64, u64)> {
    use object::{Object, ObjectSection};
    const CANNOT_UNWIND: u32 = 1;
    let Some(section) = file.section_by_name(".ARM.exidx") else { return Vec::new() };
    let Ok(data) = section.data() else { return Vec::new() };
    // The first word of each entry is a 31-bit offset from the entry to the function.
    let mut entries: Vec<(u64, bool)> = data
        .chunks_exact(8)
        .enumerate()
        .map(|(index, entry)| {
            let word = |at: usize| u32::from_le_bytes(entry[at..at + 4].try_into().unwrap());
            let start = (section.address() + 8 * index as u64).wrapping_add_signed(sign_extend(word(0) & 0x7FFF_FFFF, 31)) & 0xFFFF_FFFF;
            (start, word(4) != CANNOT_UNWIND)
        })
        .collect();
    entries.sort_unstable();
    entries.windows(2).filter(|pair| pair[0].1 && pair[0].0 < pair[1].0).map(|pair| (pair[0].0, pair[1].0)).collect()
}

/// Whether `bytes` read as A32 code. Nearly every instruction a compiler writes runs whatever
/// the flags, and so has condition 14 in its top four bits, where Thumb code read four bytes at a
/// time has any of them. The data among code, small numbers and offsets either way of zero, has 0
/// or 15 there and says nothing. Thumb code that calls through the PLT has 14 there often, for
/// the second half of a `BLX`, so this tells A32 from a label inside Thumb code and no more.
fn reads_as_a32(bytes: &[u8]) -> bool {
    let conditions: Vec<u32> = bytes.chunks_exact(4).map(|word| u32::from_le_bytes(word.try_into().unwrap()) >> 28).filter(|condition| (1..15).contains(condition)).collect();
    let always = conditions.iter().filter(|&&condition| condition == 14).count();
    conditions.len() >= 2 && always * 4 >= conditions.len() * 3
}

/// `DT_INIT` and `DT_FINI`, the functions the loader calls before and after the program, with
/// the Thumb bit as the file gives them.
fn dynamic_code_pointers(file: &object::File) -> Vec<u64> {
    use object::{Object, ObjectSection};
    const DT_INIT: u32 = 12;
    const DT_FINI: u32 = 13;
    let Some(data) = file.section_by_name(".dynamic").and_then(|section| section.data().ok()) else { return Vec::new() };
    data.chunks_exact(8)
        .filter_map(|entry| {
            let (tag, value) = (u32::from_le_bytes(entry[..4].try_into().unwrap()), u32::from_le_bytes(entry[4..].try_into().unwrap()));
            matches!(tag, DT_INIT | DT_FINI).then_some(u64::from(value))
        })
        .collect()
}

/// Where the code of `image` changes instruction set, as [`Image::instruction_sets`] has it.
///
/// Each seed is code in a known set. From there the code is followed, call by call and branch
/// by branch, as long as it goes on in a straight line, and a `BLX` to a label leads to the
/// other set. A stretch of code that nothing reaches is in the set of the code before it, as
/// the functions of one source file are; one before any is in the set of the first seed.
fn instruction_sets(image: &Image, seeds: &[(u64, InstructionSet)]) -> Vec<(u64, InstructionSet)> {
    let code: Vec<&Section> = image.sections.iter().filter(|section| section.executable).collect();
    // Per byte of each section, the set of the instruction that covers it, if one does.
    let mut seen: Vec<Vec<Option<InstructionSet>>> = code.iter().map(|section| vec![None; section.data.len()]).collect();
    let mut pending: Vec<(u64, InstructionSet)> = seeds.iter().rev().copied().collect();
    let mut probe = Image::bare(String::new(), image.format, image.machine, 0, Vec::new());
    while let Some((start, set)) = pending.pop() {
        let Some(index) = code.iter().position(|section| section.contains(start)) else { continue };
        let section = code[index];
        if seen[index][(start - section.addr) as usize].is_some() {
            continue;
        }
        // The section decoded as nothing but the one set.
        probe.instruction_sets = vec![(0, set)];
        let state = State::default();
        for decoded in Arm::decode(&probe, &section.data[(start - section.addr) as usize..], start) {
            let offset = (decoded.addr - section.addr) as usize;
            let Some(insn) = decoded.insn.filter(|insn| !Arm::ends_code(insn)) else { break };
            if seen[index][offset..offset + usize::from(decoded.len)].iter().any(Option::is_some) {
                break;
            }
            seen[index][offset..offset + usize::from(decoded.len)].fill(Some(set));
            // The code does not run on into its constants, nor does a guess at what follows a
            // call that never returns.
            if let Some((from, to)) = Arm::literal(&insn).filter(|&(from, to)| from >= section.addr && to <= section.end()) {
                let (from, to) = ((from - section.addr) as usize, (to - section.addr) as usize);
                if seen[index][from..to].iter().all(Option::is_none) {
                    seen[index][from..to].fill(Some(set));
                }
            }
            let to = |target: u64| {
                let exchanges = match insn {
                    Insn::A32(insn) => insn.condition() == 15,
                    Insn::Thumb(insn) => insn.wide() && insn.hw2 & 0x5000 == 0x4000,
                };
                let other = if set == InstructionSet::A32 { InstructionSet::Thumb } else { InstructionSet::A32 };
                (target, if exchanges { other } else { set })
            };
            match Arm::flow(&insn, &state, image) {
                None | Some(Flow::CallIndirect(_)) => {}
                Some(Flow::Call(target) | Flow::Branch(target)) => pending.push(to(target)),
                Some(Flow::Jump(target)) => {
                    pending.push(to(target));
                    break;
                }
                Some(Flow::JumpIndirect(_) | Flow::Return | Flow::Halt) => break,
            }
        }
    }
    // What nothing reaches is in the set of what comes before it, as the functions of one source
    // file are.
    let first = seeds.first().map_or(InstructionSet::A32, |&(_, set)| set);
    let mut sets: Vec<(u64, InstructionSet)> = Vec::new();
    for (section, seen) in code.iter().zip(&seen) {
        let mut current = None;
        for (offset, set) in seen.iter().enumerate().filter_map(|(offset, set)| Some((offset, (*set)?))) {
            if current != Some(set) {
                // What nothing reached at the start of the section is in the set of what follows.
                let at = if current.is_none() { section.addr } else { section.addr + offset as u64 };
                sets.push((at, set));
                current = Some(set);
            }
        }
        if current.is_none() {
            sets.push((section.addr, sets.last().map_or(first, |&(_, set)| set)));
        }
    }
    sets.dedup_by(|next, before| next.1 == before.1);
    sets
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image::{Format, Machine};

    /// An image of A32 `words` at `addr`, with the Thumb code `thumb` after them, at a word.
    fn image(words: &[u32], thumb: &[u16], addr: u64) -> Image {
        let mut code: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        let thumb_at = addr + code.len() as u64;
        code.extend(thumb.iter().flat_map(|half| half.to_le_bytes()));
        let section = Section { name: ".text".into(), addr, data: code, file_offset: None, executable: true, writable: false };
        let mut image = Image::bare(String::new(), Format::Elf, Machine::Arm, addr, vec![section]);
        image.instruction_sets = vec![(addr, InstructionSet::A32)];
        if !thumb.is_empty() {
            image.instruction_sets.push((thumb_at, InstructionSet::Thumb));
        }
        image.data_in_code = true;
        image
    }

    /// The length and the control flow of each instruction of `image`, stepping the state.
    fn flows(image: &Image) -> Vec<(u64, u8, Option<Flow>)> {
        let section = &image.sections[0];
        let mut state = State::default();
        Arm::decode(image, &section.data, section.addr)
            .map(|decoded| {
                let insn = decoded.insn.unwrap();
                let flow = Arm::flow(&insn, &state, image);
                Arm::step(&mut state, &insn);
                (decoded.addr, decoded.len, flow)
            })
            .collect()
    }

    #[test]
    fn every_kind_of_a32_transfer_goes_where_its_bits_say() {
        use Flow::*;
        let cases: &[(u32, Option<Flow>)] = &[
            // BL back by 0x23F8 from 0x4520, as objdump shows `bl 0x2130`; B; BHI; BLX to Thumb.
            (0xEBFF_F702, Some(Call(0x2130))),
            (0xEA00_0001, Some(Jump(0x452C))),
            (0x8A00_07CD, Some(Branch(0x645C))),
            (0xFB00_0001, Some(Call(0x452E))),
            // BX LR; BXNE LR, which may fall through; POP {R4, PC}; LDR PC, [SP], #4; MOV PC, LR.
            (0xE12F_FF1E, Some(Return)),
            (0x112F_FF1E, None),
            (0xE8BD_8010, Some(Return)),
            (0xE49D_F004, Some(Return)),
            (0xE1A0_F00E, Some(Return)),
            // BLX R3; BX R3; LDR PC, [R3, #4]; UDF; SVC 0; PUSH {R4, LR}.
            (0xE12F_FF33, Some(CallIndirect(None))),
            (0xE12F_FF13, Some(JumpIndirect(None))),
            (0xE593_F004, Some(JumpIndirect(None))),
            (0xE7F0_01F0, Some(Halt)),
            (0xEF00_0000, None),
            (0xE92D_4010, None),
        ];
        for &(word, expected) in cases {
            assert_eq!(flows(&image(&[word], &[], 0x4520)), [(0x4520, 4, expected)], "{word:08x}");
        }
    }

    #[test]
    fn the_decoder_switches_set_where_the_image_says() {
        // A32: BLX to the Thumb code at 0x1008, then MOV R0, R0 to pad. Thumb: BX LR; MOVS R0, #1;
        // BX LR.
        let image = image(&[0xFA00_0000, 0xE1A0_0000], &[0x4770, 0x2001, 0x4770], 0x1000);
        let lengths: Vec<(u64, u8)> = flows(&image).into_iter().map(|(addr, len, _)| (addr, len)).collect();
        assert_eq!(lengths, [(0x1000, 4), (0x1004, 4), (0x1008, 2), (0x100A, 2), (0x100C, 2)]);
        assert_eq!(flows(&image)[0].2, Some(Flow::Call(0x1008)));
    }

    #[test]
    fn a_thumb_blx_goes_to_a32_code_at_a_word() {
        // At 0x1002, BLX 0x1008: the offset counts from 0x1004, down to a word.
        let image = image(&[], &[0xBF00, 0xF000, 0xE800], 0x1000);
        let image = Image { instruction_sets: vec![(0x1000, InstructionSet::Thumb)], ..image };
        assert_eq!(flows(&image)[1], (0x1002, 4, Some(Flow::Call(0x1004))));
    }

    #[test]
    fn position_independent_code_takes_the_address_of_a_function() {
        // LDR R3, [PC, #0] reads 0x1001 at 0x2008; ADD R3, PC, R3 at 0x2004 adds 0x200C: the
        // Thumb function at 0x300C.
        let mut image = image(&[0xE59F_3000, 0xE08F_3003, 0x0000_1001], &[], 0x2000);
        // A relocation says the image is loaded anywhere, so the literal is no address itself.
        image.relative_targets = vec![(0x4000, 0x2000)];
        let section = &image.sections[0];
        let mut state = State::default();
        let taken: Vec<Option<u64>> = Arm::decode(&image, &section.data, 0x2000)
            .take(2)
            .map(|decoded| {
                let insn = decoded.insn.unwrap();
                let taken = Arm::address_taken(&insn, &state, &image);
                Arm::step(&mut state, &insn);
                taken
            })
            .collect();
        assert_eq!(taken, [None, Some(0x300C)]);
    }

    /// The jump tables that analysis finds in `words` at 0x1000.
    fn tables(words: &[u32]) -> Vec<(u64, Vec<u64>)> {
        crate::analysis::analyze(&image(words, &[], 0x1000)).jump_tables.iter().map(|table| (table.jump, table.targets.clone())).collect()
    }

    #[test]
    fn gcc_adds_four_times_an_entry_of_a_table_in_read_only_data_to_pc() {
        // LDR R3, [PC, #0x24] reads 0x0FF4 at 0x102C; ADD R3, PC, R3: the table at 0x2000.
        // CMP R0, #2; BHI 0x1028; ADD R0, R0, R0; LDRH R0, [R3, R0]; ADD PC, PC, R0, LSL #2; NOP;
        // then the cases at 0x1020, 0x1024 and the default at 0x1028, each BX LR.
        let mut words = vec![0xE59F_3024, 0xE08F_3003, 0xE350_0002, 0x8A00_0004, 0xE080_0000, 0xE193_00B0, 0xE08F_F100, 0xE1A0_0000];
        words.extend([0xE12F_FF1E, 0xE12F_FF1E, 0xE12F_FF1E, 0x0000_0FF4]);
        let mut image = image(&words, &[], 0x1000);
        // The table: halfwords 0, 1 and 0, cases at 0x1020 + 4 * entry.
        image.sections.push(Section { name: ".rodata".into(), addr: 0x2000, data: vec![0, 0, 1, 0, 0, 0], file_offset: None, executable: false, writable: false });
        let tables: Vec<(u64, Vec<u64>)> = crate::analysis::analyze(&image).jump_tables.iter().map(|table| (table.jump, table.targets.clone())).collect();
        assert_eq!(tables, [(0x1018, vec![0x1020, 0x1024])]);
    }

    #[test]
    fn clang_adds_an_offset_its_table_holds_to_the_table() {
        // CMP R0, #1; BHI 0x1024; ADR R1, 0x1014; LDR R0, [R1, R0, LSL #2]; ADD PC, R1, R0; the
        // offsets 8 and 12 from 0x1014; BX LR at the cases 0x101C and 0x1020 and the default.
        let words = [0xE350_0001, 0x8A00_0006, 0xE28F_1004, 0xE791_0100, 0xE081_F000, 8, 12, 0xE12F_FF1E, 0xE12F_FF1E, 0xE12F_FF1E];
        assert_eq!(tables(&words), [(0x1010, vec![0x101C, 0x1020])]);
    }

    #[test]
    fn a_dispatch_that_may_fall_through_has_the_default_as_a_case() {
        // CMP R0, #1; LDRLS PC, [PC, R0, LSL #2]; B 0x101C; the addresses 0x1014 and 0x1018;
        // BX LR at each and at the default.
        let words = [0xE350_0001, 0x979F_F100, 0xEA00_0003, 0x1014, 0x1018, 0xE12F_FF1E, 0xE12F_FF1E, 0xE12F_FF1E];
        assert_eq!(tables(&words), [(0x1004, vec![0x1008, 0x1014, 0x1018])]);
    }

    #[test]
    fn the_sets_follow_calls_from_the_seeds_and_runs_keep_the_set_of_the_code_before_them() {
        // A32 at 0x1000: BLX 0x100C; BX LR. Thumb at 0x1008: BX LR, which nothing reaches, then
        // at 0x100A MOVS R0, #0, then BX LR at 0x100C... reached by the BLX.
        let image = image(&[0xFA00_0001, 0xE12F_FF1E], &[0x4770, 0x2000, 0x4770, 0x4770], 0x1000);
        let sets = instruction_sets(&image, &[(0x1000, InstructionSet::A32)]);
        assert_eq!(sets, [(0x1000, InstructionSet::A32), (0x100C, InstructionSet::Thumb)]);
    }
}
