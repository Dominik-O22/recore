//! 8051 support, decoded directly from the one to three bytes of each instruction.
//!
//! Code addresses are 16 bits wide. Larger programs are banked, and [`Banking`] says where a
//! 16-bit target lies: a code address here is `bank << 16 | address`. The 8051 has address
//! spaces besides code, which get ranges of their own far above any bank: [`XDATA`], [`IDATA`]
//! and [`SFR`].
//!
//! [`Banking`]: crate::image::Banking

use rustc_hash::FxHashMap;

use crate::arch::{Arch, Decoded, Flow, Table, TextPointer};
use crate::image::{Image, Machine};
use crate::report::Analysis;

/// External data memory, reached through `DPTR`: 64 KB from here.
pub const XDATA: u64 = 1 << 32;
/// Internal data memory: 256 bytes from here, of which the first 128 are also reached by
/// direct addressing.
pub const IDATA: u64 = 2 << 32;
/// The special function registers, at their direct addresses 0x80 to 0xFF from here.
pub const SFR: u64 = 3 << 32;

/// `[start, end)` of the memory an 8051 program has besides its code, none of it in the image.
pub fn memory() -> Vec<(u64, u64)> {
    vec![(XDATA, XDATA + 0x1_0000), (IDATA, IDATA + 0x100), (SFR + 0x80, SFR + 0x100)]
}

/// The direct addresses of the two halves of `DPTR`.
const DPL: u8 = 0x82;
const DPH: u8 = 0x83;

/// Bytes in the instruction each opcode begins, or zero for 0xA5, the one opcode that is not
/// an instruction.
#[rustfmt::skip]
const LENGTH: [u8; 256] = [
 // x0 x1 x2 x3 x4 x5 x6 x7 x8 x9 xA xB xC xD xE xF
    1, 2, 3, 1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 0x: NOP AJMP LJMP RR INC
    3, 2, 3, 1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 1x: JBC ACALL LCALL RRC DEC
    3, 2, 1, 1, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 2x: JB AJMP RET RL ADD
    3, 2, 1, 1, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 3x: JNB ACALL RETI RLC ADDC
    2, 2, 2, 3, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 4x: JC AJMP ORL
    2, 2, 2, 3, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 5x: JNC ACALL ANL
    2, 2, 2, 3, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 6x: JZ AJMP XRL
    2, 2, 2, 1, 2, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, // 7x: JNZ ACALL ORL JMP MOV
    2, 2, 2, 1, 1, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, // 8x: SJMP AJMP ANL MOVC DIV MOV
    3, 2, 2, 1, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 9x: MOV ACALL MOV MOVC SUBB
    2, 2, 2, 1, 1, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, // Ax: ORL AJMP MOV INC MUL - MOV
    2, 2, 2, 1, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, // Bx: ANL ACALL CPL CPL CJNE
    2, 2, 2, 1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // Cx: PUSH AJMP CLR CLR SWAP XCH
    2, 2, 2, 1, 1, 3, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, // Dx: POP ACALL SETB SETB DA DJNZ XCHD DJNZ
    1, 2, 1, 1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // Ex: MOVX AJMP MOVX CLR MOV
    1, 2, 1, 1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // Fx: MOVX ACALL MOVX CPL MOV
];

/// Where the byte at a direct address is: in internal data below 0x80, a special function
/// register from there.
fn direct_address(direct: u8) -> u64 {
    if direct < 0x80 { IDATA + u64::from(direct) } else { SFR + u64::from(direct) }
}

/// One instruction and where it sits, which every jump but `LJMP` needs for its target.
#[derive(Clone, Copy)]
pub struct Insn {
    addr: u64,
    /// The opcode and its operand bytes. Those the instruction lacks are zero.
    bytes: [u8; 3],
}

/// How an instruction names a place in the 16-bit code space.
enum Transfer {
    Call,
    Jump,
    Branch,
}

impl Insn {
    fn opcode(self) -> u8 {
        self.bytes[0]
    }

    /// The 16-bit address after the instruction, which relative and in-page targets count from.
    fn next(self) -> u16 {
        (self.addr as u16).wrapping_add(u16::from(LENGTH[usize::from(self.opcode())]))
    }

    /// A direct jump, call or conditional branch, and the 16-bit address it names.
    fn transfer(self) -> Option<(Transfer, u16)> {
        let [opcode, first, second] = self.bytes;
        let absolute = u16::from_be_bytes([first, second]);
        // `AJMP` and `ACALL` keep the top five bits of the address and carry the other eleven.
        let in_page = self.next() & 0xF800 | u16::from(opcode >> 5) << 8 | u16::from(first);
        let relative = |offset: u8| self.next().wrapping_add_signed(i16::from(offset as i8));
        Some(match opcode {
            0x02 => (Transfer::Jump, absolute),
            0x12 => (Transfer::Call, absolute),
            _ if opcode & 0x1F == 0x01 => (Transfer::Jump, in_page),
            _ if opcode & 0x1F == 0x11 => (Transfer::Call, in_page),
            0x80 => (Transfer::Jump, relative(first)),
            // JC, JNC, JZ, JNZ, and DJNZ on a register.
            0x40 | 0x50 | 0x60 | 0x70 | 0xD8..=0xDF => (Transfer::Branch, relative(first)),
            // JBC, JB, JNB, CJNE, and DJNZ on a direct address: the offset is the third byte.
            0x10 | 0x20 | 0x30 | 0xB4..=0xBF | 0xD5 => (Transfer::Branch, relative(second)),
            _ => return None,
        })
    }

    /// The 16-bit address of the block the jump after the instruction skips: what begins behind
    /// that jump. A call of it stays in the function, since the function goes on beyond the
    /// block. SDCC calls through a pointer this way: the block pushes the pointer and returns
    /// into it.
    fn skipped_block(self, image: &Image) -> Option<u16> {
        let after = self.addr + u64::from(LENGTH[usize::from(self.opcode())]);
        let next = I8051::decode(image.bytes_from(after)?, after).next()?.insn?;
        matches!(next.transfer(), Some((Transfer::Jump, beyond)) if beyond > next.next()).then(|| next.next())
    }

    /// The direct address or the bit the instruction names in its second byte, as the address of
    /// the byte it is in: internal data below 0x80, a special function register from there.
    fn direct(self) -> Option<u64> {
        let [opcode, first, _] = self.bytes;
        let byte = direct_address;
        match opcode {
            // The bits below 0x80 are those of the bytes from 0x20; the others are the bits of
            // every eighth register.
            0x10 | 0x20 | 0x30 | 0x72 | 0x82 | 0x92 | 0xA0 | 0xA2 | 0xB0 | 0xB2 | 0xC2 | 0xD2 => Some(byte(if first < 0x80 { 0x20 + first / 8 } else { first & 0xF8 })),
            0x42 | 0x43 | 0x52 | 0x53 | 0x62 | 0x63 | 0x86..=0x8F | 0xA6..=0xAF | 0xC0 | 0xD0 => Some(byte(first)),
            _ if opcode & 0x0F == 0x05 => Some(byte(first)),
            _ => None,
        }
    }

    /// Whether the instruction may change `DPTR` other than by loading or incrementing it: it
    /// names one of the two registers that are its halves.
    fn touches_dptr(self) -> bool {
        let halves = [SFR + u64::from(DPL), SFR + u64::from(DPH)];
        // `MOV direct, direct` names its destination in the third byte.
        self.direct().is_some_and(|direct| halves.contains(&direct)) || self.opcode() == 0x85 && [DPL, DPH].contains(&self.bytes[2])
    }
}

/// What is known of the registers on a path.
#[derive(Clone, Copy, Default)]
pub struct State {
    dptr: Option<u16>,
    /// A number the index in `A` was just compared with, and whether carry is set or clear when
    /// the index is the smaller: `CJNE A, #n` sets it then, and `ADD A, #256 - n` clears it.
    compared: Option<(u8, bool)>,
    /// A number the index was found to be below, since when it has only been loaded and scaled.
    below: Option<u8>,
    /// How many times `RL A` has doubled the index since it was found to be below that.
    doubled: u8,
    /// A direct address that a number was stored at straight after it was found to be below
    /// a bound, and the bound: one half of an index made of two numbers, which `ORL` puts in
    /// the bits the other half was shifted out of.
    kept: Option<(u8, u8)>,
    /// The address `A + PC` is at, when `A` is an index that a number was just added to.
    indexed: Option<u16>,
    /// Where the bytes start that `A`, `DPL` and `DPH` were each read from by
    /// `MOVC A, @A+PC`, at an index.
    read: Option<u16>,
    low: Option<u16>,
    high: Option<u16>,
    /// `A` was just cleared.
    zero: bool,
    /// The routine called last, if the index was below a number when it was. It may be the one
    /// that scales an index, which the jump checks; nothing else holds after the call.
    scaler: Option<u16>,
}

impl State {
    /// Forgets everything once more than a jump follows a call that might have scaled an index.
    fn settle(&mut self) {
        if self.scaler.is_some() {
            *self = State::default();
        }
    }
}

/// The whole routine that scales an index too large to triple in `A`: `MOV B, #3; MUL AB`,
/// then the high byte of the product added to `DPH`.
const TRIPLE: [u8; 11] = [0x75, 0xF0, 0x03, 0xA4, 0xC5, 0x83, 0x25, 0xF0, 0xC5, 0x83, 0x22];

/// What follows a call to one of the routines of Keil's C51 library that take their return
/// address as the address of data: the data lies after the call in place of code.
#[derive(Clone, Copy)]
enum Inline {
    /// `?C?CCASE` and `?C?ICASE`, which a `switch` calls: a table of each case's address and
    /// its value, of this many bytes, then a zero address and the address of the default
    /// case. The routine jumps to the case and never returns.
    Cases { value: usize },
    /// Four bytes that the routine stores through `DPTR` before it returns past them.
    Constant,
}

/// The whole of `?C?CCASE`: `POP DPH; POP DPL; MOV R0,A`, the search, and `JMP @A+DPTR`.
const CCASE: [u8; 38] = [
    0xD0, 0x83, 0xD0, 0x82, 0xF8, 0xE4, 0x93, 0x70, 0x12, 0x74, 0x01, 0x93, 0x70, 0x0D, 0xA3, 0xA3, 0x93, 0xF8, 0x74, 0x01, 0x93, 0xF5, 0x82,
    0x88, 0x83, 0xE4, 0x73, 0x74, 0x02, 0x93, 0x68, 0x60, 0xEF, 0xA3, 0xA3, 0xA3, 0x80, 0xDF,
];

/// The whole of `?C?ICASE`, which differs in comparing `B` with the value's high byte as well.
const ICASE: [u8; 45] = [
    0xD0, 0x83, 0xD0, 0x82, 0xF8, 0xE4, 0x93, 0x70, 0x12, 0x74, 0x01, 0x93, 0x70, 0x0D, 0xA3, 0xA3, 0x93, 0xF8, 0x74, 0x01, 0x93, 0xF5, 0x82,
    0x88, 0x83, 0xE4, 0x73, 0x74, 0x02, 0x93, 0xB5, 0xF0, 0x06, 0x74, 0x03, 0x93, 0x68, 0x60, 0xE9, 0xA3, 0xA3, 0xA3, 0xA3, 0x80, 0xD8,
];

/// The routine that stores a four-byte constant: it keeps `DPTR` in `B` and `R0`, pops the
/// return address into `DPTR`, calls the helper after it four times, and jumps to where
/// `DPTR` then points. Each `.. ..` is the address of the helper.
const STORE: [Option<u8>; 23] = {
    let (call, any) = (Some(0x12), None);
    [
        Some(0xA8), Some(0x82), Some(0x85), Some(0x83), Some(0xF0), Some(0xD0), Some(0x83), Some(0xD0), Some(0x82),
        call, any, any, call, any, any, call, any, any, call, any, any, Some(0xE4), Some(0x73),
    ]
};

/// The helper: it reads the byte at `DPTR` from the code, swaps `DPTR` with `B` and `R0`, stores
/// the byte there, and swaps back, stepping both addresses on.
const STORE_BYTE: [u8; 26] = [
    0xE4, 0x93, 0xA3, 0xC5, 0x83, 0xC5, 0xF0, 0xC5, 0x83, 0xC8, 0xC5, 0x82, 0xC8, 0xF0, 0xA3, 0xC5, 0x83, 0xC5, 0xF0, 0xC5, 0x83, 0xC8, 0xC5,
    0x82, 0xC8, 0x22,
];

impl Inline {
    /// What follows a call to `target`, if the code there is one of the routines. Only a
    /// routine's exact bytes count, since they are what says how its data is laid out.
    fn after_call_to(image: &Image, target: u64) -> Option<Inline> {
        let code = image.bytes_from(target).filter(|_| image.is_code(target))?;
        if code.starts_with(&CCASE) {
            return Some(Inline::Cases { value: 1 });
        } else if code.starts_with(&ICASE) {
            return Some(Inline::Cases { value: 2 });
        }
        let helper = ((target + STORE.len() as u64) as u16).to_be_bytes();
        let (routine, rest) = code.split_at_checked(STORE.len())?;
        let calls_helper = routine.iter().zip(STORE).enumerate().all(|(at, (&byte, expected))| byte == expected.unwrap_or_else(|| helper[(at - 1) % 3]));
        (calls_helper && rest.starts_with(&STORE_BYTE)).then_some(Inline::Constant)
    }

    /// Bytes in one entry of the data.
    fn entry_size(self) -> usize {
        match self {
            Inline::Cases { value } => 2 + value,
            Inline::Constant => 4,
        }
    }

    /// The 16-bit addresses of the cases the data in `bytes` names, the default last, and the
    /// length of the data. A constant names none.
    fn cases(self, bytes: &[u8]) -> Option<(Vec<u16>, usize)> {
        let size = self.entry_size();
        if let Inline::Constant = self {
            return (bytes.len() >= size).then_some((Vec::new(), size));
        }
        let mut cases = Vec::new();
        for (index, entry) in bytes.chunks(size).enumerate() {
            let case = u16::from_be_bytes([*entry.first()?, *entry.get(1)?]);
            if case == 0 {
                let default = bytes.get(index * size + 2..)?.get(..2)?;
                cases.push(u16::from_be_bytes([default[0], default[1]]));
                return Some((cases, index * size + 4));
            }
            cases.push(case);
        }
        None
    }
}

/// The jump instructions a `switch` over a dense range jumps into with `JMP @A+DPTR`: `count`
/// of one length, back to back, at the start of `bytes`. Returns the length of each.
fn jump_slots(bytes: &[u8], count: usize) -> Option<usize> {
    let is_long = |opcode: u8| opcode == 0x02;
    // `AJMP` and `SJMP`.
    let is_short = |opcode: u8| opcode & 0x1F == 0x01 || opcode == 0x80;
    let size = if is_long(*bytes.first()?) { 3 } else { 2 };
    let slots = bytes.get(..size * count)?;
    // Nothing comes after the last jump, so a table of short jumps may end in a long one.
    let fits = |(index, slot): (usize, &[u8])| if size == 3 { is_long(slot[0]) } else { is_short(slot[0]) || index + 1 == count && is_long(slot[0]) };
    slots.chunks_exact(size).enumerate().all(fits).then_some(size)
}

/// The 8051 and its descendants with the original instruction set.
pub struct I8051;

impl Arch for I8051 {
    type Insn = Insn;
    type State = State;

    // Nothing aligns functions, so an address says nothing about what starts there.
    const FUNCTION_ALIGN: u64 = 1;
    const ALIGNMENT_IS_EVIDENCE: bool = false;
    const RUNS_ON: bool = true;
    const TILES_GAPS: bool = true;
    const TEXT_IN_CODE: bool = true;

    fn decode(bytes: &[u8], addr: u64) -> impl Iterator<Item = Decoded<Insn>> {
        let mut offset = 0;
        std::iter::from_fn(move || {
            let opcode = *bytes.get(offset)?;
            let at = addr + offset as u64;
            // No instruction: the opcode is not one, or its operands run past the end.
            let insn = bytes.get(offset..offset + usize::from(LENGTH[usize::from(opcode)])).filter(|insn| !insn.is_empty()).map(|insn| {
                let mut bytes = [0; 3];
                bytes[..insn.len()].copy_from_slice(insn);
                Insn { addr: at, bytes }
            });
            let len = if insn.is_some() { LENGTH[usize::from(opcode)] } else { 1 };
            offset += usize::from(len);
            Some(Decoded { addr: at, len, insn })
        })
    }

    type Decoder<'a> = (&'a [u8], u64);

    fn decoder(bytes: &[u8], addr: u64) -> Self::Decoder<'_> {
        (bytes, addr)
    }

    fn decode_from<'d>(&mut (bytes, base): &'d mut Self::Decoder<'_>, offset: usize) -> impl Iterator<Item = Decoded<Insn>> + 'd {
        Self::decode(&bytes[offset..], base + offset as u64)
    }

    fn flow(insn: &Insn, _: &State, image: &Image) -> Option<Flow> {
        // Code that runs into a trampoline entry goes where a jump to the entry goes.
        if let Some(&target) = image.banking.trampolines.get(&insn.addr) {
            return Some(Flow::Jump(target));
        }
        // A call through a stub that switches banks calls the function its caller names.
        if let Some(&target) = image.banking.calls.get(&insn.addr) {
            return Some(Flow::Call(target));
        }
        if let Some((transfer, target)) = insn.transfer() {
            let calls_own_block = matches!(transfer, Transfer::Call) && insn.skipped_block(image) == Some(target);
            let target = image.banking.reach(insn.addr, target);
            return Some(match transfer {
                // The function calls a block of its own, which it then jumps over.
                Transfer::Call if calls_own_block => Flow::Branch(target),
                // A call that hands its return address to a library routine comes back
                // elsewhere or not at all: it is an indirect jump, and its data follows it.
                Transfer::Call if Inline::after_call_to(image, target).is_some() => Flow::JumpIndirect(None),
                Transfer::Call => Flow::Call(target),
                Transfer::Jump => Flow::Jump(target),
                Transfer::Branch => Flow::Branch(target),
            });
        }
        match insn.opcode() {
            0x22 | 0x32 => Some(Flow::Return),
            0x73 => Some(Flow::JumpIndirect(None)),
            _ => None,
        }
    }

    /// Nothing: `MOV DPTR, #address` loads the address of data far more often than of code.
    fn address_taken(_: &Insn, _: &State) -> Option<u64> {
        None
    }

    fn memory_reference(insn: &Insn, state: &State) -> Option<u64> {
        match (insn.opcode(), state.dptr.filter(|_| state.scaler.is_none())) {
            // MOVX through DPTR, in either direction.
            (0xE0 | 0xF0, Some(dptr)) => Some(XDATA + u64::from(dptr)),
            _ => insn.direct(),
        }
    }

    /// An address is sixteen bits and a register eight, so code forms an address in one of
    /// two ways: `MOV DPTR, #address`, or two instructions with a half each, one soon after the
    /// other. A pointer that may point to any memory takes a third byte to say which, and that
    /// byte marks the address as one in the code space: 0xFF before the halves in code from
    /// Keil's compiler, 0x80 after them in code from SDCC, which puts it in `B` when the
    /// address is in `DPTR`. So does reading from the address with `MOVC`.
    fn text_pointers(image: &Image, start: u64, end: u64) -> Vec<TextPointer> {
        /// How many instructions may lie between two that load bytes of one pointer: those
        /// that put the first byte where it goes, such as `PUSH ACC` or `MOVX @DPTR, A` and
        /// `INC DPTR`.
        const APART: usize = 3;
        const MARKS: [u8; 2] = [0xFF, 0x80];
        let Some(bytes) = image.bytes_from(start) else { return Vec::new() };
        let banking = &image.banking;
        // Nothing says which bank shows while common code runs, and the text an address
        // outside the common ranges names is in whichever bank has text there.
        let from_common = start >> 16 == 0 && banking.is_common(start as u16);
        let banks: Vec<u64> = if from_common { image.sections.iter().filter(|section| section.executable).map(|section| section.addr >> 16).collect() } else { vec![start >> 16] };
        let mut found = Vec::new();
        let mut point = |from: u64, high: u8, low: u8, marked: bool| {
            let target = u16::from_be_bytes([high, low]);
            let banks = if banking.is_common(target) { &banks[..1] } else { &banks[..] };
            found.extend(banks.iter().map(|&bank| TextPointer { from, to: banking.address(bank, target), marked }));
        };
        // The bytes the last two such instructions loaded, the older first, with the address
        // of the instruction, and how many instructions ago the newer was.
        let (mut older, mut newer, mut since) = (None::<(u64, u8)>, None::<(u64, u8)>, 0);
        let mut dptr = None::<(u64, [u8; 2])>;
        // The number each of `R0` to `R7` was loaded with.
        let mut registers = [None::<u8>; 8];
        for insn in I8051::decode(&bytes[..bytes.len().min((end - start) as usize)], start).filter_map(|decoded| decoded.insn) {
            let [opcode, first, second] = insn.bytes;
            let register = usize::from(opcode & 7);
            // Nothing is known of what another path or a called function leaves.
            if insn.transfer().is_some() || matches!(opcode, 0x22 | 0x32 | 0x73) {
                (older, newer, dptr, registers) = (None, None, None, [None; 8]);
                continue;
            }
            match opcode {
                0x90 => {
                    dptr = Some((insn.addr, [first, second]));
                    point(insn.addr, first, second, false);
                }
                0x93 => {
                    if let Some((from, [high, low])) = dptr {
                        point(from, high, low, true);
                    }
                }
                _ if opcode == 0xA3 || insn.touches_dptr() => dptr = None,
                _ => {}
            }
            // MOV A, #; ADD A, #; ADDC A, #; MOV direct, #; MOV @Ri, #; MOV Rn, #; and MOV A, Rn
            // from a register a number was loaded into.
            let loaded = match opcode {
                0x74 | 0x24 | 0x34 | 0x76..=0x7F => Some(first),
                0x75 => Some(second),
                0xE8..=0xEF => registers[register],
                _ => None,
            };
            match opcode {
                0x78..=0x7F => registers[register] = Some(first),
                // INC, DEC, MOV from a direct address, XCH and MOV from A change the register.
                0x08..=0x0F | 0x18..=0x1F | 0xA8..=0xAF | 0xC8..=0xCF | 0xF8..=0xFF => registers[register] = None,
                // So does what writes to its address in the first register bank: INC, DEC, ORL,
                // ANL, XRL, MOV, XCH and POP, and MOV between two addresses.
                0x05 | 0x15 | 0x42 | 0x43 | 0x52 | 0x53 | 0x62 | 0x63 | 0x75 | 0x86..=0x8F | 0xC5 | 0xD0 | 0xF5 if first < 8 => registers[usize::from(first)] = None,
                0x85 if second < 8 => registers[usize::from(second)] = None,
                _ => {}
            }
            let Some(byte) = loaded else {
                since += 1;
                continue;
            };
            if since > APART {
                (older, newer) = (None, None);
            }
            // Unmarked, either half may be the high one: compilers differ, and so does the
            // order in which code adds a number to an address.
            if let Some((_, half)) = newer {
                point(insn.addr, half, byte, older.is_some_and(|(_, mark)| mark == MARKS[0]));
                point(insn.addr, byte, half, false);
            }
            if let (Some((_, low)), Some((from, high)), true) = (older, newer, byte == MARKS[1]) {
                point(from, high, low, true);
            }
            // MOV B, #0x80.
            if let (Some((from, [high, low])), [0x75, 0xF0, 0x80]) = (dptr, insn.bytes) {
                point(from, high, low, true);
            }
            (older, newer, since) = (newer, Some((insn.addr, byte)), 0);
        }
        found
    }

    fn is_padding(_: &Insn) -> bool {
        false
    }

    fn is_entry_marker(_: &Insn) -> bool {
        false
    }

    fn opens_landing_pad(_: &Insn) -> bool {
        false
    }

    fn step(state: &mut State, insn: &Insn) {
        let [opcode, first, second] = insn.bytes;
        state.settle();
        state.compared = None;
        let called = insn.transfer().and_then(|(transfer, routine)| matches!(transfer, Transfer::Call).then_some(routine));
        // ORL A, direct, when the index has been shifted left past the bits of the number
        // kept there: the two are one index, below the product of their bounds.
        let joined = match (opcode, state.kept, state.below) {
            (0x45, Some((kept, low)), Some(high)) if kept == first && 1 << state.doubled == u32::from(low) => high.checked_mul(low),
            _ => None,
        };
        state.kept = match (opcode, state.below) {
            // MOV direct, A.
            (0xF5, Some(bound)) => Some((first, bound)),
            // It stays there until a call, or an instruction that names the address or
            // changes the `DPTR` it is a half of.
            _ => state.kept.filter(|&(kept, _)| called.is_none() && insn.direct() != Some(direct_address(kept)) && !(matches!(opcode, 0x90 | 0xA3) && [DPL, DPH].contains(&kept))),
        };
        state.doubled = if opcode == 0x23 && joined.is_none() { state.doubled.saturating_add(1) } else { state.doubled };
        if let (Some(routine), Some(_)) = (called, state.below) {
            state.scaler = Some(routine);
            return;
        }
        // What loads or scales an index and what loads the table's address leave the index
        // below what it was below: MOV DPTR, #; MOV Rn, A; ADD A, Rn; RL A; for an index too
        // large to triple in A, MOV B, #3; MUL AB; XCH A, DPH; ADD A, B; and for an index kept
        // elsewhere while it was checked, MOV A and ADD A from a register, a direct address or
        // through R0 or R1, and ADD A, # on the way to its address.
        let scales = matches!(opcode, 0x90 | 0xF8..=0xFF | 0x24..=0x2F | 0x23 | 0xA4 | 0xE5..=0xEF) || matches!((opcode, first), (0x75, 0xF0) | (0xC5, DPH));
        state.below = joined.or(state.below.filter(|_| scales));
        if joined.is_some() {
            state.doubled = 0;
        }
        // ADD A, #n carries unless A is below 256 - n.
        state.compared = (opcode == 0x24 && first != 0).then(|| (first.wrapping_neg(), false));
        // A case's address read in halves: ADD A, #offset; MOVC A, @A+PC; MOV DPL, A, and the
        // same for DPH. The bytes read start `offset` after the MOVC.
        let read = if opcode == 0x83 { state.indexed } else { None };
        state.indexed = (opcode == 0x24).then(|| insn.next().wrapping_add(1).wrapping_add(u16::from(first)));
        match (opcode, first) {
            (0xF5, DPL) => state.low = state.read,
            (0xF5, DPH) => state.high = state.read,
            _ if called.is_some() || insn.touches_dptr() => (state.low, state.high) = (None, None),
            _ => {}
        }
        state.read = read;
        state.zero = opcode == 0xE4;
        state.dptr = match opcode {
            0x90 => Some(u16::from_be_bytes([first, second])),
            0xA3 => state.dptr.map(|dptr| dptr.wrapping_add(1)),
            // Scaling adds to DPH, and the table is still where DPTR was loaded to point.
            0xC5 if state.below.is_some() => state.dptr,
            // A called function leaves anything in it.
            _ if called.is_some() || insn.touches_dptr() => None,
            _ => state.dptr,
        };
    }

    fn branch(state: &mut State, insn: &Insn) -> State {
        state.settle();
        let compared = state.compared.take();
        state.below = None;
        state.doubled = 0;
        let mut taken = *state;
        (state.indexed, state.read, state.zero) = (None, None, false);
        (taken.indexed, taken.read, taken.zero) = (None, None, false);
        match (insn.opcode(), compared) {
            // CJNE A, #n: carry says whether A is below n, on both ways out.
            (0xB4, _) => (state.compared, taken.compared) = (Some((insn.bytes[1], true)), Some((insn.bytes[1], true))),
            // JC is taken, and JNC is not, when carry is set.
            (0x40, Some((bound, true))) | (0x50, Some((bound, false))) => taken.below = Some(bound),
            (0x40, Some((bound, false))) | (0x50, Some((bound, true))) => state.below = Some(bound),
            _ => {}
        }
        taken
    }

    /// The routines jump through `DPTR`, and a `switch` has scaled its index in `A`.
    fn after_jump(_: State, _: &Insn) -> State {
        State::default()
    }

    fn resolve_table(
        state: &State,
        image: &Image,
        _: &FxHashMap<u64, u64>,
        jump: &Insn,
        _: &dyn Fn(u64) -> bool,
        is_code: &dyn Fn(u64) -> bool,
    ) -> Option<Table> {
        // Cases are in the function that switches, so in its bank, and never behind a trampoline.
        let here = |target: u16| image.banking.address(jump.addr >> 16, target);
        let table = if let (0x73, Some(low), Some(high), true) = (jump.opcode(), state.low, state.high, state.zero) {
            // `JMP @A+DPTR` with A clear and DPTR read from two runs of bytes after the jump: the
            // low halves of the cases' addresses, and straight after them as many high halves.
            let count = usize::from(high.checked_sub(low).filter(|_| u64::from(low) == (jump.addr + 1) & 0xFFFF)?);
            let bytes = image.bytes_from(jump.addr + 1)?.get(..2 * count)?;
            let entries = (0..count).map(|index| here(u16::from_be_bytes([bytes[count + index], bytes[index]]))).collect();
            Table { address: jump.addr + 1, entry_size: 2, entries, bounded: true, inline_end: Some(jump.addr + 1 + 2 * count as u64) }
        } else if jump.opcode() == 0x73 {
            // `JMP @A+DPTR` into a table of jumps, one per value below the bound.
            let (address, count) = (here(state.dptr?), u64::from(state.below.filter(|&count| count > 0)?));
            if let Some(routine) = state.scaler {
                image.bytes_from(image.banking.reach(jump.addr, routine)).filter(|code| code.starts_with(&TRIPLE))?;
            }
            let size = jump_slots(image.bytes_from(address)?, count as usize)? as u64;
            Table { address, entry_size: size, entries: (0..count).map(|index| address + index * size).collect(), bounded: true, inline_end: None }
        } else {
            let (Transfer::Call, routine) = jump.transfer()? else { return None };
            let kind = Inline::after_call_to(image, image.banking.reach(jump.addr, routine))?;
            let address = jump.addr + u64::from(LENGTH[usize::from(jump.opcode())]);
            let (cases, length) = kind.cases(image.bytes_from(address)?)?;
            let end = address + length as u64;
            // The routine that takes a constant returns to the code after it.
            let entries = if cases.is_empty() { vec![end] } else { cases.into_iter().map(here).collect() };
            Table { address, entry_size: kind.entry_size() as u64, entries, bounded: true, inline_end: Some(end) }
        };
        table.entries.iter().all(|&target| is_code(target)).then_some(table)
    }

    fn plt_stubs(_: &Image) -> FxHashMap<u64, u64> {
        FxHashMap::default()
    }
}

/// The direct jumps and calls in the functions of `analysis` that go from common code to an
/// address outside it, as `(instruction, target)`. Nothing says which bank shows when one runs,
/// and each is taken to reach bank 0, so these are the places where that guess is made.
pub fn unbanked_transfers(image: &Image, analysis: &Analysis) -> Vec<(u64, u64)> {
    let banking = &image.banking;
    let is_common = |addr: u64| addr >> 16 == 0 && banking.is_common(addr as u16);
    let mut found = Vec::new();
    for &(start, end) in analysis.functions.iter().flat_map(|function| &function.ranges) {
        let Some(bytes) = image.bytes_from(start).filter(|_| is_common(start)) else { continue };
        for insn in I8051::decode(&bytes[..bytes.len().min((end - start) as usize)], start).filter_map(|decoded| decoded.insn) {
            if let Some((_, target)) = insn.transfer().filter(|&(_, target)| is_common(insn.addr) && !banking.is_common(target)) {
                found.push((insn.addr, u64::from(target)));
            }
        }
    }
    found.sort_unstable();
    found.dedup();
    found
}

/// One line for a summary on how the banks of an image are tied together, or `None` for an
/// image that is not banked 8051 code.
pub fn banking_summary(image: &Image, analysis: &Analysis) -> Option<String> {
    let banked = image.machine == Machine::I8051 && !image.banking.common.is_empty();
    banked.then(|| {
        let unbanked = unbanked_transfers(image, analysis).len();
        format!("{} trampolines, {unbanked} jumps and calls from common code to a bank it does not name (taken as bank 0)", image.banking.trampolines.len() + image.banking.calls.len())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image::{Banking, Format, Section};

    /// An image that is not banked, with `code` at `addr`.
    fn image(code: &[u8], addr: u64) -> Image {
        Image {
            name: String::new(),
            format: Format::Raw,
            machine: Machine::I8051,
            base: 0,
            branch_targets_marked: false,
            entry: addr,
            sections: vec![Section { name: String::new(), addr, data: code.to_vec(), file_offset: None, executable: true, writable: false }],
            zero_filled: memory(),
            import_slots: FxHashMap::default(),
            exports: Vec::new(),
            symbol_names: FxHashMap::default(),
            frames: Vec::new(),
            relative_targets: Vec::new(),
            data_in_code: true,
            banking: Banking::default(),
        }
    }

    /// The length and the control flow of the instruction `bytes` holds at `addr`.
    fn decoded(bytes: &[u8], addr: u64) -> (u8, Option<Flow>) {
        let first = I8051::decode(bytes, addr).next().unwrap();
        (first.len, I8051::flow(&first.insn.unwrap(), &State::default(), &image(bytes, addr)))
    }

    #[test]
    fn every_kind_of_jump_goes_where_its_bytes_say() {
        use Flow::*;
        let cases: &[(&[u8], u64, (u8, Option<Flow>))] = &[
            // LJMP 0x1234; LCALL 0x1234
            (&[0x02, 0x12, 0x34], 0x0100, (3, Some(Jump(0x1234)))),
            (&[0x12, 0x12, 0x34], 0x0100, (3, Some(Call(0x1234)))),
            // AJMP and ACALL: eleven bits within the 2 KB page of the next instruction, which
            // for the jump at 0x17FE is the page after its own.
            (&[0xE1, 0x34], 0x17FE, (2, Some(Jump(0x1F34)))),
            (&[0x01, 0xFF], 0x2000, (2, Some(Jump(0x20FF)))),
            (&[0x11, 0x34], 0x0100, (2, Some(Call(0x0034)))),
            (&[0xF1, 0x00], 0x2000, (2, Some(Call(0x2700)))),
            // SJMP to itself, and forward by the most it can.
            (&[0x80, 0xFE], 0x0100, (2, Some(Jump(0x0100)))),
            (&[0x80, 0x7F], 0x0100, (2, Some(Jump(0x0181)))),
            // JC +0x10; JNC -0x80; JZ -0x11; JNZ +0
            (&[0x40, 0x10], 0x0100, (2, Some(Branch(0x0112)))),
            (&[0x50, 0x80], 0x0100, (2, Some(Branch(0x0082)))),
            (&[0x60, 0xEF], 0x0200, (2, Some(Branch(0x01F1)))),
            (&[0x70, 0x00], 0x0200, (2, Some(Branch(0x0202)))),
            // JBC 0x2E, +5; JB 0x2E, +5; JNB ACC.0, -3
            (&[0x10, 0x2E, 0x05], 0x0100, (3, Some(Branch(0x0108)))),
            (&[0x20, 0x2E, 0x05], 0x0100, (3, Some(Branch(0x0108)))),
            (&[0x30, 0xE0, 0xFD], 0x0100, (3, Some(Branch(0x0100)))),
            // CJNE A, #5, +3; CJNE A, 0x30, +3; CJNE @R0, #5, -3; CJNE R7, #5, +0x10
            (&[0xB4, 0x05, 0x03], 0x0100, (3, Some(Branch(0x0106)))),
            (&[0xB5, 0x30, 0x03], 0x0100, (3, Some(Branch(0x0106)))),
            (&[0xB6, 0x05, 0xFD], 0x0100, (3, Some(Branch(0x0100)))),
            (&[0xBF, 0x05, 0x10], 0x0100, (3, Some(Branch(0x0113)))),
            // DJNZ 0x30, -3; DJNZ R0, -2; DJNZ R7, -2
            (&[0xD5, 0x30, 0xFD], 0x0100, (3, Some(Branch(0x0100)))),
            (&[0xD8, 0xFE], 0x0100, (2, Some(Branch(0x0100)))),
            (&[0xDF, 0xFE], 0x0100, (2, Some(Branch(0x0100)))),
            // RET; RETI; JMP @A+DPTR
            (&[0x22], 0x0100, (1, Some(Return))),
            (&[0x32], 0x0100, (1, Some(Return))),
            (&[0x73], 0x0100, (1, Some(JumpIndirect(None)))),
            // What only falls through, of each length: NOP; MOVC A, @A+DPTR; MOV A, #0x73;
            // MOV DPTR, #0x0222; MOV 0x81, #0x50; MOV 0x22, 0x02
            (&[0x00], 0x0100, (1, None)),
            (&[0x93], 0x0100, (1, None)),
            (&[0x74, 0x73], 0x0100, (2, None)),
            (&[0x90, 0x02, 0x22], 0x0100, (3, None)),
            (&[0x75, 0x81, 0x50], 0x0100, (3, None)),
            (&[0x85, 0x02, 0x22], 0x0100, (3, None)),
        ];
        for &(bytes, addr, expected) in cases {
            assert_eq!(decoded(bytes, addr), expected, "{bytes:02x?} at {addr:#x}");
        }
    }

    #[test]
    fn what_is_not_an_instruction_is_one_byte_of_nothing() {
        // The opcode that is none; LJMP cut short by the end of the code.
        let lengths = |bytes: &[u8]| I8051::decode(bytes, 0).map(|decoded| (decoded.len, decoded.insn.is_some())).collect::<Vec<_>>();
        assert_eq!(lengths(&[0xA5, 0x22]), [(1, false), (1, true)]);
        assert_eq!(lengths(&[0x22, 0x02, 0x12]), [(1, true), (1, false), (1, false)]);
    }

    #[test]
    fn data_is_referred_to_in_its_own_address_space() {
        // MOV DPTR, #0x1234; INC DPTR; MOVX A, @DPTR; MOV 0x30, A; MOV 0x90, A; SETB 0x0A;
        // CLR 0x93; MOV DPL, A; MOVX @DPTR, A
        let code = [0x90, 0x12, 0x34, 0xA3, 0xE0, 0xF5, 0x30, 0xF5, 0x90, 0xD2, 0x0A, 0xC2, 0x93, 0xF5, 0x82, 0xF0];
        let mut state = State::default();
        let mut referred = Vec::new();
        for insn in I8051::decode(&code, 0).filter_map(|decoded| decoded.insn) {
            referred.push(I8051::memory_reference(&insn, &state));
            I8051::step(&mut state, &insn);
        }
        let expected = [None, None, Some(XDATA + 0x1235), Some(IDATA + 0x30), Some(SFR + 0x90), Some(IDATA + 0x21), Some(SFR + 0x90), Some(SFR + 0x82), None];
        assert_eq!(referred, expected);
    }

    #[test]
    fn text_among_the_code_is_a_string_of_the_code_that_forms_its_address() {
        const CALLEE: u8 = 0x2C;
        let mut code = vec![
            // MOV R3, #0xFF; MOV R2, #0x00; MOV R1, #0x2D; LCALL: a pointer as Keil passes it.
            0x7B, 0xFF, 0x7A, 0x00, 0x79, 0x2D, 0x12, 0x00, CALLEE,
            // MOV A, #0x30; PUSH ACC; MOV A, #0x00; PUSH ACC; MOV A, #0x80; PUSH ACC; LCALL: one
            // as SDCC pushes it.
            0x74, 0x30, 0xC0, 0xE0, 0x74, 0x00, 0xC0, 0xE0, 0x74, 0x80, 0xC0, 0xE0, 0x12, 0x00, CALLEE,
            // MOV DPTR, #0x0033; CLR A; MOVC A, @A+DPTR; LCALL.
            0x90, 0x00, 0x33, 0xE4, 0x93, 0x12, 0x00, CALLEE,
            // MOV R6, #0x35; MOV R7, #0x00; LCALL: two numbers that make an address inside text.
            0x7E, 0x35, 0x7F, 0x00, 0x12, 0x00, CALLEE,
            // MOV R6, #0x44; MOV R7, #0x00; RET: two that make the address text begins at.
            0x7E, 0x44, 0x7F, 0x00, 0x22,
            // The function called.
            0x22,
        ];
        code.extend(b"ab\0%d\00123456789ABCDEF\0left over\0nobody\0");
        let analysis = crate::analyze(&image(&code, 0));
        let strings: Vec<(u64, &str)> = analysis.strings.iter().map(|string| (string.addr, string.text.as_str())).collect();
        assert_eq!(strings, [(0x2D, "ab"), (0x30, "%d"), (0x33, "0123456789ABCDEF"), (0x44, "left over"), (0x4E, "nobody")]);
        let users: Vec<(u64, u64)> = analysis.data_refs.iter().filter(|reference| image(&code, 0).is_code(reference.to)).map(|reference| (reference.from, reference.to)).collect();
        assert_eq!(users, [(0x04, 0x2D), (0x0D, 0x30), (0x18, 0x33), (0x29, 0x44)]);
    }

    #[test]
    fn a_call_to_a_switch_routine_is_a_jump_through_the_table_after_it() {
        // 0x0000: LCALL 0x0100, then the table: 0x000D for 1, 0x0010 for 2, default 0x0011.
        // 0x000D: LCALL 0x0020; RET; RET. 0x0020: RET.
        let mut code = vec![0x12, 0x01, 0x00, 0x00, 0x0D, 0x01, 0x00, 0x10, 0x02, 0x00, 0x00, 0x00, 0x11];
        code.extend([0x12, 0x00, 0x20, 0x22, 0x22]);
        code.resize(0x20, 0x00);
        code.push(0x22);
        // The opcode that is no instruction keeps the routine apart from the code.
        code.resize(0x100, 0xA5);
        code.extend(CCASE);
        let image = image(&code, 0);
        let analysis = crate::analyze(&image);
        let tables: Vec<(u64, &[u64])> = analysis.jump_tables.iter().map(|table| (table.jump, table.targets.as_slice())).collect();
        assert_eq!(tables, [(0x0000, &[0x000D, 0x0010, 0x0011][..])]);
        // The switch calls no routine, and the table is no part of the function's code.
        let functions: Vec<(u64, &[(u64, u64)])> = analysis.functions.iter().map(|function| (function.addr, function.ranges.as_slice())).collect();
        assert_eq!(functions, [(0x0000, &[(0x0000, 0x0003), (0x000D, 0x0012)][..]), (0x0020, &[(0x0020, 0x0021)][..])]);
        assert_eq!(analysis.calls.iter().map(|call| call.at).collect::<Vec<_>>(), [0x000D]);
    }

    #[test]
    fn a_call_that_stores_a_constant_returns_past_it() {
        // 0x0000: LCALL 0x0100; the constant, whose bytes would be ACALL 0x0122 and more; RET.
        let mut code = vec![0x12, 0x01, 0x00, 0x11, 0x22, 0x33, 0x44, 0x22];
        code.resize(0x100, 0xA5);
        code.extend(STORE.iter().enumerate().map(|(at, byte)| byte.unwrap_or_else(|| [0x01, 0x17][(at - 1) % 3])));
        code.extend(STORE_BYTE);
        let analysis = crate::analyze(&image(&code, 0));
        let functions: Vec<(u64, &[(u64, u64)])> = analysis.functions.iter().map(|function| (function.addr, function.ranges.as_slice())).collect();
        assert_eq!(functions, [(0x0000, &[(0x0000, 0x0003), (0x0007, 0x0008)][..])]);
        assert!(analysis.calls.is_empty());
    }

    #[test]
    fn a_call_of_the_block_the_next_jump_skips_stays_in_the_function() {
        // LCALL 0x0005; SJMP 0x000A; at 0x0005, PUSH DPL; PUSH DPH; RET; at 0x000A, RET. Then a
        // function that calls the one after it, with no jump between: LCALL 0x000F; RET; RET.
        let code = [0x12, 0x00, 0x05, 0x80, 0x05, 0xC0, 0x82, 0xC0, 0x83, 0x22, 0x22, 0x12, 0x00, 0x0F, 0x22, 0x22];
        let mut image = image(&code, 0);
        image.exports = vec![0x000B];
        let analysis = crate::analyze(&image);
        let functions: Vec<(u64, &[(u64, u64)])> = analysis.functions.iter().map(|function| (function.addr, function.ranges.as_slice())).collect();
        assert_eq!(functions, [(0x0000, &[(0x0000, 0x000B)][..]), (0x000B, &[(0x000B, 0x000F)][..]), (0x000F, &[(0x000F, 0x0010)][..])]);
    }

    #[test]
    fn a_function_that_ends_where_the_next_begins_runs_on_into_it() {
        // LCALL 0x0007; LCALL 0x0008; RET. At 0x0007, CLR A, which nothing ends, and at
        // 0x0008 the function it shares the ending of: MOV R7, A; RET.
        let code = [0x12, 0x00, 0x07, 0x12, 0x00, 0x08, 0x22, 0xE4, 0xFF, 0x22];
        let analysis = crate::analyze(&image(&code, 0));
        let runs_on: Vec<(u64, Option<u64>)> = analysis.functions.iter().map(|function| (function.addr, function.runs_on)).collect();
        assert_eq!(runs_on, [(0x0000, None), (0x0007, Some(0x0008)), (0x0008, None)]);
    }

    #[test]
    fn unreached_code_that_divides_into_functions_is_functions() {
        let starts = |code: &[u8]| crate::analyze(&image(code, 0)).functions.iter().map(|function| function.addr).collect::<Vec<_>>();
        // LCALL 0x0010; RET. Then what nothing refers to: CLR A; MOV R7, A; RET, then
        // MOV A, #1; LCALL 0x0010; RET, then CLR A; MOV R7, A; RET. At 0x0010, RET.
        let code = [0x12, 0x00, 0x10, 0x22, 0xE4, 0xFF, 0x22, 0x74, 0x01, 0x12, 0x00, 0x10, 0x22, 0xE4, 0xFF, 0x22, 0x22];
        assert_eq!(starts(&code), [0x0000, 0x0004, 0x0007, 0x000D, 0x0010]);
        // The same with a call of no function in the middle, and with bytes left over at the end.
        let code = [0x12, 0x00, 0x10, 0x22, 0xE4, 0xFF, 0x22, 0x74, 0x01, 0x12, 0x00, 0x0E, 0x22, 0xE4, 0xFF, 0x22, 0x22];
        assert_eq!(starts(&code), [0x0000, 0x0010]);
        let code = [0x12, 0x00, 0x10, 0x22, 0xE4, 0xFF, 0x22, 0x74, 0x01, 0x12, 0x00, 0x10, 0x22, 0xE4, 0xFF, 0xFF, 0x22];
        assert_eq!(starts(&code), [0x0000, 0x0010]);
        // LCALL 0x000F; RET. Then MOV A, R7; JNZ 0x000A; LJMP 0x000F; CLR C; RET, whose last two
        // instructions are where its branch goes, then CLR A; MOV R7, A; RET. At 0x000F, RET.
        let code = [0x12, 0x00, 0x0F, 0x22, 0xEF, 0x70, 0x03, 0x02, 0x00, 0x0F, 0xC3, 0x22, 0xE4, 0xFF, 0x22, 0x22];
        assert_eq!(starts(&code), [0x0000, 0x0004, 0x000C, 0x000F]);
        // A return that nothing jumps to, after CLR A; MOV R7, A; RET, is left over.
        let code = [0x12, 0x00, 0x08, 0x22, 0xE4, 0xFF, 0x22, 0x22, 0x22];
        assert_eq!(starts(&code), [0x0000, 0x0008]);
    }

    #[test]
    fn a_switch_whose_index_is_checked_by_adding_jumps_into_short_jumps() {
        // MOV A, R7; ADD A, #0xFD; JC 0x0011; MOV A, R7; ADD A, R7; MOV DPTR, #0x000B;
        // JMP @A+DPTR. At 0x000B: SJMP 0x0011; SJMP 0x0012; SJMP 0x0013. Then three RETs.
        let code = [0xEF, 0x24, 0xFD, 0x40, 0x0C, 0xEF, 0x2F, 0x90, 0x00, 0x0B, 0x73, 0x80, 0x04, 0x80, 0x03, 0x80, 0x02, 0x22, 0x22, 0x22];
        let analysis = crate::analyze(&image(&code, 0));
        let tables: Vec<(u64, &[u64])> = analysis.jump_tables.iter().map(|table| (table.jump, table.targets.as_slice())).collect();
        assert_eq!(tables, [(0x000A, &[0x000B, 0x000D, 0x000F][..])]);
    }

    #[test]
    fn a_switch_on_two_numbers_jumps_into_a_jump_for_each_pair() {
        // MOV A, R5; CJNE A, #4, next; JNC 0x0038; MOV DPL, A; MOV A, R3; CJNE A, #4, next;
        // JNC 0x0038; RL A; RL A; ORL A, DPL; RL A; MOV DPTR, #0x0017; JMP @A+DPTR. At 0x0017,
        // fifteen SJMP 0x0038 and one LJMP 0x0038, where a RET is.
        let mut code = vec![0xED, 0xB4, 0x04, 0x00, 0x50, 0x32, 0xF5, 0x82, 0xEB, 0xB4, 0x04, 0x00, 0x50, 0x2A, 0x23, 0x23, 0x45, 0x82, 0x23, 0x90, 0x00, 0x17, 0x73];
        code.extend((0..15).flat_map(|slot| [0x80, 0x38 - (0x17 + 2 * slot + 2)]));
        code.extend([0x02, 0x00, 0x38, 0x22]);
        let analysis = crate::analyze(&image(&code, 0));
        let tables: Vec<(u64, Vec<u64>)> = analysis.jump_tables.iter().map(|table| (table.jump, table.targets.clone())).collect();
        assert_eq!(tables, [(0x0016, (0..16).map(|slot| 0x0017 + 2 * slot).collect())]);
    }

    #[test]
    fn a_switch_reads_the_halves_of_a_case_address_from_the_bytes_after_its_jump() {
        // MOV A, R7; ADD A, #0x0A; MOVC A, @A+PC; MOV DPL, A; MOV A, R7; ADD A, #0x06;
        // MOVC A, @A+PC; MOV DPH, A; CLR A; JMP @A+DPTR. At 0x000E the low halves of 0x0012 and
        // 0x0013, which would be a call, and at 0x0010 the high halves. Then two RETs.
        let code = [0xEF, 0x24, 0x0A, 0x83, 0xF5, 0x82, 0xEF, 0x24, 0x06, 0x83, 0xF5, 0x83, 0xE4, 0x73, 0x12, 0x13, 0x00, 0x00, 0x22, 0x22];
        let analysis = crate::analyze(&image(&code, 0));
        let tables: Vec<(u64, &[u64])> = analysis.jump_tables.iter().map(|table| (table.jump, table.targets.as_slice())).collect();
        assert_eq!(tables, [(0x000D, &[0x0012, 0x0013][..])]);
        let functions: Vec<(u64, &[(u64, u64)])> = analysis.functions.iter().map(|function| (function.addr, function.ranges.as_slice())).collect();
        assert_eq!(functions, [(0x0000, &[(0x0000, 0x000E), (0x0012, 0x0014)][..])]);
    }

    #[test]
    fn a_dense_switch_jumps_into_as_many_jumps_as_its_bound_allows() {
        // MOV A, R7; CJNE A, #2, next; JNC 0x0013; MOV DPTR, #0x000D; MOV R0, A; ADD A, R0;
        // ADD A, R0; JMP @A+DPTR. At 0x000D: LJMP 0x0016; LJMP 0x0017. At 0x0013, the default
        // case, which is one more jump: LJMP 0x0018. Then three RETs.
        let code = [
            0xEF, 0xB4, 0x02, 0x00, 0x50, 0x0D, 0x90, 0x00, 0x0D, 0xF8, 0x28, 0x28, 0x73, 0x02, 0x00, 0x16, 0x02, 0x00, 0x17, 0x02, 0x00, 0x18,
            0x22, 0x22, 0x22,
        ];
        let analysis = crate::analyze(&image(&code, 0));
        let tables: Vec<(u64, &[u64])> = analysis.jump_tables.iter().map(|table| (table.jump, table.targets.as_slice())).collect();
        assert_eq!(tables, [(0x000C, &[0x000D, 0x0010][..])]);

        // The same with the index scaled by a call: to the routine that triples it, at 0x0040,
        // and to one that does something else, at 0x0030.
        let scaled_by = |routine: u8| {
            let mut code = vec![0xEF, 0xB4, 0x02, 0x00, 0x50, 0x0D, 0x90, 0x00, 0x0D, 0x12, 0x00, routine, 0x73, 0x02, 0x00, 0x16, 0x02, 0x00, 0x17, 0x02, 0x00, 0x18];
            code.extend([0x22, 0x22, 0x22]);
            code.resize(0x30, 0x00);
            code.extend([0x23, 0x22]);
            code.resize(0x40, 0x00);
            code.extend(TRIPLE);
            crate::analyze(&image(&code, 0)).jump_tables.iter().map(|table| (table.jump, table.targets.clone())).collect::<Vec<_>>()
        };
        assert_eq!(scaled_by(0x40), [(0x000C, vec![0x000D, 0x0010])]);
        assert_eq!(scaled_by(0x30), []);
    }
}
