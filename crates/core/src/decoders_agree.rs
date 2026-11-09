//! Every instruction word decoded twice, by recore and by yaxpeax-arm, which shares no code with
//! it: wherever either finds a direct branch or call, an address formed from the PC, or a load
//! from a label, both find it, with the same target. The checks run every word of the 2^32, so a
//! pass is a proof for what they compare:
//!
//! - Thumb: `decode_at`, `Insn::direct`, `Insn::adr` and `Insn::literal_range`, at a word and a
//!   halfword address, with and without A32 code beside it.
//! - A32: `decode_a32`, `A32::direct` and `A32::literal_range`.
//! - AArch64: `Insn::direct`, `conditional`, `pc_relative` and `load_literal`, at a page's first
//!   and last word.
//!
//! Not compared: `VLDR`, which yaxpeax-arm does not decode; A32 `ADR`, whose direction it drops;
//! registers; and what depends on the state, as the condition an `IT` block gives.
//!
//! Where the two disagree, a failure prints how many words disagree in each way, with an example
//! of each. yaxpeax-arm has bugs too, and decodes some encodings the manual makes UNPREDICTABLE,
//! which recore reads as no instruction; the reference functions below work around both, each
//! where it applies. The ARM manual's pseudocode for the encoding decides which side is right.
//!
//! Unoptimized they are slow, so `cargo test` skips them. CI runs them with the `ci` profile,
//! about 20 seconds on 16 cores, as `mise run decoders-agree` does.

use std::cell::Cell;
use std::collections::BTreeMap;
use std::panic::UnwindSafe;
use std::sync::Once;

use rayon::prelude::*;
use yaxpeax_arch::{Decoder, U8Reader};
use yaxpeax_arm::armv7::{self, ConditionCode};
use yaxpeax_arm::armv8::a64;

use crate::arm::{self, Insn as ArmInsn};
use crate::arm64;
use crate::thumb::{self, Transfer};

/// What a word does with the PC, as both decoders are asked it.
#[derive(Clone, Copy, PartialEq, Debug)]
enum Use {
    Call(u64),
    /// Leaves the code here, whatever the flags hold.
    Jump(u64),
    /// Goes on after it when its condition fails.
    Branch(u64),
    /// `adr`: the address formed.
    Address(u64),
    /// `adrp`: the page formed.
    Page(u64),
    /// A load from a label: the bytes it reads, `[start, end)`.
    Data(u64, u64),
}

fn from_transfer((target, transfer): (u64, Transfer)) -> Use {
    match transfer {
        Transfer::Call => Use::Call(target),
        Transfer::Jump => Use::Jump(target),
        Transfer::Branch => Use::Branch(target),
    }
}

/// What each side found in a disagreement `check` describes, without the numbers.
fn kind(line: &str) -> String {
    let found = line.split(": ").nth(1).unwrap_or("");
    found.split(|c: char| !c.is_ascii_alphanumeric()).filter(|part| !part.chars().all(|c| c.is_ascii_hexdigit())).collect::<Vec<_>>().join(" ")
}

/// Runs `check` on every 32-bit word, and fails when it describes a disagreement for any, with
/// a count and an example of each kind. Only the counts are kept, since a broken decoder can
/// disagree on most of the words.
fn every(check: impl Fn(u32) -> Option<String> + Sync + Send) {
    type Kinds = BTreeMap<String, (usize, String)>;
    let add = |mut kinds: Kinds, line: String| {
        kinds.entry(kind(&line)).or_insert((0, line)).0 += 1;
        kinds
    };
    let merge = |mut kinds: Kinds, other: Kinds| {
        for (kind, (count, example)) in other {
            kinds.entry(kind).or_insert((0, example)).0 += count;
        }
        kinds
    };
    let kinds = (0..=u32::MAX).into_par_iter().filter_map(check).fold(Kinds::new, add).reduce(Kinds::new, merge);
    let report: Vec<String> = kinds.iter().map(|(kind, (count, example))| format!("{count:>10}  {kind:<40} e.g. {example}")).collect();
    assert!(kinds.is_empty(), "{} words disagree:\n{}", kinds.values().map(|(count, _)| count).sum::<usize>(), report.join("\n"));
}

const AT: u64 = 0x0040_0000;

thread_local! {
    static QUIET: Cell<bool> = const { Cell::new(false) };
}

/// `decode`, with a panic as `None` and unreported. Other threads' panics are still reported.
fn quietly<T>(decode: impl FnOnce() -> Option<T> + UnwindSafe) -> Option<T> {
    static HOOK: Once = Once::new();
    HOOK.call_once(|| {
        let report = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if !QUIET.get() {
                report(info);
            }
        }));
    });
    QUIET.set(true);
    let decoded = std::panic::catch_unwind(decode);
    QUIET.set(false);
    decoded.ok().flatten()
}

/// The bytes a load of `opcode` reads.
fn width(opcode: armv7::Opcode) -> Option<u64> {
    Some(match opcode {
        armv7::Opcode::LDRB | armv7::Opcode::LDRSB => 1,
        armv7::Opcode::LDRH | armv7::Opcode::LDRSH => 2,
        armv7::Opcode::LDR => 4,
        armv7::Opcode::LDRD => 8,
        _ => return None,
    })
}

/// `[start, end)` of what a load at `[PC, #offset]` reads, with the PC at `pc`.
fn literal(insn: &armv7::Instruction, pc: u64) -> Option<Use> {
    let size = width(insn.opcode)?;
    insn.operands.iter().find_map(|operand| match *operand {
        armv7::Operand::RegDerefPreindexOffset(base, offset, up, false) if base.number() == 15 => {
            let start = if up { pc + u64::from(offset) } else { pc.wrapping_sub(u64::from(offset)) };
            Some(Use::Data(start, start + size))
        }
        _ => None,
    })
}

/// `a32`: whether the processor runs A32 code as well; a Cortex-M has no `BLX` to a label.
fn yaxpeax_thumb(bytes: &[u8], at: u64, a32: bool) -> Option<Use> {
    let insn = armv7::InstDecoder::default_thumb().decode(&mut U8Reader::new(bytes)).ok()?;
    let word_pc = (at + 4) & !3;
    match (insn.opcode, insn.operands) {
        (armv7::Opcode::ADR, [armv7::Operand::Reg(_), armv7::Operand::Imm32(offset), ..]) => return Some(Use::Address(word_pc + u64::from(offset))),
        // `ADR.W`, which yaxpeax-arm calls `ADD` or `SUB` from the PC. With `.W` it is the
        // modified-immediate `ADD.W` from the PC instead, which the manual makes UNPREDICTABLE
        // and yaxpeax-arm decodes all the same.
        (armv7::Opcode::ADD | armv7::Opcode::SUB, [armv7::Operand::Reg(_), armv7::Operand::Reg(base), armv7::Operand::Imm32(offset), _]) if base.number() == 15 && !insn.w() => {
            return Some(Use::Address(if insn.opcode == armv7::Opcode::ADD { word_pc + u64::from(offset) } else { word_pc.wrapping_sub(u64::from(offset)) }));
        }
        _ => {}
    }
    if let Some(data) = literal(&insn, word_pc) {
        return Some(data);
    }
    let offset = insn.operands.iter().find_map(|operand| match *operand {
        armv7::Operand::BranchThumbOffset(offset) => Some(offset),
        _ => None,
    })?;
    let conditional = insn.condition != ConditionCode::AL;
    // yaxpeax-arm 0.5 counts the offsets of the 16-bit `B<c>`, `CBZ` and `CBNZ` from the next
    // instruction, as its decoder's `imm + 1` shows, and every other offset from the PC.
    let from_next = !insn.wide && (conditional || matches!(insn.opcode, armv7::Opcode::CBZ | armv7::Opcode::CBNZ));
    let pc = at + if from_next { 2 } else { 4 };
    let to = |base: u64| base.wrapping_add_signed(i64::from(offset) * 2);
    Some(match insn.opcode {
        armv7::Opcode::BL => Use::Call(to(pc)),
        armv7::Opcode::BLX if a32 => Use::Call(to(pc & !3)),
        armv7::Opcode::CBZ | armv7::Opcode::CBNZ => Use::Branch(to(pc)),
        armv7::Opcode::B if conditional => Use::Branch(to(pc)),
        armv7::Opcode::B => Use::Jump(to(pc)),
        _ => return None,
    })
}

/// `a32` as for `yaxpeax_thumb`.
fn recore_thumb(bytes: &[u8], at: u64, a32: bool) -> Option<Use> {
    let insn = thumb::decode_at(bytes, at, 0, &mut 0, a32)?.insn?;
    // yaxpeax-arm does not decode VLDR, so the literal VLDR goes unchecked.
    if insn.hw1 & 0xFF3F == 0xED1F && insn.hw2 & 0x0E00 == 0x0A00 {
        return None;
    }
    insn.direct().map(from_transfer).or_else(|| insn.adr().map(|(_, address)| Use::Address(address))).or_else(|| insn.literal_range().map(|(start, end)| Use::Data(start, end)))
}

#[test]
#[ignore = "slow unoptimized; CI and `mise run decoders-agree` run it"]
fn thumb() {
    every(|word| {
        let (hw1, hw2) = (word as u16, (word >> 16) as u16);
        // A 16-bit instruction is checked once, with a zero second halfword.
        if hw1 >> 11 < 0b11101 && hw2 != 0 {
            return None;
        }
        let bytes = [hw1.to_le_bytes(), hw2.to_le_bytes()].concat();
        [(AT, true), (AT + 2, true), (AT, false), (AT + 2, false)].into_iter().find_map(|(at, a32)| {
            let ours = recore_thumb(&bytes, at, a32);
            let theirs = yaxpeax_thumb(&bytes, at, a32);
            (ours != theirs).then(|| format!("{hw1:04x} {hw2:04x} at {at:#x}, a32 {a32}: recore {ours:x?}, yaxpeax {theirs:x?}"))
        })
    });
}

fn yaxpeax_a32(word: u32, at: u64) -> Option<Use> {
    // yaxpeax-arm 0.5 panics on some A32 words: "register number out of range". Those count as
    // no instruction.
    let insn = quietly(|| armv7::InstDecoder::default().decode(&mut U8Reader::new(&word.to_le_bytes())).ok())?;
    let conditional = insn.condition != ConditionCode::AL;
    // yaxpeax-arm has added the 8 bytes the PC reads ahead to the offset of `B` and `BL`, in
    // words, but inside the 24 bits of the field: the two largest forward offsets wrap to 64 MiB
    // back.
    let words = |offset: i32| i64::from(if offset < 2 - (1 << 23) { offset + (1 << 24) } else { offset }) * 4;
    Some(match (insn.opcode, insn.operands[0]) {
        (armv7::Opcode::BL, armv7::Operand::BranchOffset(offset)) => Use::Call(at.wrapping_add_signed(words(offset))),
        (armv7::Opcode::B, armv7::Operand::BranchOffset(offset)) if conditional => Use::Branch(at.wrapping_add_signed(words(offset))),
        (armv7::Opcode::B, armv7::Operand::BranchOffset(offset)) => Use::Jump(at.wrapping_add_signed(words(offset))),
        (armv7::Opcode::BLX, armv7::Operand::BranchThumbOffset(offset)) => Use::Call((at + 8).wrapping_add_signed(i64::from(offset) * 2)),
        // An A32 `LDRD` into an odd register is UNPREDICTABLE, which yaxpeax-arm decodes
        // all the same.
        (armv7::Opcode::LDRD, armv7::Operand::Reg(first)) if first.number() % 2 != 0 => return None,
        // A load into PC: `LDR PC, [PC, #imm]` is a jump through the literal, which recore's
        // `flow` reads, not `literal_range`; the other widths are UNPREDICTABLE.
        (_, armv7::Operand::Reg(first)) if first.number() == 15 && width(insn.opcode).is_some() => return None,
        _ => return literal(&insn, at + 8),
    })
}

#[test]
#[ignore = "slow unoptimized; CI and `mise run decoders-agree` run it"]
fn a32() {
    every(|word| {
        // yaxpeax-arm does not decode VLDR, so the literal VLDR goes unchecked.
        if word & 0x0F3F_0E00 == 0x0D1F_0A00 {
            return None;
        }
        let ours = match arm::decode_a32(&word.to_le_bytes(), AT, 0).and_then(|decoded| decoded.insn) {
            Some(ArmInsn::A32(insn)) => insn.direct().map(from_transfer).or_else(|| insn.literal_range().map(|(start, end)| Use::Data(start, end))),
            _ => None,
        };
        let theirs = yaxpeax_a32(word, AT);
        (ours != theirs).then(|| format!("{word:08x}: recore {ours:x?}, yaxpeax {theirs:x?}"))
    });
}

fn yaxpeax_a64(word: u32, at: u64) -> Option<Use> {
    let insn = a64::InstDecoder::default().decode(&mut U8Reader::new(&word.to_le_bytes())).ok()?;
    let target = insn.operands.iter().find_map(|operand| match *operand {
        a64::Operand::PCOffset(offset) => Some(offset),
        _ => None,
    })?;
    let to = at.wrapping_add_signed(target);
    Some(match insn.opcode {
        a64::Opcode::BL => Use::Call(to),
        a64::Opcode::B => Use::Jump(to),
        a64::Opcode::Bcc(_) | a64::Opcode::BCcc(_) | a64::Opcode::CBZ | a64::Opcode::CBNZ | a64::Opcode::TBZ | a64::Opcode::TBNZ => Use::Branch(to),
        a64::Opcode::ADR => Use::Address(to),
        a64::Opcode::ADRP => Use::Page((at & !0xFFF).wrapping_add_signed(target)),
        a64::Opcode::LDR if matches!(insn.operands[0], a64::Operand::Register(a64::SizeCode::X, _)) => Use::Data(to, to + 8),
        _ => return None,
    })
}

fn recore_a64(word: u32, addr: u64) -> Option<Use> {
    let insn = arm64::Insn { word, addr };
    if let Some((call, target)) = insn.direct() {
        return Some(if call { Use::Call(target) } else { Use::Jump(target) });
    }
    if let Some(target) = insn.conditional() {
        return Some(Use::Branch(target));
    }
    if let Some((page, address)) = insn.pc_relative() {
        return Some(if page { Use::Page(address) } else { Use::Address(address) });
    }
    insn.load_literal().map(|start| Use::Data(start, start + 8))
}

#[test]
#[ignore = "slow unoptimized; CI and `mise run decoders-agree` run it"]
fn a64() {
    every(|word| {
        // At the start of a page and at its last word, which `adrp` rounds down.
        [AT, AT + 0xFFC].into_iter().find_map(|at| {
            let (ours, theirs) = (recore_a64(word, at), yaxpeax_a64(word, at));
            (ours != theirs).then(|| format!("{word:08x} at {at:#x}: recore {ours:x?}, yaxpeax {theirs:x?}"))
        })
    });
}
