//! Position-independent fingerprints of function bodies, for recognising library code.
//!
//! A statically linked C runtime puts the same compiled functions into many binaries. The bytes
//! differ only where they hold addresses, so hashing the instructions with those fields blanked
//! gives a fingerprint that matches across binaries built with the same compiler and library.

use rustc_hash::{FxHashMap, FxHashSet};

use iced_x86::{Decoder, DecoderOptions, FlowControl, OpKind};

use crate::arch::Decoded;
use crate::arm::{self, A32};
use crate::image::{Format, Image, InstructionSet, Machine, Section};
use crate::thumb::{self, Transfer};

/// Functions shorter than this are too alike to tell apart: many are a move and a return.
const MIN_INSTRUCTIONS: usize = 10;
const MIN_BYTES: u64 = 32;

/// The same bound for AArch64. It is higher because short functions there are more often one
/// body under several names: with each corpus project held out in turn, the names given to
/// functions of 10 to 15 instructions were wrong 14 times in 417, and 15 times in 3,738 above.
const MIN_WORDS: usize = 16;

/// FNV-1a over the bytes fed to it.
struct Hash(u64);

impl Hash {
    fn new() -> Hash {
        Hash(0xcbf2_9ce4_8422_2325)
    }
    fn feed(&mut self, byte: u8) {
        self.0 = (self.0 ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3);
    }
}

/// What shows of the function occupying `[start, end)` without decoding it, and is the same
/// wherever the function is linked: its length, and the leading byte of its first instruction
/// less any bits of an address. Functions with one fingerprint have one outline, so a table
/// that lists the outlines of its functions rules most others out for the cost of a search.
/// `None` when the function is too small to be distinctive.
pub fn outline(image: &Image, start: u64, end: u64) -> Option<u32> {
    let length = end.checked_sub(start).filter(|length| (MIN_BYTES..1 << 24).contains(length))?;
    let lead = match (image.machine, image.bytes_from(start)?) {
        (Machine::X86 | Machine::X86_64, &[opcode, ..]) => opcode,
        // The top byte holds offset bits in `b` and `bl`, and in `adr` and `adrp`.
        (Machine::Aarch64, &[_, _, _, top, ..]) if top & 0x7C == 0x14 => top & 0xFC,
        (Machine::Aarch64, &[_, _, _, top, ..]) if top & 0x1F == 0x10 => top & 0x9F,
        (Machine::Aarch64, &[_, _, _, top, ..]) => top,
        _ => return None,
    };
    Some((length as u32) << 8 | u32::from(lead))
}

/// The fingerprint of the function occupying `[start, end)`, or `None` when it is too small to
/// be distinctive.
pub fn fingerprint(image: &Image, pointer_slots: &FxHashMap<u64, u64>, start: u64, end: u64) -> Option<u64> {
    if end.checked_sub(start)? < MIN_BYTES {
        return None;
    }
    let bytes = image.bytes_from(start)?;
    let bytes = bytes.get(..(end - start) as usize)?;
    match image.machine {
        Machine::X86 => x86(32, bytes, pointer_slots, start, end, Some(MIN_INSTRUCTIONS), true, None),
        Machine::X86_64 => x86(64, bytes, pointer_slots, start, end, Some(MIN_INSTRUCTIONS), true, None),
        Machine::Aarch64 => aarch64(bytes, start, end, Some(MIN_WORDS), true),
        Machine::I8051 | Machine::Thumb | Machine::Arm => None,
    }
}

/// Hashes the code `bytes` holds from `start` to `end`, with its numbers or without them.
type RangeHash<'a> = dyn Fn(&[u8], u64, u64, bool) -> Option<u64> + 'a;

/// Two fingerprints of the code of a function's `body`, its ranges in order, however short it
/// is. The first, of its body, is equal for two builds of one function that differ only in
/// where they and what they refer to were linked, and in the padding that aligns their loops.
/// The second, of its shape, leaves out every number in the code as well: the constants, and
/// the offsets of the fields and stack slots it reaches. Two builds with a shape in common and
/// not a body are the same instructions over different numbers, as when a structure the
/// function uses gained a field. Short functions share theirs, so neither identifies anything
/// by itself. `None` where the code cannot be read or its machine is not hashed, which is the
/// 8051's.
pub fn hashes(image: &Image, pointer_slots: &FxHashMap<u64, u64>, body: &[(u64, u64)]) -> Option<(u64, u64)> {
    let x86_range = |bits| move |bytes: &[u8], start, end, numbers| x86(bits, bytes, pointer_slots, start, end, None, numbers, None);
    let range: &RangeHash = match image.machine {
        Machine::X86 => &x86_range(32),
        Machine::X86_64 => &x86_range(64),
        Machine::Aarch64 => &|bytes, start, end, numbers| aarch64(bytes, start, end, None, numbers),
        // As one, since a `MOVW` and its `MOVT` may lie on either side of a jump table that
        // splits the body.
        Machine::Arm | Machine::Thumb => return arm(image, pointer_slots, body),
        // Not hashed yet: nothing says which of its bytes are addresses.
        Machine::I8051 => return None,
    };
    body.iter().try_fold((0, 0), |(body, shape): (u64, u64), &(start, end)| {
        let bytes = image.bytes_from(start)?.get(..end.checked_sub(start)? as usize)?;
        Some((body.rotate_left(17) ^ range(bytes, start, end, true)?, shape.rotate_left(17) ^ range(bytes, start, end, false)?))
    })
}

/// The numbers in the code of `[start, end)` that the shape of [`hashes`] leaves out and the
/// body keeps, in the order of the instructions: where two builds share a shape and not a body,
/// these say what differs. Empty for code other than x86.
pub fn numbers(image: &Image, pointer_slots: &FxHashMap<u64, u64>, start: u64, end: u64) -> Vec<u64> {
    let mut found = Vec::new();
    if let Some(bytes) = image.bytes_from(start).and_then(|bytes| bytes.get(..end.checked_sub(start)? as usize)) {
        match image.machine {
            Machine::X86 => drop(x86(32, bytes, pointer_slots, start, end, None, true, Some(&mut found))),
            Machine::X86_64 => drop(x86(64, bytes, pointer_slots, start, end, None, true, Some(&mut found))),
            Machine::Aarch64 | Machine::I8051 | Machine::Thumb | Machine::Arm => {}
        }
    }
    found
}

/// An x86 function: displacements and immediates are blanked where they are relative to the
/// instruction pointer and leave the function, or where the loader relocates them.
/// With a least number of instructions the function must have that many and its padding
/// counts, as the tables of library functions were built; without one, padding is left out.
/// The numbers kept that `numbers` false would blank go to `found`.
#[allow(clippy::too_many_arguments)]
fn x86(bits: u32, bytes: &[u8], pointer_slots: &FxHashMap<u64, u64>, start: u64, end: u64, min_instructions: Option<usize>, numbers: bool, mut found: Option<&mut Vec<u64>>) -> Option<u64> {
    let mut decoder = Decoder::with_ip(bits, bytes, start, DecoderOptions::NONE);

    let mut hash = Hash::new();
    let mut instructions = 0;
    // Without padding, a branch inside the function is told by which instruction it goes to,
    // counted without the padding, since padding moves everything after it.
    let unpadded: Vec<u64> = match min_instructions {
        Some(_) => Vec::new(),
        None => Decoder::with_ip(bits, bytes, start, DecoderOptions::NONE).into_iter().filter(|instr| !crate::x86::is_padding(instr)).map(|instr| instr.ip()).collect(),
    };

    while decoder.can_decode() {
        let offset = decoder.position();
        let instr = decoder.decode();
        if instr.is_invalid() {
            return None;
        }
        if min_instructions.is_none() && crate::x86::is_padding(&instr) {
            continue;
        }
        instructions += 1;
        let offsets = decoder.get_constant_offsets(&instr);
        let raw = &bytes[offset..offset + instr.len()];

        // Which bytes of the instruction hold an address that moves between binaries.
        let mut blank = [false; 16];
        let mut mark = |at: usize, size: usize| blank[at..(at + size).min(16)].iter_mut().for_each(|b| *b = true);
        let leaves = |target: u64| target < start || target >= end;
        let mut keep = |at: usize, size: usize| {
            if let Some(found) = found.as_deref_mut() {
                found.push(raw[at..at + size].iter().rev().fold(0, |value, &byte| value << 8 | u64::from(byte)));
            }
        };

        if offsets.has_displacement() {
            let at = offsets.displacement_offset();
            let relocated = pointer_slots.contains_key(&(instr.ip() + at as u64));
            if instr.is_ip_rel_memory_operand() || relocated || !numbers {
                mark(at, offsets.displacement_size());
            } else {
                keep(at, offsets.displacement_size());
            }
        }
        if offsets.has_immediate() {
            let at = offsets.immediate_offset();
            let is_branch = matches!(
                instr.op0_kind(),
                OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
            );
            let relocated = pointer_slots.contains_key(&(instr.ip() + at as u64));
            // A call or jump to somewhere else in the binary; branches within the function
            // are relative and identical everywhere.
            let external = is_branch && (instr.flow_control() == FlowControl::Call || leaves(instr.near_branch_target()));
            let internal = is_branch && !external && min_instructions.is_none();
            if relocated || external || internal || !numbers {
                mark(at, offsets.immediate_size());
            } else if !is_branch {
                keep(at, offsets.immediate_size());
            }
            if internal {
                let ordinal = unpadded.partition_point(|&ip| ip < instr.near_branch_target()) as u32;
                ordinal.to_le_bytes().into_iter().for_each(|byte| hash.feed(byte));
            }
        }
        for (index, &byte) in raw.iter().enumerate() {
            hash.feed(if blank[index] { 0 } else { byte });
        }
    }
    (instructions >= min_instructions.unwrap_or(0)).then_some(hash.0)
}

/// An AArch64 function, a word at a time. Blanked are the offsets of calls and of branches and
/// literal loads that leave the function, the address `adr` or `adrp` forms, and the low twelve
/// bits an `add`, load or store then adds to a page. Which registers hold a page is followed
/// along the instructions in address order, which is all the pairing compilers emit needs.
fn aarch64(bytes: &[u8], start: u64, end: u64, min_words: Option<usize>, numbers: bool) -> Option<u64> {
    const OFFSET_26: u32 = 0x03FF_FFFF;
    const OFFSET_19: u32 = 0x00FF_FFE0;
    const OFFSET_14: u32 = 0x0007_FFE0;
    const PC_RELATIVE: u32 = 0x60FF_FFE0;
    const LOW_12: u32 = 0x003F_FC00;
    /// The registers a call may change: `x0` to `x18` and the link register.
    const CALLER_SAVED: u32 = 0x4007_FFFF;

    if bytes.len() / 4 < min_words.unwrap_or(0) {
        return None;
    }
    const NOP: u32 = 0xD503_201F;
    let words = || bytes.as_chunks::<4>().0.iter().map(|chunk| u32::from_le_bytes(*chunk));
    // Without padding, a branch inside the function is told by which instruction it goes to,
    // counted without the padding, since padding moves everything after it: for each word,
    // how many before it are not padding.
    let unpadded: Vec<u32> = match min_words {
        Some(_) => Vec::new(),
        None => words().scan(0, |count, word| Some(std::mem::replace(count, *count + u32::from(word != NOP)))).collect(),
    };
    let mut hash: u64 = 0;
    // Bit `n` is set while register `n` holds a page address.
    let mut pages: u32 = 0;
    for (index, word) in words().enumerate() {
        if min_words.is_none() && word == NOP {
            continue;
        }
        // Where a branch inside the function goes, once its offset is blanked.
        let mut inside = None;
        let (rd, rn) = (word & 31, word >> 5 & 31);
        // Whether the branch offset in the bits of `field`, counted in words, leaves the function.
        let mut leaves = |field: u32| {
            let unused = 64 - field.count_ones();
            let offset = (i64::from((word & field) >> field.trailing_zeros()) << unused >> unused) * 4;
            let target = (start + index as u64 * 4).wrapping_add_signed(offset);
            let leaves = target < start || target >= end;
            if let (false, Some(&ordinal)) = (leaves, unpadded.get(((target.wrapping_sub(start)) / 4) as usize)) {
                inside = Some((field, ordinal));
            }
            leaves
        };
        let blank_if = |condition: bool, field: u32| if condition { field } else { 0 };
        let mut blank = 0;
        if word & 0x7C00_0000 == 0x1400_0000 {
            // `b` and `bl`.
            let is_call = word >> 31 == 1;
            blank = blank_if(is_call || leaves(OFFSET_26), OFFSET_26);
            if is_call {
                pages &= !CALLER_SAVED;
            }
        } else if word & 0xFF00_0000 == 0x5400_0000 || word & 0x7E00_0000 == 0x3400_0000 {
            // `b.cond`, `cbz` and `cbnz`.
            blank = blank_if(leaves(OFFSET_19), OFFSET_19);
        } else if word & 0x7E00_0000 == 0x3600_0000 {
            // `tbz` and `tbnz`.
            blank = blank_if(leaves(OFFSET_14), OFFSET_14);
        } else if word & 0xFFFF_FC1F == 0xD63F_0000 {
            // `blr`.
            pages &= !CALLER_SAVED;
        } else if word & 0x1F00_0000 == 0x1000_0000 {
            // `adrp` and `adr`. What `adr` reaches is nearly always data outside the function.
            blank = PC_RELATIVE;
            pages = pages & !(1 << rd) | (word >> 31) << rd;
        } else if word & 0x3B00_0000 == 0x1800_0000 {
            // A load from a literal.
            blank = blank_if(leaves(OFFSET_19), OFFSET_19);
            pages &= !(1 << rd);
        } else if word & 0xFFC0_0000 == 0x9100_0000 {
            // 64-bit `add xd, xn, #imm`.
            blank = blank_if(pages >> rn & 1 == 1, LOW_12);
            pages &= !(1 << rd);
        } else if word & 0x3B00_0000 == 0x3900_0000 {
            // A load or store at `[xn, #imm]`. A load into a general register overwrites it.
            blank = blank_if(pages >> rn & 1 == 1, LOW_12);
            if word >> 22 & 3 != 0 && word >> 26 & 1 == 0 {
                pages &= !(1 << rd);
            }
        } else if word >> 25 & 0b0101 == 0b0100 {
            // Other loads and stores: the general registers loaded, and the base when it moves.
            let is_pair = word & 0x3A00_0000 == 0x2800_0000;
            if word >> 22 & 1 == 1 && word >> 26 & 1 == 0 {
                pages &= !(1 << rd);
                if is_pair {
                    pages &= !(1 << (word >> 10 & 31));
                }
            }
            let writes_base = if is_pair { word >> 23 & 1 == 1 } else { word >> 24 & 1 == 0 && word >> 10 & 1 == 1 };
            if writes_base {
                pages &= !(1 << rn);
            }
        } else if word >> 25 & 0b0111 != 0b0111 {
            // Everything else that is not floating-point or vector arithmetic writes `rd`.
            pages &= !(1 << rd);
        }
        // One multiplication a word; the rotation carries high bits back into the low ones.
        // The number in an `add` or `sub` of an immediate, in a load or store at an offset,
        // and in one of a pair.
        if !numbers {
            if word & 0x1F00_0000 == 0x1100_0000 || word & 0x3B00_0000 == 0x3900_0000 {
                blank |= LOW_12;
            } else if word & 0x3A00_0000 == 0x2800_0000 {
                blank |= 0x003F_8000;
            }
        }
        let word = match inside {
            Some((field, ordinal)) => u64::from(word & !field) ^ u64::from(ordinal) << 32,
            None => u64::from(word & !blank),
        };
        hash = (hash.rotate_left(5) ^ word).wrapping_mul(0x517c_c1b7_2722_0a95);
    }
    Some(hash)
}

/// The instructions of an ARM function's `body` in order, each A32 or Thumb as the image says,
/// without the pools that literal loads read among them. A pool that a load before it reads is
/// passed over as it comes. One that a load after it reads is found once decoded through, and
/// the body is decoded again passing over it, so that the code after every pool decodes from
/// where it begins. A pool stays passed over only while a load of the pass reads it, so one
/// that bytes of another, decoded as a load, seemed to read goes once they are passed over.
/// Any load decoded is trusted, so bytes that are no code and no pool a load reads, such as
/// one an `ADR` reaches, may still pass over the code after them as a pool.
fn arm_instructions(image: &Image, body: &[(u64, u64)]) -> Option<Vec<Decoded<arm::Insn>>> {
    let as_arm = |one: Decoded<thumb::Insn>| Decoded { addr: one.addr, len: one.len, insn: one.insn.map(arm::Insn::Thumb) };
    let halfwords = |(at, to): (u64, u64)| (at & !1..to).step_by(2);
    let covers = |one: &Decoded<arm::Insn>| (one.addr..one.addr + u64::from(one.len)).step_by(2);
    // The halfwords of the pools passed over from the start of a pass.
    let mut behind = FxHashSet::default();
    // The decoded instructions of the pass, and the halfwords of the pools their loads read.
    let (mut decoded, mut read) = (Vec::new(), FxHashSet::default());
    // Data taken for code may find more pools each pass.
    for _ in 0..3 {
        decoded.clear();
        read.clear();
        for &(start, end) in body {
            let bytes = image.bytes_from(start)?.get(..end.checked_sub(start)? as usize)?;
            let (mut offset, mut it) = (0, 0);
            while offset < bytes.len() {
                let addr = start + offset as u64;
                if behind.contains(&addr) || read.contains(&addr) {
                    (offset, it) = (offset + 2, 0);
                    continue;
                }
                let one = match (image.machine, image.instruction_set(addr).0) {
                    (Machine::Thumb, _) => thumb::decode_at(bytes, start, offset, &mut it, false).map(as_arm),
                    (_, InstructionSet::A32) => arm::decode_a32(bytes, start, offset),
                    (_, InstructionSet::Thumb) => thumb::decode_at(bytes, start, offset, &mut it, true).map(as_arm),
                };
                // Only a range of an odd length leaves a byte that is no instruction at all.
                let Some(one) = one else { break };
                if let Some((pool, _)) = one.insn.and_then(arm::Insn::literal) {
                    read.extend(halfwords(pool));
                }
                offset += usize::from(one.len.max(1));
                decoded.push(one);
            }
        }
        let through = decoded.iter().flat_map(covers).filter(|half| read.contains(half));
        let next: FxHashSet<u64> = behind.iter().copied().filter(|half| read.contains(half)).chain(through).collect();
        if next == behind {
            break;
        }
        behind = next;
    }
    // What still overlaps a pool after the last pass is left out.
    decoded.retain(|one| !covers(one).any(|half| read.contains(&half)));
    Some(decoded)
}

/// The body and shape hashes of a 32-bit ARM function, see [`hashes`]. Blanked are the offsets
/// of calls, and of branches, `ADR` and literal loads that reach outside the range of the body
/// they are in, and the halves of a `MOVW` and `MOVT` pair that form an address. A literal
/// load is hashed with what it loads, blanked where that is an address, and the shape without
/// it.
fn arm(image: &Image, pointer_slots: &FxHashMap<u64, u64>, body: &[(u64, u64)]) -> Option<(u64, u64)> {
    let decoded = arm_instructions(image, body)?;
    // The ranges of a body may move apart: a tail the analysis took for part of the function.
    let leaves = |at: u64, target: u64| !body.iter().any(|&(start, end)| (start..end).contains(&at) && (start..end).contains(&target));

    // Where an address may point: into the image or its zeroed globals, to the end of one,
    // where a linker's symbols for the ends point, and on a Cortex-M into SRAM, which a raw
    // image does not describe.
    let ends: FxHashSet<u64> = image.sections.iter().map(Section::end).chain(image.zero_filled.iter().map(|&(_, end)| end)).collect();
    let sram = |value: u64| image.machine == Machine::Thumb && (thumb::SRAM.0..thumb::SRAM.1).contains(&value);
    let lands = |value: u32| {
        let value = u64::from(value);
        image.section_at(value).is_some() || image.is_zero_filled(value) || ends.contains(&value) || sram(value)
    };
    // The PC an `ADD` later adds to what the instruction at `index` puts in `register`, before
    // anything else of its kind puts something there: the offset is then from that PC.
    let added_pc = |index: usize, register: usize| {
        decoded[index + 1..].iter().filter_map(|one| one.insn).find_map(|insn| match (insn.pc_sum(), insn.literal(), insn.move_half()) {
            (Some((offset, pc)), ..) if offset == register => Some(Some(pc)),
            (_, Some((_, Some(loaded))), _) | (_, _, Some((loaded, _, _))) if loaded == register => Some(None),
            _ => None,
        })?
    };
    // Position-independent code holds no address itself, as the loader would have to relocate
    // it: it holds offsets from the PC and from its global offset table, which it adds to a
    // register that holds the table's address.
    let table = image.sections.iter().find(|section| section.name == ".got" && !image.relative_targets.is_empty()).map(|section| section.addr as u32);
    // Whether the word the instruction at `index` puts in `register` is an address.
    let is_address = |value: u32, index: usize, register: usize| {
        added_pc(index, register).is_some_and(|pc| lands((pc as u32).wrapping_add(value)))
            || match table {
                Some(table) => lands(table.wrapping_add(value)),
                None => lands(value),
            }
    };

    // The halves of the pairs that form an address: each `MOVT` with the nearest `MOVW` of its
    // register before it, and each `MOVW` with the nearest `MOVT` after it, in either direction
    // up to one of its own kind that sets the register whatever the condition. A pair under
    // each of two conditions is then two pairs.
    let moves: Vec<Option<(usize, u32, bool)>> = decoded.iter().map(|one| one.insn.and_then(arm::Insn::move_half)).collect();
    let partner = |index: usize, register: usize, top: bool| {
        let step = |other: usize| match moves[other] {
            Some((with, value, other_top)) if with == register && other_top != top => Some(Some((other, value))),
            Some((with, ..)) if with == register && decoded[other].insn.is_some_and(|insn| !insn.conditional()) => Some(None),
            _ => None,
        };
        if top { (0..index).rev().find_map(step)? } else { (index + 1..moves.len()).find_map(step)? }
    };
    let mut halves = vec![false; decoded.len()];
    for (index, half) in moves.iter().enumerate() {
        let Some((register, value, top)) = *half else { continue };
        let Some((partner, other)) = partner(index, register, top) else { continue };
        let (high, low, top_index) = if top { (value, other, index) } else { (other, value, partner) };
        if is_address(high << 16 | low, top_index, register) {
            (halves[index], halves[partner]) = (true, true);
        }
    }

    let (mut body_hash, mut shape_hash) = (0u64, 0u64);
    let feed = |hash: &mut u64, value: u64| *hash = (hash.rotate_left(5) ^ value).wrapping_mul(0x517c_c1b7_2722_0a95);
    for (index, one) in decoded.iter().enumerate() {
        let leaves = |target| leaves(one.addr, target);
        let (bits, (address, number)) = match one.insn {
            Some(arm::Insn::A32(insn)) => (insn.word, a32_blank(insn, &leaves, halves[index])),
            Some(arm::Insn::Thumb(insn)) => (u32::from(insn.hw1) | u32::from(insn.hw2) << 16, thumb_blank(insn, &leaves, halves[index])),
            None => (image.bytes_from(one.addr)?.iter().take(usize::from(one.len)).fold(0, |word, &byte| word << 8 | u32::from(byte)), (0, 0)),
        };
        let length = u64::from(one.len) << 32;
        feed(&mut body_hash, u64::from(bits & !address) | length);
        feed(&mut shape_hash, u64::from(bits & !(address | number)) | length);
        // What a literal load reads: a number, or an address.
        if let Some(((at, to), word)) = one.insn.and_then(arm::Insn::literal) {
            let Some(loaded) = image.bytes_from(at).and_then(|data| data.get(..(to - at) as usize)) else { continue };
            let value = loaded.iter().rev().fold(0u64, |value, &byte| value << 8 | u64::from(byte));
            let address = word.is_some_and(|register| pointer_slots.contains_key(&at) || is_address(value as u32, index, register));
            feed(&mut body_hash, if address { 1 << 63 } else { value });
        }
    }
    Some((body_hash, shape_hash))
}

/// The bits of an A32 instruction that hold an address, which [`arm`] leaves out, and those
/// that hold a number, which the shape leaves out too. `half` says the instruction is half of
/// a pair that forms an address.
fn a32_blank(insn: A32, leaves: &dyn Fn(u64) -> bool, half: bool) -> (u32, u32) {
    let word = insn.word;
    let address = |leaves: bool, field: u32| (if leaves { field } else { 0 }, 0);
    if let Some((target, transfer)) = insn.direct() {
        // `BLX` to a label keeps a bit of its offset where the condition would be.
        return address(transfer == Transfer::Call || leaves(target), if word >> 28 == 15 { 0x01FF_FFFF } else { 0x00FF_FFFF });
    }
    if let Some((at, _)) = insn.literal_range() {
        // The offset and which way it goes: twelve bits, eight of a halfword or `VLDR`.
        let field = match word >> 25 & 7 {
            0b010 => 0x0080_0FFF,
            0b000 => 0x0080_0F0F,
            _ => 0x0080_00FF,
        };
        return address(leaves(at), field);
    }
    if let Some((_, target)) = insn.adr() {
        // The offset and whether it is added or taken away.
        return address(leaves(target), 0x01E0_0FFF);
    }
    if insn.move_half().is_some() {
        return if half { (0x000F_0FFF, 0) } else { (0, 0x000F_0FFF) };
    }
    // The constant of a data-processing instruction, and the offset of a load or store.
    let number = if word >> 25 & 1 == 1 && insn.data_processing().is_some() || word >> 25 & 7 == 0b010 && insn.transfer().is_some() {
        0xFFF
    } else if word >> 25 & 7 == 0 && word >> 22 & 1 == 1 && insn.transfer().is_some() {
        0xF0F
    } else {
        0
    };
    (0, number)
}

/// The same as [`a32_blank`] for a Thumb instruction, its first halfword low and its second
/// high.
fn thumb_blank(insn: thumb::Insn, leaves: &dyn Fn(u64) -> bool, half: bool) -> (u32, u32) {
    let (hw1, hw2) = (u32::from(insn.hw1), u32::from(insn.hw2));
    let both = |first: u32, second: u32| first | second << 16;
    let address = |leaves: bool, field: u32| (if leaves { field } else { 0 }, 0);
    if let Some((target, transfer)) = insn.direct() {
        let field = match (insn.wide(), hw1 >> 11) {
            (false, 0b11100) => 0x07FF,
            // CBZ and CBNZ.
            (false, 0b10110 | 0b10111) => 0x02F8,
            (false, _) => 0x00FF,
            // B<c>.W keeps its condition.
            (true, _) if hw2 & 0x5000 == 0 => both(0x043F, 0x2FFF),
            (true, _) => both(0x07FF, 0x2FFF),
        };
        return address(transfer == Transfer::Call || leaves(target), field);
    }
    if let Some((at, _)) = insn.literal_range() {
        let field = match insn.wide() {
            false => 0x00FF,
            // LDRD and VLDR count in words, eight bits of them.
            true if matches!(hw1 & 0xFF7F, 0xE95F | 0xED1F | 0xED5F) => both(0x0080, 0x00FF),
            true => both(0x0080, 0x0FFF),
        };
        return address(leaves(at), field);
    }
    if let Some((_, target)) = insn.adr() {
        return address(leaves(target), if insn.wide() { both(0x04A0, 0x70FF) } else { 0x00FF });
    }
    if insn.move_half().is_some() {
        let field = both(0x040F, 0x70FF);
        return if half { (field, 0) } else { (0, field) };
    }
    // The constants of data-processing instructions and the offsets of loads and stores.
    let number = if !insn.wide() {
        match hw1 >> 11 {
            // MOV, CMP, ADD and SUB of eight bits; loads and stores at SP; ADD Rd, SP.
            0b00100..=0b00111 | 0b10010 | 0b10011 | 0b10101 => 0x00FF,
            // Loads and stores at five bits of offset.
            0b01100..=0b10001 => 0x07C0,
            // ADD and SUB of three bits.
            0b00011 if hw1 & 0x0400 != 0 => 0x01C0,
            // ADD SP and SUB SP.
            0b10110 if hw1 & 0x0F00 == 0 => 0x007F,
            _ => 0,
        }
    } else if hw1 >> 11 == 0b11110 && hw2 & 0x8000 == 0 {
        both(0x0400, 0x70FF)
    } else if hw1 & 0xFE80 == 0xF880 {
        // Loads and stores of twelve bits of offset, signed loads too.
        both(0, 0x0FFF)
    } else if hw1 & 0xFE00 == 0xF800 && hw2 & 0x0800 != 0 || hw1 & 0xFE40 == 0xE840 && hw1 & 0x0120 != 0 {
        // Of eight bits, and LDRD and STRD.
        both(0, 0x00FF)
    } else {
        0
    };
    (0, number)
}

/// Known fingerprints and the library function each belongs to: a table that is searched where
/// it lies, so a program pays nothing to load it and touches only the pages a search reaches.
///
/// The table is the number of outlines and the number of fingerprints in four bytes each, the
/// outlines in four bytes each, the fingerprints in eight bytes each, for each fingerprint in
/// four bytes where its name ends, and the names back to back. Outlines and fingerprints are in
/// ascending order and all numbers are little-endian. `recore-corpus signatures` writes one.
pub struct Signatures<'a> {
    outlines: &'a [u8],
    hashes: &'a [u8],
    ends: &'a [u8],
    names: &'a [u8],
}

/// The position of the first of `count` numbers `width` bytes wide that is not below `wanted`.
fn lower_bound(numbers: &[u8], width: usize, wanted: u64) -> usize {
    let (mut low, mut high) = (0, numbers.len() / width);
    while low < high {
        let middle = (low + high) / 2;
        if number(numbers, width, middle) < wanted {
            low = middle + 1;
        } else {
            high = middle;
        }
    }
    low
}

/// The number at `index` among those `width` bytes wide.
fn number(numbers: &[u8], width: usize, index: usize) -> u64 {
    let mut raw = [0; 8];
    raw[..width].copy_from_slice(&numbers[index * width..][..width]);
    u64::from_le_bytes(raw)
}

impl<'a> Signatures<'a> {
    /// The signatures built into this crate for images of `format` on `machine`. Empty where
    /// the corpora hold too little shared library code to name anything, which is Mach-O.
    pub fn builtin(format: Format, machine: Machine) -> Signatures<'static> {
        let table: &[u8] = match (format, machine) {
            (Format::Pe, Machine::X86) => include_bytes!("../data/pe-x86.sigs"),
            (Format::Pe, Machine::X86_64) => include_bytes!("../data/pe-x86_64.sigs"),
            (Format::Elf, Machine::X86_64) => include_bytes!("../data/elf-x86_64.sigs"),
            (Format::Elf, Machine::Aarch64) => include_bytes!("../data/elf-aarch64.sigs"),
            _ => &[0; 8],
        };
        Signatures::read(table).expect("built-in signature tables are well formed")
    }

    /// The table in `bytes`, or `None` when they are not laid out as one.
    pub fn read(bytes: &'a [u8]) -> Option<Signatures<'a>> {
        let (outlines, rest) = bytes.split_first_chunk::<4>()?;
        let (count, rest) = rest.split_first_chunk::<4>()?;
        let count = u32::from_le_bytes(*count) as usize;
        let (outlines, rest) = rest.split_at_checked(u32::from_le_bytes(*outlines) as usize * 4)?;
        let (hashes, rest) = rest.split_at_checked(count * 8)?;
        let (ends, names) = rest.split_at_checked(count * 4)?;
        (count == 0 || number(ends, 4, count - 1) == names.len() as u64).then_some(Signatures { outlines, hashes, ends, names })
    }

    /// The bytes of a table of `(fingerprint, outline, name)` entries, which must be in
    /// ascending order of fingerprint.
    pub fn write(entries: &[(u64, u32, &str)]) -> Vec<u8> {
        let mut outlines: Vec<u32> = entries.iter().map(|entry| entry.1).collect();
        outlines.sort_unstable();
        outlines.dedup();
        let mut table = (outlines.len() as u32).to_le_bytes().to_vec();
        table.extend((entries.len() as u32).to_le_bytes());
        table.extend(outlines.into_iter().flat_map(u32::to_le_bytes));
        table.extend(entries.iter().flat_map(|entry| entry.0.to_le_bytes()));
        let mut end = 0;
        for entry in entries {
            end += entry.2.len() as u32;
            table.extend(end.to_le_bytes());
        }
        table.extend(entries.iter().flat_map(|entry| entry.2.bytes()));
        table
    }

    /// The name of the library function with this fingerprint.
    pub fn name(&self, fingerprint: u64) -> Option<&'a str> {
        let index = lower_bound(self.hashes, 8, fingerprint);
        if index == self.len() || number(self.hashes, 8, index) != fingerprint {
            return None;
        }
        let start = if index == 0 { 0 } else { number(self.ends, 4, index - 1) };
        std::str::from_utf8(self.names.get(start as usize..number(self.ends, 4, index) as usize)?).ok()
    }

    /// The name of the library function occupying `[start, end)`, if it is one the table knows.
    /// The function is only decoded when its outline is that of some function in the table.
    pub fn recognise(&self, image: &Image, pointer_slots: &FxHashMap<u64, u64>, start: u64, end: u64) -> Option<&'a str> {
        let outline = u64::from(outline(image, start, end)?);
        let index = lower_bound(self.outlines, 4, outline);
        if index * 4 == self.outlines.len() || number(self.outlines, 4, index) != outline {
            return None;
        }
        self.name(fingerprint(image, pointer_slots, start, end)?)
    }

    pub fn len(&self) -> usize {
        self.hashes.len() / 8
    }

    pub fn is_empty(&self) -> bool {
        self.hashes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The fingerprint of a function at `start` made of `words` and then enough distinct `mov`
    /// instructions to be long enough.
    fn fingerprint_of(words: &[u32], start: u64) -> Option<u64> {
        let padding = (0..MIN_WORDS as u32).map(|n| 0xD280_0000 | n << 5);
        let bytes: Vec<u8> = words.iter().copied().chain(padding).flat_map(u32::to_le_bytes).collect();
        aarch64(&bytes, start, start + bytes.len() as u64, Some(MIN_WORDS), true)
    }

    #[test]
    fn aarch64_fingerprint_ignores_where_the_function_and_its_data_are() {
        // adrp x8, <page>; ldr x0, [x8, #off]; adrp x1, <page>; add x1, x1, #off; bl <callee>
        let here = [0x9000_0008, 0xF940_0500, 0xB000_0041, 0x9100_4021, 0x9400_0010];
        let there = [0xF000_0128, 0xF941_3100, 0x9000_0001, 0x9123_4021, 0x97FF_FF00];
        assert!(fingerprint_of(&here, 0x1000).is_some());
        assert_eq!(fingerprint_of(&here, 0x1000), fingerprint_of(&there, 0x7_3000));
    }

    #[test]
    fn aarch64_fingerprint_keeps_offsets_that_are_not_addresses() {
        // ldr x0, [x8, #8] against ldr x0, [x8, #16]: a field of whatever x8 points to.
        assert_ne!(fingerprint_of(&[0xF940_0500], 0x1000), fingerprint_of(&[0xF940_0900], 0x1000));
        // The same after x8 stopped holding a page: adrp x8; ldr x8, [x8]; ldr x0, [x8, #off].
        assert_ne!(
            fingerprint_of(&[0x9000_0008, 0xF940_0108, 0xF940_0500], 0x1000),
            fingerprint_of(&[0x9000_0008, 0xF940_0108, 0xF940_0900], 0x1000)
        );
        // cbz x0 to the next instruction against the one after: a branch inside the function.
        assert_ne!(fingerprint_of(&[0xB400_0020], 0x1000), fingerprint_of(&[0xB400_0040], 0x1000));
    }

    /// The body and shape hashes of `code` placed at `at`, beside 256 bytes of data at `data`,
    /// with a body of the whole of the code or of the ranges in it given.
    fn arm_hashes(machine: Machine, code: Vec<u8>, at: u64, data: u64, body: Option<&[(u64, u64)]>) -> (u64, u64) {
        let section = |name: &str, addr, data, executable| Section { name: name.into(), addr, data, file_offset: None, executable, writable: false };
        let whole = [(at, at + code.len() as u64)];
        let image = Image::bare(String::new(), Format::Elf, machine, at, vec![section(".text", at, code, true), section(".data", data, vec![0; 256], false)]);
        let body: Vec<(u64, u64)> = body.map_or(whole.to_vec(), |body| body.iter().map(|&(start, end)| (at + start, at + end)).collect());
        hashes(&image, &FxHashMap::default(), &body).unwrap()
    }

    /// The `MOVW` or, with `top`, the `MOVT` of `value` into `rd`.
    fn a32_half(rd: u32, value: u32, top: bool) -> u32 {
        0xE300_0000 | u32::from(top) << 22 | (value >> 12 & 15) << 16 | rd << 12 | value & 0xFFF
    }

    /// Where the functions below call, which stays put while they move.
    const CALLEE: u64 = 0x8000;

    /// An A32 function at `at` that calls `CALLEE`, builds an address in `data` with `MOVW` and
    /// `MOVT`, loads another from its literal pool, and moves `constant` into r2.
    fn a32_function(at: u64, data: u64, constant: u32) -> Vec<u8> {
        let call = 0xEB00_0000 | (CALLEE.wrapping_sub(at + 16 + 8) >> 2) as u32 & 0xFF_FFFF;
        let words = [
            0xE92D_4010,                                   // push {r4, lr}
            0xE59F_0010,                                   // ldr r0, [pc, #16]: the pool word
            a32_half(1, data as u32 + 0x10, false),        // movw r1
            a32_half(1, (data as u32 + 0x10) >> 16, true), // movt r1
            call,                                          // bl
            0xE3A0_2000 | constant,                        // mov r2, #constant
            0xE8BD_8010,                                   // pop {r4, pc}
            data as u32 + 0x20,
        ];
        words.into_iter().flat_map(u32::to_le_bytes).collect()
    }

    /// The same in Thumb, with `BL` as a pair of halfwords and a word-aligned pool.
    fn thumb_function(at: u64, data: u64, constant: u32) -> Vec<u8> {
        let half = |opcode: u16, value: u32| [opcode | (value >> 1 & 0x400) as u16 | (value >> 12 & 15) as u16, ((value & 0x700) << 4 | 1 << 8 | value & 0xFF) as u16];
        let offset = CALLEE.wrapping_sub(at + 12 + 4) as u32;
        let (s, i1, i2) = (offset >> 24 & 1, offset >> 23 & 1, offset >> 22 & 1);
        let call = [(0xF000 | s << 10 | offset >> 12 & 0x3FF) as u16, (0xD000 | ((1 - i1) ^ s) << 13 | ((1 - i2) ^ s) << 11 | offset >> 1 & 0x7FF) as u16];
        let address = data as u32 + 0x10;
        let pool = data as u32 + 0x20;
        let halfwords = [
            [0xB510, 0x4804],                   // push {r4, lr}; ldr r0, [pc, #16]
            half(0xF240, address & 0xFFFF),     // movw r1
            half(0xF2C0, address >> 16),        // movt r1
            call,                               // bl
            [0x2200 | constant as u16, 0xBD10], // movs r2, #constant; pop {r4, pc}
            [pool as u16, (pool >> 16) as u16],
        ];
        halfwords.into_iter().flatten().flat_map(u16::to_le_bytes).collect()
    }

    #[test]
    fn arm_hashes_ignore_where_the_function_and_its_data_are() {
        /// Builds a function at an address, with its data at another and a constant in it.
        type Build = fn(u64, u64, u32) -> Vec<u8>;
        let builds: [(Machine, Build); 2] = [(Machine::Arm, a32_function), (Machine::Thumb, thumb_function)];
        for (machine, build) in builds {
            let hashes = |at, data, constant| arm_hashes(machine, build(at, data, constant), at, data, None);
            let here = hashes(0x1_0000, 0x2_0000, 5);
            assert_eq!(here, hashes(0x1_4000, 0x3_1000, 5));
            // Another constant is another body of the same shape.
            let other = hashes(0x1_0000, 0x2_0000, 6);
            assert_ne!(here.0, other.0);
            assert_eq!(here.1, other.1);
        }
    }

    #[test]
    fn arm_hashes_keep_instructions_and_pooled_constants() {
        let (at, data) = (0x1_0000, 0x2_0000);
        let hashes = |code| arm_hashes(Machine::Arm, code, at, data, None);
        let mut code = a32_function(at, data, 5);
        let before = hashes(code.clone());
        // mov r2, #5 becomes mov r3, #5.
        code[20..24].copy_from_slice(&0xE3A0_3005u32.to_le_bytes());
        assert_ne!(before.1, hashes(code).1);
        // A pool word between the code and the data, which points at neither, is a number.
        let pooled = |word: u32| {
            let mut code = a32_function(at, data, 5);
            code[28..32].copy_from_slice(&word.to_le_bytes());
            hashes(code).0
        };
        assert_ne!(pooled(0x1_8000), pooled(0x1_8004));
    }

    #[test]
    fn arm_hashes_pair_halves_and_skip_pools_across_a_jump_table() {
        // A body in two ranges around a table of case addresses. The first sets r2 to
        // `constant` and then to the low half of an address, whose top half the second range
        // sets. The second holds a pool word, an address, that a load after it reads.
        let build = |at: u64, data: u64, constant: u32| {
            let address = data as u32 + 0x10;
            let words = [
                a32_half(2, constant, false),
                a32_half(2, address & 0xFFFF, false),
                0xE79F_F103,                           // ldr pc, [pc, r3, lsl #2]
                at as u32 + 20,                        // the table
                at as u32 + 28,
                a32_half(2, address >> 16, true),
                data as u32 + 0x20,                    // the pool
                0xE51F_000C,                           // ldr r0, [pc, #-12]
                0xE12F_FF1E,                           // bx lr
            ];
            words.into_iter().flat_map(u32::to_le_bytes).collect::<Vec<u8>>()
        };
        let hashes = |at, data, constant| arm_hashes(Machine::Arm, build(at, data, constant), at, data, Some(&[(0, 12), (20, 36)]));
        assert_eq!(hashes(0x1_0000, 0x2_0000, 5), hashes(0x1_4000, 0x3_1000, 5));
        assert_ne!(hashes(0x1_0000, 0x2_0000, 5).0, hashes(0x1_0000, 0x2_0000, 6).0);
    }

    #[test]
    fn arm_hashes_keep_code_that_a_pool_read_as_a_load_seemed_to_cover() {
        // Thumb: a pool that only the load after it reads, whose first halfword reads as
        // ldr r0, [pc, #4], a load from the movs r1 after the load.
        let build = |constant: u16| {
            let halfwords = [
                0xE002, 0xBF00,         // b past the pool; nop
                0x4801, 0x0002,         // the pool
                0xF85F, 0x0008,         // ldr.w r0, [pc, #-8]
                0x2100 | constant,      // movs r1, #constant
                0x2203, 0x4770, 0xBF00, // movs r2, #3; bx lr; nop
            ];
            halfwords.into_iter().flat_map(u16::to_le_bytes).collect::<Vec<u8>>()
        };
        let hashes = |constant| arm_hashes(Machine::Thumb, build(constant), 0x1_0000, 0x2_0000, None);
        assert_ne!(hashes(5).0, hashes(6).0);
    }

    #[test]
    fn arm_hashes_keep_code_that_a_pool_read_as_a_load_seemed_to_read() {
        // A32: a pool that only the load after it reads, which reads as ldr r0, [pc, #-16], a
        // load from the mov r1 before it. A pass decodes through both; the pass after skips
        // both, and finds that no load it decoded reads the mov.
        let build = |constant: u32| {
            let words = [
                0xE3A0_1000 | constant, // mov r1, #constant
                0xEA00_0000,            // b past the pool
                0xE51F_0010,            // the pool
                0xE51F_200C,            // ldr r2, [pc, #-12]
                0xE12F_FF1E,            // bx lr
            ];
            words.into_iter().flat_map(u32::to_le_bytes).collect::<Vec<u8>>()
        };
        let hashes = |constant| arm_hashes(Machine::Arm, build(constant), 0x1_0000, 0x2_0000, None);
        assert_ne!(hashes(5).0, hashes(6).0);
    }

    #[test]
    fn arm_hashes_mask_offsets_the_code_adds_the_pc_to_and_sram() {
        // A word loaded from the pool after the code, `data + 0x10` less the PC that the
        // `ADD` after the load adds to it, or with `pc` false that much from 0x2000_0000.
        let a32 = |at: u64, data: u64, pc: bool| {
            let add = if pc { 0xE08F_3003 } else { 0xE081_3003 }; // add r3, pc, r3 or add r3, r1, r3
            let word = (data + 0x10).wrapping_sub(at + 12) as u32;
            [0xE59F_3004, add, 0xE12F_FF1E, word].into_iter().flat_map(u32::to_le_bytes).collect::<Vec<u8>>()
        };
        let thumb = |at: u64, data: u64, pc: bool| {
            // ldr r3, [pc, #4]; add r3, pc or add r3, r1; bx lr; nop; and the word.
            let word = if pc { (data + 0x10).wrapping_sub(at + 6) as u32 } else { 0x2000_0000 + (data as u32 & 0xFFFF) };
            let halfwords = [0x4B01, if pc { 0x447B } else { 0x440B }, 0x4770, 0xBF00, word as u16, (word >> 16) as u16];
            halfwords.into_iter().flat_map(u16::to_le_bytes).collect::<Vec<u8>>()
        };
        // ldr r3, [pc, r3] or, taking it away, ldr r3, [pc, -r3], where the add was.
        let load = |up: bool| {
            move |at: u64, data: u64, _| {
                let word = (data + 0x10).wrapping_sub(at + 12) as u32;
                [0xE59F_3004, if up { 0xE79F_3003 } else { 0xE71F_3003 }, 0xE12F_FF1E, word].into_iter().flat_map(u32::to_le_bytes).collect::<Vec<u8>>()
            }
        };
        let (up, down) = (load(true), load(false));
        type Build<'a> = &'a dyn Fn(u64, u64, bool) -> Vec<u8>;
        let builds: [(Machine, Build, bool); 4] = [(Machine::Arm, &a32, true), (Machine::Arm, &up, true), (Machine::Thumb, &thumb, true), (Machine::Thumb, &thumb, false)];
        for (machine, build, pc) in builds {
            let hashes = |at, data| arm_hashes(machine, build(at, data, pc), at, data, None);
            assert_eq!(hashes(0x1_0000, 0x9_0000), hashes(0x1_4000, 0xA_1000));
        }
        // Without the PC added the word is a number.
        let unadded: [&dyn Fn(u64, u64, bool) -> Vec<u8>; 2] = [&a32, &down];
        for build in unadded {
            let hashes = |at, data| arm_hashes(Machine::Arm, build(at, data, false), at, data, None);
            assert_ne!(hashes(0x1_0000, 0x9_0000).0, hashes(0x1_4000, 0xA_1000).0);
        }
    }

    #[test]
    fn arm_hashes_in_position_independent_code_mask_offsets_from_the_got_only() {
        // ldr r2, [pc, #4]; ldr r2, [r3, r2]; bx lr; and a word: a slot of the table at
        // 0x3_0000 that r3 holds, or a number.
        let hashes = |word: u32| {
            let code: Vec<u8> = [0xE59F_2004, 0xE793_2002, 0xE12F_FF1E, word].into_iter().flat_map(u32::to_le_bytes).collect();
            let section = |name: &str, addr, data: Vec<u8>, executable| Section { name: name.into(), addr, data, file_offset: None, executable, writable: false };
            let mut image = Image::bare(String::new(), Format::Elf, Machine::Arm, 0x1_0000, vec![section(".text", 0x1_0000, code, true), section(".got", 0x3_0000, vec![0; 0x100], false)]);
            image.relative_targets.push((0x3_0000, 0x1_0000));
            hashes(&image, &FxHashMap::default(), &[(0x1_0000, 0x1_0010)]).unwrap().0
        };
        assert_eq!(hashes(0x10), hashes(0x20));
        assert_ne!(hashes(0x1234), hashes(0x1238));
        // Numbers that would be addresses in code linked to one address.
        assert_ne!(hashes(0x1_0004), hashes(0x1_0008));
    }

    #[test]
    fn a_written_table_gives_each_fingerprint_its_name() {
        let bytes = Signatures::write(&[(3, 0x4055, "memcpy"), (0x8000_0000_0000_0001, 0x2041, "core::fmt::write"), (u64::MAX, 0x4055, "_start")]);
        let table = Signatures::read(&bytes).unwrap();
        assert_eq!(table.len(), 3);
        assert_eq!(table.name(3), Some("memcpy"));
        assert_eq!(table.name(0x8000_0000_0000_0001), Some("core::fmt::write"));
        assert_eq!(table.name(u64::MAX), Some("_start"));
        assert_eq!(table.name(4), None);
        assert!(Signatures::read(&bytes[..bytes.len() - 1]).is_none());
    }

    #[test]
    fn built_in_tables_are_sorted_so_every_entry_is_found() {
        for (format, machine) in [(Format::Pe, Machine::X86), (Format::Pe, Machine::X86_64), (Format::Elf, Machine::X86_64), (Format::Elf, Machine::Aarch64)] {
            let table = Signatures::builtin(format, machine);
            assert!(!table.is_empty());
            let hash = |index| number(table.hashes, 8, index);
            assert!((1..table.len()).all(|index| hash(index - 1) < hash(index)));
            assert!((0..table.len()).all(|index| table.name(hash(index)).is_some_and(|name| !name.is_empty())));
            assert!((1..table.outlines.len() / 4).all(|index| number(table.outlines, 4, index - 1) < number(table.outlines, 4, index)));
        }
    }
}
