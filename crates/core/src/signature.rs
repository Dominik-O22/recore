//! Position-independent fingerprints of function bodies, for recognising library code.
//!
//! A statically linked C runtime puts the same compiled functions into many binaries. The bytes
//! differ only where they hold addresses, so hashing the instructions with those fields blanked
//! gives a fingerprint that matches across binaries built with the same compiler and library.

use rustc_hash::FxHashMap;

use iced_x86::{Decoder, DecoderOptions, FlowControl, OpKind};

use crate::image::{Format, Image, Machine};

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
        Machine::I8051 | Machine::Thumb => None,
    }
}

/// The fingerprint of the code in `[start, end)` however short it is: equal for two builds of
/// one function that differ only in where they and what they refer to were linked, and in the
/// padding that aligns their loops. Short functions share theirs, so it identifies nothing by
/// itself.
pub fn body_hash(image: &Image, pointer_slots: &FxHashMap<u64, u64>, start: u64, end: u64) -> Option<u64> {
    whole(image, pointer_slots, start, end, true)
}

/// [`body_hash`] with every number in the code left out as well: the constants, and the
/// offsets of the fields and stack slots it reaches. Two builds of a function with this in
/// common and not their [`body_hash`] are the same instructions over different numbers, as
/// when a structure the function uses gained a field.
pub fn shape_hash(image: &Image, pointer_slots: &FxHashMap<u64, u64>, start: u64, end: u64) -> Option<u64> {
    whole(image, pointer_slots, start, end, false)
}

fn whole(image: &Image, pointer_slots: &FxHashMap<u64, u64>, start: u64, end: u64, numbers: bool) -> Option<u64> {
    let bytes = image.bytes_from(start)?.get(..end.checked_sub(start)? as usize)?;
    match image.machine {
        Machine::X86 => x86(32, bytes, pointer_slots, start, end, None, numbers, None),
        Machine::X86_64 => x86(64, bytes, pointer_slots, start, end, None, numbers, None),
        Machine::Aarch64 => aarch64(bytes, start, end, None, numbers),
        // Not fingerprinted yet: nothing says which of their bytes are addresses.
        Machine::I8051 | Machine::Thumb => None,
    }
}

/// The numbers in the code of `[start, end)` that [`shape_hash`] leaves out and [`body_hash`]
/// keeps, in the order of the instructions: where two builds share a shape and not a body,
/// these say what differs. Empty for code other than x86.
pub fn numbers(image: &Image, pointer_slots: &FxHashMap<u64, u64>, start: u64, end: u64) -> Vec<u64> {
    let mut found = Vec::new();
    if let Some(bytes) = image.bytes_from(start).and_then(|bytes| bytes.get(..end.checked_sub(start)? as usize)) {
        match image.machine {
            Machine::X86 => drop(x86(32, bytes, pointer_slots, start, end, None, true, Some(&mut found))),
            Machine::X86_64 => drop(x86(64, bytes, pointer_slots, start, end, None, true, Some(&mut found))),
            Machine::Aarch64 | Machine::I8051 | Machine::Thumb => {}
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
    let words = || bytes.chunks_exact(4).map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()));
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
