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

/// The fingerprint of the function occupying `[start, end)`, or `None` when it is too small to
/// be distinctive.
pub fn fingerprint(image: &Image, pointer_slots: &FxHashMap<u64, u64>, start: u64, end: u64) -> Option<u64> {
    if end.checked_sub(start)? < MIN_BYTES {
        return None;
    }
    let bytes = image.bytes_from(start)?;
    let bytes = bytes.get(..(end - start) as usize)?;
    match image.machine {
        Machine::X86 => x86(32, bytes, pointer_slots, start, end),
        Machine::X86_64 => x86(64, bytes, pointer_slots, start, end),
        Machine::Aarch64 => aarch64(bytes, start, end),
    }
}

/// An x86 function: displacements and immediates are blanked where they are relative to the
/// instruction pointer and leave the function, or where the loader relocates them.
fn x86(bits: u32, bytes: &[u8], pointer_slots: &FxHashMap<u64, u64>, start: u64, end: u64) -> Option<u64> {
    let mut decoder = Decoder::with_ip(bits, bytes, start, DecoderOptions::NONE);

    let mut hash = Hash::new();
    let mut instructions = 0;

    while decoder.can_decode() {
        let offset = decoder.position();
        let instr = decoder.decode();
        if instr.is_invalid() {
            return None;
        }
        instructions += 1;
        let offsets = decoder.get_constant_offsets(&instr);
        let raw = &bytes[offset..offset + instr.len()];

        // Which bytes of the instruction hold an address that moves between binaries.
        let mut blank = [false; 16];
        let mut mark = |at: usize, size: usize| blank[at..(at + size).min(16)].iter_mut().for_each(|b| *b = true);
        let leaves = |target: u64| target < start || target >= end;

        if offsets.has_displacement() {
            let at = offsets.displacement_offset();
            let relocated = pointer_slots.contains_key(&(instr.ip() + at as u64));
            if instr.is_ip_rel_memory_operand() || relocated {
                mark(at, offsets.displacement_size());
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
            if relocated || external {
                mark(at, offsets.immediate_size());
            }
        }
        for (index, &byte) in raw.iter().enumerate() {
            hash.feed(if blank[index] { 0 } else { byte });
        }
    }
    (instructions >= MIN_INSTRUCTIONS).then_some(hash.0)
}

/// An AArch64 function, a word at a time. Blanked are the offsets of calls and of branches and
/// literal loads that leave the function, the address `adr` or `adrp` forms, and the low twelve
/// bits an `add`, load or store then adds to a page. Which registers hold a page is followed
/// along the instructions in address order, which is all the pairing compilers emit needs.
fn aarch64(bytes: &[u8], start: u64, end: u64) -> Option<u64> {
    const OFFSET_26: u32 = 0x03FF_FFFF;
    const OFFSET_19: u32 = 0x00FF_FFE0;
    const OFFSET_14: u32 = 0x0007_FFE0;
    const PC_RELATIVE: u32 = 0x60FF_FFE0;
    const LOW_12: u32 = 0x003F_FC00;
    /// The registers a call may change: `x0` to `x18` and the link register.
    const CALLER_SAVED: u32 = 0x4007_FFFF;

    if bytes.len() / 4 < MIN_WORDS {
        return None;
    }
    let mut hash: u64 = 0;
    // Bit `n` is set while register `n` holds a page address.
    let mut pages: u32 = 0;
    for (index, chunk) in bytes.chunks_exact(4).enumerate() {
        let word = u32::from_le_bytes(chunk.try_into().unwrap());
        let (rd, rn) = (word & 31, word >> 5 & 31);
        // Whether the branch offset in the bits of `field`, counted in words, leaves the function.
        let leaves = |field: u32| {
            let unused = 64 - field.count_ones();
            let offset = (i64::from((word & field) >> field.trailing_zeros()) << unused >> unused) * 4;
            let target = (start + index as u64 * 4).wrapping_add_signed(offset);
            target < start || target >= end
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
        hash = (hash.rotate_left(5) ^ u64::from(word & !blank)).wrapping_mul(0x517c_c1b7_2722_0a95);
    }
    Some(hash)
}

/// Known fingerprints and the library function each belongs to: a table that is searched where
/// it lies, so a program pays nothing to load it and touches only the pages a search reaches.
///
/// The table is a count `n` in four bytes, `n` fingerprints of eight bytes each in ascending
/// order, `n` offsets of four bytes each giving where each name ends, and the names back to
/// back. All numbers are little-endian. `recore-corpus signatures` writes one.
pub struct Signatures<'a> {
    hashes: &'a [u8],
    ends: &'a [u8],
    names: &'a [u8],
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
            _ => &[0; 4],
        };
        Signatures::read(table).expect("built-in signature tables are well formed")
    }

    /// The table in `bytes`, or `None` when they are not laid out as one.
    pub fn read(bytes: &'a [u8]) -> Option<Signatures<'a>> {
        let (count, rest) = bytes.split_first_chunk::<4>()?;
        let count = u32::from_le_bytes(*count) as usize;
        let (hashes, rest) = rest.split_at_checked(count * 8)?;
        let (ends, names) = rest.split_at_checked(count * 4)?;
        let table = Signatures { hashes, ends, names };
        (count == 0 || table.end(count - 1) == names.len()).then_some(table)
    }

    /// The bytes of a table holding `entries`, which must be in ascending order of fingerprint.
    pub fn write<'n>(entries: impl Iterator<Item = (u64, &'n str)> + Clone) -> Vec<u8> {
        let mut table = (entries.clone().count() as u32).to_le_bytes().to_vec();
        table.extend(entries.clone().flat_map(|(hash, _)| hash.to_le_bytes()));
        let mut end = 0;
        for (_, name) in entries.clone() {
            end += name.len() as u32;
            table.extend(end.to_le_bytes());
        }
        table.extend(entries.flat_map(|(_, name)| name.bytes()));
        table
    }

    fn hash(&self, index: usize) -> u64 {
        u64::from_le_bytes(self.hashes[index * 8..][..8].try_into().unwrap())
    }

    fn end(&self, index: usize) -> usize {
        u32::from_le_bytes(self.ends[index * 4..][..4].try_into().unwrap()) as usize
    }

    /// The name of the library function with this fingerprint.
    pub fn name(&self, fingerprint: u64) -> Option<&'a str> {
        let (mut low, mut high) = (0, self.len());
        while low < high {
            let middle = (low + high) / 2;
            if self.hash(middle) < fingerprint {
                low = middle + 1;
            } else {
                high = middle;
            }
        }
        if low == self.len() || self.hash(low) != fingerprint {
            return None;
        }
        let start = if low == 0 { 0 } else { self.end(low - 1) };
        std::str::from_utf8(self.names.get(start..self.end(low))?).ok()
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
        aarch64(&bytes, start, start + bytes.len() as u64)
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
        let entries = [(3, "memcpy"), (0x8000_0000_0000_0001, "core::fmt::write"), (u64::MAX, "_start")];
        let bytes = Signatures::write(entries.iter().copied());
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
            assert!((1..table.len()).all(|index| table.hash(index - 1) < table.hash(index)));
            assert!((0..table.len()).all(|index| table.name(table.hash(index)).is_some_and(|name| !name.is_empty())));
        }
    }
}
