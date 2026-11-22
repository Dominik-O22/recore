//! The tables a Linux kernel or module keeps of the code it patches at boot or while it runs,
//! and what each says about that code. Each is a section the kernel's build names, which a
//! stripped file keeps, and [`crate::relocatable::link`] keeps a module's.
//! - `__jump_table` lists each jump label: an instruction the kernel turns from a `nop` into a
//!   jump or back, and where it then jumps. Built for arm64 before 5.10, an entry holds absolute
//!   pointers, which relocations make pointers into code, each inside a function.
//! - `.altinstructions` lists each alternative: instructions the kernel overwrites with others
//!   on a CPU that has some feature. arm64 since 5.10 assembles the others into the code
//!   section, after the function, where they never run.
//! - `__bug_table` lists the trap of each `BUG()` and `WARN()`. After a warning's, the kernel
//!   goes on.
//!
//! Built with Clang's kCFI, a kernel or module also puts the hash of a function's type in the
//! word before each function whose address it takes, where a call through a pointer checks it.
//! A module's `$d` mapping symbols mark each as data. Where nothing marks them, as in a stripped
//! `vmlinux` or a raw `Image`, [`kcfi_hashes`] finds them.

use std::collections::HashSet;

use rustc_hash::FxHashSet;

use crate::arch::{Arch, Flow};
use crate::arm64::{Arm64, Insn, State};
use crate::image::{Image, Machine, Section};

/// `struct jump_entry` with absolute pointers: the label's instruction, where it jumps, its key.
const JUMP_ENTRY: u64 = 24;

/// arm64's `struct alt_instr`: the offsets of the original and of the replacement from their
/// fields, the CPU feature, then the length of each in bytes.
const ALT_INSTR: usize = 12;

/// The layouts of `struct bug_entry` with relative pointers, as arm64 and x86-64 build it, as
/// (entry size, offset of the flags). Each opens with the offset of the trap from the entry;
/// built with `CONFIG_DEBUG_BUGVERBOSE`, the file name's offset and the line follow it.
const BUG_ENTRIES: [(usize, usize); 2] = [(12, 10), (8, 4)];

/// The flag of a `bug_entry` that a `WARN()` made.
const BUGFLAG_WARNING: u16 = 1;

/// Reads the tables an ELF or raw `image` has into what the analysis reads: drops the pointers
/// `__jump_table` relocates from `relative_targets`, and sets `replacement_code` and
/// `resuming_traps`. A table whose layout the reader cannot establish is left unread. Where no
/// mapping symbol marks data among arm64 code, the kCFI hashes become `marked_data`.
pub(crate) fn read(image: &mut Image) {
    if !matches!(image.machine, Machine::Aarch64 | Machine::X86_64) {
        return;
    }
    if let Some(labels) = jump_labels(image) {
        image.relative_targets.retain(|(slot, _)| !labels.contains(slot));
    }
    if image.machine == Machine::Aarch64 {
        image.replacement_code = replacements(image);
        if image.marked_data.is_empty() && is_kernel(image) {
            image.marked_data = kcfi_hashes(image);
        }
    }
    image.resuming_traps = warnings(image);
}

fn section<'a>(image: &'a Image, name: &str) -> Option<&'a Section> {
    image.sections.iter().find(|s| s.name == name)
}

/// The slots of `__jump_table` that hold a jump label's instruction or where it jumps. The
/// layout holds when the table is whole entries and both of those are pointers into code in each.
fn jump_labels(image: &Image) -> Option<HashSet<u64>> {
    // Whole entries first: an entry's two slots then lie inside the table, whatever its address.
    let table = section(image, "__jump_table").filter(|s| (s.data.len() as u64).is_multiple_of(JUMP_ENTRY)).map(|s| s.addr..s.end())?;
    let into_code: HashSet<u64> = image.relative_targets.iter().filter(|&&(slot, target)| table.contains(&slot) && image.is_code(target)).map(|&(slot, _)| slot).collect();
    let labels: HashSet<u64> = table.clone().step_by(JUMP_ENTRY as usize).flat_map(|entry| [entry, entry + 8]).collect();
    labels.is_subset(&into_code).then_some(labels)
}

/// Where the offset the tables store at `place`, 32 bits from that place, points.
fn pointer(place: u64, offset: &[u8]) -> u64 {
    place.wrapping_add_signed(i64::from(i32::from_le_bytes(offset[..4].try_into().unwrap())))
}

/// `[start, end)` of each replacement arm64's `.altinstructions` places in code, sorted. The
/// layout holds when every original is a word of code and every replacement as long as its
/// original, as the build makes it, or empty, where a function of the kernel writes the code. A
/// replacement elsewhere, as before 5.10 in a section of its own that is not code, is left alone.
fn replacements(image: &Image) -> Vec<(u64, u64)> {
    let Some(table) = section(image, ".altinstructions").filter(|s| s.data.len().is_multiple_of(ALT_INSTR)) else { return Vec::new() };
    let mut ranges = Vec::new();
    for (index, entry) in table.data.as_chunks::<ALT_INSTR>().0.iter().enumerate() {
        let at = table.addr + (index * ALT_INSTR) as u64;
        let (original, replacement, length) = (pointer(at, &entry[..4]), pointer(at + 4, &entry[4..8]), u64::from(entry[11]));
        if !original.is_multiple_of(4) || !image.is_code(original) || !length.is_multiple_of(4) || (length > 0 && entry[10] != entry[11]) {
            return Vec::new();
        }
        if length > 0 && image.section_at(replacement).is_some_and(|s| s.executable && s.contains(replacement.saturating_add(length - 1))) {
            ranges.push((replacement, replacement + length));
        }
    }
    ranges.sort_unstable();
    ranges
}

/// The traps of the warnings `__bug_table` lists, sorted. Of the layouts, the one where every
/// entry finds a trap is the table's.
fn warnings(image: &Image) -> Vec<u64> {
    let Some(table) = section(image, "__bug_table") else { return Vec::new() };
    let is_trap = |addr: u64| {
        let bytes = image.bytes_from(addr).unwrap_or_default();
        match image.machine {
            // `brk`
            Machine::Aarch64 => bytes.get(..4).is_some_and(|word| u32::from_le_bytes(word.try_into().unwrap()) & 0xFFE0_001F == 0xD420_0000),
            // `ud2`
            Machine::X86_64 => bytes.starts_with(&[0x0f, 0x0b]),
            _ => false,
        }
    };
    let read = |(size, flags): (usize, usize)| {
        if !table.data.len().is_multiple_of(size) {
            return None;
        }
        let mut warnings = Vec::new();
        for (index, entry) in table.data.chunks_exact(size).enumerate() {
            let trap = pointer(table.addr + (index * size) as u64, entry);
            if !is_trap(trap) {
                return None;
            }
            if u16::from_le_bytes([entry[flags], entry[flags + 1]]) & BUGFLAG_WARNING != 0 {
                warnings.push(trap);
            }
        }
        Some(warnings)
    };
    let mut warnings = BUG_ENTRIES.into_iter().find_map(read).unwrap_or_default();
    warnings.sort_unstable();
    warnings
}

/// What arm64's Linux image header holds at 0x38: `ARM\x64`.
const IMAGE_MAGIC: [u8; 4] = *b"ARMd";

/// Whether `image` is an arm64 Linux kernel's, whose `.head.text`, and the raw `Image` made from
/// it, open with the image header. Only a kernel has kCFI hashes that nothing marks, and only it
/// pays to look for them.
fn is_kernel(image: &Image) -> bool {
    image.sections.iter().any(|section| section.data.get(0x38..0x3c) == Some(&IMAGE_MAGIC[..]))
}

/// kCFI's trap on arm64: `brk` with 0x8000 and up, the register that holds the hash the call
/// expects at bit 5 and the one that holds the target at bit 0.
const KCFI_TRAP: u32 = 0xD430_0000;
const KCFI_TRAP_MASK: u32 = 0xFFFF_801F;

/// `movk wN, #imm` and `movk wN, #imm, lsl #16`, without their operands.
const MOVK_LOW: u32 = 0x7280_0000;
const MOVK_HIGH: u32 = 0x72A0_0000;
const MOVK_MASK: u32 = 0xFFE0_001F;

/// The hashes kCFI's checks in arm64 code expect. Before a call through a pointer, Clang loads
/// the hash before the target, the one the call expects, compares them, and traps if they differ:
///
/// ```text
/// ldur wA, [xN, #-4]
/// movk wB, #low
/// movk wB, #high, lsl #16
/// cmp  wA, wB
/// b.eq 1f
/// brk  #(0x8000 | B << 5 | N)
/// ```
fn checked_hashes(image: &Image) -> FxHashSet<u32> {
    let mut hashes = FxHashSet::default();
    for section in image.sections.iter().filter(|s| s.executable && s.addr.is_multiple_of(4)) {
        let words = section.data.as_chunks::<4>().0;
        let word = |index: usize| words.get(index).map(|bytes| u32::from_le_bytes(*bytes));
        for at in memchr::memmem::find_iter(&section.data, &KCFI_TRAP.to_le_bytes()[2..]).filter(|at| at % 4 == 2) {
            let index = at / 4;
            let Some(trap) = word(index).filter(|trap| trap & KCFI_TRAP_MASK == KCFI_TRAP) else { continue };
            let register = trap >> 10 & 31;
            let (Some(low), Some(high)) = (index.checked_sub(4).and_then(word), index.checked_sub(3).and_then(word)) else { continue };
            if low & MOVK_MASK == MOVK_LOW | register && high & MOVK_MASK == MOVK_HIGH | register {
                hashes.insert(low >> 5 & 0xFFFF | (high >> 5 & 0xFFFF) << 16);
            }
        }
    }
    hashes
}

/// How far forward a function that tests an argument before `paciasp` jumps at most: in GKI
/// 6.12, as far as 108 of 115 such tests, and 48 of 1,223 hashes read as a conditional branch.
const ARGUMENT_TEST_REACH: u64 = 4096;

/// `[start, end)` of each kCFI hash in arm64 code, sorted, for code no mapping symbol marks. Empty
/// for code without kCFI's checks.
///
/// A word that holds a hash a check expects is one. A function that no call through a pointer
/// in the image reaches has a hash no check expects, as an exported function only modules call
/// does: there, a word that follows code that ends and comes before an entry marker such as
/// `paciasp` is one, unless it may be code. Code that ends is a jump, a return, a trap, a call
/// that may not return, or the replacement code of an alternative, which never runs where it
/// lies. A word before the marker may be the end of such code, or the first instruction of a
/// function that tests an argument before it saves its return address: a conditional branch a
/// short way forward, past the marker. A hash read as a branch goes anywhere.
fn kcfi_hashes(image: &Image) -> Vec<(u64, u64)> {
    let checked = checked_hashes(image);
    if checked.is_empty() {
        return Vec::new();
    }
    let state = State::default();
    let flow = |insn: &Insn| Arm64::flow(insn, &state, image);
    let may_be_code = |insn: &Insn| match flow(insn) {
        None => false,
        Some(Flow::Branch(target)) => target > insn.addr && target - insn.addr <= ARGUMENT_TEST_REACH,
        Some(_) => true,
    };
    let mut replacements = image.replacement_code.iter().peekable();
    let mut hashes = Vec::new();
    for section in image.sections.iter().filter(|s| s.executable && s.addr.is_multiple_of(4)) {
        let words = section.data.as_chunks::<4>().0;
        let insn = |index: usize, addr: u64| words.get(index).map(|bytes| Insn { word: u32::from_le_bytes(*bytes), addr });
        // Whether what came last, padding aside, ends code.
        let mut after_break = false;
        for index in 0..words.len() {
            let addr = section.addr.saturating_add(4 * index as u64);
            while replacements.next_if(|&&(_, end)| end <= addr).is_some() {}
            if replacements.peek().is_some_and(|&&(start, _)| start <= addr) {
                after_break = true;
                continue;
            }
            let Some(word) = insn(index, addr).filter(|word| !Arm64::is_padding(word)) else { continue };
            let before_entry = || insn(index + 1, addr.saturating_add(4)).is_some_and(|next| Arm64::is_entry_marker(&next));
            if checked.contains(&word.word) || after_break && !may_be_code(&word) && before_entry() {
                hashes.push((addr, addr.saturating_add(4)));
                after_break = false;
            } else {
                after_break = flow(&word).is_some_and(|flow| !matches!(flow, Flow::Branch(_)));
            }
        }
    }
    hashes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image::Format;

    const TEXT: u64 = 0x1000;
    const TABLE: u64 = 0x2000;
    const DATA: u64 = 0x3000;
    const NOP: u32 = 0xd503_201f;
    const RET: u32 = 0xd65f_03c0;
    const MOV_X0_0: u32 = 0xd280_0000;
    const MOV_X0_1: u32 = 0xd280_0020;
    const BRK_0X800: u32 = 0xd421_0000;
    const PACIASP: u32 = 0xd503_233f;
    const AUTIASP: u32 = 0xd503_23bf;

    fn bl(from: u64, to: u64) -> u32 {
        0x9400_0000 | (to.wrapping_sub(from) >> 2) as u32 & 0x03ff_ffff
    }

    /// An arm64 module of `code` from [`TEXT`], entered there, with `table` at [`TABLE`] in a
    /// section named `name`, and 8 bytes of data at [`DATA`], read as [`Image::parse`] reads one.
    fn module(code: &[u32], name: &str, table: Vec<u8>, relative_targets: Vec<(u64, u64)>) -> Image {
        let section = |name: &str, addr: u64, data: Vec<u8>, executable: bool| Section {
            name: name.into(),
            addr,
            data,
            file_offset: None,
            executable,
            writable: !executable,
        };
        let text = section(".text", TEXT, code.iter().flat_map(|word| word.to_le_bytes()).collect(), true);
        let sections = vec![text, section(name, TABLE, table, false), section(".data", DATA, vec![0; 8], false)];
        let mut image = Image { relative_targets, ..Image::bare("module".into(), Format::Elf, Machine::Aarch64, TEXT, sections) };
        read(&mut image);
        image
    }

    fn starts(image: &Image) -> Vec<u64> {
        crate::analyze(image).functions.iter().map(|f| f.addr).collect()
    }

    /// An absolute `jump_entry` points at a jump label's `nop` and at where it jumps, both inside
    /// one function, and at its key, which is data.
    #[test]
    fn a_jump_label_starts_no_function() {
        let code = [NOP, MOV_X0_0, RET, MOV_X0_1, RET];
        let entry = [TEXT, TEXT + 12, DATA];
        let table = entry.iter().flat_map(|pointer| pointer.to_le_bytes()).collect();
        let image = module(&code, "__jump_table", table, vec![(TABLE, TEXT), (TABLE + 8, TEXT + 12), (TABLE + 16, DATA)]);
        assert_eq!(starts(&image), vec![TEXT]);
        assert_eq!(image.relative_targets, vec![(TABLE + 16, DATA)]);
        // A section of that name whose entries are not of this layout keeps its pointers.
        let pointers = vec![(TABLE, TEXT), (TABLE + 8, DATA), (TABLE + 16, TEXT + 12)];
        assert_eq!(module(&code, "__jump_table", vec![0; 24], pointers.clone()).relative_targets, pointers);
        // So does one that is not whole entries, at the last address there is.
        let section = Section { name: "__jump_table".into(), addr: u64::MAX - 1, data: vec![0], file_offset: None, executable: false, writable: true };
        let mut image = Image::bare("module".into(), Format::Elf, Machine::Aarch64, 0, vec![section]);
        read(&mut image);
        assert!(image.relative_targets.is_empty());
    }

    /// The replacement for the first function's two words sits after it, and the function after
    /// that is found only where the code before it ends.
    #[test]
    fn an_alternatives_replacement_is_not_code() {
        let (first, replacement, second) = (TEXT + 8, TEXT + 16, TEXT + 24);
        let code = [bl(TEXT, first), RET, MOV_X0_0, RET, MOV_X0_1, NOP, PACIASP, MOV_X0_1, AUTIASP, RET];
        let mut entry = Vec::new();
        entry.extend((first.wrapping_sub(TABLE) as i32).to_le_bytes());
        entry.extend((replacement.wrapping_sub(TABLE + 4) as i32).to_le_bytes());
        entry.extend([0, 0, 8, 8]);
        let image = module(&code, ".altinstructions", entry, Vec::new());
        assert_eq!(image.replacement_code, vec![(replacement, replacement + 8)]);
        assert_eq!(starts(&image), vec![TEXT, first, second]);
    }

    /// A function that calls through a pointer checks the hash before the target, then the hash
    /// a function no check expects, then a function that opens with `paciasp`. Nothing calls
    /// either function, and neither hash marks itself. Last, a function without a hash tests an
    /// argument before `paciasp`. A section opens with the image header, as a kernel's does.
    #[test]
    fn kcfi_hashes_are_data_and_start_the_function_after_them() {
        let (checked, unchecked) = (0x77bf_192du32, 0x5e0f_3a91u32);
        let movk = |base: u32, half: u32| base | (half & 0xFFFF) << 5 | 17;
        let check = [
            0xb85f_c030, // ldur w16, [x1, #-4]
            movk(MOVK_LOW, checked),
            movk(MOVK_HIGH, checked >> 16),
            0x6b11_021f, // cmp w16, w17
            0x5400_0040, // b.eq +8
            0xd430_4420, // brk #0x8221
        ];
        let (first, second) = (TEXT + 36, TEXT + 48);
        let rest = [0xd63f_0020 /* blr x1 */, RET, checked, MOV_X0_1, RET, unchecked, PACIASP, MOV_X0_0, AUTIASP, RET];
        let tests_argument = [0xb400_0081 /* cbz x1, +16 */, PACIASP, MOV_X0_1, AUTIASP, RET];
        let code: Vec<u32> = check.into_iter().chain(rest).chain(tests_argument).collect();
        let kernel = |code: &[u32], header: bool| {
            let data = code.iter().flat_map(|word| word.to_le_bytes()).collect();
            let text = Section { name: ".text".into(), addr: TEXT, data, file_offset: None, executable: true, writable: false };
            let mut head = vec![0; 0x40];
            head[0x38..0x3c].copy_from_slice(if header { &IMAGE_MAGIC } else { b"ELF!" });
            let head = Section { name: ".head".into(), addr: TABLE, data: head, file_offset: None, executable: false, writable: false };
            let mut image = Image::bare("vmlinux".into(), Format::Elf, Machine::Aarch64, TEXT, vec![text, head]);
            read(&mut image);
            image
        };
        let image = kernel(&code, true);
        assert_eq!(image.marked_data, vec![(first - 4, first), (second - 4, second)]);
        assert_eq!(starts(&image), vec![TEXT, first, second]);
        // Without a check, or in a file that is no kernel, nothing is taken for a hash.
        let mut unchecked_code = code.clone();
        unchecked_code[5] = NOP;
        assert!(kernel(&unchecked_code, true).marked_data.is_empty());
        assert!(kernel(&code, false).marked_data.is_empty());
    }

    /// `WARN()` calls a function that returns, then traps, and the kernel goes on after the trap.
    /// After `BUG()`'s trap it does not: that trap still says the call before it never returns.
    #[test]
    fn a_warning_trap_says_nothing_of_the_call_before_it() {
        let (warns, bugs, warned, failed) = (TEXT + 12, TEXT + 24, TEXT + 36, TEXT + 44);
        let code =
            [bl(TEXT, warns), bl(TEXT + 4, bugs), RET, bl(warns, warned), BRK_0X800, RET, bl(bugs, failed), BRK_0X800, RET, MOV_X0_1, RET, MOV_X0_0, RET];
        let entry = |trap: u64, at: u64, flags: u16| [&(trap.wrapping_sub(at) as i32).to_le_bytes()[..], &[0; 6], &flags.to_le_bytes()].concat();
        let table = [entry(warns + 4, TABLE, BUGFLAG_WARNING), entry(bugs + 4, TABLE + 12, 0)].concat();
        let image = module(&code, "__bug_table", table, Vec::new());
        assert_eq!(image.resuming_traps, vec![warns + 4]);
        let noreturn: Vec<u64> = crate::analyze(&image).functions.iter().filter(|f| f.noreturn && [warned, failed].contains(&f.addr)).map(|f| f.addr).collect();
        assert_eq!(noreturn, vec![failed]);
    }
}
