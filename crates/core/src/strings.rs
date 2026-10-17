//! Recognising text strings in an image's data.

use crate::arch::TextPointer;
use crate::image::Image;
use crate::report::StringLiteral;

/// Shortest run of characters accepted as a string when only a pointer in data refers to it.
/// Shorter runs are too often coincidence.
const MIN_CHARS: usize = 4;
/// Shortest run accepted when an instruction refers to the address directly, which is itself
/// good evidence. Keeps short literals such as `"id"` or `"%d"`.
const MIN_CHARS_FROM_CODE: usize = 2;
const MAX_CHARS: usize = 4096;

/// Shortest run accepted as a string that nothing found refers to. A program reaches such a
/// string through an address it computes, and only its length speaks for it.
const MIN_CHARS_UNREFERENCED: usize = 6;

/// The 8-bit strings in the image's data sections that begin right after another string or a
/// zero byte, and are not among `known`, which is sorted by address. These are the strings the
/// analysis found no reference to.
pub fn unreferenced(image: &Image, known: &[StringLiteral]) -> Vec<StringLiteral> {
    let data = |name: &str| name.starts_with(".rodata") || name == ".rdata" || name == ".data";
    let mut found = Vec::new();
    for section in image.sections.iter().filter(|section| !section.executable && data(&section.name)) {
        unreferenced_in(section.addr, &section.data, known, &mut found);
    }
    found
}

/// The same for an image that keeps its text among the code: in the bytes of its code sections
/// that are not instructions. `code` is every stretch of instructions, sorted.
pub fn unreferenced_among_code(image: &Image, code: &[(u64, u64)], known: &[StringLiteral]) -> Vec<StringLiteral> {
    let mut found = Vec::new();
    for section in image.sections.iter().filter(|section| section.executable) {
        let inside = code[code.partition_point(|&(_, end)| end <= section.addr)..].iter().take_while(|&&(start, _)| start < section.end());
        let mut from = section.addr;
        for &(start, end) in inside.chain([&(section.end(), section.end())]) {
            if from < start {
                unreferenced_in(from, &section.data[(from - section.addr) as usize..(start - section.addr) as usize], known, &mut found);
            }
            from = end;
        }
    }
    found
}

/// Adds the strings among `bytes`, which lie at `base`, that [`unreferenced`] is after.
fn unreferenced_in(base: u64, bytes: &[u8], known: &[StringLiteral], found: &mut Vec<StringLiteral>) {
    let end = base + bytes.len() as u64;
    // Bytes that a known string covers are skipped.
    let mut known = known[known.partition_point(|string| string.addr < base)..].iter().take_while(|string| string.addr < end).peekable();
    let mut offset = 0;
    while offset < bytes.len() {
        let addr = base + offset as u64;
        if let Some(string) = known.next_if(|string| string.addr <= addr) {
            let width = if string.wide { 2 } else { 1 };
            offset = offset.max((string.addr - base) as usize + width * (string.text.len() + 1));
            continue;
        }
        let run = bytes[offset..].iter().take(MAX_CHARS).take_while(|&&byte| is_text(u32::from(byte))).count();
        let starts_fresh = offset == 0 || bytes[offset - 1] == 0;
        if starts_fresh && run >= MIN_CHARS_UNREFERENCED && bytes.get(offset + run) == Some(&0) {
            found.push(StringLiteral { addr, text: String::from_utf8_lossy(&bytes[offset..offset + run]).into_owned(), wide: false });
        }
        offset += run + 1;
    }
}

/// The text among the code that `pointers` point to, sorted by address, and the pointers that
/// point to some, sorted. `code` is every stretch of instructions, sorted: text is in none.
///
/// A pointer the code marks as one into the code space is taken at its word, like a reference
/// from an instruction elsewhere. One it does not mark may be two numbers that happen to make
/// the address, so more has to speak for the text: it is longer, and the address is where it
/// begins.
pub fn among_code(image: &Image, code: &[(u64, u64)], mut pointers: Vec<TextPointer>) -> (Vec<StringLiteral>, Vec<TextPointer>) {
    let in_code = |addr: u64| code[..code.partition_point(|&(start, _)| start <= addr)].last().is_some_and(|&(_, end)| addr < end);
    let text_at = |pointer: &TextPointer| {
        let addr = pointer.to;
        let section = image.section_at(addr).filter(|section| section.executable && !in_code(addr))?;
        let offset = (addr - section.addr) as usize;
        let run = section.data[offset..].iter().take(MAX_CHARS).take_while(|&&byte| is_text(u32::from(byte))).count();
        let begins = offset == 0 || !is_text(u32::from(section.data[offset - 1])) || in_code(addr - 1);
        let enough = if pointer.marked { run >= MIN_CHARS_FROM_CODE } else { run >= MIN_CHARS && begins };
        let ends = section.data.get(offset + run) == Some(&0) && !in_code(addr + run as u64);
        (enough && ends).then(|| StringLiteral { addr, text: String::from_utf8_lossy(&section.data[offset..offset + run]).into_owned(), wide: false })
    };
    // A marked pointer first among those from one instruction to one address.
    pointers.sort_unstable_by_key(|pointer| (pointer.from, pointer.to, !pointer.marked));
    pointers.dedup_by_key(|pointer| (pointer.from, pointer.to));
    let mut strings = Vec::new();
    pointers.retain(|pointer| text_at(pointer).map(|string| strings.push(string)).is_some());
    strings.sort_by_key(|string| string.addr);
    strings.dedup_by_key(|string| string.addr);
    (strings, pointers)
}

fn is_text(c: u32) -> bool {
    matches!(c, 0x20..=0x7E | 0x09 | 0x0A | 0x0D)
}

/// The NUL-terminated string at `addr`, if the bytes there are one: 8-bit text, or UTF-16 of
/// characters in the same range. `from_code` says an instruction refers to the address, not
/// only a pointer in data. Code sections are not searched.
pub fn string_at(image: &Image, addr: u64, from_code: bool) -> Option<StringLiteral> {
    let min_chars = if from_code { MIN_CHARS_FROM_CODE } else { MIN_CHARS };
    let section = image.section_at(addr).filter(|s| !s.executable)?;
    let bytes = &section.data[(addr - section.addr) as usize..];

    let narrow: Vec<u8> = bytes.iter().copied().take(MAX_CHARS).take_while(|&b| is_text(u32::from(b))).collect();
    if narrow.len() >= min_chars && bytes.get(narrow.len()) == Some(&0) {
        return Some(StringLiteral { addr, text: String::from_utf8(narrow).ok()?, wide: false });
    }

    let units = || bytes.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]]));
    let wide: Vec<u16> = units().take(MAX_CHARS).take_while(|&unit| is_text(u32::from(unit))).collect();
    (wide.len() >= min_chars && units().nth(wide.len()) == Some(0))
        .then(|| StringLiteral { addr, text: String::from_utf16_lossy(&wide), wide: true })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image::{Format, Machine, Section};

    #[test]
    fn finds_strings_nothing_refers_to_between_the_known_ones() {
        let data = b"known one\0left over text\0\x01\x02abcdefgh\0tiny\0";
        let section = Section { name: ".rodata".into(), addr: 0x2000, data: data.to_vec(), file_offset: None, executable: false, writable: false };
        let image = Image::bare("test".into(), Format::Elf, Machine::X86_64, 0, vec![section]);
        let known = [StringLiteral { addr: 0x2000, text: "known one".into(), wide: false }];
        let found: Vec<(u64, String)> = unreferenced(&image, &known).into_iter().map(|string| (string.addr, string.text)).collect();
        // Not the known string, not text that starts in the middle of other bytes, not a short run.
        assert_eq!(found, [(0x200a, "left over text".to_string())]);
    }
}
