//! Recognising text strings in an image's data.

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
        // Bytes of the section that a known string covers are skipped.
        let mut known = known[known.partition_point(|string| string.addr < section.addr)..].iter().take_while(|string| string.addr < section.end()).peekable();
        let mut offset = 0;
        while offset < section.data.len() {
            let addr = section.addr + offset as u64;
            if let Some(string) = known.next_if(|string| string.addr <= addr) {
                let width = if string.wide { 2 } else { 1 };
                offset = offset.max((string.addr - section.addr) as usize + width * (string.text.len() + 1));
                continue;
            }
            let run = section.data[offset..].iter().take(MAX_CHARS).take_while(|&&byte| is_text(u32::from(byte))).count();
            let starts_fresh = offset == 0 || section.data[offset - 1] == 0;
            if starts_fresh && run >= MIN_CHARS_UNREFERENCED && section.data.get(offset + run) == Some(&0) {
                found.push(StringLiteral { addr, text: String::from_utf8_lossy(&section.data[offset..offset + run]).into_owned(), wide: false });
            }
            offset += run + 1;
        }
    }
    found
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
        let image = Image {
            name: "test".into(),
            format: Format::Elf,
            machine: Machine::X86_64,
            base: 0,
            branch_targets_marked: false,
            entry: 0,
            sections: vec![Section { name: ".rodata".into(), addr: 0x2000, data: data.to_vec(), file_offset: None, executable: false, writable: false }],
            zero_filled: Vec::new(),
            import_slots: Default::default(),
            exports: Vec::new(),
            symbol_names: Default::default(),
            frames: Vec::new(),
            relative_targets: Vec::new(),
            data_in_code: false,
        };
        let known = [StringLiteral { addr: 0x2000, text: "known one".into(), wide: false }];
        let found: Vec<(u64, String)> = unreferenced(&image, &known).into_iter().map(|string| (string.addr, string.text)).collect();
        // Not the known string, not text that starts in the middle of other bytes, not a short run.
        assert_eq!(found, [(0x200a, "left over text".to_string())]);
    }
}
