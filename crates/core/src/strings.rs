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
