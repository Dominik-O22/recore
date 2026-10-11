//! Recognising text strings in an image's data.

use crate::image::Image;
use crate::report::StringLiteral;

/// Shortest run of characters accepted as a string. Shorter runs are too often coincidence.
const MIN_CHARS: usize = 4;
const MAX_CHARS: usize = 4096;

fn is_text(c: u32) -> bool {
    matches!(c, 0x20..=0x7E | 0x09 | 0x0A | 0x0D)
}

/// The NUL-terminated string at `addr`, if the bytes there are one: 8-bit text, or UTF-16 of
/// characters in the same range. Code sections are not searched.
pub fn string_at(image: &Image, addr: u64) -> Option<StringLiteral> {
    let section = image.section_at(addr).filter(|s| !s.executable)?;
    let bytes = &section.data[(addr - section.addr) as usize..];

    let narrow: Vec<u8> = bytes.iter().copied().take(MAX_CHARS).take_while(|&b| is_text(u32::from(b))).collect();
    if narrow.len() >= MIN_CHARS && bytes.get(narrow.len()) == Some(&0) {
        return Some(StringLiteral { addr, text: String::from_utf8(narrow).ok()?, wide: false });
    }

    let units = || bytes.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]]));
    let wide: Vec<u16> = units().take(MAX_CHARS).take_while(|&unit| is_text(u32::from(unit))).collect();
    (wide.len() >= MIN_CHARS && units().nth(wide.len()) == Some(0))
        .then(|| StringLiteral { addr, text: String::from_utf16_lossy(&wide), wide: true })
}
