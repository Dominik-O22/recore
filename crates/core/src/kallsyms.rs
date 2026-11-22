//! kallsyms: the table of its own symbols that a Linux kernel keeps among its read-only data,
//! read from a raw arm64 `Image`, which has no other symbols and nothing else that says where it
//! loads.
//!
//! The kernel's build, `scripts/kallsyms.c`, writes the table as arrays, each at a multiple of 8
//! bytes on a 64-bit kernel:
//! - `kallsyms_num_syms`: the number of symbols, in 8 bytes.
//! - `kallsyms_names`: each symbol's name, compressed: a length, then that many token numbers.
//!   Where the length's first byte has bit 7 set, a second byte holds its high bits (since 6.1).
//!   The first character a name expands to is the letter `nm` gives the symbol's kind.
//! - `kallsyms_markers`: where the name of every 256th symbol starts among the names, in words of
//!   4 bytes, or of 8 in older kernels.
//! - `kallsyms_seqs_of_names`, in 6.2 and in Android's 6.1, but where 6.12 moves it past the
//!   addresses: the symbols in the order of their names, 3 bytes each.
//! - `kallsyms_token_table`: 256 strings, each ending in a NUL, which the token numbers stand
//!   for. A character that names use stands for itself, so the digits are ten one-character
//!   tokens in a row.
//! - `kallsyms_token_index`: where each of those strings starts, in 2 bytes.
//! - The addresses, sorted: since 4.6, 4-byte offsets from `kallsyms_relative_base`, an 8-byte
//!   address that follows them, and before it the addresses themselves, `kallsyms_addresses`.
//!   5.10 puts them before `kallsyms_num_syms`, 6.12 after the token index.
//!
//! Nothing in the image names the arrays. [`read`] finds the token table by its digits, and each
//! other array where the build puts it, checked against the others: the index against the
//! table, each marker against the names, the count against the markers and the gap the names'
//! order leaves, and the addresses against the order the build sorts them in and the symbols
//! that open the kernel's code.

use std::ops::RangeInclusive;

/// A symbol of kallsyms.
pub struct Symbol {
    pub addr: u64,
    /// The letter `nm` gives its kind: `t` or `T` for code, `W` for a weak function, and `d`,
    /// `r`, `b` and their capitals for data.
    pub kind: u8,
    pub name: String,
}

impl Symbol {
    /// Whether `nm` places the symbol in code.
    pub fn is_text(&self) -> bool {
        matches!(self.kind, b't' | b'T' | b'w' | b'W')
    }
}

/// The token table's digits, each a token and its NUL.
const DIGITS: &[u8] = b"0\x001\x002\x003\x004\x005\x006\x007\x008\x009\x00";

/// The longest a name may be with its kind's letter, `KSYM_NAME_LEN` since 6.1: the build leaves
/// out a symbol whose name is as long, so no name expands to more, and none takes more tokens,
/// since each it uses stands for a character or more. Before 6.1 the limit was 128.
const MAX_NAME: usize = 512;

/// Where the build places each array: at a multiple of this.
const ALIGN: usize = 8;

/// The most symbols `kallsyms_seqs_of_names` can number, in its 3 bytes each.
const MAX_SEQS: usize = 1 << 24;

/// The symbols of the kallsyms in `data`, a raw arm64 kernel image, sorted by address, the first
/// `_text`, where the image loads to end below 2^64. None where the image holds no token table,
/// or where the arrays around it do not hold together.
pub fn read(data: &[u8]) -> Option<Vec<Symbol>> {
    // Only the token table that its index confirms is read further: a file has one.
    let tokens = memchr::memmem::find_iter(data, DIGITS).find_map(|digits| Tokens::around(data, digits))?;
    markers(data, tokens.start).find_map(|markers| {
        let (names, count) = names(data, &markers)?;
        // The addresses are cheaper to check than the names to expand, so they go first.
        let mut sorted = addresses(data, count, names - ALIGN, tokens.index_end).filter(|addresses| addresses.is_sorted()).peekable();
        sorted.peek()?;
        let symbols = decode(data, names, count, &tokens)?;
        let addresses = sorted.find(|addresses| holds(addresses, &symbols, data.len()))?;
        Some(symbols.into_iter().zip(addresses).map(|((kind, name), addr)| Symbol { addr, kind, name }).collect())
    })
}

/// The token table, and where the token index after it ends.
struct Tokens<'a> {
    start: usize,
    strings: Vec<&'a [u8]>,
    index_end: usize,
}

impl<'a> Tokens<'a> {
    /// The token table in which the digits at `digits` are the tokens 0x30 to 0x39, where the
    /// token index after it says where each of its strings starts.
    fn around(data: &'a [u8], digits: usize) -> Option<Tokens<'a>> {
        let mut start = digits;
        for _ in 0..b'0' {
            // The token before ends with the NUL before `start`.
            let end = start.checked_sub(1).filter(|&end| data[end] == 0)?;
            let from = end.saturating_sub(MAX_NAME);
            start = match memchr::memrchr(0, &data[from..end]) {
                Some(at) => from + at + 1,
                None if from == 0 => 0,
                None => return None,
            };
        }
        let mut strings = Vec::with_capacity(256);
        let mut at = start;
        for _ in 0..256 {
            let rest = data.get(at..)?;
            let length = memchr::memchr(0, &rest[..rest.len().min(MAX_NAME)])?;
            strings.push(&rest[..length]);
            at += length + 1;
        }
        let index = at.next_multiple_of(ALIGN);
        let words = data.get(index..)?.get(..512)?.as_chunks::<2>().0;
        let mut offset = 0;
        for (string, word) in strings.iter().zip(words) {
            if usize::from(u16::from_le_bytes(*word)) != offset {
                return None;
            }
            offset += string.len() + 1;
        }
        Some(Tokens { start, strings, index_end: index + 512 })
    }
}

/// The little-endian word of `width` bytes at `at`.
fn word(data: &[u8], at: usize, width: usize) -> Option<u64> {
    let bytes = data.get(at..)?.get(..width)?;
    Some(bytes.iter().rev().fold(0, |word, &byte| word << 8 | u64::from(byte)))
}

/// The markers, where they start, and how many symbols they may stand for.
struct Markers {
    /// Each further into the names than the one before, from 0.
    offsets: Vec<u64>,
    at: usize,
    counts: RangeInclusive<usize>,
}

impl Markers {
    /// The markers in `offsets` at `at`, one for each 256 symbols and one for the rest.
    fn new(offsets: Vec<u64>, at: usize) -> Markers {
        let most = offsets.len().saturating_mul(256);
        Markers { counts: most - 255..=most, offsets, at }
    }
}

/// The markers the build may have put before the token table at `table`. First where they end
/// against it, but for the padding that aligns it: in words of 4 bytes, the last or the padding
/// against the table, or of 8. Then before `kallsyms_seqs_of_names`, whose size, 3 bytes a
/// symbol and padding, says where each count puts its markers, which hold for that count alone.
fn markers(data: &[u8], table: usize) -> impl Iterator<Item = Markers> + '_ {
    let against = [(4, 0), (4, 4), (8, 0)].into_iter().filter_map(move |(width, padding)| {
        let mut end = table.checked_sub(padding)?;
        let mut offsets = Vec::new();
        loop {
            end = end.checked_sub(width)?;
            let marker = word(data, end, width)?;
            if offsets.last().is_some_and(|&later| marker >= later) {
                return None;
            }
            offsets.push(marker);
            if marker == 0 {
                break;
            }
        }
        offsets.reverse();
        Some(Markers::new(offsets, end))
    });
    let before_seqs = (ALIGN..=table.min(3 * MAX_SEQS)).step_by(ALIGN).flat_map(move |gap| {
        // The counts whose 3 bytes each the build pads to `gap`.
        ((gap - ALIGN + 1).div_ceil(3)..=gap / 3).filter_map(move |count| {
            let words = count.div_ceil(256);
            let at = table.checked_sub(gap)?.checked_sub((4 * words).next_multiple_of(ALIGN))?;
            let mut offsets = vec![word(data, at, 4).filter(|&first| first == 0)?];
            for index in 1..words {
                offsets.push(word(data, at + 4 * index, 4).filter(|&marker| marker > offsets[index - 1])?);
            }
            Some(Markers { offsets, at, counts: count..=count })
        })
    });
    against.chain(before_seqs)
}

/// The length of the name at `at`, and the bytes that say it. None for a name of no tokens or of
/// more than a name may expand to.
fn length(data: &[u8], at: usize) -> Option<(usize, usize)> {
    let first = *data.get(at)?;
    let (length, said) = match first & 0x80 {
        0 => (usize::from(first), 1),
        _ => (usize::from(first & 0x7F) | usize::from(*data.get(at.checked_add(1)?)?) << 7, 2),
    };
    (1..=MAX_NAME).contains(&length).then_some((length, said))
}

/// Where the `count` names from `at` end.
fn skip(data: &[u8], mut at: usize, count: usize) -> Option<usize> {
    for _ in 0..count {
        let (length, said) = length(data, at)?;
        at = at.checked_add(said + length)?;
    }
    Some(at)
}

/// Where the names start and how many there are, for `markers`. The count is the 8 bytes before
/// the names, and one the markers allow. Every marker is the start of its name, and the last
/// name ends where the markers start, but for padding.
fn names(data: &[u8], markers: &Markers) -> Option<(usize, usize)> {
    let last = usize::try_from(*markers.offsets.last()?).ok()?;
    let before_last = (markers.offsets.len() - 1).saturating_mul(256);
    // At least one name follows the last marker, and at most 256.
    let latest = markers.at.checked_sub(last)?.checked_sub(1)?;
    let earliest = latest.saturating_sub(256 * (MAX_NAME + 2));
    // Of the starts whose names after the last marker end at the markers, the latest is the
    // table's, and only it is walked whole: it costs as many steps as there are symbols.
    let (start, count) = (earliest.next_multiple_of(ALIGN)..latest + 1).step_by(ALIGN).rev().find_map(|start| {
        let count = usize::try_from(word(data, start.checked_sub(ALIGN)?, ALIGN)?).ok().filter(|count| markers.counts.contains(count))?;
        let end = skip(data, start + last, count.checked_sub(before_last)?)?;
        (end <= markers.at && markers.at - end < ALIGN).then_some((start, count))
    })?;
    let mut end = start;
    for (group, &marker) in markers.offsets.iter().enumerate() {
        if (end - start) as u64 != marker {
            return None;
        }
        end = skip(data, end, (count - 256 * group).min(256))?;
    }
    Some((start, count))
}

/// Each of the `count` names from `names` as its kind and the name, expanded from its tokens.
fn decode(data: &[u8], names: usize, count: usize, tokens: &Tokens) -> Option<Vec<(u8, String)>> {
    let mut symbols = Vec::with_capacity(count);
    let mut at = names;
    let mut expanded = Vec::new();
    for _ in 0..count {
        let (length, said) = length(data, at)?;
        let compressed = data.get(at + said..)?.get(..length)?;
        expanded.clear();
        for &token in compressed {
            expanded.extend_from_slice(tokens.strings[usize::from(token)]);
            if expanded.len() > MAX_NAME {
                return None;
            }
        }
        let (&kind, name) = expanded.split_first()?;
        symbols.push((kind, String::from_utf8_lossy(name).into_owned()));
        at += said + length;
    }
    Some(symbols)
}

/// The places the addresses of `count` symbols may be, each read as the addresses: 4-byte offsets
/// after the token index that ends at `index_end`, and the base after them, or before the count
/// at `count_at`, with the base between, or the addresses themselves before the count.
fn addresses(data: &[u8], count: usize, count_at: usize, index_end: usize) -> impl Iterator<Item = Vec<u64>> + '_ {
    let offsets_size = count.checked_mul(4).map(|size| size.next_multiple_of(ALIGN));
    let after = offsets_size.and_then(|size| Some((index_end, index_end.checked_add(size)?)));
    let before = count_at.checked_sub(ALIGN).and_then(|base| Some((base.checked_sub(offsets_size?)?, base)));
    let relative = [after, before].into_iter().flatten().map(move |(offsets, base)| {
        let base = word(data, base, ALIGN)?;
        let offsets = data.get(offsets..)?.get(..count.checked_mul(4)?)?.as_chunks::<4>().0;
        offsets.iter().map(|offset| base.checked_add(u64::from(u32::from_le_bytes(*offset)))).collect::<Option<Vec<u64>>>()
    });
    let absolute = std::iter::once_with(move || {
        let start = count_at.checked_sub(count.checked_mul(ALIGN)?)?;
        (0..count).map(|index| word(data, start + index * ALIGN, ALIGN)).collect::<Option<Vec<u64>>>()
    });
    relative.chain(absolute).flatten()
}

/// Whether the sorted `addresses` belong to `symbols`: starting at `_text`, the first byte of an
/// image of `size` bytes, which ends below 2^64, and below `_etext`, where its code ends.
fn holds(addresses: &[u64], symbols: &[(u8, String)], size: usize) -> bool {
    let at = |name: &str| symbols.iter().position(|(_, symbol)| symbol == name).map(|index| addresses[index]);
    let (Some(text), Some(etext)) = (at("_text"), at("_etext")) else { return false };
    addresses.first() == Some(&text) && text < etext && text.checked_add(size as u64).is_some()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// The tokens of a table where each byte stands for itself but 1, which stands for `ab`,
    /// and NUL, which no name uses.
    fn token_table() -> Vec<Vec<u8>> {
        (0..=255u8)
            .map(|byte| match byte {
                0 => vec![0x7f],
                1 => b"ab".to_vec(),
                byte => vec![byte],
            })
            .collect()
    }

    /// Pads `out` with zeros to a multiple of 8.
    fn align(out: &mut Vec<u8>) {
        out.resize(out.len().next_multiple_of(ALIGN), 0);
    }

    /// The order a build writes the arrays in.
    #[derive(Clone, Copy)]
    pub(crate) enum Order {
        /// 4.6 to 6.x: offsets, the base, the count, names, markers, tokens, index.
        OffsetsFirst,
        /// 6.x: the count, names, markers, tokens, index, offsets, the base.
        OffsetsLast,
        /// Before 4.6: 8-byte addresses, the count, names, markers in 8 bytes, tokens, index.
        Absolute,
        /// 6.2 and Android's 6.1: as `OffsetsFirst`, with the names' order, 3 bytes a symbol,
        /// between the markers and the tokens.
        SeqsOfNames,
    }

    /// A kernel's read-only data with the kallsyms of `symbols`, as `(address, kind and name)`,
    /// after `before` bytes of other data. Each name is compressed with [`token_table`].
    pub(crate) fn kallsyms(symbols: &[(u64, &str)], order: Order, before: usize) -> Vec<u8> {
        let base = symbols[0].0;
        let mut out = vec![0x55; before];
        align(&mut out);
        let offsets = |out: &mut Vec<u8>| {
            out.extend(symbols.iter().flat_map(|&(addr, _)| ((addr - base) as u32).to_le_bytes()));
            align(out);
            out.extend(base.to_le_bytes());
        };
        match order {
            Order::OffsetsFirst | Order::SeqsOfNames => offsets(&mut out),
            Order::Absolute => out.extend(symbols.iter().flat_map(|&(addr, _)| addr.to_le_bytes())),
            Order::OffsetsLast => {}
        }
        out.extend((symbols.len() as u64).to_le_bytes());
        let names = out.len();
        let mut markers = Vec::new();
        for (index, (_, name)) in symbols.iter().enumerate() {
            if index % 256 == 0 {
                markers.push((out.len() - names) as u64);
            }
            let compressed = name.replace("ab", "\x01");
            // A name of 128 bytes or more says its length in two.
            match compressed.len() {
                length @ 0..0x80 => out.push(length as u8),
                length => out.extend([length as u8 | 0x80, (length >> 7) as u8]),
            }
            out.extend(compressed.bytes());
        }
        align(&mut out);
        let width = if matches!(order, Order::Absolute) { 8 } else { 4 };
        out.extend(markers.iter().flat_map(|marker| marker.to_le_bytes()[..width].to_vec()));
        align(&mut out);
        if let Order::SeqsOfNames = order {
            let mut by_name: Vec<usize> = (0..symbols.len()).collect();
            by_name.sort_by_key(|&index| &symbols[index].1[1..]);
            out.extend(by_name.iter().flat_map(|&index| (index as u32).to_be_bytes()[1..].to_vec()));
            align(&mut out);
        }
        let (mut index, mut offset) = (Vec::new(), 0u16);
        for token in token_table() {
            index.extend(offset.to_le_bytes());
            offset += token.len() as u16 + 1;
            out.extend(token);
            out.push(0);
        }
        align(&mut out);
        out.extend(index);
        if let Order::OffsetsLast = order {
            offsets(&mut out);
        }
        out.extend([0x55; 24]);
        out
    }

    const TEXT: u64 = 0xffff_ffc0_8000_0000;

    /// The symbols of a small kernel: `_text`, a function, a weak one, data, and `_etext`.
    fn small() -> Vec<(u64, &'static str)> {
        vec![(TEXT, "T_text"), (TEXT + 0x40, "tabort_abc"), (TEXT + 0x80, "Wmemcpy"), (TEXT + 0x80, "Tlabel"), (TEXT + 0x100, "T_etext"), (TEXT + 0x100, "dtable")]
    }

    fn read_back(data: &[u8]) -> Option<Vec<(u64, char, String)>> {
        Some(read(data)?.into_iter().map(|symbol| (symbol.addr, symbol.kind as char, symbol.name)).collect())
    }

    fn expected(symbols: &[(u64, &str)]) -> Vec<(u64, char, String)> {
        symbols.iter().map(|&(addr, name)| (addr, name.as_bytes()[0] as char, name[1..].to_string())).collect()
    }

    #[test]
    fn every_order_reads_back() {
        for order in [Order::OffsetsFirst, Order::OffsetsLast, Order::Absolute] {
            for before in [0, 3, 1000] {
                let data = kallsyms(&small(), order, before);
                assert_eq!(read_back(&data), Some(expected(&small())), "{before} bytes before");
            }
        }
    }

    /// `_text`, `count` functions, a function whose name is `long`, and `_etext`.
    fn functions(count: usize, long: &str) -> Vec<(u64, String)> {
        let mut symbols = vec![(TEXT, "T_text".to_string())];
        symbols.extend((0..count).map(|index| (TEXT + 4 * index as u64 + 4, format!("tfunction_{index}"))));
        symbols.push((TEXT + 0x1000, long.to_string()));
        symbols.push((TEXT + 0x2000, "T_etext".to_string()));
        symbols
    }

    fn borrowed(symbols: &[(u64, String)]) -> Vec<(u64, &str)> {
        symbols.iter().map(|(addr, name)| (*addr, name.as_str())).collect()
    }

    /// 600 symbols take three markers, and a name of 200 bytes says its length in two.
    #[test]
    fn many_symbols_and_a_long_name_read_back() {
        let symbols = functions(600, &format!("t{}", "q".repeat(200)));
        for order in [Order::OffsetsFirst, Order::OffsetsLast] {
            assert_eq!(read_back(&kallsyms(&borrowed(&symbols), order, 16)), Some(expected(&borrowed(&symbols))));
        }
    }

    /// Where the names' order lies between the markers and the tokens, its size says how many
    /// symbols there are, with markers that fill their last 8 bytes or leave 4 of them as padding.
    #[test]
    fn the_names_order_between_markers_and_tokens_is_passed() {
        for (count, markers) in [(1, 1), (300, 2), (600, 3)] {
            let symbols = functions(count, "tlast");
            assert_eq!(symbols.len().div_ceil(256), markers);
            for before in [0, 3] {
                let symbols = borrowed(&symbols);
                assert_eq!(read_back(&kallsyms(&symbols, Order::SeqsOfNames, before)), Some(expected(&symbols)), "{count} functions");
            }
        }
    }

    /// A name may expand to `KSYM_NAME_LEN` bytes with its kind, and no more.
    #[test]
    fn a_name_longer_than_the_kernel_allows_is_refused() {
        // 1 is the token `ab`, so each name takes 257 tokens.
        let longest = format!("t{}c", "ab".repeat(255));
        let symbols = functions(3, &longest);
        assert_eq!(read_back(&kallsyms(&borrowed(&symbols), Order::OffsetsLast, 0)).map(|symbols| symbols[4].2.len()), Some(511));
        let symbols = functions(3, &format!("t{}", "ab".repeat(256)));
        assert!(read(&kallsyms(&borrowed(&symbols), Order::OffsetsLast, 0)).is_none());
    }

    /// A marker that does not say where its name starts refuses the table, though every other
    /// marker and the last name's end agree.
    #[test]
    fn a_marker_out_of_place_is_refused() {
        let symbols = functions(600, "tlast");
        let mut data = kallsyms(&borrowed(&symbols), Order::OffsetsLast, 0);
        assert!(read(&data).is_some());
        // Three markers of 4 bytes and 4 of padding end against the token table.
        let table = data.windows(5).position(|window| window == b"\x7f\0ab\0").unwrap();
        let second = table - 16 + 4;
        let marker = u32::from_le_bytes(data[second..second + 4].try_into().unwrap());
        data[second..second + 4].copy_from_slice(&(marker + 1).to_le_bytes());
        assert!(read(&data).is_none());
    }

    /// A table whose arrays do not agree is no table, and the image is read without one.
    #[test]
    fn a_table_that_does_not_hold_is_refused() {
        let data = kallsyms(&small(), Order::OffsetsFirst, 16);
        let count_at = data.windows(8).position(|window| window == 6u64.to_le_bytes()).unwrap();
        // A count the markers do not allow, and one too many for the names.
        for count in [300u64, 7] {
            let mut broken = data.clone();
            broken[count_at..count_at + 8].copy_from_slice(&count.to_le_bytes());
            assert!(read(&broken).is_none(), "count {count}");
        }
        // Addresses out of order.
        let mut broken = data.clone();
        broken[16 + 4..16 + 8].copy_from_slice(&0x200u32.to_le_bytes());
        assert!(read(&broken).is_none());
        // No `_etext`.
        let mut symbols = small();
        symbols[4].1 = "T_ztext";
        assert!(read(&kallsyms(&symbols, Order::OffsetsFirst, 16)).is_none());
        // A token index that does not say where the tokens start.
        let mut broken = data.clone();
        let index = broken.len() - 24 - 512;
        broken[index + 2] ^= 1;
        assert!(read(&broken).is_none());
    }

    /// Bytes cut short anywhere read as no table, and never panic.
    #[test]
    fn a_table_cut_short_reads_as_none() {
        let data = kallsyms(&small(), Order::OffsetsLast, 16);
        for end in (0..data.len() - 24).step_by(7) {
            assert!(read(&data[..end]).is_none(), "cut at {end}");
        }
    }
}
