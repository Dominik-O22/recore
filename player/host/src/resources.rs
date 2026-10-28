//! The executable's string table (RT_STRING resources), for `LoadStringA`. The resource directory
//! is the optional header's data directory 2: three levels of IMAGE_RESOURCE_DIRECTORY (type,
//! name, language), each a 16-byte header and 8-byte entries of id and offset, the high bit of
//! an offset marking another directory. A string block `n` holds strings `16 * (n - 1)` to
//! `16 * n - 1`, each a u16 length and that many UTF-16 units.

use std::collections::HashMap;

const RT_STRING: u32 = 6;

/// Every string of the table by id, from the first language of each block, in Windows-1252.
pub fn strings(exe: &[u8]) -> HashMap<u32, Vec<u8>> {
    let mut out = HashMap::new();
    let Some((root, file_at)) = resource_dir(exe) else { return out };
    let u16_at = |at: usize| exe.get(at..at + 2).map(|b| u16::from_le_bytes([b[0], b[1]]));
    let u32_at = |at: usize| exe.get(at..at + 4).map(|b| u32::from_le_bytes(b.try_into().expect("4 bytes")));
    let entries = |dir: usize| -> Vec<(u32, u32)> {
        let (named, ids) = (u16_at(dir + 12).unwrap_or(0), u16_at(dir + 14).unwrap_or(0));
        (0..usize::from(named + ids)).filter_map(|i| Some((u32_at(dir + 16 + 8 * i)?, u32_at(dir + 20 + 8 * i)?))).collect()
    };
    let Some(&(_, types)) = entries(root).iter().find(|(id, _)| *id == RT_STRING) else { return out };
    for (block, names) in entries(root + (types & 0x7fff_ffff) as usize) {
        let Some(&(_, data)) = entries(root + (names & 0x7fff_ffff) as usize).first() else { continue };
        let entry = root + data as usize;
        let (Some(rva), Some(size)) = (u32_at(entry), u32_at(entry + 4)) else { continue };
        let Some(mut at) = file_at(rva) else { continue };
        let end = at + size as usize;
        for i in 0..16 {
            let Some(len) = u16_at(at).filter(|_| at < end) else { break };
            let units: Vec<u16> = (0..usize::from(len)).filter_map(|k| u16_at(at + 2 + 2 * k)).collect();
            if len > 0 {
                out.insert(16 * (block - 1) + i, units.iter().map(|&u| u8::try_from(u).unwrap_or(b'?')).collect());
            }
            at += 2 + 2 * usize::from(len);
        }
    }
    out
}

/// The file offset of the resource directory, and a map from RVAs to file offsets.
fn resource_dir(exe: &[u8]) -> Option<(usize, impl Fn(u32) -> Option<usize> + '_)> {
    let u16_at = |at: usize| exe.get(at..at + 2).map(|b| u16::from_le_bytes([b[0], b[1]]));
    let u32_at = |at: usize| exe.get(at..at + 4).map(|b| u32::from_le_bytes(b.try_into().expect("4 bytes")));
    let pe = u32_at(0x3c)? as usize;
    let (count, optional) = (usize::from(u16_at(pe + 6)?), usize::from(u16_at(pe + 20)?));
    let rva = u32_at(pe + 24 + 96 + 2 * 8)?;
    let table = pe + 24 + optional;
    let sections: Vec<(u32, u32, u32)> = (0..count).filter_map(|i| Some((u32_at(table + 40 * i + 12)?, u32_at(table + 40 * i + 8)?, u32_at(table + 40 * i + 20)?))).collect();
    let file_at = move |rva: u32| sections.iter().find(|(at, size, _)| (*at..at + size).contains(&rva)).map(|(at, _, raw)| (raw + rva - at) as usize);
    Some((file_at(rva)?, file_at))
}
