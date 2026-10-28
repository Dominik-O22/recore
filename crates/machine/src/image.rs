//! The parts of a 32-bit PE file the machine needs: its sections at their addresses, its entry
//! point and its imports with the address of each import's slot.

use std::{fs, path::Path};

use anyhow::{Context, Result, bail, ensure};

pub struct Section {
    pub addr: u32,
    pub size: u32,
    pub data: Vec<u8>,
    /// Whether it holds code: IMAGE_SCN_CNT_CODE or IMAGE_SCN_MEM_EXECUTE.
    pub executable: bool,
}

pub struct Import {
    /// The slot the loader fills with the function's address.
    pub slot: u32,
    pub dll: String,
    pub name: String,
}

pub struct Image {
    pub base: u32,
    pub entry: u32,
    pub sections: Vec<Section>,
    pub imports: Vec<Import>,
    /// The address and size of the first RT_VERSION resource.
    pub version: Option<(u32, u32)>,
}

fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().expect("4 bytes"))
}

fn c_str(b: &[u8], at: usize) -> String {
    let end = b[at..].iter().position(|&c| c == 0).map_or(b.len(), |n| at + n);
    String::from_utf8_lossy(&b[at..end]).into_owned()
}

impl Image {
    /// From the first executable section's start to the last one's end: the addresses
    /// [`crate::install`] keeps a slot for each of.
    pub fn code(&self) -> std::ops::Range<u32> {
        let code = self.sections.iter().filter(|s| s.executable);
        let start = code.clone().map(|s| s.addr).min().unwrap_or(0);
        start..code.map(|s| s.addr + s.size).max().unwrap_or(start)
    }

    pub fn load(path: &Path) -> Result<Image> {
        let file = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        ensure!(file.get(..2) == Some(b"MZ"), "{} is not a PE file", path.display());
        let pe = u32_at(&file, 0x3c) as usize;
        ensure!(file.get(pe..pe + 4) == Some(b"PE\0\0"), "no PE header");
        let count = u16_at(&file, pe + 6) as usize;
        let optional = pe + 24;
        if u16_at(&file, optional) != 0x10b {
            bail!("not a 32-bit PE");
        }
        let entry_rva = u32_at(&file, optional + 16);
        let base = u32_at(&file, optional + 28);
        let import_rva = u32_at(&file, optional + 96 + 8);
        let table = optional + u16_at(&file, pe + 20) as usize;
        let mut sections = Vec::new();
        for i in 0..count {
            let s = table + 40 * i;
            let (size, rva, raw_size, raw) = (u32_at(&file, s + 8), u32_at(&file, s + 12), u32_at(&file, s + 16), u32_at(&file, s + 20));
            let executable = u32_at(&file, s + 36) & 0x2000_0020 != 0;
            let mut data = file.get(raw as usize..(raw + raw_size.min(size.max(raw_size))) as usize).unwrap_or(&[]).to_vec();
            data.resize(size.max(raw_size) as usize, 0);
            sections.push(Section { addr: base + rva, size: size.max(raw_size), data, executable });
        }
        let rva_bytes = |rva: u32| -> Option<&[u8]> {
            let addr = base + rva;
            sections.iter().find(|s| addr >= s.addr && addr < s.addr + s.size).map(|s| &s.data[(addr - s.addr) as usize..])
        };
        let mut imports = Vec::new();
        let mut at = 0;
        while let Some(d) = rva_bytes(import_rva + at) {
            let (lookup, name, first) = (u32_at(d, 0), u32_at(d, 12), u32_at(d, 16));
            if name == 0 {
                break;
            }
            let dll = c_str(rva_bytes(name).context("import dll name")?, 0);
            let mut n = 0;
            loop {
                let entry = u32_at(rva_bytes(if lookup != 0 { lookup } else { first } + 4 * n).context("import lookup")?, 0);
                if entry == 0 {
                    break;
                }
                let name = if entry & 0x8000_0000 != 0 { format!("#{}", entry & 0xffff) } else { c_str(rva_bytes(entry + 2).context("import name")?, 0) };
                imports.push(Import { slot: base + first + 4 * n, dll: dll.to_lowercase(), name });
                n += 1;
            }
            at += 20;
        }
        let resource_rva = u32_at(&file, optional + 96 + 16);
        let version = (resource_rva != 0).then(|| -> Option<(u32, u32)> {
            let root = rva_bytes(resource_rva)?;
            // A directory: 16 bytes of header with the named and the numbered entry counts at
            // +12 and +14, then 8-byte entries of name or id and offset (high bit: a directory).
            let entry = |dir: &[u8], id: Option<u32>| -> Option<u32> {
                let n = u16_at(dir, 12) as usize + u16_at(dir, 14) as usize;
                (0..n).map(|i| (u32_at(dir, 16 + 8 * i), u32_at(dir, 20 + 8 * i))).find(|&(name, _)| id.is_none_or(|id| name == id)).map(|(_, off)| off)
            };
            let types = entry(root, Some(16))?;
            let names = rva_bytes(resource_rva + (types & 0x7fff_ffff))?;
            let langs = rva_bytes(resource_rva + (entry(names, None)? & 0x7fff_ffff))?;
            let data = rva_bytes(resource_rva + (entry(langs, None)? & 0x7fff_ffff))?;
            Some((base + u32_at(data, 0), u32_at(data, 4)))
        }).flatten();
        Ok(Image { base, entry: base + entry_rva, sections, imports, version })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_code_runs_from_the_first_executable_section_to_the_last() {
        let section = |addr, size, executable| Section { addr, size, data: Vec::new(), executable };
        let sections = vec![section(0x40_1000, 0x1000, true), section(0x40_2000, 0x800, false), section(0x40_3000, 0x2000, true), section(0x40_6000, 0x1000, false)];
        let image = Image { base: 0x40_0000, entry: 0x40_1000, sections, imports: Vec::new(), version: None };
        assert_eq!(image.code(), 0x40_1000..0x40_5000);
    }
}
