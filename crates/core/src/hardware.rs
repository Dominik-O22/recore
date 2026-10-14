//! Names for the hardware a raw image runs on, and which of it most wants naming.
//!
//! Firmware talks to its chip through fixed addresses: registers, ports, memory-mapped devices.
//! What they are called is not in the image. A layout names a file that says, by the space
//! each address is in:
//!
//! ```toml
//! [sfr]
//! P4 = 0xc0
//!
//! [xdata]
//! LCD_CONTROL = 0x8100
//!
//! [bit]
//! EA = 0xaf
//!
//! [code]
//! main = 0x001a40
//! ```
//!
//! `sfr`, `xdata`, `idata` and `bit` are the spaces of an 8051, whose standard registers and
//! their bits are named without any file. On a machine with one address space, as a Cortex-M
//! has, `memory` takes any address, such as a device's registers:
//!
//! ```toml
//! [memory]
//! USART1_SR = 0x40013800
//! ```
//!
//! A Cortex-M's system registers, which every one has at the same addresses, are named without
//! any file. `code` takes the addresses the image loads at, on any machine. The names go
//! wherever the image's own would: [`Image::symbol_names`].

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;

use crate::FxHashMap;
use crate::i8051::{IDATA, SFR, XDATA};
use crate::image::{Image, Machine};
use crate::program::Program;

/// The 256 bits an 8051 addresses one at a time, from here. Nothing loads there and no
/// instruction is recorded as referring there: it is a space of names only. Bits below 0x80
/// are those of the internal data bytes from 0x20, the others those of every eighth register.
pub const BIT: u64 = 4 << 32;

/// The registers every 8051 has, by their direct addresses.
const STANDARD: [(&str, u64); 21] = [
    ("P0", 0x80),
    ("SP", 0x81),
    ("DPL", 0x82),
    ("DPH", 0x83),
    ("PCON", 0x87),
    ("TCON", 0x88),
    ("TMOD", 0x89),
    ("TL0", 0x8A),
    ("TL1", 0x8B),
    ("TH0", 0x8C),
    ("TH1", 0x8D),
    ("P1", 0x90),
    ("SCON", 0x98),
    ("SBUF", 0x99),
    ("P2", 0xA0),
    ("IE", 0xA8),
    ("P3", 0xB0),
    ("IP", 0xB8),
    ("PSW", 0xD0),
    ("ACC", 0xE0),
    ("B", 0xF0),
];

/// The bits of those registers that every 8051 has, by their bit addresses.
const STANDARD_BITS: [(&str, u64); 43] = [
    ("IT0", 0x88),
    ("IE0", 0x89),
    ("IT1", 0x8A),
    ("IE1", 0x8B),
    ("TR0", 0x8C),
    ("TF0", 0x8D),
    ("TR1", 0x8E),
    ("TF1", 0x8F),
    ("RI", 0x98),
    ("TI", 0x99),
    ("RB8", 0x9A),
    ("TB8", 0x9B),
    ("REN", 0x9C),
    ("SM2", 0x9D),
    ("SM1", 0x9E),
    ("SM0", 0x9F),
    ("EX0", 0xA8),
    ("ET0", 0xA9),
    ("EX1", 0xAA),
    ("ET1", 0xAB),
    ("ES", 0xAC),
    ("EA", 0xAF),
    ("RXD", 0xB0),
    ("TXD", 0xB1),
    ("INT0", 0xB2),
    ("INT1", 0xB3),
    ("T0", 0xB4),
    ("T1", 0xB5),
    ("WR", 0xB6),
    ("RD", 0xB7),
    ("PX0", 0xB8),
    ("PT0", 0xB9),
    ("PX1", 0xBA),
    ("PT1", 0xBB),
    ("PS", 0xBC),
    ("P", 0xD0),
    ("OV", 0xD2),
    ("RS0", 0xD3),
    ("RS1", 0xD4),
    ("F0", 0xD5),
    ("AC", 0xD6),
    ("CY", 0xD7),
    ("F1", 0xD1),
];

/// A names file: in each space, names and the address each is for.
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct Names {
    #[serde(default)]
    sfr: BTreeMap<String, u64>,
    #[serde(default)]
    xdata: BTreeMap<String, u64>,
    #[serde(default)]
    idata: BTreeMap<String, u64>,
    #[serde(default)]
    bit: BTreeMap<String, u64>,
    #[serde(default)]
    code: BTreeMap<String, u64>,
    #[serde(default)]
    memory: BTreeMap<String, u64>,
}

/// The names of addresses in an image for `machine`: those every such machine has, and those
/// the names file at `file` gives, which come first where both name an address.
pub fn names(machine: Machine, file: Option<&Path>) -> Result<FxHashMap<u64, String>> {
    let Some(file) = file else { return read(machine, "") };
    read(machine, &std::fs::read_to_string(file).with_context(|| format!("reading {file:?}"))?).with_context(|| format!("reading the names {file:?}"))
}

/// The same, from the text of a names file.
fn read(machine: Machine, text: &str) -> Result<FxHashMap<u64, String>> {
    let given: Names = toml::from_str(text)?;
    // Each space: what the file calls it, its names, the address of its start, and its addresses.
    let spaces = [
        ("sfr", &given.sfr, SFR, 0x80..0x100),
        ("xdata", &given.xdata, XDATA, 0..0x1_0000),
        ("idata", &given.idata, IDATA, 0..0x100),
        ("bit", &given.bit, BIT, 0..0x100),
        ("code", &given.code, 0, 0..XDATA),
        ("memory", &given.memory, 0, 0..XDATA),
    ];
    let mut names = FxHashMap::default();
    for (space, named, base, addresses) in spaces {
        ensure!(named.is_empty() || base == 0 || machine == Machine::I8051, "`{space}` names addresses of an 8051, which this image is not for");
        ensure!(named.is_empty() || space != "memory" || machine != Machine::I8051, "an 8051 has no one `memory`: its names go in `sfr`, `xdata`, `idata` or `bit`");
        for (name, &addr) in named {
            ensure!(addresses.contains(&addr), "`{name}` is at {addr:#x}, which is not an address in `{space}`");
            if let Some(other) = names.insert(base + addr, name.clone()) {
                bail!("`{other}` and `{name}` both name {addr:#x} in `{space}`");
            }
        }
    }
    if machine == Machine::I8051 {
        let standard = STANDARD.iter().map(|&(name, addr)| (name, SFR + addr)).chain(STANDARD_BITS.iter().map(|&(name, bit)| (name, BIT + bit)));
        for (name, addr) in standard {
            names.entry(addr).or_insert_with(|| name.to_string());
        }
    }
    if machine == Machine::Thumb {
        for (name, addr) in system_registers() {
            names.entry(addr).or_insert(name);
        }
    }
    Ok(names)
}

/// The registers of a Cortex-M's System Control Space, by the names the ARMv7-M Architecture
/// Reference Manual gives them: SysTick, the interrupt controller (NVIC), the system control
/// block (SCB), the memory protection unit, the debug registers and those of the floating-point
/// unit. ARMv6-M has a subset of them at the same addresses.
fn system_registers() -> Vec<(String, u64)> {
    const SINGLE: [(&str, u64); 37] = [
        ("ICTR", 0xE000_E004),
        ("ACTLR", 0xE000_E008),
        ("SYST_CSR", 0xE000_E010),
        ("SYST_RVR", 0xE000_E014),
        ("SYST_CVR", 0xE000_E018),
        ("SYST_CALIB", 0xE000_E01C),
        ("CPUID", 0xE000_ED00),
        ("ICSR", 0xE000_ED04),
        ("VTOR", 0xE000_ED08),
        ("AIRCR", 0xE000_ED0C),
        ("SCR", 0xE000_ED10),
        ("CCR", 0xE000_ED14),
        ("SHPR1", 0xE000_ED18),
        ("SHPR2", 0xE000_ED1C),
        ("SHPR3", 0xE000_ED20),
        ("SHCSR", 0xE000_ED24),
        ("CFSR", 0xE000_ED28),
        ("HFSR", 0xE000_ED2C),
        ("DFSR", 0xE000_ED30),
        ("MMFAR", 0xE000_ED34),
        ("BFAR", 0xE000_ED38),
        ("AFSR", 0xE000_ED3C),
        ("CPACR", 0xE000_ED88),
        ("MPU_TYPE", 0xE000_ED90),
        ("MPU_CTRL", 0xE000_ED94),
        ("MPU_RNR", 0xE000_ED98),
        ("MPU_RBAR", 0xE000_ED9C),
        ("MPU_RASR", 0xE000_EDA0),
        ("DHCSR", 0xE000_EDF0),
        ("DCRSR", 0xE000_EDF4),
        ("DCRDR", 0xE000_EDF8),
        ("DEMCR", 0xE000_EDFC),
        ("STIR", 0xE000_EF00),
        ("FPCCR", 0xE000_EF34),
        ("FPCAR", 0xE000_EF38),
        ("FPDSCR", 0xE000_EF3C),
        ("MVFR0", 0xE000_EF40),
    ];
    // The NVIC's registers come in banks of one bit per interrupt, 496 at most, and its
    // priorities a byte per interrupt.
    const BANKS: [(&str, u64, u64); 6] = [("NVIC_ISER", 0xE000_E100, 16), ("NVIC_ICER", 0xE000_E180, 16), ("NVIC_ISPR", 0xE000_E200, 16), ("NVIC_ICPR", 0xE000_E280, 16), ("NVIC_IABR", 0xE000_E300, 16), ("NVIC_IPR", 0xE000_E400, 124)];
    let banks = BANKS.iter().flat_map(|&(name, base, count)| (0..count).map(move |n| (format!("{name}{n}"), base + 4 * n)));
    SINGLE.iter().map(|&(name, addr)| (name.to_string(), addr)).chain(banks).collect()
}

/// The space of an 8051 a data address is in, as a names file calls it, and the address there;
/// on a Cortex-M, the part of its memory the architecture sets aside for what the address is
/// in, and the address. None for an address of code, and on a machine with one space.
pub fn space(image: &Image, addr: u64) -> Option<(&'static str, u64)> {
    if image.machine == Machine::Thumb {
        return crate::thumb::MEMORY.iter().find(|&&(start, end, _)| (start..end).contains(&addr)).map(|&(_, _, name)| (name, addr));
    }
    let spaces = [(BIT, "bit"), (SFR, "sfr"), (IDATA, "idata"), (XDATA, "xdata")];
    let (base, space) = spaces.into_iter().find(|&(base, _)| image.machine == Machine::I8051 && addr >= base)?;
    Some((space, addr - base))
}

/// A data address the way a person writes it: the space it is in and the address there. Other
/// addresses are written as they are.
pub fn place(image: &Image, addr: u64) -> String {
    match space(image, addr) {
        Some((space, addr)) => format!("{space} {addr:#x}"),
        None => format!("{addr:#x}"),
    }
}

/// The names of the bits of the byte at `addr` that have one, with the address of each bit.
pub fn bits(image: &Image, addr: u64) -> Vec<(u64, &str)> {
    let first = match addr {
        _ if image.machine != Machine::I8051 => return Vec::new(),
        _ if (IDATA + 0x20..IDATA + 0x30).contains(&addr) => (addr - IDATA - 0x20) * 8,
        _ if addr >= SFR + 0x80 && addr % 8 == 0 => addr - SFR,
        _ => return Vec::new(),
    };
    (first..first + 8).filter_map(|bit| Some((bit, image.symbol_names.get(&(BIT + bit))?.as_str()))).collect()
}

/// Whether an 8051 instruction reads the direct address, the bit or the external data it
/// names, and whether it writes there.
fn access_8051(opcode: u8) -> (bool, bool) {
    match opcode {
        // MOVX A, @DPTR and MOVX @DPTR, A.
        0xE0 => (true, false),
        0xF0 => (false, true),
        // JB, JNB, and the bit as an operand of carry: ORL, ANL, MOV C, and their complements.
        0x20 | 0x30 | 0x72 | 0x82 | 0xA0 | 0xA2 | 0xB0 => (true, false),
        // MOV bit, C; CLR bit; SETB bit.
        0x92 | 0xC2 | 0xD2 => (false, true),
        // ADD, ADDC, ORL, ANL, XRL and SUBB into A, CJNE, MOV A, and MOV from a direct address
        // to another, to a register or through one; PUSH.
        0x25 | 0x35 | 0x45 | 0x55 | 0x65 | 0x95 | 0xB5 | 0xE5 | 0x85 | 0xA6..=0xAF | 0xC0 => (true, false),
        // MOV to a direct address from a constant, from A, from a register or through one; POP.
        0x75 | 0xF5 | 0x86..=0x8F | 0xD0 => (false, true),
        // What changes its operand in place: INC, DEC, ORL, ANL and XRL into it, XCH, DJNZ,
        // JBC and CPL bit.
        _ => (true, true),
    }
}

/// A data address the code reads or writes.
#[derive(Debug, PartialEq)]
pub struct Accessed {
    pub addr: u64,
    /// Instructions that read it, and that write it. One that does both counts as both, and so
    /// does any instruction on a machine where the two are not told apart.
    pub reads: usize,
    pub writes: usize,
    /// Entries of the functions those instructions are in.
    pub functions: BTreeSet<u64>,
}

/// The data addresses the code of `program` reads or writes that `is_named` does not hold a
/// name for, the most accessed first: where a name would explain the most code.
pub fn unnamed(program: &Program, is_named: impl Fn(u64) -> bool) -> Vec<Accessed> {
    let image = &program.image;
    let mut found: BTreeMap<u64, Accessed> = BTreeMap::new();
    for reference in program.analysis.data_refs.iter().filter(|reference| reference.access && !image.is_code(reference.to) && !is_named(reference.to)) {
        let opcode = image.bytes_from(reference.from).and_then(|bytes| bytes.first().copied());
        let (reads, writes) = match (image.machine, opcode) {
            (Machine::I8051, Some(opcode)) => access_8051(opcode),
            (Machine::Thumb, Some(_)) => image.bytes_from(reference.from).and_then(crate::thumb::access).unwrap_or((true, true)),
            _ => (true, true),
        };
        let accessed = found.entry(reference.to).or_insert_with(|| Accessed { addr: reference.to, reads: 0, writes: 0, functions: BTreeSet::new() });
        accessed.reads += usize::from(reads);
        accessed.writes += usize::from(writes);
        accessed.functions.extend(program.owners(reference.from));
    }
    let mut found: Vec<Accessed> = found.into_values().collect();
    found.sort_by_key(|accessed| std::cmp::Reverse(accessed.reads + accessed.writes));
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_8051_has_its_standard_registers_and_a_file_adds_and_replaces() {
        let standard = read(Machine::I8051, "").unwrap();
        assert_eq!((standard[&(SFR + 0x81)].as_str(), standard[&(SFR + 0xE0)].as_str(), standard[&(BIT + 0xAF)].as_str(), standard.len()), ("SP", "ACC", "EA", 64));
        assert!(read(Machine::X86_64, "").unwrap().is_empty());

        let file = "[sfr]\nPORT0 = 0x80\nP4 = 0xc0\n[xdata]\nLCD = 0x8100\n[bit]\nIRQ_ON = 0xaf\nLED = 0x93\n[code]\nmain = 0x1a40\n";
        let named = read(Machine::I8051, file).unwrap();
        let name = |addr: u64| named[&addr].as_str();
        assert_eq!([name(SFR + 0x80), name(SFR + 0xC0), name(XDATA + 0x8100), name(BIT + 0xAF), name(BIT + 0x93), name(0x1A40), name(SFR + 0x90)], ["PORT0", "P4", "LCD", "IRQ_ON", "LED", "main", "P1"]);
        assert!(read(Machine::X86_64, file).is_err(), "only an 8051 has these spaces");
        assert!(read(Machine::I8051, "[sfr]\nSTACK = 0x7f\n").is_err(), "0x7f is internal data, not a register");
    }

    #[test]
    fn a_cortex_m_has_its_system_registers_and_a_file_names_its_devices() {
        let standard = read(Machine::Thumb, "").unwrap();
        let name = |addr: u64| standard.get(&addr).map(String::as_str);
        assert_eq!([name(0xE000_E010), name(0xE000_ED08), name(0xE000_E104), name(0xE000_E5EC), name(0x4001_3800)], [Some("SYST_CSR"), Some("VTOR"), Some("NVIC_ISER1"), Some("NVIC_IPR123"), None]);
        let named = read(Machine::Thumb, "[memory]\nUSART1_SR = 0x40013800\nTICK_RELOAD = 0xe000e014\n").unwrap();
        assert_eq!([named[&0x4001_3800].as_str(), named[&0xE000_E014].as_str()], ["USART1_SR", "TICK_RELOAD"]);
        assert!(read(Machine::I8051, "[memory]\nX = 0x10\n").is_err(), "an 8051 has several spaces");
    }

    #[test]
    fn the_addresses_without_a_name_come_most_accessed_first() {
        // MOV DPTR, #0x8100; MOVX A, @DPTR; MOVX @DPTR, A; MOV 0xC0, A; INC 0x30; MOV SP, #0x60; RET.
        let code = [0x90, 0x81, 0x00, 0xE0, 0xF0, 0xF5, 0xC0, 0x05, 0x30, 0x75, 0x81, 0x60, 0x22];
        let layout: crate::layout::Layout = toml::from_str("machine = \"8051\"\nentry = [0]\nregion = []").unwrap();
        let section = crate::image::Section { name: String::new(), addr: 0, data: code.to_vec(), file_offset: None, executable: true, writable: false };
        let mut image = layout.image(String::new(), vec![section], None).unwrap();
        image.symbol_names = read(Machine::I8051, "").unwrap();
        let analysis = crate::analyze(&image);
        let program = Program::new(image, analysis);
        let found = unnamed(&program, |addr| program.image.symbol_names.contains_key(&addr));
        let rows: Vec<(String, usize, usize)> = found.iter().map(|accessed| (place(&program.image, accessed.addr), accessed.reads, accessed.writes)).collect();
        // SP has its name. The others are ordered by how many instructions touch each.
        assert_eq!(rows, [("xdata 0x8100".to_string(), 1, 1), ("idata 0x30".to_string(), 1, 1), ("sfr 0xc0".to_string(), 0, 1)]);
        assert_eq!(found[0].functions, BTreeSet::from([0]));
    }

    #[test]
    fn an_instruction_reads_writes_or_changes_what_it_names() {
        // MOV A, direct; MOV direct, A; INC direct; MOVX @DPTR, A; JB bit; SETB bit.
        assert_eq!([0xE5, 0xF5, 0x05, 0xF0, 0x20, 0xD2].map(access_8051), [(true, false), (false, true), (true, true), (false, true), (true, false), (false, true)]);
    }
}
