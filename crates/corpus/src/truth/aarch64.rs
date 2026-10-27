//! AArch64 function scan, decoded with yaxpeax-arm so that truth shares no decoder with the
//! analysis core.

use std::collections::HashMap;

use object::{Object, ObjectSection, ObjectSymbol, SectionKind};
use yaxpeax_arch::{Decoder, U8Reader};
use yaxpeax_arm::armv8::a64::{InstDecoder, Instruction, Opcode, Operand, SizeCode};

use super::{Callee, Scan};

const NOP: u32 = 0xd503_201f;
const BTI_C: u32 = 0xd503_245f;

/// Decodes one 4-byte word. `udf` counts as undecodable: compilers do not emit it as code, so in
/// practice it is a zero word of padding or data.
fn decode(word: &[u8; 4]) -> Option<Instruction> {
    let instr = InstDecoder::default().decode(&mut U8Reader::new(word)).ok()?;
    (!matches!(instr.opcode, Opcode::Invalid | Opcode::UDF)).then_some(instr)
}

/// The page address an `adrp` at `at` computes into register `.0`.
fn adrp(instr: &Instruction, at: u64) -> Option<(u16, u64)> {
    match (instr.opcode, instr.operands[0], instr.operands[1]) {
        (Opcode::ADRP, Operand::Register(SizeCode::X, reg), Operand::PCOffset(offset)) => {
            Some((reg, (at & !0xfff).wrapping_add_signed(offset)))
        }
        _ => None,
    }
}

/// `ldr xD, [xN, #offset]` as `(D, N, offset)`.
fn load(instr: &Instruction) -> Option<(u16, u16, i32)> {
    match (instr.opcode, instr.operands[0], instr.operands[1]) {
        (Opcode::LDR, Operand::Register(SizeCode::X, dest), Operand::RegPreIndex(base, offset, false)) => Some((dest, base, offset)),
        _ => None,
    }
}

/// Maps each PLT stub's address to the GOT slot it jumps through.
///
/// A stub is `adrp x16, page; ldr x17, [x16, #off]; add x16, x16, #off; br x17`, preceded by
/// `bti c` in BTI-enabled binaries, in which case calls land on the `bti c`.
pub fn plt_stubs(binary: &object::File) -> HashMap<u64, u64> {
    let mut stubs = HashMap::new();
    for section in binary.sections().filter(|s| s.name().is_ok_and(|name| name.starts_with(".plt"))) {
        let Ok(data) = section.data() else { continue };
        let words = data.as_chunks::<4>().0;
        for (index, window) in words.windows(4).enumerate() {
            let at = section.address() + 4 * index as u64;
            let [Some(first), Some(second), Some(third), Some(fourth)] = [0, 1, 2, 3].map(|i| decode(&window[i])) else { continue };
            let (Some((16, page)), Some((17, 16, offset))) = (adrp(&first, at), load(&second)) else { continue };
            let jumps = (third.opcode, fourth.opcode, fourth.operands[0]) == (Opcode::ADD, Opcode::BR, Operand::Register(SizeCode::X, 17));
            if !jumps {
                continue;
            }
            let slot = page.wrapping_add_signed(offset.into());
            stubs.insert(at, slot);
            if index > 0 && words[index - 1] == BTI_C.to_le_bytes() {
                stubs.insert(at - 4, slot);
            }
        }
    }
    stubs
}

/// Ranges of literal data inside executable sections, sorted, from the `$d` and `$x` mapping
/// symbols of the debug file: data runs from a `$d` to the next `$x` or the end of its section.
pub fn data_ranges(binary: &object::File, debug: &object::File) -> Vec<(u64, u64)> {
    let mut ranges = Vec::new();
    for section in binary.sections().filter(|s| s.kind() == SectionKind::Text && s.size() > 0) {
        let (start, end) = (section.address(), section.address() + section.size());
        // Mapping symbols of non-loaded sections (DWARF) hold section offsets that look like text
        // addresses, so the symbol must belong to this very section of the debug file.
        let in_section = |symbol: &object::Symbol| {
            let owner = symbol.section_index().and_then(|index| debug.section_by_index(index).ok());
            owner.is_some_and(|owner| owner.address() == start && owner.name().ok() == section.name().ok())
        };
        let mut marks: Vec<(u64, bool)> = debug
            .symbols()
            .filter(|symbol| symbol.address() >= start && symbol.address() < end && in_section(symbol))
            .filter_map(|symbol| {
                let name = symbol.name().ok()?;
                let is_data = name == "$d" || name.starts_with("$d.");
                (is_data || name == "$x" || name.starts_with("$x.")).then_some((symbol.address(), is_data))
            })
            .collect();
        marks.sort_unstable();
        marks.push((end, false));
        for pair in marks.windows(2) {
            if pair[0].1 && pair[0].0 < pair[1].0 {
                ranges.push((pair[0].0, pair[1].0));
            }
        }
    }
    ranges.sort_unstable();
    ranges
}

/// What a register holds while following an `adrp`/`ldr` pair to an indirect call.
#[derive(Clone, Copy)]
enum Known {
    Page(u64),
    /// Loaded from the GOT slot at this address.
    Slot(u64),
}

/// Decodes one function body linearly, skipping the words `data` marks as literal data.
pub fn scan(bytes: &[u8], addr: u64, data: &[(u64, u64)]) -> Scan {
    let mut scan = Scan::default();
    let is_data = |at: u64| {
        let index = data.partition_point(|&(start, _)| start <= at);
        index > 0 && at < data[index - 1].1
    };
    // Only an unbroken run of `adrp` and `ldr` leading up to a `blr` is trusted.
    let mut known: HashMap<u16, Known> = HashMap::new();
    let mut last_real: Option<(u64, bool)> = None;
    let (words, rest) = bytes.as_chunks::<4>();
    scan.undecodable_bytes += rest.len() as u64;

    for (index, word) in words.iter().enumerate() {
        let at = addr + 4 * index as u64;
        if is_data(at) {
            scan.data_bytes += 4;
            known.clear();
            continue;
        }
        let Some(instr) = decode(word) else {
            scan.undecodable_bytes += 4;
            known.clear();
            continue;
        };
        scan.instructions += 1;

        let is_call = matches!(instr.opcode, Opcode::BL | Opcode::BLR | Opcode::BLRAA | Opcode::BLRAAZ | Opcode::BLRAB | Opcode::BLRABZ);
        if *word != NOP.to_le_bytes() {
            last_real = Some((at, is_call));
        }
        match (instr.opcode, instr.operands[0]) {
            (Opcode::BL, Operand::PCOffset(offset)) => scan.calls.push((at, Callee::Direct(at.wrapping_add_signed(offset)))),
            (Opcode::BLR, Operand::Register(SizeCode::X, reg)) => {
                if let Some(&Known::Slot(slot)) = known.get(&reg) {
                    scan.calls.push((at, Callee::Slot(slot)));
                }
            }
            _ => {}
        }

        if let Some((reg, page)) = adrp(&instr, at) {
            known.insert(reg, Known::Page(page));
        } else if let Some((dest, base, offset)) = load(&instr) {
            match known.get(&base) {
                Some(&Known::Page(page)) => known.insert(dest, Known::Slot(page.wrapping_add_signed(offset.into()))),
                _ => known.remove(&dest),
            };
        } else {
            known.clear();
        }
    }
    if let Some((addr, true)) = last_real {
        scan.final_call = Some(addr);
    }
    scan
}
