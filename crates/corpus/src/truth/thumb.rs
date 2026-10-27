//! Ground truth for a Cortex-M program built by `corpus/build_thumb.py`.
//!
//! The raw image is cut from an ELF, which is kept as the program's debug file. Its symbol table
//! gives each function's start and size: bit 0 of a Thumb function's value is the mark of Thumb
//! code, not part of its address. Code that a `$t` mapping symbol marks and no function symbol
//! covers, as an object of libgcc linked whole but without its symbols, is a function too, up to
//! the next. Its mapping symbols say where code (`$t`) and data (`$d`)
//! alternate inside the code, as a literal pool or a jump table does, and its DWARF which
//! functions never return. Instructions are decoded with yaxpeax-arm, so that truth shares no
//! decoder with recore.
//!
//! A `switch` jumps through a table that lies in the code right after its dispatch, as one
//! `$d` run. Clang dispatches four ways: `TBB` and `TBH` on Thumb-2, whose entries are half
//! the distance from the instruction after the dispatch to the case; on Thumb-1, `ADD PC, Rm`
//! after a load of a byte or a halfword entry, which is half the distance from the `ADD`'s own
//! PC; and `MOV PC, Rm` after a load of a word, which is the case's address with the Thumb bit.
//! GCC's Thumb-1 code calls one of libgcc's switch helpers instead, with its table right after the
//! `BL`, and the helper returns to twice the entry past the table.
//! A table of an odd number of bytes is padded with a zero, whose target would be the table.
//! A literal pool may follow a table in the same run of data: the table ends at the first
//! literal that a load reads.

use std::collections::{BTreeMap, HashSet};
use std::path::Path;

use anyhow::{Context, Result};
use object::{Object, ObjectSection, ObjectSymbol, SectionKind, SymbolKind};
use yaxpeax_arch::{Decoder, LengthedInstruction, U8Reader};
use yaxpeax_arm::armv7::{InstDecoder, Instruction, Opcode, Operand, Reg};

use super::{Callee, Callees, Function, Scan, Truth, classify, dwarf_noreturn, is_mapping_symbol};
use crate::jumptables::{Extracted, JumpTable, JumpTables, Rejected};

/// The name of a program, which its layout is named after.
fn name(layout: &Path) -> String {
    layout.file_stem().unwrap_or_default().to_string_lossy().into_owned()
}

/// The ELF's code: its executable sections as `(address, bytes)`, and the `[start, end)` runs of
/// data in them that the `$d` mapping symbols mark, sorted.
struct Code<'a> {
    sections: Vec<(u64, &'a [u8])>,
    data: Vec<(u64, u64)>,
}

impl<'a> Code<'a> {
    fn read(elf: &'a object::File) -> Code<'a> {
        let sections: Vec<(u64, &[u8])> = elf.sections().filter(|s| s.kind() == SectionKind::Text).filter_map(|s| Some((s.address(), s.data().ok()?))).collect();
        let mut marks: Vec<(u64, bool)> = elf
            .symbols()
            .filter_map(|symbol| {
                let name = symbol.name().ok()?;
                let is_data = name == "$d" || name.starts_with("$d.");
                (is_data || name == "$t" || name.starts_with("$t.")).then_some((symbol.address(), is_data))
            })
            .collect();
        marks.extend(sections.iter().map(|&(addr, bytes)| (addr + bytes.len() as u64, false)));
        marks.sort_unstable();
        // A `$d` after a `$d` continues its run, as GCC marks the byte that pads a `TBB` table.
        marks.dedup_by_key(|&mut (_, is_data)| is_data);
        let data = marks.windows(2).filter(|pair| pair[0].1 && pair[0].0 < pair[1].0).map(|pair| (pair[0].0, pair[1].0)).collect();
        Code { sections, data }
    }

    fn bytes(&self, start: u64, end: u64) -> Option<&'a [u8]> {
        let &(addr, bytes) = self.sections.iter().find(|&&(addr, bytes)| start >= addr && end <= addr + bytes.len() as u64)?;
        bytes.get((start - addr) as usize..(end - addr) as usize)
    }

    /// The data run that `at` is in.
    fn data_at(&self, at: u64) -> Option<(u64, u64)> {
        let index = self.data.partition_point(|&(start, _)| start <= at);
        self.data[..index].last().copied().filter(|&(_, end)| at < end)
    }

    /// The instructions of `[start, end)`, by address, stepping over its data.
    fn instructions(&self, start: u64, end: u64) -> Vec<(u64, u8, Option<Instruction>)> {
        let decoder = InstDecoder::default_thumb();
        let mut found = Vec::new();
        let mut at = start;
        while at < end {
            if let Some((_, data_end)) = self.data_at(at) {
                at = data_end;
                continue;
            }
            let Some(bytes) = self.bytes(at, end) else { break };
            match decoder.decode(&mut U8Reader::new(bytes)) {
                Ok(instruction) => {
                    let len = instruction.len().to_const() as u8;
                    found.push((at, len, Some(instruction)));
                    at += u64::from(len);
                }
                Err(_) => {
                    found.push((at, 2, None));
                    at += 2;
                }
            }
        }
        found
    }
}

/// The functions of the ELF, by address, without the Thumb bit. Of several names at one address,
/// as the weak names of one default handler are, the first in the symbol table stays. Code that
/// only a `$t` marks has no name, and ends where the next function or its section does.
fn functions(elf: &object::File, code: &Code) -> BTreeMap<u64, (String, u64)> {
    let mut by_addr = BTreeMap::new();
    for symbol in elf.symbols().filter(|symbol| symbol.kind() == SymbolKind::Text) {
        let name = symbol.name().unwrap_or_default();
        let addr = symbol.address() & !1;
        if is_mapping_symbol(name) || name.starts_with("$t") || code.bytes(addr, addr + 1).is_none() {
            continue;
        }
        by_addr.entry(addr).or_insert((name.to_string(), symbol.size()));
    }
    let unnamed: Vec<u64> = elf.symbols().filter(|symbol| symbol.name().is_ok_and(|name| name == "$t" || name.starts_with("$t."))).map(|symbol| symbol.address()).collect();
    for addr in unnamed {
        let covered = by_addr.range(..=addr).next_back().is_some_and(|(&start, (_, size))| start == addr || addr < start + size);
        if covered {
            continue;
        }
        let Some(&(section, bytes)) = code.sections.iter().find(|&&(start, bytes)| (start..start + bytes.len() as u64).contains(&addr)) else { continue };
        let end = by_addr.range(addr..).next().map_or(section + bytes.len() as u64, |(&next, _)| next).min(section + bytes.len() as u64);
        by_addr.insert(addr, (String::new(), end - addr));
    }
    by_addr
}

/// The scan of one function's code: its instructions, its data, and its direct calls.
fn scan(code: &Code, start: u64, end: u64) -> Scan {
    let mut scan = Scan::default();
    let instructions = code.instructions(start, end);
    let decoded: u64 = instructions.iter().map(|&(_, len, _)| u64::from(len)).sum();
    scan.data_bytes = (end - start).saturating_sub(decoded);
    let mut last = None;
    for (at, len, instruction) in instructions {
        let Some(instruction) = instruction else {
            scan.undecodable_bytes += u64::from(len);
            continue;
        };
        scan.instructions += 1;
        let call = (instruction.opcode == Opcode::BL).then(|| branch_target(&instruction, at)).flatten();
        if let Some(target) = call {
            scan.calls.push((at, Callee::Direct(target)));
        }
        if !is_nop(&instruction) {
            last = Some((at, call.is_some()));
        }
    }
    scan.final_call = last.filter(|&(_, is_call)| is_call).map(|(at, _)| at);
    scan
}

/// Where a branch at `at` goes. The offset counts from the instruction after the next.
fn branch_target(instruction: &Instruction, at: u64) -> Option<u64> {
    match instruction.operands[0] {
        Operand::BranchThumbOffset(offset) => Some(at.wrapping_add(4).wrapping_add_signed(i64::from(offset) * 2)),
        _ => None,
    }
}

/// `NOP`, or `MOV R8, R8`, the Thumb-1 filler.
fn is_nop(instruction: &Instruction) -> bool {
    instruction.opcode == Opcode::NOP || instruction.opcode == Opcode::MOV && instruction.operands[..2] == [Operand::Reg(Reg::from_u8(8)), Operand::Reg(Reg::from_u8(8))]
}

/// The functions of the program `layout` loads, from the ELF at `debug_path`. Only the layout
/// comes through recore, for the regions of code.
pub fn extract(layout: &Path, debug_path: &Path) -> Result<Truth> {
    let image = recore::Image::load(layout)?;
    let data = std::fs::read(debug_path).with_context(|| format!("reading {debug_path:?}"))?;
    let elf = object::File::parse(&*data)?;
    let code = Code::read(&elf);
    let noreturn = dwarf_noreturn(&elf).unwrap_or_default();
    let by_addr = functions(&elf, &code);
    let functions: Vec<Function> = by_addr
        .iter()
        .map(|(&addr, (name, size))| Function {
            addr,
            size: *size,
            name: name.clone(),
            fragment: false,
            noreturn: noreturn.addrs.contains(&addr) || noreturn.names.contains(name),
            thunk: false,
        })
        .collect();
    let noreturn_addrs: HashSet<u64> = functions.iter().filter(|f| f.noreturn).map(|f| f.addr).collect();
    let scans = functions.iter().map(|function| scan(&code, function.addr, function.addr + function.size));
    let calls = classify(
        scans,
        &Callees { noreturn_addrs: &noreturn_addrs, stubs: &Default::default(), slots: &Default::default(), is_noreturn_import: &|_| false, widen_slots: false },
    );
    let exec: Vec<(u64, u64)> = image.sections.iter().filter(|section| section.executable).map(|section| (section.addr, section.end())).collect();
    let regions: Vec<(u64, u64)> = image.sections.iter().map(|section| (section.addr, section.end())).collect();
    Ok(Truth {
        name: name(layout),
        text: (regions.iter().map(|&(start, _)| start).min().unwrap_or(0), regions.iter().map(|&(_, end)| end).max().unwrap_or(0)),
        exec,
        functions,
        instructions: calls.instructions,
        noreturn_calls: calls.noreturn_calls,
        terminal_calls: calls.terminal_calls,
        noreturn_imports: Vec::new(),
        undecodable_bytes: calls.undecodable_bytes,
        data_bytes: calls.data_bytes,
    })
}

/// The register an instruction names as its operand `index`.
fn register(instruction: &Instruction, index: usize) -> Option<u8> {
    match instruction.operands[index] {
        Operand::Reg(reg) => Some(reg.number()),
        _ => None,
    }
}

/// GCC's Thumb-1 switch helpers: the name, the size of an entry, and whether the entry is signed.
const CASE_HELPERS: [(&str, u64, bool); 4] =
    [("__gnu_thumb1_case_uqi", 1, false), ("__gnu_thumb1_case_sqi", 1, true), ("__gnu_thumb1_case_uhi", 2, false), ("__gnu_thumb1_case_shi", 2, true)];

/// The switch helpers among the ELF's functions, by address, as the size of an entry and whether
/// it is signed.
fn case_helpers(functions: &BTreeMap<u64, (String, u64)>) -> BTreeMap<u64, (u64, bool)> {
    functions
        .iter()
        .filter_map(|(&addr, (name, _))| CASE_HELPERS.iter().find(|&&(helper, ..)| helper == name).map(|&(_, size, signed)| (addr, (size, signed))))
        .collect()
}

/// How a dispatch finds the case in an entry of its table: the size of an entry, and the case's
/// address from the entry's value.
enum Dispatch {
    /// `TBB`, `TBH`, `ADD PC, Rm` or a `BL` to a switch helper: twice the entry from this address.
    Relative { size: u64, signed: bool, base: u64 },
    /// `MOV PC, Rm`: the entry, Thumb bit and all, in the table an `ADR` before it names.
    Absolute { table: u64 },
}

/// `[start, end)` of each literal a load in `instructions` reads at an offset from PC.
fn literals(instructions: &[(u64, u8, Option<Instruction>)]) -> Vec<(u64, u64)> {
    let size = |opcode: Opcode| match opcode {
        Opcode::LDR => Some(4),
        Opcode::LDRH | Opcode::LDRSH => Some(2),
        Opcode::LDRB | Opcode::LDRSB => Some(1),
        _ => None,
    };
    instructions
        .iter()
        .filter_map(|(at, _, instruction)| {
            let instruction = instruction.as_ref()?;
            let Operand::RegDerefPreindexOffset(base, offset, up, _) = instruction.operands[1] else { return None };
            let size = size(instruction.opcode).filter(|_| base.number() == 15)?;
            let pc = (at + 4) & !3;
            let start = if up { pc + u64::from(offset) } else { pc - u64::from(offset) };
            Some((start, start + size))
        })
        .collect()
}

/// What the instructions before a run of data say about it: the dispatch that reads it as a
/// table, if one does, or why it is no table that can be read. `helpers` are the switch helpers
/// by address.
fn dispatch(before: &[(u64, u8, Option<Instruction>)], helpers: &BTreeMap<u64, (u64, bool)>) -> Option<Result<(u64, Dispatch), String>> {
    // An instruction may pad the table to its alignment.
    let real: Vec<&(u64, u8, Option<Instruction>)> = before.iter().rev().filter(|(_, _, instruction)| !instruction.as_ref().is_some_and(is_nop)).take(4).collect();
    let &&(at, _, Some(ref jump)) = real.first()? else { return None };
    let writes_pc = register(jump, 0) == Some(15);
    let loaded = |opcodes: &[Opcode]| real[1..].iter().find_map(|(_, _, instruction)| instruction.as_ref().filter(|instruction| opcodes.contains(&instruction.opcode)));
    Some(Ok(match jump.opcode {
        Opcode::TBB => (at, Dispatch::Relative { size: 1, signed: false, base: at + 4 }),
        Opcode::TBH => (at, Dispatch::Relative { size: 2, signed: false, base: at + 4 }),
        Opcode::BL => {
            let &(size, signed) = helpers.get(&branch_target(jump, at)?)?;
            (at, Dispatch::Relative { size, signed, base: at + 4 })
        }
        Opcode::ADD if writes_pc => {
            let size = match loaded(&[Opcode::LDRB, Opcode::LDRH]).map(|load| load.opcode) {
                Some(Opcode::LDRB) => 1,
                Some(_) => 2,
                None => return Some(Err("ADD PC with no load of an entry before it".into())),
            };
            (at, Dispatch::Relative { size, signed: false, base: at + 4 })
        }
        Opcode::MOV if writes_pc => {
            let adr = real[1..].iter().find_map(|(at, _, instruction)| match instruction.as_ref()?.operands {
                [Operand::Reg(_), Operand::Imm32(offset), ..] if instruction.as_ref()?.opcode == Opcode::ADR => Some(((at + 4) & !3) + u64::from(offset)),
                _ => None,
            });
            match (loaded(&[Opcode::LDR]), adr) {
                (Some(_), Some(table)) => (at, Dispatch::Absolute { table }),
                _ => return Some(Err("MOV PC with no ADR of a table and load of an entry before it".into())),
            }
        }
        _ => return None,
    }))
}

/// The jump tables of the program `layout` loads, from the ELF at `debug_path`.
pub fn jump_tables(layout: &Path, debug_path: &Path) -> Result<Option<Extracted>> {
    let data = std::fs::read(debug_path).with_context(|| format!("reading {debug_path:?}"))?;
    let elf = object::File::parse(&*data)?;
    let code = Code::read(&elf);
    let (mut tables, mut rejected) = (Vec::new(), Vec::new());
    let functions = functions(&elf, &code);
    let helpers = case_helpers(&functions);
    for (&start, (_, size)) in &functions {
        let end = start + size;
        let instructions = code.instructions(start, end);
        for &(table, table_end) in code.data.iter().filter(|&&(table, _)| table > start && table < end) {
            match table_at(&|start, end| code.bytes(start, end), &helpers, &instructions, table, table_end, start, end) {
                None => {}
                Some(Ok(found)) => tables.push(found),
                Some(Err(reason)) => rejected.push(Rejected { table, reason }),
            }
        }
    }
    tables.sort_by_key(|table| table.jump);
    let listed = tables.len() + rejected.len();
    Ok(Some(Extracted { truth: JumpTables { name: name(layout), tables }, listed, rejected }))
}

/// The table that the data run `[table, table_end)` of the function `[start, end)` holds, if the
/// Thumb `instructions` of the function before it end in a dispatch that reads it, or why it
/// cannot be read. `helpers` are the switch helpers by address.
pub(super) fn table_at<'a>(
    bytes: &dyn Fn(u64, u64) -> Option<&'a [u8]>,
    helpers: &BTreeMap<u64, (u64, bool)>,
    instructions: &[(u64, u8, Option<Instruction>)],
    table: u64,
    table_end: u64,
    start: u64,
    end: u64,
) -> Option<Result<JumpTable, String>> {
    let before = &instructions[..instructions.partition_point(|&(at, _, _)| at < table)];
    let (jump, kind) = match dispatch(before, helpers)? {
        Err(reason) => return Some(Err(reason)),
        Ok(found) => found,
    };
    // A run of data may begin with a literal before the table the ADR names, and an ADR may name
    // data of another run, which is not this table.
    let table = match kind {
        Dispatch::Absolute { table: named } if !(table..table_end).contains(&named) => return Some(Err(format!("an ADR of {named:#x}, outside the data at {table:#x}"))),
        Dispatch::Absolute { table } => table,
        Dispatch::Relative { .. } => table,
    };
    let table_end = literals(instructions).iter().map(|&(literal, _)| literal).filter(|&literal| literal >= table && literal < table_end).min().unwrap_or(table_end);
    // A pool of literals after the table and the instruction that pads it, as GCC puts one.
    if table_end == table {
        return None;
    }
    let Some(bytes) = bytes(table, table_end) else { return Some(Err("a table outside the code".into())) };
    let mut targets: Vec<u64> = match kind {
        Dispatch::Relative { size, signed, base } => bytes
            .chunks_exact(size as usize)
            .map(|entry| {
                let value = entry.iter().rev().fold(0i64, |value, &byte| value << 8 | i64::from(byte));
                let bits = 64 - 8 * size as u32;
                base.wrapping_add_signed(2 * if signed { value << bits >> bits } else { value })
            })
            .collect(),
        Dispatch::Absolute { .. } => bytes.as_chunks::<4>().0.iter().map(|entry| u64::from(u32::from_le_bytes(*entry)) & !1).collect(),
    };
    // Padding: an entry whose case would be the table itself.
    targets.retain(|&target| !(table..table_end).contains(&target));
    targets.sort_unstable();
    targets.dedup();
    if let Some(&outside) = targets.iter().find(|&&target| target < start || target >= end) {
        return Some(Err(format!("a case at {outside:#x} outside the function")));
    }
    Some(Ok(JumpTable { jump, table, targets, unreachable: None }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_signed_table_after_a_call_to_a_switch_helper() {
        // `BL 0x200`, to `__gnu_thumb1_case_shi`, then entries of 4 and -4.
        let code = [0x00, 0xf0, 0x7e, 0xf8, 0x04, 0x00, 0xfc, 0xff];
        let bytes = |start: u64, end: u64| code.get((start - 0x100) as usize..(end - 0x100) as usize);
        let bl = InstDecoder::default_thumb().decode(&mut U8Reader::new(&code)).unwrap();
        let helpers = BTreeMap::from([(0x200, (2, true))]);
        let table = table_at(&bytes, &helpers, &[(0x100, 4, Some(bl))], 0x104, 0x108, 0xf0, 0x120).unwrap().unwrap();
        assert_eq!((table.jump, table.table, table.targets), (0x100, 0x104, vec![0xfc, 0x10c]));
    }
}
