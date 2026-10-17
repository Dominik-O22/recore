//! Ground truth for a 32-bit ARM Linux binary, from its debug file.
//!
//! Debian strips the binary and keeps its symbol table in the debug file, mapping symbols and
//! all: `$a` starts A32 code, `$t` Thumb code and `$d` data, each running to the next. Bit 0 of
//! a function symbol is the mark of Thumb code, not part of its address. Instructions are decoded
//! with yaxpeax-arm in the instruction set the symbols give, so that truth shares no decoder with
//! recore.
//!
//! GCC dispatches a `switch` three ways. Thumb-2 code uses `TBB` and `TBH`, whose table follows
//! as one `$d` run, read as the Cortex-M truth reads it. A32 code adds to PC four times an entry
//! that a byte or halfword table in `.rodata` gives, `ADD PC, PC, Rm, LSL #2`, or without such a
//! table jumps into a row of branches after the dispatch, one per case. Without PIC it loads PC
//! from a table of addresses that follows, `LDR PC, [PC, Rm, LSL #2]`. Clang, which builds the
//! Rust programs, adds to the table's address an offset the table holds: `ADD PC, Rt, Re`. Where
//! the table is not among the code, its length is the bound the compare before the dispatch puts
//! on the index. A dispatch that is conditional, as `ADDLS PC, PC, Rm, LSL #2`, has the
//! instruction after it as a case too.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;

use anyhow::{Context, Result};
use object::{Object, ObjectSection, ObjectSymbol, SectionKind, SymbolKind};
use yaxpeax_arch::{Decoder, LengthedInstruction, U8Reader};
use yaxpeax_arm::armv7::{ConditionCode, InstDecoder, Instruction, Opcode, Operand, RegShiftStyle, ShiftStyle};

use super::{Callee, Callees, Function, Scan, Truth, classify, dwarf_noreturn, is_conditionally_noreturn, is_fragment, is_mapping_symbol, is_runtime_noreturn};
use crate::jumptables::{Extracted, JumpTable, JumpTables, Rejected};

/// What the bytes from a mapping symbol on are.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Run {
    A32,
    Thumb,
    Data,
}

/// One decoded instruction, or bytes that do not decode, with the instruction set it is in.
type Decoded = (u64, u8, Run, Option<Instruction>);

/// The binary's code: its executable sections as `(address, bytes)`, and the mapping symbols of
/// the debug file that fall in them, sorted.
struct Code<'a> {
    sections: Vec<(u64, &'a [u8])>,
    marks: Vec<(u64, Run)>,
}

impl<'a> Code<'a> {
    fn read(binary: &'a object::File, debug: &object::File) -> Code<'a> {
        let sections: Vec<(u64, &[u8])> = binary.sections().filter(|s| s.kind() == SectionKind::Text && s.size() > 0).filter_map(|s| Some((s.address(), s.data().ok()?))).collect();
        // Mapping symbols of sections that are not loaded, as DWARF's, hold offsets that look like
        // code addresses, so a symbol counts only where its own section is code.
        let in_code = |symbol: &object::Symbol| {
            let owner = symbol.section_index().and_then(|index| debug.section_by_index(index).ok());
            owner.is_some_and(|owner| owner.kind() == SectionKind::Text || sections.iter().any(|&(addr, _)| addr == owner.address() && owner.address() != 0))
        };
        let mut marks: Vec<(u64, Run)> = debug
            .symbols()
            .filter(in_code)
            .filter_map(|symbol| {
                let name = symbol.name().ok()?;
                let kind = name.split('.').next()?;
                let run = match kind {
                    "$a" => Run::A32,
                    "$t" => Run::Thumb,
                    "$d" => Run::Data,
                    _ => return None,
                };
                Some((symbol.address(), run))
            })
            .collect();
        marks.sort_unstable_by_key(|&(addr, _)| addr);
        marks.dedup_by_key(|&mut (addr, _)| addr);
        // GCC marks the byte that pads a table of an odd length as data of its own.
        marks.dedup_by_key(|&mut (_, run)| run);
        Code { sections, marks }
    }

    fn bytes(&self, start: u64, end: u64) -> Option<&'a [u8]> {
        let &(addr, bytes) = self.sections.iter().find(|&&(addr, bytes)| start >= addr && end <= addr + bytes.len() as u64)?;
        bytes.get((start - addr) as usize..(end - addr) as usize)
    }

    /// The instructions of the function at `[start, end)`, whose symbol says it begins in
    /// `first`, by address, stepping over its data.
    fn instructions(&self, start: u64, end: u64, first: Run) -> Vec<Decoded> {
        let (arm, thumb) = (InstDecoder::default(), InstDecoder::default_thumb());
        let first_inside = self.marks.partition_point(|&(addr, _)| addr <= start);
        let inside = &self.marks[first_inside..self.marks.partition_point(|&(addr, _)| addr < end).max(first_inside)];
        let mut found = Vec::new();
        let (mut at, mut run, mut next) = (start, first, 0);
        while at < end {
            while next < inside.len() && inside[next].0 <= at {
                run = inside[next].1;
                next += 1;
            }
            let run_end = inside.get(next).map_or(end, |&(addr, _)| addr);
            if run == Run::Data {
                at = run_end;
                continue;
            }
            let decoder = if run == Run::A32 { &arm } else { &thumb };
            let Some(bytes) = self.bytes(at, run_end) else { break };
            match decoder.decode(&mut U8Reader::new(bytes)) {
                Ok(instruction) => {
                    let len = instruction.len().to_const() as u8;
                    found.push((at, len, run, Some(instruction)));
                    at += u64::from(len);
                }
                Err(_) => {
                    let len = if run == Run::A32 { 4 } else { 2 };
                    found.push((at, len, run, None));
                    at += u64::from(len);
                }
            }
        }
        found
    }

    /// `[start, end)` of every `$d` run, sorted.
    fn data(&self) -> Vec<(u64, u64)> {
        let section_end = |at: u64| self.sections.iter().find(|&&(addr, bytes)| at >= addr && at < addr + bytes.len() as u64).map_or(at, |&(addr, bytes)| addr + bytes.len() as u64);
        self.marks
            .iter()
            .enumerate()
            .filter(|(_, (_, run))| *run == Run::Data)
            .map(|(index, &(start, _))| (start, self.marks.get(index + 1).map_or(section_end(start), |&(next, _)| next.min(section_end(start)))))
            .collect()
    }
}

/// The functions of the debug file, by address without the Thumb bit, with their size and the
/// instruction set they begin in. Of several names at one address the first that is no
/// fragment stays.
fn functions(debug: &object::File, code: &Code) -> BTreeMap<u64, (String, u64, Run)> {
    let mut by_addr: BTreeMap<u64, (String, u64, Run)> = BTreeMap::new();
    for symbol in debug.symbols().filter(|symbol| symbol.kind() == SymbolKind::Text) {
        let name = symbol.name().unwrap_or_default();
        let addr = symbol.address() & !1;
        if is_mapping_symbol(name) || name.starts_with("$a") || name.starts_with("$t") || code.bytes(addr, addr + 1).is_none() {
            continue;
        }
        let run = if symbol.address() & 1 != 0 { Run::Thumb } else { Run::A32 };
        match by_addr.get(&addr) {
            Some((existing, _, _)) if !is_fragment(existing) => {}
            _ => {
                by_addr.insert(addr, (name.to_string(), symbol.size(), run));
            }
        }
    }
    by_addr
}

/// Where a direct branch, call or `BLX` at `at` goes. A32 reads PC 8 bytes on, Thumb 4, and a
/// `BLX` from Thumb counts from that PC down to a word.
fn branch_target(instruction: &Instruction, at: u64, run: Run) -> Option<u64> {
    let pc = at + if run == Run::A32 { 8 } else { 4 };
    match (instruction.operands[0], instruction.opcode, run) {
        // yaxpeax-arm has already added the 8 bytes to this offset.
        (Operand::BranchOffset(offset), _, _) => Some(at.wrapping_add_signed(i64::from(offset) * 4)),
        (Operand::BranchThumbOffset(offset), Opcode::BLX, Run::Thumb) => Some((pc & !3).wrapping_add_signed(i64::from(offset) * 2)),
        (Operand::BranchThumbOffset(offset), _, _) => Some(pc.wrapping_add_signed(i64::from(offset) * 2)),
        _ => None,
    }
}

/// `NOP`, and the moves of a register to itself that pad A32 and Thumb-1 code.
fn is_nop(instruction: &Instruction) -> bool {
    instruction.opcode == Opcode::NOP || instruction.opcode == Opcode::MOV && matches!(instruction.operands[..2], [Operand::Reg(a), Operand::Reg(b)] if a == b)
}

/// The scan of one function's code: its instructions, its data, and its direct calls.
fn scan(code: &Code, start: u64, end: u64, first: Run) -> Scan {
    let mut scan = Scan::default();
    let instructions = code.instructions(start, end, first);
    let decoded: u64 = instructions.iter().map(|&(_, len, _, _)| u64::from(len)).sum();
    scan.data_bytes = (end - start).saturating_sub(decoded);
    let mut last = None;
    for (at, len, run, instruction) in instructions {
        let Some(instruction) = instruction else {
            scan.undecodable_bytes += u64::from(len);
            continue;
        };
        scan.instructions += 1;
        let direct = matches!(instruction.opcode, Opcode::BL | Opcode::BLX) && instruction.condition == ConditionCode::AL;
        let call = direct.then(|| branch_target(&instruction, at, run)).flatten();
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

/// The constant of an A32 data-processing immediate: eight bits rotated right by twice four.
fn a32_immediate(word: u32) -> u32 {
    (word & 0xFF).rotate_right(2 * (word >> 8 & 15))
}

/// Maps each PLT stub to the slot it jumps through. GNU ld's A32 stub is `ADD IP, PC, #a;
/// ADD IP, IP, #b; LDR PC, [IP, #c]!`, and a Thumb caller that cannot `BLX` reaches it through
/// `BX PC; NOP` right before it.
pub fn plt_stubs(binary: &object::File) -> HashMap<u64, u64> {
    let mut stubs = HashMap::new();
    for section in binary.sections().filter(|s| s.name().is_ok_and(|name| name.starts_with(".plt"))) {
        let Ok(data) = section.data() else { continue };
        let words: Vec<u32> = data.chunks_exact(4).map(|word| u32::from_le_bytes(word.try_into().unwrap())).collect();
        for (index, window) in words.windows(3).enumerate() {
            let at = section.address() + 4 * index as u64;
            let is = |word: u32, pattern: u32| word & 0xFFFF_F000 == pattern;
            if !(is(window[0], 0xE28F_C000) && is(window[1], 0xE28C_C000) && is(window[2], 0xE5BC_F000)) {
                continue;
            }
            let slot = at + 8 + u64::from(a32_immediate(window[0])) + u64::from(a32_immediate(window[1])) + u64::from(window[2] & 0xFFF);
            stubs.insert(at, slot);
            if index > 0 && words[index - 1] == 0x46C0_4778 {
                stubs.insert(at - 4, slot);
            }
        }
    }
    stubs
}

/// The functions of a 32-bit ARM binary, from its debug file.
pub fn extract(binary_path: &Path, binary: &object::File, debug: &object::File) -> Result<Truth> {
    let code = Code::read(binary, debug);
    let noreturn = dwarf_noreturn(debug).unwrap_or_default();
    let by_addr = functions(debug, &code);
    let functions: Vec<Function> = by_addr
        .iter()
        .map(|(&addr, (name, size, _))| Function {
            addr,
            size: *size,
            name: name.clone(),
            fragment: is_fragment(name),
            noreturn: noreturn.addrs.contains(&addr) || noreturn.names.contains(name),
            thunk: false,
        })
        .collect();
    let noreturn_addrs: HashSet<u64> = functions.iter().filter(|f| f.noreturn).map(|f| f.addr).collect();
    let (stubs, slots) = (plt_stubs(binary), super::import_slots(binary));
    let scans = by_addr.iter().map(|(&addr, &(_, size, run))| scan(&code, addr, addr + size, run));
    let calls = classify(
        scans,
        &Callees {
            noreturn_addrs: &noreturn_addrs,
            stubs: &stubs,
            slots: &slots,
            is_noreturn_import: &|name| !is_conditionally_noreturn(name) && (noreturn.declared.contains(name) || is_runtime_noreturn(name)),
            widen_slots: false,
        },
    );
    let exec: Vec<(u64, u64)> = code.sections.iter().map(|&(addr, bytes)| (addr, addr + bytes.len() as u64)).collect();
    let text = binary.section_by_name(".text").map(|s| (s.address(), s.address() + s.size())).context("no .text section")?;
    Ok(Truth {
        name: binary_path.file_name().unwrap().to_string_lossy().into_owned(),
        text,
        exec,
        functions,
        instructions: calls.instructions,
        noreturn_calls: calls.noreturn_calls,
        terminal_calls: calls.terminal_calls,
        noreturn_imports: calls.noreturn_imports.into_iter().collect(),
        undecodable_bytes: calls.undecodable_bytes,
        data_bytes: calls.data_bytes,
    })
}

const PC: u8 = 15;

/// The register an instruction names as its operand `index`.
fn register(instruction: &Instruction, index: usize) -> Option<u8> {
    match instruction.operands[index] {
        Operand::Reg(reg) => Some(reg.number()),
        _ => None,
    }
}

/// `Rm` of an operand `Rm, LSL #2`.
fn times_four(operand: Operand) -> Option<u8> {
    let shift = match operand {
        Operand::RegShift(shift) => shift,
        Operand::RegDerefPreindexRegShift(base, shift, true, false) if base.number() == PC => shift,
        _ => return None,
    };
    match shift.into_shift() {
        RegShiftStyle::RegImm(shift) if shift.stype() == ShiftStyle::LSL && shift.imm() == 2 => Some(shift.shiftee().number()),
        _ => None,
    }
}

/// The last instruction before `index` that writes `register`, in the order the code is laid
/// out, as far back as a call that may change it. A wrong guess here gives cases that are no
/// instructions of the function, which the table is rejected for.
fn definition(instructions: &[Decoded], index: usize, register: u8) -> Option<usize> {
    const CALLER_SAVED: u16 = 0b0101_0000_0000_1111;
    for at in (0..index).rev() {
        // yaxpeax-arm does not know every instruction, `UXTB` among them, and those write
        // registers too. A wrong guess here is caught as the comment above says.
        let Some(instruction) = instructions[at].3.as_ref() else { continue };
        if matches!(instruction.opcode, Opcode::BL | Opcode::BLX) && CALLER_SAVED >> register & 1 != 0 {
            return None;
        }
        let writes = match instruction.operands[0] {
            Operand::Reg(reg) => reg.number() == register && !matches!(instruction.opcode, Opcode::CMP | Opcode::CMN | Opcode::TST | Opcode::TEQ | Opcode::STR | Opcode::STRB | Opcode::STRH),
            _ => false,
        };
        if writes {
            return Some(at);
        }
    }
    None
}

/// The two registers a load adds for its address: `[Rn, Rm]`.
fn register_pair(operand: Operand) -> Option<(u8, u8)> {
    match operand {
        Operand::RegDerefPreindexReg(first, second, true, false) => Some((first.number(), second.number())),
        Operand::RegDerefPreindexRegShift(first, shift, true, false) => match shift.into_shift() {
            RegShiftStyle::RegImm(shift) if shift.imm() == 0 && shift.stype() == ShiftStyle::LSL => Some((first.number(), shift.shiftee().number())),
            _ => None,
        },
        _ => None,
    }
}

/// The highest value of `compared` that the compare and branch before `index` let through:
/// `CMP Rn, #bound` then a branch away when it is higher, or a dispatch that runs only when it
/// is lower or the same.
fn bound(instructions: &[Decoded], index: usize, compared: u8) -> Option<u64> {
    for at in (0..index).rev() {
        let instruction = instructions[at].3.as_ref()?;
        if instruction.opcode == Opcode::CMP && register(instruction, 0) == Some(compared) {
            return match instruction.operands[1] {
                Operand::Imm32(bound) => Some(u64::from(bound)),
                Operand::Imm12(bound) => Some(u64::from(bound)),
                _ => None,
            };
        }
        let writes = matches!(instruction.operands[0], Operand::Reg(reg) if reg.number() == compared) && !matches!(instruction.opcode, Opcode::CMP | Opcode::STR | Opcode::STRB | Opcode::STRH);
        if writes {
            return None;
        }
    }
    None
}

/// Where the code before `index` puts the address of a table in `register`: a literal with
/// an offset from PC, added to the PC of an `ADD Rd, PC, Rd`.
fn table_address(code: &Code, instructions: &[Decoded], index: usize, target: u8) -> Option<u64> {
    let add = definition(instructions, index, target)?;
    let (add_at, _, _, Some(instruction)) = &instructions[add] else { return None };
    let operands = (instruction.opcode, register(instruction, 1), register(instruction, 2));
    let other = match operands {
        (Opcode::ADD, Some(PC), Some(other)) | (Opcode::ADD, Some(other), Some(PC)) => other,
        _ => return None,
    };
    let load = definition(instructions, add, other)?;
    let (load_at, _, _, Some(load)) = &instructions[load] else { return None };
    let Operand::RegDerefPreindexOffset(base, offset, up, false) = load.operands[1] else { return None };
    if load.opcode != Opcode::LDR || base.number() != PC {
        return None;
    }
    let pc = load_at + 8;
    let literal = if up { pc + u64::from(offset) } else { pc - u64::from(offset) };
    let word = u32::from_le_bytes(code.bytes(literal, literal + 4)?.try_into().ok()?);
    Some((add_at + 8).wrapping_add(u64::from(word)) & 0xFFFF_FFFF)
}

/// The address of each literal an A32 load in `instructions` reads at an offset from PC.
fn a32_literals(instructions: &[Decoded]) -> Vec<u64> {
    instructions
        .iter()
        .filter_map(|(at, _, run, instruction)| {
            let instruction = instruction.as_ref().filter(|_| *run == Run::A32)?;
            let Operand::RegDerefPreindexOffset(base, offset, up, false) = instruction.operands[1] else { return None };
            (base.number() == PC && matches!(instruction.opcode, Opcode::LDR | Opcode::LDRB | Opcode::LDRH | Opcode::LDRD | Opcode::LDRSB | Opcode::LDRSH)).then(|| if up { at + 8 + u64::from(offset) } else { at + 8 - u64::from(offset) })
        })
        .collect()
}

/// An A32 dispatch at `index`, if the instruction there is one: the table it reads, or why it
/// cannot be read.
fn a32_dispatch(code: &Code, readonly: &[(u64, &[u8])], data: &[(u64, u64)], instructions: &[Decoded], index: usize) -> Option<Result<JumpTable, String>> {
    let (jump, _, Run::A32, Some(instruction)) = &instructions[index] else { return None };
    let jump = *jump;
    if register(instruction, 0) != Some(PC) {
        return None;
    }
    let base = jump + 8;
    match instruction.opcode {
        // LDR PC, [PC, Rm, LSL #2]: the table of addresses that follows, one `$d` run.
        Opcode::LDR => {
            times_four(instruction.operands[1])?;
            let Some(&(start, end)) = data.iter().find(|&&(start, _)| start == base) else { return Some(Err("LDR PC with no data after it".into())) };
            let bytes = code.bytes(start, end)?;
            let targets = bytes.chunks_exact(4).map(|entry| u64::from(u32::from_le_bytes(entry.try_into().unwrap())) & !1).collect();
            Some(Ok(JumpTable { jump, table: start, targets, unreachable: None }))
        }
        // ADD PC, Rt, Re: clang's table of offsets from its own start, which an `ADR` before
        // names, in the `$d` run after the jump. A literal may come before or after it.
        Opcode::ADD if register(instruction, 1) != Some(PC) && register(instruction, 2).is_some() => {
            let adr = [register(instruction, 1)?, register(instruction, 2)?].into_iter().find_map(|base| {
                let (at, _, _, Some(adr)) = &instructions[definition(instructions, index, base)?] else { return None };
                match (adr.opcode, register(adr, 1), adr.operands[2]) {
                    (Opcode::ADR | Opcode::ADD, Some(PC), Operand::Imm32(offset)) => Some(at + 8 + u64::from(offset)),
                    (Opcode::SUB, Some(PC), Operand::Imm32(offset)) => Some(at + 8 - u64::from(offset)),
                    _ => None,
                }
            });
            let Some(table) = adr else { return Some(Err("ADD PC, Rt, Re with no ADR of a table".into())) };
            let Some(&(_, end)) = data.iter().find(|&&(start, end)| start <= table && table < end && start == jump + 4) else { return Some(Err(format!("ADD PC, Rt, Re with the table at {table:#x} not in the data after it"))) };
            let end = a32_literals(instructions).into_iter().filter(|&literal| literal > table && literal < end).min().unwrap_or(end);
            let bytes = code.bytes(table, end)?;
            let targets = bytes.chunks_exact(4).map(|entry| table.wrapping_add(u64::from(u32::from_le_bytes(entry.try_into().unwrap()))) & 0xFFFF_FFFF).collect();
            Some(Ok(JumpTable { jump, table, targets, unreachable: None }))
        }
        // ADD PC, PC, Rm, LSL #2: four times an entry, or the index itself into a row of branches.
        Opcode::ADD if register(instruction, 1) == Some(PC) => {
            let index_register = times_four(instruction.operands[2])?;
            let entry = definition(instructions, index, index_register);
            let loaded = entry.and_then(|entry| {
                let instruction = instructions[entry].3.as_ref()?;
                let (size, signed) = match instruction.opcode {
                    Opcode::LDRB => (1, false),
                    Opcode::LDRH => (2, false),
                    Opcode::LDRSB => (1, true),
                    Opcode::LDRSH => (2, true),
                    _ => return None,
                };
                let (first, second) = register_pair(instruction.operands[1])?;
                Some((entry, size, signed, first, second))
            });
            if let Some((entry, size, signed, first, second)) = loaded {
                // One of the two is the table, the other the index, doubled for halfwords.
                let (table, index_register) = [(first, second), (second, first)].into_iter().find_map(|(table, index)| Some((table_address(code, instructions, entry, table)?, index)))?;
                let (checked, index_before) = if size == 2 {
                    let double = definition(instructions, entry, index_register)?;
                    let instruction = instructions[double].3.as_ref()?;
                    match (instruction.opcode, register(instruction, 1), register(instruction, 2)) {
                        (Opcode::ADD, Some(a), Some(b)) if a == b => (double, a),
                        _ => return Some(Err(format!("a halfword table at {table:#x} with an index not doubled by ADD"))),
                    }
                } else {
                    (entry, index_register)
                };
                let Some(highest) = bound(instructions, checked, index_before) else { return Some(Err(format!("no bound on the index of the table at {table:#x}"))) };
                let Some(bytes) = readonly.iter().find_map(|&(addr, bytes)| (table >= addr).then(|| bytes.get((table - addr) as usize..(table - addr + (highest + 1) * size) as usize)).flatten()) else {
                    return Some(Err(format!("the table at {table:#x} outside read-only data")));
                };
                let unused = 64 - 8 * size as u32;
                let value = |entry: &[u8]| {
                    let value = entry.iter().rev().fold(0u64, |value, &byte| value << 8 | u64::from(byte));
                    if signed { ((value << unused) as i64) >> unused } else { value as i64 }
                };
                let targets = bytes.chunks_exact(size as usize).map(|entry| base.wrapping_add_signed(4 * value(entry))).collect();
                return Some(Ok(JumpTable { jump, table, targets, unreachable: None }));
            }
            // A row of branches: entry n is the branch at `base + 4 * n`. Without a bound this is
            // no switch but a jump into unrolled code, as libgcc's division makes.
            let highest = bound(instructions, index, index_register)?;
            let targets = (0..=highest).map(|n| base + 4 * n).collect();
            Some(Ok(JumpTable { jump, table: base, targets, unreachable: None }))
        }
        _ => None,
    }
}

/// The jump tables of a 32-bit ARM binary, from its debug file.
pub fn jump_tables(name: String, binary: &object::File, debug: &object::File) -> Result<Option<Extracted>> {
    let code = Code::read(binary, debug);
    let data = code.data();
    let readonly: Vec<(u64, &[u8])> = binary.sections().filter(|s| s.kind() == SectionKind::ReadOnlyData).filter_map(|s| Some((s.address(), s.data().ok()?))).collect();
    let (mut tables, mut rejected) = (Vec::new(), Vec::new());
    for (&start, &(_, size, run)) in &functions(debug, &code) {
        let end = start + size;
        let instructions = code.instructions(start, end, run);
        // Thumb: a run of data inside the function that a TBB, TBH or ADD PC before it reads.
        let thumb: Vec<(u64, u8, Option<Instruction>)> = instructions.iter().filter(|(_, _, run, _)| *run == Run::Thumb).map(|(at, len, _, instruction)| (*at, *len, *instruction)).collect();
        for &(table, table_end) in data.iter().filter(|&&(table, _)| table > start && table < end) {
            match super::thumb::table_at(&|start, end| code.bytes(start, end), &thumb, table, table_end, start, end) {
                None => {}
                Some(Ok(found)) => tables.push(found),
                Some(Err(reason)) => rejected.push(Rejected { table, reason }),
            }
        }
        for index in 0..instructions.len() {
            match a32_dispatch(&code, &readonly, &data, &instructions, index) {
                None => {}
                Some(Ok(mut table)) => {
                    // A dispatch that runs only for an index in range falls through to the default.
                    if instructions[index].3.is_some_and(|instruction| instruction.condition != ConditionCode::AL) {
                        table.targets.push(table.jump + 4);
                    }
                    table.targets.sort_unstable();
                    table.targets.dedup();
                    match table.targets.iter().find(|&&target| instructions.binary_search_by_key(&target, |&(at, _, _, _)| at).is_err()) {
                        Some(&stray) => rejected.push(Rejected { table: table.table, reason: format!("a case at {stray:#x}, no instruction of the function") }),
                        None => tables.push(table),
                    }
                }
                Some(Err(reason)) => rejected.push(Rejected { table: instructions[index].0, reason }),
            }
        }
    }
    tables.sort_by_key(|table| table.jump);
    let listed = tables.len() + rejected.len();
    Ok(Some(Extracted { truth: JumpTables { name, tables }, listed, rejected }))
}

/// How many functions of the 32-bit ARM binaries of `corpus` recore puts in the instruction set
/// that their symbol says, as `(right, all)`, with each wrong one printed when `detail`.
pub fn score_instruction_sets(corpus: &Path, detail: bool) -> Result<(usize, usize)> {
    use rayon::prelude::*;
    let binaries = crate::binaries(corpus)?;
    let counts: Vec<(usize, usize)> = binaries
        .par_iter()
        .filter_map(|binary| {
            let image = recore::Image::load(binary).ok().filter(|image| image.machine == recore::image::Machine::Arm)?;
            let data = std::fs::read(crate::debug_file(corpus, &crate::name_of(binary))).ok()?;
            let debug = object::File::parse(&*data).ok()?;
            let (mut right, mut all) = (0, 0);
            for symbol in debug.symbols().filter(|symbol| symbol.kind() == SymbolKind::Text && symbol.size() > 0 && image.is_code(symbol.address() & !1)) {
                let expected = if symbol.address() & 1 != 0 { recore::image::InstructionSet::Thumb } else { recore::image::InstructionSet::A32 };
                let (found, _) = image.instruction_set(symbol.address() & !1);
                all += 1;
                if found == expected {
                    right += 1;
                } else if detail {
                    println!("{} {:#x} {}: {expected:?}, recore says {found:?}", image.name, symbol.address() & !1, symbol.name().unwrap_or_default());
                }
            }
            Some((right, all))
        })
        .collect();
    Ok(counts.into_iter().fold((0, 0), |(right, all), (r, a)| (right + r, all + a)))
}
