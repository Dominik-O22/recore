//! Jump-table ground truth for binaries built by `corpus/jt/build.py`.
//!
//! clang's `-mllvm -emit-jump-table-sizes-section` leaves a `.llvm_jump_table_sizes` section in
//! the debug file: one `(table address, entry count)` pair of `u64`s per jump table. Entries are
//! 4-byte signed offsets from the table's own address, so the targets come straight from the
//! linked binary. What the metadata does not say is which indirect jump reads each table. That
//! is recovered by a forward dataflow over the function the targets lie in, following the table
//! address from its `lea` through the entry load and the add to the `jmp`.
//!
//! Nothing is guessed: a table whose targets are not instruction boundaries of one function, or
//! whose dispatch the dataflow cannot follow, is rejected with a reason.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;

use anyhow::{Context, Result, ensure};
use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, InstructionInfoFactory, Mnemonic, OpAccess, OpKind, Register};
use object::{Object, ObjectSection, ObjectSymbol, SectionKind, SymbolKind};
use serde::{Deserialize, Serialize};

const META_SECTION: &str = ".llvm_jump_table_sizes";
const ENTRY_SIZE: u64 = 4;

/// One switch dispatch: an indirect jump and everything it can reach.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JumpTable {
    /// Address of the indirect jump instruction.
    pub jump: u64,
    /// Address of the table it indexes. Duplicated dispatch blocks share one table.
    pub table: u64,
    /// Distinct target addresses, sorted.
    pub targets: Vec<u64>,
    /// Set when some entries point at the end of the function, which is how clang fills cases it
    /// proved unreachable. That address is not a target, but reporting it is not an error either.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unreachable: Option<u64>,
}

/// Jump-table truth for one binary, as written to `jumptables/<name>.json`.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JumpTables {
    pub name: String,
    /// Sorted by `jump`.
    pub tables: Vec<JumpTable>,
}

/// A table listed in the metadata that is left out of the truth.
#[derive(Debug)]
pub struct Rejected {
    pub table: u64,
    pub reason: String,
}

/// Result of [`extract`].
pub struct Extracted {
    pub truth: JumpTables,
    /// Number of tables the compiler metadata lists.
    pub listed: usize,
    pub rejected: Vec<Rejected>,
}

/// A table as the metadata and the binary's bytes describe it, before a jump is found for it.
struct Table {
    addr: u64,
    targets: BTreeSet<u64>,
    /// The function's end address, if any entry points there.
    unreachable: Option<u64>,
}

/// What a register or stack slot is known to hold, by index into the function's tables.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Value {
    /// The table's address.
    Base(usize),
    /// A sign-extended entry loaded from the table.
    Entry(usize),
    /// Entry plus base: a case address.
    Target(usize),
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Loc {
    Reg(Register),
    /// A spill slot: `[rsp + disp]` or `[rbp + disp]`.
    Slot(Register, u64),
}

/// Locations with a known value. Absent means unknown.
type State = HashMap<Loc, Value>;

const CALLER_SAVED: [Register; 9] = [
    Register::RAX,
    Register::RCX,
    Register::RDX,
    Register::RSI,
    Register::RDI,
    Register::R8,
    Register::R9,
    Register::R10,
    Register::R11,
];

fn is_frame(register: Register) -> bool {
    matches!(register, Register::RSP | Register::RBP)
}

/// The spill slot a memory operand addresses, if it has the `[rsp/rbp + disp]` shape.
fn slot(instr: &Instruction) -> Option<Loc> {
    (is_frame(instr.memory_base()) && instr.memory_index() == Register::None)
        .then(|| Loc::Slot(instr.memory_base(), instr.memory_displacement64()))
}

/// The location operand `op` names, if it is a 64-bit register or a spill slot.
fn operand(instr: &Instruction, op: u32) -> Option<Loc> {
    match instr.op_kind(op) {
        OpKind::Register if instr.op_register(op).is_gpr64() => Some(Loc::Reg(instr.op_register(op))),
        OpKind::Memory => slot(instr),
        _ => None,
    }
}

/// The value `instr` leaves in its destination, given the state before it.
fn defines(instr: &Instruction, state: &State, by_addr: &HashMap<u64, usize>) -> Option<(Loc, Value)> {
    let value = |op| operand(instr, op).and_then(|loc| state.get(&loc).copied());
    let value = match instr.mnemonic() {
        Mnemonic::Lea if instr.is_ip_rel_memory_operand() => Value::Base(*by_addr.get(&instr.ip_rel_memory_address())?),
        // The entry load. A displacement is accepted: it is a folded `case - lowest` bias.
        Mnemonic::Movsxd if instr.op1_kind() == OpKind::Memory && instr.memory_index_scale() == ENTRY_SIZE as u32 => {
            match state.get(&Loc::Reg(instr.memory_base())) {
                Some(&Value::Base(table)) if instr.memory_index() != Register::None => Value::Entry(table),
                _ => return None,
            }
        }
        Mnemonic::Add => match (value(0)?, value(1)?) {
            (Value::Entry(a), Value::Base(b)) | (Value::Base(a), Value::Entry(b)) if a == b => Value::Target(a),
            _ => return None,
        },
        Mnemonic::Mov => value(1)?,
        _ => return None,
    };
    Some((operand(instr, 0)?, value))
}

/// Applies `instr` to `state`: forgets everything it overwrites, then records what it defines.
fn transfer(instr: &Instruction, state: &mut State, info: &mut InstructionInfoFactory, by_addr: &HashMap<u64, usize>) {
    let defined = defines(instr, state, by_addr);
    let writes = |access| matches!(access, OpAccess::Write | OpAccess::CondWrite | OpAccess::ReadWrite | OpAccess::ReadCondWrite);
    let is_call = matches!(instr.flow_control(), FlowControl::Call | FlowControl::IndirectCall);
    let used = info.info(instr);
    for register in used.used_registers().iter().filter(|r| writes(r.access())).map(|r| r.register().full_register()) {
        state.remove(&Loc::Reg(register));
        // Moving the stack or frame pointer renumbers every slot, except across a balanced call.
        if is_frame(register) && !is_call {
            state.retain(|loc, _| !matches!(loc, Loc::Slot(base, _) if *base == register));
        }
    }
    for memory in used.used_memory().iter().filter(|m| writes(m.access())) {
        if is_frame(memory.base()) && memory.index() == Register::None {
            state.remove(&Loc::Slot(memory.base(), memory.displacement()));
        }
    }
    if is_call {
        CALLER_SAVED.iter().for_each(|&register| {
            state.remove(&Loc::Reg(register));
        });
    }
    if let Some((loc, value)) = defined {
        state.insert(loc, value);
    }
}

/// Finds the indirect jumps of one function that dispatch through `tables`, as `(jump, table index)`.
///
/// A worklist dataflow over the function's instructions. States meet by keeping only what agrees,
/// so a jump is attributed only when every path the analysis sees reaches it with the same table.
/// Edges out of an indirect jump exist only once that jump is attributed; callers must therefore
/// discard the result unless every table found its jump, or an unseen edge could hide a conflict.
fn dispatches(instrs: &[Instruction], tables: &[Table]) -> BTreeMap<u64, usize> {
    let by_addr: HashMap<u64, usize> = tables.iter().enumerate().map(|(index, table)| (table.addr, index)).collect();
    let index_of: HashMap<u64, usize> = instrs.iter().enumerate().map(|(index, instr)| (instr.ip(), index)).collect();
    let mut info = InstructionInfoFactory::new();
    let mut entry: Vec<Option<State>> = vec![None; instrs.len()];
    let mut jumps = BTreeMap::new();
    entry[0] = Some(State::new());
    let mut work = vec![0];

    while let Some(index) = work.pop() {
        let instr = &instrs[index];
        let mut state = entry[index].clone().expect("queued instructions have a state");
        let mut successors: Vec<usize> = Vec::new();
        let branch = index_of.get(&instr.near_branch_target()).copied();
        match instr.flow_control() {
            FlowControl::UnconditionalBranch => successors.extend(branch),
            FlowControl::ConditionalBranch => successors.extend(branch.into_iter().chain([index + 1])),
            FlowControl::IndirectBranch => {
                if let Some(&Value::Target(table)) = operand(instr, 0).and_then(|loc| state.get(&loc)) {
                    jumps.insert(instr.ip(), table);
                    successors.extend(tables[table].targets.iter().map(|target| index_of[target]));
                } else {
                    // A join may have taken away what an earlier visit saw here.
                    jumps.remove(&instr.ip());
                }
            }
            FlowControl::Return | FlowControl::Interrupt | FlowControl::Exception => {}
            _ => successors.push(index + 1),
        }
        transfer(instr, &mut state, &mut info, &by_addr);

        for successor in successors.into_iter().filter(|&s| s < instrs.len()) {
            let changed = match &mut entry[successor] {
                Some(existing) => {
                    let before = existing.len();
                    existing.retain(|loc, value| state.get(loc) == Some(value));
                    existing.len() != before
                }
                slot @ None => {
                    *slot = Some(state.clone());
                    true
                }
            };
            if changed {
                work.push(successor);
            }
        }
    }
    jumps
}

/// Function ranges `(start, size)` from the debug symbol table, sorted, one per address.
fn functions(debug: &object::File) -> Vec<(u64, u64)> {
    let mut functions: Vec<(u64, u64)> = debug
        .symbols()
        .filter(|symbol| symbol.kind() == SymbolKind::Text && symbol.size() > 0)
        .map(|symbol| (symbol.address(), symbol.size()))
        .collect();
    functions.sort_unstable();
    functions.dedup_by_key(|function| function.0);
    functions
}

/// Derives jump-table truth for one binary, or `None` if its debug file carries no metadata.
pub fn extract(binary_path: &Path, debug_path: &Path) -> Result<Option<Extracted>> {
    let binary_data = std::fs::read(binary_path).with_context(|| format!("reading {binary_path:?}"))?;
    let debug_data = std::fs::read(debug_path).with_context(|| format!("reading {debug_path:?}"))?;
    let binary = object::File::parse(&*binary_data)?;
    let debug = object::File::parse(&*debug_data)?;

    let Some(meta) = debug.section_by_name(META_SECTION) else { return Ok(None) };
    let meta = meta.data()?;
    ensure!(meta.len() % 16 == 0, "{META_SECTION} is not a whole number of (address, count) pairs");
    let u64_at = |offset: usize| u64::from_le_bytes(meta[offset..offset + 8].try_into().unwrap());
    let listed: Vec<(u64, u64)> = (0..meta.len()).step_by(16).map(|offset| (u64_at(offset), u64_at(offset + 8))).collect();

    let functions = functions(&debug);
    let function_of = |addr: u64| {
        let index = functions.partition_point(|&(start, _)| start <= addr).checked_sub(1)?;
        (addr < functions[index].0 + functions[index].1).then_some(index)
    };
    let data_sections: Vec<_> = binary.sections().filter(|s| s.kind() == SectionKind::ReadOnlyData).collect();
    let text_sections: Vec<_> = binary.sections().filter(|s| s.kind() == SectionKind::Text).collect();

    let mut rejected = Vec::new();
    // Tables grouped by the function their targets lie in.
    let mut by_function: BTreeMap<usize, Vec<Table>> = BTreeMap::new();
    for &(addr, count) in &listed {
        let read = || -> Result<(usize, Table), String> {
            let bytes = count
                .checked_mul(ENTRY_SIZE)
                .filter(|&size| size > 0)
                .and_then(|size| data_sections.iter().find_map(|s| s.data_range(addr, size).ok().flatten()))
                .ok_or_else(|| format!("{count} entries are not inside a read-only data section"))?;
            let mut targets: BTreeSet<u64> = bytes
                .chunks_exact(ENTRY_SIZE as usize)
                .map(|entry| addr.wrapping_add_signed(i32::from_le_bytes(entry.try_into().unwrap()).into()))
                .collect();
            // The lowest target is real code even when unreachable entries point past the end.
            let function = function_of(*targets.first().unwrap()).ok_or("first target is outside every function")?;
            let (start, size) = functions[function];
            let unreachable = targets.take(&(start + size));
            match targets.iter().find(|&&target| target < start || target >= start + size) {
                Some(stray) => Err(format!("target {stray:#x} is outside the function at {start:#x}")),
                None => Ok((function, Table { addr, targets, unreachable })),
            }
        };
        match read() {
            Ok((function, table)) => by_function.entry(function).or_default().push(table),
            Err(reason) => rejected.push(Rejected { table: addr, reason }),
        }
    }

    let mut tables = Vec::new();
    for (function, candidates) in by_function {
        let (start, size) = functions[function];
        let mut reject_all = |reason: &str| {
            rejected.extend(candidates.iter().map(|table| Rejected { table: table.addr, reason: format!("function {start:#x}: {reason}") }));
        };
        let Some(bytes) = text_sections.iter().find_map(|s| s.data_range(start, size).ok().flatten()) else {
            reject_all("not inside an executable section");
            continue;
        };
        let instrs: Vec<Instruction> = Decoder::with_ip(64, bytes, start, DecoderOptions::NONE).into_iter().collect();
        if instrs.iter().any(Instruction::is_invalid) {
            reject_all("does not decode cleanly");
            continue;
        }
        let boundaries: BTreeSet<u64> = instrs.iter().map(Instruction::ip).collect();
        if let Some(stray) = candidates.iter().flat_map(|table| &table.targets).find(|target| !boundaries.contains(target)) {
            reject_all(&format!("target {stray:#x} is not an instruction boundary"));
            continue;
        }
        let jumps = dispatches(&instrs, &candidates);
        // An unattributed table means control-flow edges the dataflow never saw, so its other
        // conclusions about this function are not trusted either.
        let unused: Vec<String> = (0..candidates.len())
            .filter(|index| !jumps.values().any(|table| table == index))
            .map(|index| format!("{:#x}", candidates[index].addr))
            .collect();
        if !unused.is_empty() {
            reject_all(&format!("no dispatch found for table {}", unused.join(", ")));
            continue;
        }
        tables.extend(jumps.into_iter().map(|(jump, index)| JumpTable {
            jump,
            table: candidates[index].addr,
            targets: candidates[index].targets.iter().copied().collect(),
            unreachable: candidates[index].unreachable,
        }));
    }
    tables.sort_unstable_by_key(|table| table.jump);
    rejected.sort_unstable_by_key(|r| r.table);

    let name = binary_path.file_name().unwrap().to_string_lossy().into_owned();
    Ok(Some(Extracted { truth: JumpTables { name, tables }, listed: listed.len(), rejected }))
}
