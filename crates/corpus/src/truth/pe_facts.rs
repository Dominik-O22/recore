//! Measurements over a PE corpus that an analyzer author needs but truth files do not carry:
//! how the exception directory relates to PDB functions, how imports are called, where jump
//! tables sit and whether relocations mark them, what fills the gaps between functions, how
//! functions open and how they are reached.
//!
//! Everything is a named counter, summed over the corpus by `recore-corpus pe-facts`.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;

use anyhow::Result;
use iced_x86::{Code, Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic, OpKind, Register};

use super::pe::Image;
use super::{Callee, Function};

/// Named counters for one image, or summed over many.
#[derive(Default)]
pub struct Facts(pub BTreeMap<&'static str, u64>);

impl Facts {
    fn add(&mut self, key: &'static str, n: u64) {
        *self.0.entry(key).or_default() += n;
    }

    fn count(&mut self, key: &'static str) {
        self.add(key, 1);
    }

    pub fn merge(&mut self, other: &Facts) {
        other.0.iter().for_each(|(key, n)| self.add(key, *n));
    }
}

/// How a function is reached, strongest evidence first.
#[derive(Default)]
struct References {
    called: HashSet<u64>,
    /// Target of a jump from outside the function: a tail call.
    jumped: HashSet<u64>,
    /// Address materialised by an instruction (`lea`, `push offset`, `mov reg, offset`).
    taken_in_code: HashSet<u64>,
    /// Address stored in data, found through its base relocation.
    in_data: HashSet<u64>,
}

fn u32_at(bytes: &[u8], offset: usize) -> u64 {
    bytes.get(offset..offset + 4).map_or(0, |b| u64::from(u32::from_le_bytes(b.try_into().unwrap())))
}

fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    bytes.get(offset..offset + 8).map_or(0, |b| u64::from_le_bytes(b.try_into().unwrap()))
}

/// Field offsets in `IMAGE_LOAD_CONFIG_DIRECTORY`, which differ between PE32 and PE32+.
struct LoadConfig {
    seh_table: usize,
    seh_count: usize,
    guard_check: usize,
    guard_dispatch: usize,
    guard_table: usize,
    guard_count: usize,
    guard_flags: usize,
    ehcont_count: usize,
}

const LOAD_CONFIG_32: LoadConfig = LoadConfig {
    seh_table: 0x40,
    seh_count: 0x44,
    guard_check: 0x48,
    guard_dispatch: 0x4c,
    guard_table: 0x50,
    guard_count: 0x54,
    guard_flags: 0x58,
    ehcont_count: 0xa8,
};
const LOAD_CONFIG_64: LoadConfig = LoadConfig {
    seh_table: 0x60,
    seh_count: 0x68,
    guard_check: 0x70,
    guard_dispatch: 0x78,
    guard_table: 0x80,
    guard_count: 0x88,
    guard_flags: 0x90,
    ehcont_count: 0x110,
};

/// Set by the linker under `/guard:cf`. The C runtime's template sets `CF_INSTRUMENTED` on its
/// own, so that bit says nothing.
const GUARD_CF_FUNCTION_TABLE_PRESENT: u64 = 0x400;
const UNW_FLAG_CHAININFO: u8 = 0x4;

/// The opening of an i386 function, by the idiom it starts with.
fn prologue(image: &Image, function: &Function) -> &'static str {
    let mut instrs = image.decode(function.addr, function.addr + function.size.min(48));
    let mut next = || instrs.next().unwrap_or_default();
    let mut first = next();
    let hotpatch = first.code() == Code::Mov_r32_rm32 && first.op0_register() == Register::EDI && first.op1_register() == Register::EDI
        || first.code() == Code::Mov_rm32_r32 && first.op0_register() == Register::EDI && first.op1_register() == Register::EDI;
    if hotpatch {
        first = next();
    }
    let second = next();
    let is_push = |instr: &Instruction, register| instr.mnemonic() == Mnemonic::Push && instr.op0_register() == register;
    let frame = is_push(&first, Register::EBP)
        && second.mnemonic() == Mnemonic::Mov
        && second.op0_register() == Register::EBP
        && second.op1_register() == Register::ESP;
    // `push size; push offset scope_table; call __SEH_prolog4` and the C++ `__EH_prolog` forms.
    let third = next();
    let helper = |instr: &Instruction| {
        instr.flow_control() == FlowControl::Call
            && matches!(image.resolve(Callee::Direct(instr.near_branch_target())), Callee::Direct(target)
                if image.functions.get(&target).is_some_and(|f| f.name.contains("SEH_prolog") || f.name.contains("EH_prolog")))
    };
    match () {
        _ if helper(&second) || helper(&third) => "prologue seh/eh prolog helper",
        _ if frame && hotpatch => "prologue mov edi,edi; push ebp; mov ebp,esp",
        _ if frame => "prologue push ebp; mov ebp,esp",
        _ if hotpatch => "prologue mov edi,edi; no frame",
        _ if first.mnemonic() == Mnemonic::Push => "prologue no frame, opens with push",
        _ if first.mnemonic() == Mnemonic::Sub && first.op0_register() == Register::ESP => "prologue no frame, opens with sub esp",
        _ if first.mnemonic() == Mnemonic::Jmp => "prologue none, opens with jmp",
        _ => "prologue no frame, other",
    }
}

/// Counts what lies between functions in `[start, end)`.
fn gap(image: &Image, facts: &mut Facts, start: u64, end: u64) {
    let Some(bytes) = image.bytes(start, end - start) else {
        facts.add("gap bytes not in file", end - start);
        return;
    };
    let pointer = u64::from(image.bitness / 8);
    let mut at = start;
    while at < end {
        let byte = bytes[(at - start) as usize];
        if image.relocations.binary_search(&at).is_ok() {
            facts.add("gap bytes relocated pointers", pointer.min(end - at));
            at += pointer;
            continue;
        } else {
            facts.count(match byte {
                0xcc => "gap bytes int3",
                0x90 => "gap bytes nop (0x90)",
                0x00 => "gap bytes zero",
                _ => "gap bytes other",
            });
        }
        at += 1;
    }
}

/// Measures one image.
pub fn facts(binary_path: &Path, pdb_path: &Path) -> Result<Facts> {
    let data = std::fs::read(binary_path)?;
    let image = Image::load(&data, pdb_path)?;
    let mut facts = Facts::default();
    let is64 = image.bitness == 64;
    facts.count("images");
    facts.add("images without base relocations", u64::from(image.relocations.is_empty()));

    let config = if is64 { LOAD_CONFIG_64 } else { LOAD_CONFIG_32 };
    let word = |offset| if is64 { u64_at(image.load_config, offset) } else { u32_at(image.load_config, offset) };
    let guard_flags = u32_at(image.load_config, config.guard_flags);
    let guarded = guard_flags & GUARD_CF_FUNCTION_TABLE_PRESENT != 0;
    facts.add("images with control-flow guard (/guard:cf)", u64::from(guarded));
    facts.add("images with EH continuation table (/guard:ehcont)", u64::from(word(config.ehcont_count) != 0));
    let guard_pointers = [word(config.guard_check), word(config.guard_dispatch)];
    // Entry points other tables of the image name: valid indirect-call targets under CFG (an
    // RVA plus `flags >> 28` bytes of metadata each), and i386 SafeSEH exception handlers.
    let entry_kind = |addr: u64| match image.functions.get(&addr) {
        Some(function) if function.thunk => 1,
        Some(function) if function.fragment => 2,
        Some(_) => 0,
        None => 3,
    };
    if guarded {
        let stride = 4 + ((guard_flags >> 28) & 0xf);
        for index in 0..word(config.guard_count) {
            let target = image.bytes(word(config.guard_table) + index * stride, 4).map_or(0, |b| image.base + u32_at(b, 0));
            facts.count(["CFG table: function start", "CFG table: thunk", "CFG table: fragment", "CFG table: not a PDB function"][entry_kind(target)]);
        }
    }
    if !is64 {
        facts.add("images with a SafeSEH handler table", u64::from(word(config.seh_count) != 0));
        for index in 0..word(config.seh_count) {
            let handler = image.bytes(word(config.seh_table) + index * 4, 4).map_or(0, |b| image.base + u32_at(b, 0));
            facts.count(["SafeSEH table: function start", "SafeSEH table: thunk", "SafeSEH table: fragment", "SafeSEH table: not a PDB function"][entry_kind(handler)]);
        }
    }

    let functions: Vec<&Function> = image.functions.values().collect();
    let function_at = |addr: u64| {
        let index = functions.partition_point(|function| function.addr <= addr).checked_sub(1)?;
        (addr < functions[index].addr + functions[index].size).then_some(functions[index])
    };

    // The function an address refers to, looking through thunks.
    let entry_of = |addr: u64| match image.resolve(Callee::Direct(addr)) {
        Callee::Direct(function) => image.functions.contains_key(&function).then_some(function),
        Callee::Slot(_) => None,
    };
    let mut references = References::default();
    let mut operand_relocations: HashSet<u64> = HashSet::new();
    let mut boundaries: HashSet<u64> = HashSet::new();
    let mut data_ranges: Vec<(u64, u64)> = Vec::new();

    for function in &functions {
        let kind = match (function.thunk, function.fragment) {
            (true, _) => "functions: thunks",
            (_, true) if function.name.ends_with("$sepcode") => "functions: separated code",
            (_, true) if function.name.starts_with("__ehhandler$") => "functions: i386 EH handler stubs",
            (_, true) if function.name.starts_with("__unwindfunclet$") => "functions: i386 unwind funclets",
            (_, true) => "functions: exception funclets",
            _ if image.public_only.contains(&function.addr) => "functions: real, public symbol only",
            _ => "functions: real, with debug info",
        };
        facts.count(kind);
        facts.add("functions: flagged noreturn", u64::from(function.noreturn));
        if function.size == 0 {
            facts.count("functions: without a size");
            continue;
        }
        let (start, end) = (function.addr, function.addr + function.size);
        let Some(bytes) = image.bytes(start, function.size) else { continue };
        facts.add("function bytes", function.size);
        let real = !function.fragment;
        if real {
            facts.count(match start % 16 {
                0 => "start aligned to 16",
                _ if start % 4 == 0 => "start aligned to 4 only",
                _ => "start unaligned",
            });
            if !is64 {
                facts.count(prologue(&image, function));
            }
        }
        let code = image.code_ranges(start, end);
        // Data runs are what the code ranges leave over.
        let mut runs: Vec<(u64, u64)> = Vec::new();
        let mut at = start;
        for &(code_start, code_end) in code.iter().chain([&(end, end)]) {
            if code_start > at {
                runs.push((at, code_start));
            }
            at = code_end;
        }
        facts.add("functions with data inside their length", u64::from(!runs.is_empty()));
        let entries = image.pdata.partition_point(|entry| entry.end <= start);
        let entries: Vec<_> = image.pdata[entries..].iter().take_while(|entry| entry.begin < end).collect();
        for &(run_start, run_end) in &runs {
            facts.count("data runs");
            facts.add("data bytes inside function lengths", run_end - run_start);
            let first = image.relocations.partition_point(|&slot| slot < run_start);
            let pointers = image.relocations[first..].iter().take_while(|&&slot| slot < run_end).count() as u64;
            facts.add("data bytes: relocated pointers (jump table entries, i386)", pointers * 4);
            if is64 && !entries.is_empty() {
                let covered: u64 = entries.iter().map(|entry| entry.end.min(run_end).saturating_sub(entry.begin.max(run_start))).sum();
                facts.add("data bytes covered by a pdata entry", covered);
                let last_end = entries.iter().map(|entry| entry.end).filter(|&e| e <= run_start).max();
                facts.count(match last_end {
                    Some(last) if last == run_start => "data runs: begin exactly where a pdata entry ends",
                    Some(last) if run_start - last < 16 => "data runs: begin within 16 bytes after a pdata entry",
                    _ => "data runs: begin elsewhere relative to pdata",
                });
            }
        }
        data_ranges.extend(&runs);
        let in_run = |addr: u64| runs.iter().any(|&(s, e)| addr >= s && addr < e);

        let mut has_image_base = false;
        let mut based_tables: HashSet<u64> = HashSet::new();
        let mut returns: Vec<u64> = Vec::new();
        for &(code_start, code_end) in &code {
        let mut decoder = Decoder::with_ip(image.bitness, &bytes[(code_start - start) as usize..(code_end - start) as usize], code_start, DecoderOptions::NONE);
        while decoder.can_decode() {
            let instr = decoder.decode();
            if instr.is_invalid() {
                facts.count("undecodable bytes inside function lengths");
                continue;
            }
            facts.count("instructions");
            boundaries.insert(instr.ip());

            // Addresses the instruction carries: relocated on i386, RIP-relative on x86-64.
            let offsets = decoder.get_constant_offsets(&instr);
            let mut carried: Vec<u64> = Vec::new();
            for (present, offset) in [(offsets.has_displacement(), offsets.displacement_offset()), (offsets.has_immediate(), offsets.immediate_offset())] {
                let slot = instr.ip() + offset as u64;
                if present && image.relocations.binary_search(&slot).is_ok() {
                    operand_relocations.insert(slot);
                    carried.extend(image.pointer(slot));
                }
            }
            if instr.is_ip_rel_memory_operand() && instr.mnemonic() == Mnemonic::Lea {
                carried.push(instr.ip_rel_memory_address());
            }
            references.taken_in_code.extend(carried.iter().filter_map(|&addr| entry_of(addr)));

            let slot = if instr.is_ip_rel_memory_operand() {
                Some(instr.ip_rel_memory_address())
            } else if !is64 && instr.op0_kind() == OpKind::Memory && instr.memory_base() == Register::None && instr.memory_index() == Register::None {
                Some(instr.memory_displacement64())
            } else {
                None
            };
            let import = slot.filter(|slot| image.slots.contains_key(slot));
            let guard = slot.is_some_and(|slot| guard_pointers.contains(&slot) && slot != 0);
            match instr.flow_control() {
                FlowControl::Call => {
                    let target = instr.near_branch_target();
                    if let Callee::Direct(function) = image.resolve(Callee::Direct(target)) {
                        references.called.insert(function);
                    }
                    let through_thunk = image.functions.get(&target).is_some_and(|f| f.thunk);
                    facts.count(match image.resolve(Callee::Direct(target)) {
                        Callee::Slot(_) => "calls: direct to an import thunk (jmp [IAT])",
                        Callee::Direct(_) if through_thunk => "calls: direct to a jump thunk (ILT)",
                        Callee::Direct(_) => "calls: direct to a function",
                    });
                }
                FlowControl::IndirectCall if import.is_some() => facts.count("calls: call [IAT slot]"),
                FlowControl::IndirectCall if guard => facts.count("calls: through CFG check/dispatch pointer"),
                FlowControl::IndirectCall => facts.count("calls: other indirect"),
                FlowControl::IndirectBranch if import.is_some() && !function.thunk => facts.count("tail jumps: jmp [IAT slot] in a function"),
                FlowControl::IndirectBranch if guard => facts.count("tail jumps: through CFG dispatch pointer"),
                FlowControl::IndirectBranch if !function.thunk => {
                    facts.count("indirect jumps (not import, not CFG)");
                    // i386 dispatch: `jmp dword ptr [index*4 + table]`.
                    if !is64 && instr.memory_index_scale() == 4 && instr.memory_base() == Register::None && instr.memory_index() != Register::None {
                        let table = instr.memory_displacement64();
                        facts.count(match table {
                            _ if in_run(table) => "jump dispatch: table in the function's own data",
                            _ if table >= start && table < end => "jump dispatch: address inside the function's code (biased index)",
                            _ if image.in_exec(table) => "jump dispatch: table elsewhere in an executable section",
                            _ => "jump dispatch: table outside executable sections",
                        });
                        // Does every entry carry a base relocation? The table is bounded here by
                        // PDB data symbols alone, so the count does not presuppose the answer.
                        let mut slot = table;
                        while in_run(slot) && (slot == table || !image.data_symbols.contains(&slot)) {
                            let relocated = image.relocations.binary_search(&slot).is_ok();
                            facts.count(match image.pointer(slot).is_some_and(|target| target >= start && target < end) {
                                true if relocated => "jump table slots: into the function, relocated",
                                true => "jump table slots: into the function, not relocated",
                                false if relocated => "jump table slots: relocated, target outside the function",
                                false => "jump table slots: neither (padding)",
                            });
                            slot += 4;
                        }
                    }
                }
                FlowControl::UnconditionalBranch | FlowControl::ConditionalBranch => {
                    let target = instr.near_branch_target();
                    if !(target >= start && target < end) && real {
                        references.jumped.extend(entry_of(target));
                    }
                }
                FlowControl::Return => returns.push(if instr.op_count() == 1 { instr.immediate(0) } else { 0 }),
                FlowControl::Interrupt if instr.mnemonic() == Mnemonic::Int && instr.immediate(0) == 0x29 => facts.count("int 0x29 (__fastfail)"),
                _ => {}
            }
            // x86-64 MSVC dispatch: `mov r32, [base + index*4 + table_rva]`.
            if let Some(table) = image.based_table(&instr, &mut has_image_base).filter(|_| is64) {
                based_tables.insert(table);
                if instr.mnemonic() == Mnemonic::Mov && instr.memory_index_scale() == 4 {
                    facts.count(match table {
                        _ if in_run(table) => "jump dispatch: table in the function's own data",
                        _ if table >= start && table < end => "jump dispatch: address inside the function's code (biased index)",
                        _ => "jump dispatch: table elsewhere in an executable section",
                    });
                }
            }
        }
        }
        for &(run_start, _) in &runs {
            let symbol = image.data_symbols.contains(&run_start);
            let image_says = if is64 { based_tables.contains(&run_start) } else { image.relocations.binary_search(&run_start).is_ok() };
            facts.count(match (symbol, image_says, is64) {
                (true, true, false) => "data runs: begin at a PDB data symbol and a relocated pointer",
                (true, true, true) => "data runs: begin at a PDB data symbol and a base-relative table",
                (true, false, _) => "data runs: begin at a PDB data symbol only",
                (false, true, false) => "data runs: begin at a relocated pointer only",
                (false, true, true) => "data runs: begin at a base-relative table only",
                (false, false, _) => "data runs: begin at neither",
            });
        }

        // i386: is the callee's stack cleanup (`ret N`) recoverable from the PDB?
        if !is64 && real && !returns.is_empty() {
            let cleanup = returns.iter().copied().max().unwrap();
            facts.count(if cleanup > 0 { "returns: function uses ret N (callee cleanup)" } else { "returns: function uses plain ret" });
            if let Some(&params) = image.frame_params.get(&start) {
                facts.count("returns: function has frame data");
                if cleanup > 0 {
                    facts.count(if u64::from(params) == cleanup { "returns: ret N equals frame data params size" } else { "returns: ret N differs from frame data params size" });
                }
            }
            let decorated = image.publics.get(&start).and_then(|name| name.rsplit_once('@')).and_then(|(_, n)| n.parse::<u64>().ok());
            if let (Some(bytes), Some(name)) = (decorated, image.publics.get(&start).filter(|name| name.starts_with(['_', '@']))) {
                // fastcall passes up to 8 bytes in registers, which the callee does not pop.
                let expected = if name.starts_with('@') { bytes.saturating_sub(8) } else { bytes };
                facts.count(if expected == cleanup { "returns: ret N equals @N decoration" } else { "returns: ret N differs from @N decoration" });
            }
        }
    }

    // Decorated names: which i386 calling conventions the symbols show.
    if !is64 {
        for name in image.functions.keys().filter_map(|addr| image.publics.get(addr)) {
            let sized = name.rsplit_once('@').is_some_and(|(_, n)| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()));
            facts.count(match name.as_bytes().first() {
                Some(b'?') => "decoration: C++ mangled (?name)",
                Some(b'@') if sized => "decoration: fastcall (@name@N)",
                Some(b'_') if sized => "decoration: stdcall (_name@N)",
                Some(b'_') => "decoration: cdecl (_name)",
                _ if sized => "decoration: vectorcall or other (name@@N)",
                _ => "decoration: none",
            });
        }
    }
    for name in image.slots.values() {
        facts.count(match name.as_bytes().first() {
            Some(b'?') => "imports: C++ mangled name",
            _ if name.contains('#') => "imports: by ordinal",
            _ if name.contains('@') => "imports: decorated C name",
            _ => "imports: plain name",
        });
    }

    // Relocations that land in executable sections.
    data_ranges.sort_unstable();
    for &slot in &image.relocations {
        let value = image.pointer(slot);
        if image.in_exec(slot) {
            let in_table = data_ranges.iter().any(|&(s, e)| slot >= s && slot < e);
            facts.count(match () {
                _ if operand_relocations.contains(&slot) => "relocations in code: instruction operand",
                _ if in_table => "relocations in code: in a function's data",
                _ if function_at(slot).is_some() => "relocations in code: inside a function, unexplained",
                _ => "relocations in code: between functions, not a recognised table",
            });
        }
        if !operand_relocations.contains(&slot) {
            references.in_data.extend(value.and_then(entry_of));
        }
    }

    // Gaps between functions.
    let mut covered: Vec<(u64, u64)> = functions.iter().filter(|f| f.size > 0).map(|f| (f.addr, f.addr + f.size)).collect();
    covered.sort_unstable();
    for &(section_start, section_end) in &image.exec {
        facts.add("executable section bytes", section_end - section_start);
        let mut at = section_start;
        for &(start, end) in covered.iter().filter(|&&(start, _)| start >= section_start && start < section_end) {
            if start > at {
                gap(&image, &mut facts, at, start);
            } else if start < at {
                facts.add("function bytes overlapping an earlier function", at.min(end) - start);
            }
            at = at.max(end);
        }
        if at < section_end {
            gap(&image, &mut facts, at, section_end);
        }
    }

    // Labels must be instruction boundaries wherever they fall inside decoded code.
    for &label in &image.labels {
        facts.count(match () {
            _ if function_at(label).is_none() => "labels outside function lengths",
            _ if boundaries.contains(&label) => "labels on an instruction boundary",
            _ if data_ranges.iter().any(|&(s, e)| label >= s && label < e) => "labels inside recognised data",
            _ => "labels off any instruction boundary",
        });
    }
    facts.add("data symbols in executable sections", image.data_symbols.len() as u64);

    // The exception directory against PDB functions.
    let real_sized: Vec<&&Function> = functions.iter().filter(|f| !f.fragment && f.size > 0).collect();
    if is64 {
        for function in &real_sized {
            let (start, end) = (function.addr, function.addr + function.size);
            let first = image.pdata.partition_point(|entry| entry.end <= start);
            let entries: Vec<_> = image.pdata[first..].iter().take_while(|entry| entry.begin < end).collect();
            facts.count(match entries.as_slice() {
                [] => "pdata: function has no entry (leaf)",
                [only] if only.begin == start && only.end == end => "pdata: one entry, exactly the PDB range",
                [only] if only.begin == start => "pdata: one entry from the start, other end",
                [first, ..] if first.begin == start => "pdata: several entries, first at the start",
                _ => "pdata: entries but none at the function start",
            });
        }
        for entry in &image.pdata {
            let chained = image.bytes(entry.unwind, 1).is_some_and(|b| (b[0] >> 3) & UNW_FLAG_CHAININFO != 0);
            facts.add("pdata: entries with chained unwind info", u64::from(chained));
            facts.count(match image.functions.get(&entry.begin) {
                Some(function) if function.thunk => "pdata entry begins: at a thunk",
                Some(function) if function.fragment => "pdata entry begins: at a fragment (sepcode, funclet)",
                Some(_) => "pdata entry begins: at a function start",
                None if function_at(entry.begin).is_some() && chained => "pdata entry begins: inside a function, chained",
                None if function_at(entry.begin).is_some() => "pdata entry begins: inside a function, not chained",
                None => "pdata entry begins: outside every PDB function",
            });
        }
    }

    // How each real function is reached.
    let exported: HashSet<u64> = image.exports.iter().copied().chain([image.entry]).filter_map(entry_of).collect();
    let by_begin: HashMap<u64, ()> = image.pdata.iter().map(|entry| (entry.begin, ())).collect();
    for function in functions.iter().filter(|f| !f.fragment) {
        let addr = function.addr;
        facts.count(match () {
            _ if references.called.contains(&addr) => "reached: by a direct call",
            _ if references.jumped.contains(&addr) => "reached: by a tail jump only",
            _ if references.taken_in_code.contains(&addr) => "reached: address taken in code only",
            _ if references.in_data.contains(&addr) => "reached: pointer in data only",
            _ if exported.contains(&addr) => "reached: export or entry point only",
            _ if by_begin.contains_key(&addr) => "reached: no reference, but a pdata entry",
            _ => "reached: no reference found",
        });
    }
    Ok(facts)
}
