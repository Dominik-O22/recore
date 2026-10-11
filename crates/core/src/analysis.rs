//! Function recovery and non-returning call analysis for x86-64.
//!
//! Function starts come from `.eh_frame`, exports, the entry point, and then from the targets of
//! calls and tail jumps found while decoding. Each function is decoded linearly inside its range,
//! which is sound for compiler output because jump tables live in read-only data, not in code.

use std::collections::{HashMap, HashSet};

use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction};
use rayon::prelude::*;

use crate::discover::{discover, is_function_section};
use crate::image::Image;
use crate::noreturn::is_noreturn_import;
use crate::report::{AnalyzedFunction, Analysis, CallSite, CallTarget, Import, Origin};
use crate::x86::{classify, is_padding, Flow};

#[derive(Debug, Clone, Copy)]
struct Control {
    addr: u64,
    #[allow(dead_code)]
    next: u64,
    flow: Flow,
}

struct Function {
    start: u64,
    end: u64,
    /// Control-flow instructions in address order.
    controls: Vec<Control>,
    instructions: u64,
}

/// Decodes `[start, end)` linearly and keeps its control-flow instructions. With `trim`, `end` is
/// only an upper bound and the function ends before any trailing padding.
fn decode(image: &Image, start: u64, end: u64, trim: bool) -> Function {
    let mut function = Function { start, end, controls: Vec::new(), instructions: 0 };
    let Some(bytes) = image.bytes_from(start) else {
        return function;
    };
    let bytes = &bytes[..bytes.len().min((end - start) as usize)];
    let mut decoder = Decoder::with_ip(64, bytes, start, DecoderOptions::NONE);
    let mut instr = Instruction::default();
    let mut body_end = start;
    while decoder.can_decode() {
        decoder.decode_out(&mut instr);
        if instr.is_invalid() {
            continue;
        }
        function.instructions += 1;
        if !is_padding(&instr) {
            body_end = instr.next_ip();
        }
        if let Some(flow) = classify(&instr) {
            function.controls.push(Control { addr: instr.ip(), next: instr.next_ip(), flow });
        }
    }
    if trim {
        function.end = body_end;
        function.controls.retain(|c| c.addr < body_end);
    }
    function
}

/// Resolves what a call or jump target is, when it is not a local function.
struct Imports<'a> {
    image: &'a Image,
    /// PLT stub address to the slot it jumps through.
    stubs: HashMap<u64, u64>,
}

impl<'a> Imports<'a> {
    fn new(image: &'a Image) -> Self {
        let mut stubs = HashMap::new();
        for section in image.sections.iter().filter(|s| s.executable && s.name.starts_with(".plt")) {
            let mut decoder = Decoder::with_ip(64, &section.data, section.addr, DecoderOptions::NONE);
            let mut stub_start = section.addr;
            let mut instr = Instruction::default();
            while decoder.can_decode() {
                decoder.decode_out(&mut instr);
                if instr.flow_control() == FlowControl::IndirectBranch && instr.is_ip_rel_memory_operand() {
                    let slot = instr.ip_rel_memory_address();
                    if image.import_slots.contains_key(&slot) {
                        stubs.insert(stub_start, slot);
                    }
                }
                // Stubs are padded to 16 bytes; the next one starts at the next boundary.
                if instr.next_ip() % 16 == 0 {
                    stub_start = instr.next_ip();
                }
            }
        }
        Imports { image, stubs }
    }

    /// The import behind a slot address, if the slot is one.
    fn slot(&self, slot: Option<u64>) -> Option<&'a str> {
        self.image.import_slots.get(&slot?).map(String::as_str)
    }

    /// The slot a PLT stub at `addr` jumps through.
    fn stub_slot(&self, addr: u64) -> Option<u64> {
        self.stubs.get(&addr).copied()
    }

    /// The import a PLT stub at `addr` reaches.
    fn stub(&self, addr: u64) -> Option<&'a str> {
        self.slot(self.stub_slot(addr))
    }
}

/// Whether any path from the function's entry can return to its caller, given the functions
/// currently known not to return. Unresolved indirect jumps count as possibly returning.
fn may_return(function: &Function, noreturn: &HashSet<u64>, imports: &Imports) -> bool {
    let controls = &function.controls;
    let in_range = |addr: u64| addr >= function.start && addr < function.end;
    let target_returns = |target: u64| match imports.stub(target) {
        Some(name) => !is_noreturn_import(name),
        None => !noreturn.contains(&target),
    };

    let mut visited = vec![false; controls.len()];
    let mut pending = vec![function.start];
    while let Some(addr) = pending.pop() {
        // Everything up to the next control instruction falls through.
        let mut index = controls.partition_point(|c| c.addr < addr);
        loop {
            let Some(control) = controls.get(index) else {
                break; // Ran off the end of the range.
            };
            if std::mem::replace(&mut visited[index], true) {
                break;
            }
            match control.flow {
                Flow::Return => return true,
                Flow::Halt => break,
                Flow::Jump(target) => {
                    if in_range(target) {
                        pending.push(target);
                    } else if target_returns(target) {
                        return true;
                    }
                    break;
                }
                Flow::Branch(target) => {
                    if in_range(target) {
                        pending.push(target);
                    } else if target_returns(target) {
                        return true;
                    }
                }
                Flow::JumpIndirect(slot) => match imports.slot(slot) {
                    Some(name) if is_noreturn_import(name) => break,
                    _ => return true,
                },
                Flow::Call(target) => {
                    if !target_returns(target) {
                        break;
                    }
                }
                Flow::CallIndirect(slot) => {
                    if imports.slot(slot).is_some_and(is_noreturn_import) {
                        break;
                    }
                }
            }
            index += 1;
        }
    }
    false
}

pub fn analyze(image: &Image) -> Analysis {
    let imports = Imports::new(image);
    let frames: Vec<(u64, u64)> = image
        .frames
        .iter()
        .copied()
        .filter(|&(start, _)| image.section_at(start).is_some_and(is_function_section))
        .collect();
    let frame_end: HashMap<u64, u64> = frames.iter().copied().collect();

    let discovery = discover(image, &frames);
    let starts: Vec<u64> = discovery.starts.keys().copied().collect();
    let functions: Vec<Function> = starts
        .par_iter()
        .enumerate()
        .map(|(index, &start)| match frame_end.get(&start) {
            Some(&end) => decode(image, start, end, false),
            None => {
                let section_end = image.section_at(start).map_or(start, |s| s.end());
                let bound = starts.get(index + 1).copied().unwrap_or(section_end).min(section_end);
                decode(image, start, bound, true)
            }
        })
        .collect();

    // Least fixpoint: a function joins the set once no path through it can return.
    let mut noreturn: HashSet<u64> = HashSet::new();
    loop {
        let added: Vec<u64> = functions
            .par_iter()
            .filter(|f| !noreturn.contains(&f.start) && !may_return(f, &noreturn, &imports))
            .map(|f| f.start)
            .collect();
        if added.is_empty() {
            break;
        }
        noreturn.extend(added);
    }

    let is_start = |addr: u64| starts.binary_search(&addr).is_ok();
    let leaves = |function: &Function, target: u64| target < function.start || target >= function.end;

    // A frame nothing refers to as a function, entered only by jumps from one other function,
    // is a split-off piece of that function.
    let mut jumped_from: HashMap<u64, Vec<u64>> = HashMap::new();
    for function in &functions {
        for control in &function.controls {
            if let Flow::Jump(target) | Flow::Branch(target) = control.flow {
                if leaves(function, target) && is_start(target) {
                    jumped_from.entry(target).or_default().push(function.start);
                }
            }
        }
    }
    let fragment_of: HashMap<u64, u64> = jumped_from
        .iter()
        .filter(|&(target, sources)| {
            !discovery.referenced.contains(target)
                && discovery.starts[target] == Origin::Frame
                && sources.iter().all(|&source| source == sources[0])
        })
        .map(|(&target, sources)| (target, sources[0]))
        .collect();

    let mut calls: Vec<CallSite> = functions
        .par_iter()
        .flat_map_iter(|function| {
            let fragment_of = &fragment_of;
            let noreturn = &noreturn;
            let imports = &imports;
            function.controls.iter().filter_map(move |control| {
                let local = |target: u64, tail: bool| {
                    // Moving between a function and its own fragment is ordinary control flow.
                    let same_function = fragment_of.get(&target) == Some(&function.start)
                        || fragment_of.get(&function.start) == Some(&target);
                    (is_start(target) && !same_function)
                        .then(|| (CallTarget::Function(target), noreturn.contains(&target), tail))
                };
                let import = |slot: u64, tail: bool| {
                    imports.slot(Some(slot)).map(|name| (CallTarget::Import(slot), is_noreturn_import(name), tail))
                };
                let (target, noreturn, tail) = match control.flow {
                    Flow::Call(target) => imports.stub_slot(target).and_then(|slot| import(slot, false)).or_else(|| local(target, false)),
                    Flow::CallIndirect(Some(slot)) => import(slot, false),
                    Flow::Jump(target) | Flow::Branch(target) if leaves(function, target) => {
                        imports.stub_slot(target).and_then(|slot| import(slot, true)).or_else(|| local(target, true))
                    }
                    Flow::JumpIndirect(Some(slot)) => import(slot, true),
                    _ => None,
                }?;
                Some(CallSite { at: control.addr, target, noreturn, tail })
            })
        })
        .collect();
    calls.sort_unstable_by_key(|call| call.at);

    let noreturn_calls: Vec<u64> = calls.iter().filter(|call| call.noreturn && !call.tail).map(|call| call.at).collect();
    let used_slots: HashSet<u64> = calls
        .iter()
        .filter_map(|call| match call.target {
            CallTarget::Import(slot) => Some(slot),
            CallTarget::Function(_) => None,
        })
        .collect();
    let mut import_list: Vec<Import> = used_slots
        .into_iter()
        .map(|slot| {
            let name = image.import_slots[&slot].clone();
            Import { slot, noreturn: is_noreturn_import(&name), name }
        })
        .collect();
    import_list.sort_unstable_by_key(|import| import.slot);

    Analysis {
        name: image.name.clone(),
        instructions: functions.iter().map(|f| f.instructions).sum(),
        functions: functions
            .iter()
            .map(|f| AnalyzedFunction {
                addr: f.start,
                ranges: vec![(f.start, f.end)],
                noreturn: noreturn.contains(&f.start),
                thunk: false,
                origin: discovery.starts[&f.start],
                fragment_of: fragment_of.get(&f.start).copied(),
            })
            .collect(),
        noreturn_calls,
        jump_tables: discovery.jump_tables,
        calls,
        imports: import_list,
    }
}
