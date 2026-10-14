//! The tools that show code below the level of C: instructions, p-code and data flow.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::fmt::Write;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use recore::cfg::{Cfg, Exit, cfg};
use recore::program::parse_addr;
use recore::report::CallTarget;
use recore_decomp::Flow;
use recore_decomp::flow::{Kind, Op};
use serde::Deserialize;

use crate::binary::Binary;
use crate::tools::{addr_arg, cut, describe, resolve_function};

/// Instructions shown for a whole function unless the caller sets `count`.
const FUNCTION_COUNT: usize = 500;
/// Instructions shown from an address unless the caller sets `count`.
const WINDOW_COUNT: usize = 32;
/// No instruction of the supported processors is longer.
const LONGEST_INSTRUCTION: u64 = 16;
/// P-code operations shown unless the caller sets `limit`.
const OPERATIONS: usize = 400;

#[derive(Deserialize)]
pub struct Disassemble {
    function: Option<String>,
    addr: Option<String>,
    count: Option<usize>,
    #[serde(default)]
    pcode: bool,
}

/// What the analysis and the edits know about one instruction, for the end of its line.
fn notes(binary: &Binary, graph: Option<&Cfg>, addr: u64, end: u64) -> String {
    let program = &binary.program;
    let mut notes = Vec::new();
    for call in program.calls_in(addr, end) {
        let target = match call.target {
            CallTarget::Function(target) => program.label(target),
            CallTarget::Import(slot) => program.import_name(slot).unwrap_or("?").to_string(),
        };
        // A message send names its selector, and the one method this binary has for it.
        let target = match recore::objc::send_at(&program.analysis, call.at) {
            Some(send) => format!("{}{}", send.label(), send.implementation.map_or_else(String::new, |method| format!(", implemented only by {}", program.label(method)))),
            None => target,
        };
        notes.push(format!("{} {target}", if call.tail { "tail-calls" } else { "calls" }));
    }
    if graph.is_some_and(|graph| graph.unresolved_calls.contains(&addr)) {
        notes.push("call target unknown".into());
    }
    if let Some(table) = program.analysis.jump_tables.iter().find(|table| table.jump == addr) {
        notes.push(format!("switch to {}", table.targets.iter().map(|target| format!("{target:#x}")).collect::<Vec<_>>().join(" ")));
    }
    for reference in program.refs_in(addr, end) {
        notes.push(format!("{:#x} {}", reference.to, describe(binary, reference.to)));
    }
    if let Some(comment) = binary.edits.comments.get(&addr) {
        notes.push(format!("// {comment}"));
    }
    if notes.is_empty() { String::new() } else { format!("  ; {}", notes.join("; ")) }
}

pub fn disassemble(binary: &mut Binary, args: Disassemble) -> Result<String> {
    let (entry, asked) = match (&args.function, &args.addr) {
        (Some(function), None) => {
            let entry = resolve_function(binary, function)?;
            (Some(entry), binary.program.body(entry).first().map_or(entry, |range| range.0))
        }
        (None, Some(addr)) => {
            let addr = addr_arg(addr)?;
            ensure!(binary.program.image.is_code(addr), "{addr:#x} is not code; `bytes` shows data");
            (binary.program.function_at(addr).ok(), addr)
        }
        _ => bail!("`disassemble` needs either `function` or `addr`"),
    };
    let count = args.count.unwrap_or(if args.function.is_some() { FUNCTION_COUNT } else { WINDOW_COUNT }).max(1);
    let body = entry.map(|entry| binary.program.body(entry)).unwrap_or_default();
    let graph = entry.map(|_| cfg(&binary.program.image, &binary.program.analysis, &body));

    let mut out = String::new();
    // Inside a function, start on an instruction: the one the address is in.
    let start = match &graph {
        Some(graph) => {
            let index = graph.instructions.partition_point(|&instruction| instruction <= asked);
            let start = index.checked_sub(1).map_or(asked, |index| graph.instructions[index]);
            if start != asked && body.iter().any(|&(from, to)| asked >= from && asked < to) {
                writeln!(out, "{asked:#x} is inside the instruction at {start:#x}")?;
                start
            } else {
                asked
            }
        }
        None => asked,
    };
    // The ranges to list: the rest of the function from `start`, or a window of plain code.
    let ranges: Vec<(u64, u64)> = match entry {
        Some(_) => body.iter().filter(|&&(_, end)| end > start).map(|&(from, end)| (from.max(start), end)).collect(),
        None => {
            let section_end = binary.program.image.section_at(start).map_or(start, |section| section.end());
            vec![(start, section_end.min(start + count as u64 * LONGEST_INSTRUCTION))]
        }
    };
    let mut instructions = Vec::new();
    for (from, end) in ranges {
        let wanted = (count - instructions.len()) as u64;
        if wanted == 0 {
            break;
        }
        instructions.extend(binary.listing(from, end.min(from + wanted * LONGEST_INSTRUCTION), args.pcode)?);
    }
    let total = graph.as_ref().map(|graph| graph.instructions.len());
    let more = instructions.get(count).map(|next| next.addr);
    instructions.truncate(count);

    if let (Some(entry), Some(graph)) = (entry, &graph) {
        writeln!(out, "function {}: {} blocks, {} instructions", binary.program.label(entry), graph.blocks.len(), graph.instructions.len())?;
    } else {
        writeln!(out, "{start:#x} is in no function the analysis found")?;
    }
    let runs_on = entry.and_then(|entry| binary.program.function(entry)).and_then(|function| function.runs_on);
    let blocks: BTreeMap<u64, &recore::cfg::Block> = graph.iter().flat_map(|graph| &graph.blocks).map(|block| (block.start, block)).collect();
    for instruction in &instructions {
        if let Some(block) = blocks.get(&instruction.addr) {
            let mut leaves: Vec<String> = block.successors.iter().map(|successor| format!("{successor:#x}")).collect();
            leaves.extend(block.exit.map(|exit| {
                match exit {
                    Exit::Return => "returns",
                    Exit::TailCall => "tail call",
                    Exit::NoReturn => "does not return",
                    Exit::Unresolved => "jump target unknown",
                }
                .to_string()
            }));
            writeln!(out, "block {:#x} -> {}", block.start, match (leaves.is_empty(), runs_on.filter(|&next| next == block.end)) {
                (false, _) => leaves.join(", "),
                (true, Some(next)) => format!("runs on into {}", binary.program.label(next)),
                (true, None) => "falls out of the function".into(),
            })?;
        }
        let end = instruction.addr + instruction.len;
        let bytes = binary.program.image.bytes_from(instruction.addr).unwrap_or(&[]);
        let hex: String = bytes[..bytes.len().min(instruction.len as usize)].iter().map(|byte| format!("{byte:02x}")).collect();
        writeln!(out, "  {:#x}  {hex:<16}  {}{}", instruction.addr, instruction.text, notes(binary, graph.as_ref(), instruction.addr, end))?;
        for operation in &instruction.pcode {
            writeln!(out, "      {operation}")?;
        }
    }
    if let Some(next) = more {
        let of = total.map_or_else(String::new, |total| format!(" of {total}"));
        writeln!(out, "{} instructions{of} shown; continue with addr {next:#x}", instructions.len())?;
    }
    Ok(out)
}

/// One operation as a line: the value it defines, the operation, and what it reads.
fn operation(binary: &Binary, flow: &Flow, op: &Op) -> String {
    let inputs: Vec<String> = op.inputs.iter().map(|&id| flow.name(id)).collect();
    let output = op.output.map_or_else(String::new, |id| format!("{} = ", flow.name(id)));
    let callee = op.callee.as_ref().map_or_else(String::new, |callee| match binary.program.function(callee.addr) {
        Some(_) => format!(" {}", binary.program.label(callee.addr)),
        None => format!(" {}", callee.name),
    });
    format!("{:#x}  {output}{}{callee}{}{}", op.addr, op.code, if inputs.is_empty() { "" } else { " " }, inputs.join(", "))
}

#[derive(Deserialize)]
pub struct Pcode {
    function: String,
    limit: Option<usize>,
    timeout: Option<f64>,
}

fn timeout_arg(seconds: Option<f64>) -> Result<Duration> {
    Duration::try_from_secs_f64(seconds.unwrap_or(30.0)).map_err(|_| anyhow::anyhow!("`timeout` must be a positive number of seconds"))
}

pub fn pcode(binary: &mut Binary, args: Pcode) -> Result<String> {
    let entry = resolve_function(binary, &args.function)?;
    let flow = binary.flow(entry, timeout_arg(args.timeout)?)?;
    let limit = args.limit.unwrap_or(OPERATIONS);
    let mut parameters: Vec<(usize, &str, u32)> = flow.values.values().filter_map(|value| match &value.kind {
        Kind::Param { index, name } => Some((*index, name.as_str(), value.size)),
        _ => None,
    }).collect();
    parameters.sort_unstable();
    parameters.dedup();
    let mut out = String::new();
    writeln!(out, "function {}: {} blocks, {} operations", binary.program.label(entry), flow.blocks.len(), flow.ops.len())?;
    writeln!(out, "parameters: {}", if parameters.is_empty() { "none".into() } else { parameters.iter().map(|(_, name, size)| format!("{name} ({size} bytes)")).collect::<Vec<_>>().join(", ") })?;
    // An INDIRECT says that a call may have changed a global, and a global copied to itself
    // that it outlives the function or is the same on
    // every path. There is one per call, return or join and global, and they say
    // nothing the calls and returns do not.
    let global = |id: u32| match flow.values.get(&id).map(|value| &value.kind) {
        Some(Kind::Global { addr, .. }) => Some(*addr),
        _ => None,
    };
    let kept = |op: &Op| matches!(op.code.as_str(), "COPY" | "MULTIEQUAL") && op.output.and_then(global).is_some_and(|to| op.inputs.iter().all(|&input| global(input) == Some(to)));
    let visible = |op: &&Op| op.code != "INDIRECT" && !kept(op);
    let total = flow.ops.iter().filter(visible).count();
    let mut shown = 0;
    for (index, block) in flow.blocks.iter().enumerate() {
        let successors: Vec<String> = block.successors.iter().map(|successor| successor.to_string()).collect();
        writeln!(out, "block {index} {:#x}-{:#x} -> {}", block.start, block.stop, if successors.is_empty() { "exit".into() } else { successors.join(" ") })?;
        for op in flow.ops.iter().filter(|op| op.block == index).filter(visible) {
            if shown == limit {
                writeln!(out, "...{}", cut(limit, total, "operations ", &format!("`limit` {total} shows all")))?;
                return Ok(out);
            }
            shown += 1;
            writeln!(out, "  {}", operation(binary, &flow, op))?;
        }
    }
    Ok(out)
}

#[derive(Deserialize)]
pub struct Trace {
    function: String,
    /// Follow this parameter forward, counted from 1 as the decompiler names them.
    param: Option<usize>,
    /// Follow what the function returns back to where it comes from.
    #[serde(default)]
    returns: bool,
    /// With `arg`: follow an argument of the call at this address back to where it comes from.
    call: Option<String>,
    arg: Option<usize>,
    depth: Option<usize>,
    timeout: Option<f64>,
}

/// Functions decompiled for one trace, the function asked about included.
const TRACE_FUNCTIONS: usize = 16;
/// Lines one trace may print.
const TRACE_LINES: usize = 300;
/// Callers followed when a value turns out to be a parameter.
const TRACE_CALLERS: usize = 4;

struct Tracer<'a> {
    binary: &'a mut Binary,
    timeout: Duration,
    flows: HashMap<u64, Flow>,
    out: String,
    lines: usize,
    /// `(function, value)` pairs already followed, so that recursion and loops end.
    seen: BTreeSet<(u64, u32)>,
}

impl Tracer<'_> {
    fn line(&mut self, indent: usize, text: &str) {
        self.lines += 1;
        if self.lines <= TRACE_LINES {
            let _ = writeln!(self.out, "{:indent$}{text}", "", indent = 2 * indent);
        }
    }

    /// The data flow of a function, decompiled on first use. `None` once the trace has used up
    /// its decompilations or the function fails, which the trace says where it happens.
    fn flow(&mut self, entry: u64) -> Option<Flow> {
        if !self.flows.contains_key(&entry) {
            if self.flows.len() == TRACE_FUNCTIONS {
                return None;
            }
            let flow = self.binary.flow(entry, self.timeout).ok()?;
            self.flows.insert(entry, flow);
        }
        self.flows.get(&entry).cloned()
    }

    /// Follows values to everything computed from them: into the functions they are passed to,
    /// and out to memory, conditions and the return value.
    fn forward(&mut self, entry: u64, seeds: Vec<u32>, depth: usize, indent: usize) {
        let Some(flow) = self.flow(entry) else { return self.line(indent, &format!("{} was not decompiled: budget or failure", self.binary.program.label(entry))) };
        let mut queue: VecDeque<u32> = seeds.into();
        let mut printed = BTreeSet::new();
        while let Some(id) = queue.pop_front() {
            if !self.seen.insert((entry, id)) {
                continue;
            }
            for (index, op) in flow.ops.iter().enumerate().filter(|(_, op)| op.inputs.contains(&id)) {
                // A call that may change the value's storage passes the value on unseen.
                if op.code != "INDIRECT" && printed.insert(index) {
                    let text = operation(self.binary, &flow, op);
                    self.line(indent, &text);
                }
                match op.code.as_str() {
                    "CALL" | "CALLIND" => {
                        let position = op.inputs.iter().position(|&input| input == id).expect("filtered on it");
                        let local = op.callee.as_ref().map(|callee| callee.addr).filter(|&callee| self.binary.program.function(callee).is_some());
                        match local {
                            Some(callee) if depth > 0 => {
                                self.line(indent + 1, &format!("as argument {} of {}:", position + 1, self.binary.program.label(callee)));
                                let parameters = self.flow(callee).map(|flow| parameter(&flow, position)).unwrap_or_default();
                                if parameters.is_empty() {
                                    self.line(indent + 2, "the callee does not read that parameter, or was not decompiled");
                                } else {
                                    self.forward(callee, parameters, depth - 1, indent + 2);
                                }
                            }
                            _ => self.line(indent + 1, &format!("passed as argument {}; not followed further", position + 1)),
                        }
                    }
                    "STORE" => self.line(indent + 1, "written to memory; later reads of that memory are not followed"),
                    "RETURN" => self.line(indent + 1, "returned to the caller"),
                    _ => queue.extend(op.output),
                }
            }
        }
    }

    /// Follows values back to what they are computed from: constants, parameters (and from
    /// there the arguments callers pass), memory, and the results of calls.
    fn backward(&mut self, entry: u64, seeds: Vec<u32>, depth: usize, indent: usize) {
        let Some(flow) = self.flow(entry) else { return self.line(indent, &format!("{} was not decompiled: budget or failure", self.binary.program.label(entry))) };
        let mut queue: VecDeque<u32> = seeds.into();
        while let Some(id) = queue.pop_front() {
            if !self.seen.insert((entry, id)) {
                continue;
            }
            let Some(value) = flow.values.get(&id) else { continue };
            if let Some(op) = flow.definition(id) {
                if op.code == "INDIRECT" {
                    queue.extend(&op.inputs);
                    continue;
                }
                let text = operation(self.binary, &flow, op);
                self.line(indent, &text);
                let local = op.callee.as_ref().map(|callee| callee.addr).filter(|&callee| self.binary.program.function(callee).is_some());
                match (op.code.as_str(), local) {
                    ("CALL", Some(callee)) if depth > 0 => {
                        self.line(indent + 1, &format!("what {} returns:", self.binary.program.label(callee)));
                        let returned = self.flow(callee).map(|flow| returned(&flow)).unwrap_or_default();
                        self.backward(callee, returned, depth - 1, indent + 2);
                    }
                    ("CALL" | "CALLIND", _) => self.line(indent + 1, "the result of a call; not followed further"),
                    _ => queue.extend(&op.inputs),
                }
                continue;
            }
            match &value.kind {
                Kind::Const(constant) => self.line(indent, &format!("constant {constant:#x}")),
                Kind::Global { addr, .. } => {
                    let what = describe(self.binary, *addr);
                    self.line(indent, &format!("read from {addr:#x} {what}"));
                }
                Kind::Param { index, name } => {
                    let callers: Vec<u64> = self.binary.program.sites_reaching(entry).collect();
                    self.line(indent, &format!("parameter {name} of {}, called from {} places", self.binary.program.label(entry), callers.len()));
                    if depth == 0 {
                        continue;
                    }
                    for site in callers.into_iter().take(TRACE_CALLERS) {
                        let Ok(caller) = self.binary.program.function_at(site) else { continue };
                        self.line(indent + 1, &format!("at {site:#x} in {}:", self.binary.program.label(caller)));
                        let argument = self.flow(caller).and_then(|flow| flow.ops.iter().find(|op| op.addr == site && op.code.starts_with("CALL")).and_then(|op| op.inputs.get(*index).copied()));
                        match argument {
                            Some(argument) => self.backward(caller, vec![argument], depth - 1, indent + 2),
                            None => self.line(indent + 2, "the call there passes no such argument, or the caller was not decompiled"),
                        }
                    }
                }
                Kind::Local(name) => self.line(indent, &format!("{name}, which has no single definition here: a stack slot or an uninitialized value")),
                Kind::Temp(storage) => self.line(indent, &format!("{storage} on entry: a register the function reads without it being a parameter")),
            }
        }
    }
}

/// The values of a function that are its parameter at `index`, from zero.
fn parameter(flow: &Flow, index: usize) -> Vec<u32> {
    flow.values.iter().filter(|(_, value)| matches!(&value.kind, Kind::Param { index: at, .. } if *at == index)).map(|(&id, _)| id).collect()
}

/// The values a function returns, over all of its returns.
fn returned(flow: &Flow) -> Vec<u32> {
    flow.ops.iter().filter(|op| op.code == "RETURN").flat_map(|op| op.inputs.iter().copied()).collect()
}

pub fn trace(binary: &mut Binary, args: Trace) -> Result<String> {
    let entry = resolve_function(binary, &args.function)?;
    let timeout = timeout_arg(args.timeout)?;
    let depth = args.depth.unwrap_or(2);
    let label = binary.program.label(entry);
    let mut tracer = Tracer { binary, timeout, flows: HashMap::new(), out: String::new(), lines: 0, seen: BTreeSet::new() };
    let flow = tracer.binary.flow(entry, timeout)?;
    tracer.flows.insert(entry, flow.clone());
    match (args.param, args.returns, &args.call) {
        (Some(number), false, None) => {
            ensure!(number >= 1, "`param` counts from 1");
            let seeds = parameter(&flow, number - 1);
            ensure!(!seeds.is_empty(), "{label} has no parameter {number} that it reads; `pcode` lists its parameters");
            tracer.line(0, &format!("where parameter {number} of {label} goes:"));
            tracer.forward(entry, seeds, depth, 1);
        }
        (None, true, None) => {
            let seeds = returned(&flow);
            ensure!(!seeds.is_empty(), "{label} returns no value");
            tracer.line(0, &format!("where the value {label} returns comes from:"));
            tracer.backward(entry, seeds, depth, 1);
        }
        (None, false, Some(call)) => {
            let site = parse_addr(call).with_context(|| format!("`{call}` is not a hex address"))?;
            let number = args.arg.context("`call` needs `arg`, the argument to follow, counted from 1")?;
            ensure!(number >= 1, "`arg` counts from 1");
            let op = flow.ops.iter().find(|op| op.addr == site && op.code.starts_with("CALL")).with_context(|| format!("{label} has no call at {site:#x}; `pcode` lists its calls"))?;
            let seed = *op.inputs.get(number - 1).with_context(|| format!("the call at {site:#x} passes {} arguments", op.inputs.len()))?;
            tracer.line(0, &format!("where argument {number} of the call at {site:#x} in {label} comes from:"));
            tracer.backward(entry, vec![seed], depth, 1);
        }
        _ => bail!("`trace` needs exactly one of `param`, `returns` and `call` with `arg`"),
    }
    let (lines, decompiled) = (tracer.lines, tracer.flows.len());
    let mut out = tracer.out;
    if lines > TRACE_LINES {
        writeln!(out, "...{}", cut(TRACE_LINES, lines, "lines ", "a smaller `depth` narrows the trace to fit"))?;
    }
    writeln!(out, "{decompiled} functions decompiled, {TRACE_FUNCTIONS} at most. Values that pass through memory are not followed.")?;
    Ok(out)
}
