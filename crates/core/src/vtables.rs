//! Vtables that no type information describes, and the calls made through vtables.
//!
//! A constructor stores the address of its class's vtable at the start of the object, and a
//! virtual call loads it back and calls through one of its slots:
//!
//! ```text
//! mov dword [esi], 0x402000   ; the constructor
//! ...
//! mov eax, [esi]              ; the call
//! mov ecx, esi
//! call [eax+0x10]             ; slot 4
//! ```
//!
//! An image without run-time type information still has the vtables: each is an address that
//! an instruction stores at the start of an object, where the words that follow are function
//! entries. A call through one is resolved by following the object in a register from where its
//! vtable is known to where the call loads it, over the paths through the function: after the
//! store, or from the entry of a method, where `this` holds an object whose vtable is one of
//! those that hold the method. A subclass that inherits the method holds it in its own vtable,
//! in the same slot, so those vtables are all the ones the object may have.

use rayon::prelude::*;
use rustc_hash::{FxHashMap, FxHashSet};

use crate::arch::{Arch, Effect, Flow, Operand, Place, Register};
use crate::cfg::cfg_with;
use crate::image::Image;
use crate::report::{Analysis, CallTarget, Class, VirtualCall};

/// Most slots read from one vtable.
const LONGEST: u64 = 1024;

/// The vtables that an instruction stores at the start of an object, each as a class named after
/// its address, where no class in `known` has it. `refs` are `(instruction, data address,
/// reads or writes it)` for what code refers to for certain, and `uncertain` for what code
/// decoded on a guess does. A vtable ends at the first word that is not a function entry, as
/// `is_entry` says, or at the next address that code refers to for certain.
pub fn untyped<A: Arch>(image: &Image, known: &[Class], refs: &[(u64, u64, bool)], uncertain: &[(u64, u64, bool)], is_entry: impl Fn(u64) -> bool + Sync) -> Vec<Class> {
    if A::THIS.is_none() {
        return Vec::new();
    }
    let pointer = image.machine.pointer_size();
    let word = |slot: u64| Some(image.bytes_from(slot)?.get(..pointer as usize)?.iter().rev().fold(0, |value, &byte| value << 8 | u64::from(byte)));
    let stores = |from: u64, value: u64| {
        let insn = A::decode(image, image.bytes_from(from).unwrap_or(&[]), from).next().and_then(|decoded| decoded.insn);
        insn.is_some_and(|insn| matches!(A::object_effect(&insn), Effect::Store { to: Place::Field { offset: 0, .. }, from: Operand::Constant(stored) } if stored == value))
    };
    let mut stored: Vec<u64> = refs
        .par_iter()
        .chain(uncertain)
        .filter(|&&(_, to, access)| !access && to % pointer == 0 && image.section_at(to).is_some_and(|section| !section.executable) && word(to).is_some_and(&is_entry))
        .filter(|&&(from, to, _)| stores(from, to))
        .map(|&(_, to, _)| to)
        .collect();
    stored.sort_unstable();
    stored.dedup();
    let known: FxHashSet<u64> = known.iter().map(|class| class.vtable).collect();
    if stored.iter().all(|vtable| known.contains(vtable)) {
        return Vec::new();
    }
    let mut referenced: Vec<u64> = refs.par_iter().map(|&(_, to, _)| to).collect();
    referenced.par_sort_unstable();
    let mut vtables: Vec<u64> = stored.iter().chain(&known).copied().collect();
    vtables.sort_unstable();
    let after = |ends: &[u64], addr: u64| ends.get(ends.partition_point(|&end| end <= addr)).copied().unwrap_or(u64::MAX);
    stored
        .into_iter()
        .filter(|vtable| !known.contains(vtable))
        .filter_map(|vtable| {
            let next = after(&referenced, vtable).min(after(&vtables, vtable));
            let methods: Vec<u64> = (0..LONGEST)
                .map(|index| vtable + index * pointer)
                .take_while(|&slot| slot < next)
                .map_while(|slot| word(slot).filter(|&target| is_entry(target)))
                .collect();
            (!methods.is_empty()).then(|| Class { name: format!("vtable_{vtable:x}"), vtable, methods, bases: Vec::new(), objc: false })
        })
        .collect()
}

/// What a register holds as far as the vtables of objects go. A set of vtables is a number of
/// [`Sets`].
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
enum Value {
    #[default]
    Unknown,
    /// A number the code put there, which may be an address, or zero for no object.
    Constant(u64),
    /// An object whose vtable is one of a set.
    Object(u32),
    /// The vtable of such an object, which the object holds at offset zero.
    Vtable(u32),
}

/// What the general-purpose registers hold at one point of a function.
type Registers = [Value; 16];

fn get(registers: &Registers, register: Register) -> Value {
    registers.get(usize::from(register)).copied().unwrap_or_default()
}

fn set(registers: &mut Registers, register: Register, value: Value) {
    if let Some(held) = registers.get_mut(usize::from(register)) {
        *held = value;
    }
}

fn clear(registers: &mut Registers, mask: u32) {
    for (index, held) in registers.iter_mut().enumerate() {
        if mask & 1 << index != 0 {
            *held = Value::Unknown;
        }
    }
}

/// What a register holds where two paths meet: what it holds on both, or nothing known. A null
/// pointer says nothing about which object it is.
fn meet(a: Value, b: Value) -> Value {
    match (a, b) {
        (a, b) if a == b => a,
        (Value::Constant(0), held @ Value::Object(_)) | (held @ Value::Object(_), Value::Constant(0)) => held,
        _ => Value::Unknown,
    }
}

/// Sets of vtables, each sorted and numbered once.
#[derive(Default)]
struct Sets {
    sets: Vec<Vec<u64>>,
    numbers: FxHashMap<Vec<u64>, u32>,
}

impl Sets {
    fn number(&mut self, set: Vec<u64>) -> u32 {
        let next = self.sets.len() as u32;
        *self.numbers.entry(set).or_insert_with_key(|set| {
            self.sets.push(set.clone());
            next
        })
    }
}

/// The image's vtables.
struct Vtables<'a> {
    pointer: u64,
    this: Register,
    methods: FxHashMap<u64, &'a [u64]>,
    sets: Sets,
    /// The set of each vtable alone, by its address.
    alone: FxHashMap<u64, u32>,
}

impl Vtables<'_> {
    /// What the call through `offset` into the vtable of an object goes to, where the vtable is
    /// one of `set`, at `at`: `None` where no vtable of the set has a function in that slot.
    fn call(&self, at: u64, set: u32, offset: i64, tail: bool, is_entry: &impl Fn(u64) -> bool) -> Option<VirtualCall> {
        let slot = u64::try_from(offset).ok().filter(|offset| offset % self.pointer == 0)? / self.pointer;
        let held = |vtable: &u64| self.methods[vtable].get(slot as usize).copied().filter(|&target| is_entry(target));
        let vtables: Vec<u64> = self.sets.sets[set as usize].iter().copied().filter(|vtable| held(vtable).is_some()).collect();
        let mut targets: Vec<u64> = vtables.iter().filter_map(held).collect();
        targets.sort_unstable();
        targets.dedup();
        (!targets.is_empty()).then_some(VirtualCall { at, slot, vtables, targets, tail })
    }
}

/// A function as objects are followed through it: its blocks, and what each instruction does.
struct Body {
    /// The block control enters the function at.
    entry: Option<usize>,
    blocks: Vec<Block>,
    /// The blocks each block passes control to, by index: those of block `i` are
    /// `successors[edges[i]..edges[i + 1]]`.
    successors: Vec<u32>,
    edges: Vec<u32>,
    /// The instructions of every block, but those that do nothing followed.
    steps: Vec<Step>,
}

/// A basic block of a [`Body`].
struct Block {
    /// Its instructions, in [`Body::steps`].
    steps: std::ops::Range<usize>,
}

/// An instruction as objects are followed through it.
struct Step {
    at: u64,
    effect: Effect,
    /// It is a jump: a call through a slot that it makes is a tail call.
    jumps: bool,
}

impl Body {
    fn new<A: Arch>(image: &Image, analysis: &Analysis, start: u64, ranges: &[(u64, u64)]) -> Body {
        let cfg = cfg_with::<A>(image, analysis, ranges);
        let block_at = |addr: u64| cfg.blocks.binary_search_by_key(&addr, |block| block.start).ok();
        let (mut successors, mut edges, mut steps) = (Vec::new(), vec![0], Vec::new());
        let blocks = cfg
            .blocks
            .iter()
            .map(|block| {
                successors.extend(block.successors.iter().filter_map(|&successor| block_at(successor)).map(|index| index as u32));
                edges.push(successors.len() as u32);
                let first = steps.len();
                let bytes = image.bytes_from(block.start).unwrap_or(&[]);
                for decoded in A::decode(image, &bytes[..bytes.len().min((block.end - block.start) as usize)], block.start) {
                    let Some(insn) = decoded.insn else { continue };
                    let effect = A::object_effect(&insn);
                    if effect == Effect::Clobbers(0) {
                        continue;
                    }
                    let jumps = matches!(effect, Effect::Through { .. }) && matches!(A::flow(&insn, &A::State::default(), image), Some(Flow::JumpIndirect(_)));
                    steps.push(Step { at: decoded.addr, effect, jumps });
                }
                Block { steps: first..steps.len() }
            })
            .collect();
        Body { entry: block_at(start), blocks, successors, edges, steps }
    }

    fn successors(&self, block: usize) -> impl Iterator<Item = usize> + '_ {
        self.successors[self.edges[block] as usize..self.edges[block + 1] as usize].iter().map(|&index| index as usize)
    }
}

/// The calls through vtables in the function `body`, where `this` holds `this` at its entry.
fn follow(vtables: &Vtables, body: &Body, this: Value, is_entry: &impl Fn(u64) -> bool) -> Vec<VirtualCall> {
    let operand = |registers: &Registers, operand: Operand| match operand {
        Operand::Register(register) => get(registers, register),
        Operand::Constant(value) => Value::Constant(value),
    };
    // Steps the registers over one instruction, and adds a call it resolves to `calls`.
    let step = |registers: &mut Registers, &Step { at, effect, jumps }: &Step, calls: &mut Vec<VirtualCall>| match effect {
        Effect::Set { to, from } => set(registers, to, operand(registers, from)),
        Effect::Load { to, from } => {
            let loaded = match from {
                Place::Field { base, offset: 0 } => match get(registers, base) {
                    Value::Object(set) => Value::Vtable(set),
                    _ => Value::Unknown,
                },
                Place::Field { .. } | Place::Global(_) => Value::Unknown,
            };
            set(registers, to, loaded);
        }
        Effect::Store { to, from } => {
            let mut stored = operand(registers, from);
            if let Value::Constant(vtable) = stored
                && let Some(&alone) = vtables.alone.get(&vtable)
            {
                stored = Value::Vtable(alone);
            }
            // A constructor's store.
            if let (Place::Field { base, offset: 0 }, Value::Vtable(vtable)) = (to, stored) {
                set(registers, base, Value::Object(vtable));
            }
        }
        Effect::Through { slot, clobbers } => {
            if let Place::Field { base, offset } = slot
                && let Value::Vtable(set) = get(registers, base)
            {
                calls.extend(vtables.call(at, set, offset, jumps, is_entry));
            }
            clear(registers, clobbers);
        }
        Effect::Clobbers(mask) => clear(registers, mask),
    };

    // What the registers hold where each block starts, once a path from the entry reaches it.
    let mut before: Vec<Option<Registers>> = vec![None; body.blocks.len()];
    let mut pending = Vec::new();
    if let Some(entry) = body.entry {
        let mut registers = Registers::default();
        set(&mut registers, vtables.this, this);
        before[entry] = Some(registers);
        pending.push(entry);
    }
    while let Some(index) = pending.pop() {
        let mut registers = before[index].expect("only reached blocks are pending");
        for instruction in &body.steps[body.blocks[index].steps.clone()] {
            step(&mut registers, instruction, &mut Vec::new());
        }
        for next in body.successors(index) {
            let merged = before[next].map_or(registers, |known| std::array::from_fn(|register| meet(known[register], registers[register])));
            if before[next] != Some(merged) {
                before[next] = Some(merged);
                pending.push(next);
            }
        }
    }
    // Blocks no path from the entry reaches, such as exception handlers, start knowing nothing.
    let mut calls = Vec::new();
    for (block, registers) in body.blocks.iter().zip(before) {
        let mut registers = registers.unwrap_or_default();
        for instruction in &body.steps[block.steps.clone()] {
            step(&mut registers, instruction, &mut calls);
        }
    }
    calls
}

/// What the analysis says of the functions, indexed to follow objects through only the functions
/// they get into.
struct Graph {
    /// `(start, end, function)` for each range of each function, sorted.
    pieces: Vec<(u64, u64, u64)>,
    /// The ranges that overlap another, where functions share code, by index in `pieces`.
    shared: Vec<usize>,
}

impl Graph {
    fn new(analysis: &Analysis) -> Graph {
        let mut pieces: Vec<(u64, u64, u64)> = analysis.functions.iter().flat_map(|function| function.ranges.iter().map(|&(start, end)| (start, end, function.fragment_of.unwrap_or(function.addr)))).collect();
        pieces.sort_unstable();
        let mut furthest = 0;
        let mut shared = Vec::new();
        for (index, &(start, end, _)) in pieces.iter().enumerate() {
            if start < furthest || pieces.get(index + 1).is_some_and(|next| next.0 < end) {
                shared.push(index);
            }
            furthest = furthest.max(end);
        }
        Graph { pieces, shared }
    }

    /// The functions whose ranges hold `addr`. Another range can hold an address of one only
    /// where the two overlap.
    fn functions_at(&self, addr: u64) -> Vec<u64> {
        let Some(last) = self.pieces.partition_point(|piece| piece.0 <= addr).checked_sub(1) else { return Vec::new() };
        let holds = |index: usize| (self.pieces[index].0..self.pieces[index].1).contains(&addr).then_some(self.pieces[index].2);
        match self.shared.binary_search(&last) {
            Ok(_) => self.shared.iter().filter_map(|&index| holds(index)).collect(),
            Err(_) => holds(last).into_iter().collect(),
        }
    }
}

/// The calls through the vtables of objects whose vtables are known, sorted by address: of the
/// analysis's classes, which have vtables and are not Objective-C's.
///
/// Objects are followed in the functions that refer to a vtable, which is how one stores it, and
/// in methods, where `this` holds an object of the vtables that hold the method unless a direct
/// call reaches it.
pub fn virtual_calls<A: Arch>(image: &Image, analysis: &Analysis) -> Vec<VirtualCall> {
    let Some(this) = A::THIS else { return Vec::new() };
    let classes: Vec<&Class> = analysis.classes.iter().filter(|class| !class.objc).collect();
    if classes.is_empty() {
        return Vec::new();
    }
    let mut vtables = Vtables { pointer: image.machine.pointer_size(), this, methods: classes.iter().map(|class| (class.vtable, class.methods.as_slice())).collect(), sets: Sets::default(), alone: FxHashMap::default() };
    vtables.alone = classes.iter().map(|class| (class.vtable, vtables.sets.number(vec![class.vtable]))).collect();
    // A method is called through its vtable with an object of that vtable.
    let mut holders: FxHashMap<u64, Vec<u64>> = FxHashMap::default();
    for class in &classes {
        for &method in &class.methods {
            holders.entry(method).or_default().push(class.vtable);
        }
    }
    let seeds: FxHashMap<u64, Value> = holders
        .into_iter()
        .map(|(method, mut holding)| {
            holding.sort_unstable();
            holding.dedup();
            (method, Value::Object(vtables.sets.number(holding)))
        })
        .collect();
    let called: FxHashSet<u64> = analysis.calls.iter().filter_map(|call| if let CallTarget::Function(callee) = call.target { Some(callee) } else { None }).collect();

    let is_entry = |addr: u64| analysis.functions.binary_search_by_key(&addr, |function| function.addr).is_ok_and(|index| analysis.functions[index].fragment_of.is_none());
    let graph = Graph::new(analysis);
    let mut fragments: FxHashMap<u64, Vec<(u64, u64)>> = FxHashMap::default();
    for function in &analysis.functions {
        if let Some(owner) = function.fragment_of {
            fragments.entry(owner).or_default().extend(&function.ranges);
        }
    }
    // The body of the function at `start`, with those of its fragments.
    let body = |start: u64| {
        let functions = &analysis.functions;
        let own = functions.binary_search_by_key(&start, |function| function.addr).map_or(&[][..], |index| &functions[index].ranges);
        let mut ranges: Vec<(u64, u64)> = own.iter().chain(fragments.get(&start).into_iter().flatten()).copied().collect();
        ranges.sort_unstable();
        Body::new::<A>(image, analysis, start, &ranges)
    };
    let constructors = analysis.data_refs.iter().filter(|data_ref| !data_ref.access && vtables.alone.contains_key(&data_ref.to)).flat_map(|data_ref| graph.functions_at(data_ref.from));
    let mut starts: Vec<u64> = seeds.keys().copied().chain(constructors).filter(|&start| is_entry(start)).collect();
    starts.sort_unstable();
    starts.dedup();
    let mut calls: Vec<VirtualCall> = starts
        .par_iter()
        .flat_map_iter(|&start| {
            let this = seeds.get(&start).copied().filter(|_| !called.contains(&start)).unwrap_or_default();
            follow(&vtables, &body(start), this, &is_entry)
        })
        .collect();
    calls.sort_unstable_by_key(|call| call.at);
    calls.dedup_by_key(|call| call.at);
    calls
}
