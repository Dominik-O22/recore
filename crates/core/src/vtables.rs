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
//! in the same slot, so those vtables are all the ones the object may have. Between functions
//! the object passes through `this`, through what a function returns, and through globals.

use rayon::prelude::*;
use rustc_hash::{FxHashMap, FxHashSet};

use crate::arch::{Arch, Effect, Flow, Operand, Place, Register};
use crate::cfg::{Exit, cfg_with};
use crate::image::Image;
use crate::phase;
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

/// What a register, or a place objects pass through, holds as far as the vtables of objects go.
/// A set of vtables is a number of [`Sets`].
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

/// The number of the empty set: what a place holds that nothing has yet been seen to put
/// there, while that is being worked out.
const NONE_YET: u32 = 0;

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

/// What a register holds where two paths meet: what it holds on both, or nothing known. A path
/// with no object yet, or a null pointer, says nothing about which object it is; `used` is set
/// where what the other path holds stands only because one has no object yet.
fn meet(a: Value, b: Value, used: &mut bool) -> Value {
    match (a, b) {
        (a, b) if a == b => a,
        (Value::Object(NONE_YET), held @ Value::Object(_)) | (held @ Value::Object(_), Value::Object(NONE_YET)) => {
            *used = true;
            held
        }
        (Value::Constant(0), held @ Value::Object(_)) | (held @ Value::Object(_), Value::Constant(0)) => held,
        (Value::Vtable(NONE_YET), held @ Value::Vtable(_)) | (held @ Value::Vtable(_), Value::Vtable(NONE_YET)) => {
            *used = true;
            held
        }
        _ => Value::Unknown,
    }
}

/// Whether a value is one that a place with nothing put in it yet holds.
fn none_yet(value: Value) -> bool {
    matches!(value, Value::Object(NONE_YET) | Value::Vtable(NONE_YET))
}

/// Sets of vtables, each sorted and numbered once. The empty set is [`NONE_YET`].
struct Sets {
    sets: Vec<Vec<u64>>,
    numbers: FxHashMap<Vec<u64>, u32>,
}

impl Sets {
    fn new() -> Sets {
        let mut sets = Sets { sets: Vec::new(), numbers: FxHashMap::default() };
        sets.number(Vec::new());
        sets
    }

    fn number(&mut self, set: Vec<u64>) -> u32 {
        let next = self.sets.len() as u32;
        *self.numbers.entry(set).or_insert_with_key(|set| {
            self.sets.push(set.clone());
            next
        })
    }

    /// What a place holds that each of `values` is put there: objects or vtables of the sets
    /// together, where every value is one kind or a null pointer. A place nothing is put in,
    /// or only null pointers, holds nothing known.
    fn join(&mut self, values: &[Value]) -> Value {
        let mut joined = None;
        for &value in values {
            joined = match (joined, value) {
                (_, Value::Constant(0)) => joined,
                (_, Value::Constant(_) | Value::Unknown) => return Value::Unknown,
                (None, value) => Some(value),
                (Some(Value::Object(a)), Value::Object(b)) => Some(Value::Object(self.union(a, b))),
                (Some(Value::Vtable(a)), Value::Vtable(b)) => Some(Value::Vtable(self.union(a, b))),
                _ => return Value::Unknown,
            };
        }
        joined.unwrap_or(Value::Unknown)
    }

    fn union(&mut self, a: u32, b: u32) -> u32 {
        if a == b {
            return a;
        }
        let mut members = [self.sets[a as usize].as_slice(), &self.sets[b as usize]].concat();
        members.sort_unstable();
        members.dedup();
        self.number(members)
    }
}

/// A place an object or a vtable passes through from one function to another. What it holds is
/// what every function that puts something there puts there.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
enum Key {
    /// `this` where the function at the address starts: what each direct call passes, and an
    /// object of the vtables that hold the function, where it is a method.
    This(u64),
    /// What the function at the address returns.
    Result(u64),
    /// The memory at a fixed address.
    Global(u64),
}

/// The image's vtables.
struct Vtables<'a> {
    pointer: u64,
    this: Register,
    result: Register,
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

/// What following objects through one function finds.
#[derive(Default)]
struct Followed {
    calls: Vec<VirtualCall>,
    /// What it puts in each place, in an order that is the same each time round.
    puts: Vec<(Key, Value)>,
    /// The places it takes something from, other than its own `this`.
    takes: Vec<Key>,
    /// Whether what it found depends on what a place it takes from holds where nothing has been
    /// put in that place yet. Where it does not, it finds the same once something has.
    uses_none_yet: bool,
}

/// A function as objects are followed through it: its blocks, and what each instruction does,
/// worked out once for every time it is followed.
struct Body {
    start: u64,
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
    /// What the function returns where control leaves it at the end of the block.
    returns: Returns,
}

#[derive(Clone, Copy, PartialEq)]
enum Returns {
    /// Control does not leave the function here, or never comes back.
    Nothing,
    /// What the result register holds.
    Result,
    /// What the function jumps to returns, which is not known: an import, or code reached
    /// through a pointer. A tail call to a function of the image returns what that returns.
    Unknown,
}

/// An instruction as objects are followed through it.
struct Step {
    at: u64,
    effect: Effect,
    /// The function it calls or tail-calls, and whether it is a tail call.
    call: Option<(u64, bool)>,
    /// It is a jump: a call through a slot that it makes is a tail call.
    jumps: bool,
}

impl Body {
    fn new<A: Arch>(image: &Image, analysis: &Analysis, start: u64, ranges: &[(u64, u64)]) -> Body {
        let cfg = cfg_with::<A>(image, analysis, ranges);
        let calls: Vec<(u64, u64, bool)> = ranges
            .iter()
            .flat_map(|&(from, to)| analysis.calls[analysis.calls.partition_point(|call| call.at < from)..].iter().take_while(move |call| call.at < to))
            .filter_map(|call| match call.target {
                CallTarget::Function(callee) => Some((call.at, callee, call.tail)),
                CallTarget::Import(_) => None,
            })
            .collect();
        let block_at = |addr: u64| cfg.blocks.binary_search_by_key(&addr, |block| block.start).ok();
        let (mut successors, mut edges, mut steps) = (Vec::new(), vec![0], Vec::new());
        let blocks = cfg
            .blocks
            .iter()
            .map(|block| {
                successors.extend(block.successors.iter().filter_map(|&successor| block_at(successor)).map(|index| index as u32));
                edges.push(successors.len() as u32);
                let last = cfg.instructions[cfg.instructions.partition_point(|&at| at < block.end) - 1];
                let returns = match block.exit {
                    Some(Exit::Return) => Returns::Result,
                    Some(Exit::TailCall | Exit::Unresolved) if calls.binary_search_by_key(&last, |call| call.0).is_err() => Returns::Unknown,
                    _ => Returns::Nothing,
                };
                let first = steps.len();
                let bytes = image.bytes_from(block.start).unwrap_or(&[]);
                let mut calls = calls[calls.partition_point(|call| call.0 < block.start)..].iter().peekable();
                for decoded in A::decode(image, &bytes[..bytes.len().min((block.end - block.start) as usize)], block.start) {
                    let call = calls.next_if(|call| call.0 == decoded.addr).map(|&(_, callee, tail)| (callee, tail));
                    let Some(insn) = decoded.insn else { continue };
                    let effect = A::object_effect(&insn);
                    if effect == Effect::Clobbers(0) && call.is_none() {
                        continue;
                    }
                    let jumps = matches!(effect, Effect::Through { .. }) && matches!(A::flow(&insn, &A::State::default(), image), Some(Flow::JumpIndirect(_)));
                    steps.push(Step { at: decoded.addr, effect, call, jumps });
                }
                Block { steps: first..steps.len(), returns }
            })
            .collect();
        Body { start, entry: block_at(start), blocks, successors, edges, steps }
    }

    fn successors(&self, block: usize) -> impl Iterator<Item = usize> + '_ {
        self.successors[self.edges[block] as usize..self.edges[block + 1] as usize].iter().map(|&index| index as usize)
    }
}

/// Follows objects through the function `body`, where each place holds what `held` says.
fn follow(vtables: &Vtables, body: &Body, held: impl Fn(Key) -> Value, is_entry: &impl Fn(u64) -> bool) -> Followed {
    let start = body.start;
    let operand = |registers: &Registers, operand: Operand| match operand {
        Operand::Register(register) => get(registers, register),
        Operand::Constant(value) => Value::Constant(value),
    };
    // Steps the registers over one instruction, and tells `seen` of each place it puts
    // something in or takes something from, and of each call it resolves.
    let step = |registers: &mut Registers, &Step { at, effect, call, jumps }: &Step, seen: &mut dyn FnMut(Seen)| {
        if let Some((callee, _)) = call {
            seen(Seen::Put(Key::This(callee), get(registers, vtables.this)));
        }
        match effect {
            Effect::Set { to, from } => set(registers, to, operand(registers, from)),
            Effect::Load { to, from } => {
                let loaded = match from {
                    Place::Field { base, offset: 0 } => match get(registers, base) {
                        Value::Object(set) => Value::Vtable(set),
                        _ => Value::Unknown,
                    },
                    Place::Field { .. } => Value::Unknown,
                    Place::Global(addr) => {
                        seen(Seen::Take(Key::Global(addr)));
                        held(Key::Global(addr))
                    }
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
                match to {
                    // A constructor's store.
                    Place::Field { base, offset: 0 } => {
                        if let Value::Vtable(vtable) = stored {
                            set(registers, base, Value::Object(vtable));
                        }
                    }
                    Place::Field { .. } => {}
                    Place::Global(addr) => seen(Seen::Put(Key::Global(addr), stored)),
                }
            }
            Effect::Through { slot, clobbers } => {
                if let Place::Field { base, offset } = slot
                    && let Value::Vtable(set) = get(registers, base)
                {
                    if set == NONE_YET {
                        seen(Seen::NoneYet);
                    }
                    if let Some(call) = vtables.call(at, set, offset, jumps, is_entry) {
                        seen(Seen::Call(call));
                    }
                }
                clear(registers, clobbers);
            }
            Effect::Clobbers(mask) => clear(registers, mask),
        }
        // What a call returns, and what a tail call does, which returns what its callee returns.
        if let Some((callee, tail)) = call {
            seen(Seen::Take(Key::Result(callee)));
            match tail {
                false => set(registers, vtables.result, held(Key::Result(callee))),
                true => seen(Seen::Put(Key::Result(start), held(Key::Result(callee)))),
            }
        }
    };

    // What the registers hold where each block starts, once a path from the entry reaches it.
    let mut before: Vec<Option<Registers>> = vec![None; body.blocks.len()];
    let mut pending = Vec::new();
    if let Some(entry) = body.entry {
        let mut registers = Registers::default();
        set(&mut registers, vtables.this, held(Key::This(start)));
        before[entry] = Some(registers);
        pending.push(entry);
    }
    let mut followed = Followed::default();
    while let Some(index) = pending.pop() {
        let mut registers = before[index].expect("only reached blocks are pending");
        for instruction in &body.steps[body.blocks[index].steps.clone()] {
            step(&mut registers, instruction, &mut |_| {});
        }
        for next in body.successors(index) {
            let merged = before[next].map_or(registers, |known| std::array::from_fn(|register| meet(known[register], registers[register], &mut followed.uses_none_yet)));
            if before[next] != Some(merged) {
                before[next] = Some(merged);
                pending.push(next);
            }
        }
    }
    // Blocks no path from the entry reaches, such as exception handlers, start knowing nothing.
    for (block, registers) in body.blocks.iter().zip(before) {
        let mut registers = registers.unwrap_or_default();
        for instruction in &body.steps[block.steps.clone()] {
            step(&mut registers, instruction, &mut |seen| match seen {
                Seen::Call(call) => followed.calls.push(call),
                Seen::Put(key, value) => {
                    followed.uses_none_yet |= none_yet(value);
                    followed.puts.push((key, value));
                }
                Seen::Take(key) => followed.takes.push(key),
                Seen::NoneYet => followed.uses_none_yet = true,
            });
        }
        // What a tail call to a function returns, `step` saw to.
        let returned = match block.returns {
            Returns::Result => Some(get(&registers, vtables.result)),
            Returns::Unknown => Some(Value::Unknown),
            Returns::Nothing => None,
        };
        followed.uses_none_yet |= returned.is_some_and(none_yet);
        followed.puts.extend(returned.map(|value| (Key::Result(start), value)));
    }
    followed.takes.sort_unstable();
    followed.takes.dedup();
    followed
}

/// What an instruction tells the pass that follows objects.
enum Seen {
    Call(VirtualCall),
    Put(Key, Value),
    Take(Key),
    /// A call goes through the vtable of an object that a place with nothing in it yet holds.
    NoneYet,
}

/// What the analysis says of calls and of memory at fixed addresses, indexed to follow objects
/// through only the functions they get into.
struct Graph<'a> {
    image: &'a Image,
    analysis: &'a Analysis,
    /// `(start, end, function)` for each range of each function, sorted.
    pieces: Vec<(u64, u64, u64)>,
    /// The ranges that overlap another, where functions share code, by index in `pieces`.
    shared: Vec<usize>,
    /// `(callee, instruction)` for each call and tail call to a function of the image, sorted.
    calls: Vec<(u64, u64)>,
    /// The functions that call each function, sorted, worked out when first asked for.
    callers: FxHashMap<u64, Vec<u64>>,
    /// `(address, instruction)` for each instruction that reads or writes data at a fixed
    /// address, sorted, made when first needed.
    accesses: Option<Vec<(u64, u64)>>,
    /// The functions that store something other than a null pointer at each fixed address,
    /// worked out when first asked for.
    writers: FxHashMap<u64, Vec<u64>>,
}

impl<'a> Graph<'a> {
    fn new(image: &'a Image, analysis: &'a Analysis) -> Graph<'a> {
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
        let mut calls: Vec<(u64, u64)> = analysis
            .calls
            .iter()
            .filter_map(|call| match call.target {
                CallTarget::Function(callee) => Some((callee, call.at)),
                CallTarget::Import(_) => None,
            })
            .collect();
        calls.par_sort_unstable();
        Graph { image, analysis, pieces, shared, calls, callers: FxHashMap::default(), accesses: None, writers: FxHashMap::default() }
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

    fn callers(&mut self, callee: u64) -> &[u64] {
        if !self.callers.contains_key(&callee) {
            let sites = &self.calls[self.calls.partition_point(|call| call.0 < callee)..self.calls.partition_point(|call| call.0 <= callee)];
            let mut callers: Vec<u64> = sites.iter().flat_map(|&(_, at)| self.functions_at(at)).collect();
            callers.sort_unstable();
            callers.dedup();
            self.callers.insert(callee, callers);
        }
        &self.callers[&callee]
    }

    /// Whether the functions at `a` and `b` call each other.
    fn mutual(&mut self, a: u64, b: u64) -> bool {
        self.callers(a).binary_search(&b).is_ok() && self.callers(b).binary_search(&a).is_ok()
    }

    /// The instructions that read or write data at `addr`.
    fn accesses(&mut self, addr: u64) -> &[(u64, u64)] {
        let accesses = self.accesses.get_or_insert_with(|| {
            let mut accesses: Vec<(u64, u64)> = self.analysis.data_refs.iter().filter(|data_ref| data_ref.access).map(|data_ref| (data_ref.to, data_ref.from)).collect();
            accesses.par_sort_unstable();
            accesses
        });
        &accesses[accesses.partition_point(|access| access.0 < addr)..accesses.partition_point(|access| access.0 <= addr)]
    }

    /// The functions that read or write data at `addr`.
    fn accessors(&mut self, addr: u64) -> Vec<u64> {
        let sites: Vec<u64> = self.accesses(addr).iter().map(|&(_, at)| at).collect();
        sites.into_iter().flat_map(|at| self.functions_at(at)).collect()
    }

    fn writers<A: Arch>(&mut self, addr: u64) -> &[u64] {
        if !self.writers.contains_key(&addr) {
            let image = self.image;
            let writes = |at: u64| {
                let insn = A::decode(image, image.bytes_from(at).unwrap_or(&[]), at).next().and_then(|decoded| decoded.insn);
                insn.is_some_and(|insn| matches!(A::object_effect(&insn), Effect::Store { to: Place::Global(to), from } if to == addr && from != Operand::Constant(0)))
            };
            let sites: Vec<u64> = self.accesses(addr).iter().map(|&(_, at)| at).filter(|&at| writes(at)).collect();
            let mut writers: Vec<u64> = sites.into_iter().flat_map(|at| self.functions_at(at)).collect();
            writers.sort_unstable();
            writers.dedup();
            self.writers.insert(addr, writers);
        }
        &self.writers[&addr]
    }
}

/// The [`Body`] of each function followed so far, by its entry.
struct Bodies<'a> {
    image: &'a Image,
    analysis: &'a Analysis,
    /// The ranges of each function's fragments, by the function's entry.
    fragments: FxHashMap<u64, Vec<(u64, u64)>>,
    bodies: FxHashMap<u64, Body>,
}

impl<'a> Bodies<'a> {
    fn new(image: &'a Image, analysis: &'a Analysis) -> Bodies<'a> {
        let mut fragments: FxHashMap<u64, Vec<(u64, u64)>> = FxHashMap::default();
        for function in &analysis.functions {
            if let Some(owner) = function.fragment_of {
                fragments.entry(owner).or_default().extend(&function.ranges);
            }
        }
        Bodies { image, analysis, fragments, bodies: FxHashMap::default() }
    }

    /// The body of the function at `start`, with those of its fragments.
    fn build<A: Arch>(&self, start: u64) -> Body {
        let functions = &self.analysis.functions;
        let own = functions.binary_search_by_key(&start, |function| function.addr).map_or(&[][..], |index| &functions[index].ranges);
        let mut ranges: Vec<(u64, u64)> = own.iter().chain(self.fragments.get(&start).into_iter().flatten()).copied().collect();
        ranges.sort_unstable();
        Body::new::<A>(self.image, self.analysis, start, &ranges)
    }
}

/// What each function followed puts in each place, one slot per put: a function puts in the
/// same places each time round, in the same order, and only what it puts there changes.
#[derive(Default)]
struct Puts {
    slots: Vec<Value>,
    /// The first of each function's slots, and how many it has.
    of: FxHashMap<u64, (usize, usize)>,
    by_key: FxHashMap<Key, Vec<usize>>,
    takers: FxHashMap<Key, Vec<u64>>,
}

impl Puts {
    /// Keeps what following the function at `start` found, and adds each place whose puts
    /// changed to `touched`: the first time, each place it puts in or takes from.
    fn record(&mut self, start: u64, found: &Followed, touched: &mut FxHashSet<Key>) {
        match self.of.get(&start) {
            Some(&(first, count)) => {
                debug_assert_eq!(count, found.puts.len(), "{start:#x} puts in other places than the last time round");
                for (slot, &(key, value)) in (first..).zip(&found.puts) {
                    if std::mem::replace(&mut self.slots[slot], value) != value {
                        touched.insert(key);
                    }
                }
            }
            None => {
                self.of.insert(start, (self.slots.len(), found.puts.len()));
                for &(key, value) in &found.puts {
                    self.by_key.entry(key).or_default().push(self.slots.len());
                    self.slots.push(value);
                    touched.insert(key);
                }
                for &key in &found.takes {
                    self.takers.entry(key).or_default().push(start);
                    touched.insert(key);
                }
            }
        }
    }

    fn followed(&self, start: u64) -> bool {
        self.of.contains_key(&start)
    }

    /// What the functions followed put in `key`.
    fn values(&self, key: Key) -> impl Iterator<Item = Value> + '_ {
        self.by_key.get(&key).into_iter().flatten().map(|&slot| self.slots[slot])
    }

    /// The functions followed that take from `key`, other than in their own `this`.
    fn takers(&self, key: Key) -> &[u64] {
        self.takers.get(&key).map_or(&[], Vec::as_slice)
    }
}

/// The calls through the vtables of objects whose vtables are known, sorted by address: of the
/// analysis's classes, which have vtables and are not Objective-C's.
///
/// Objects pass between functions through `this`, through what a function returns, and through
/// memory at fixed addresses. What each such place holds is what every function puts there,
/// which is worked out to a fixed point: optimistically, from places that hold nothing yet, so
/// that a function that passes `this` on to itself, or to one that calls it back, still learns
/// what its other callers pass. Only the functions objects can get into are followed, as
/// [`reach`] finds them; any other puts in a place what nothing is known of.
pub fn virtual_calls<A: Arch>(image: &Image, analysis: &Analysis) -> Vec<VirtualCall> {
    let Some(this) = A::THIS else { return Vec::new() };
    let classes: Vec<&Class> = analysis.classes.iter().filter(|class| !class.objc).collect();
    if classes.is_empty() {
        return Vec::new();
    }
    let mut vtables = Vtables {
        pointer: image.machine.pointer_size(),
        this,
        result: A::RESULT,
        methods: classes.iter().map(|class| (class.vtable, class.methods.as_slice())).collect(),
        sets: Sets::new(),
        alone: FxHashMap::default(),
    };
    vtables.alone = classes.iter().map(|class| (class.vtable, vtables.sets.number(vec![class.vtable]))).collect();
    // A method is called through its vtable with an object of that vtable.
    let mut holders: FxHashMap<u64, Vec<u64>> = FxHashMap::default();
    for class in &classes {
        for &method in &class.methods {
            holders.entry(method).or_default().push(class.vtable);
        }
    }
    let seeds: FxHashMap<Key, Value> = holders
        .into_iter()
        .map(|(method, mut holding)| {
            holding.sort_unstable();
            holding.dedup();
            (Key::This(method), Value::Object(vtables.sets.number(holding)))
        })
        .collect();

    let is_entry = |addr: u64| analysis.functions.binary_search_by_key(&addr, |function| function.addr).is_ok_and(|index| analysis.functions[index].fragment_of.is_none());
    let mut graph = Graph::new(image, analysis);
    let mut bodies = Bodies::new(image, analysis);
    // Objects start in the functions that refer to a vtable, which is how one stores it, and in
    // methods.
    let methods = seeds.keys().filter_map(|key| if let Key::This(method) = *key { Some(method) } else { None });
    let constructors = analysis.data_refs.iter().filter(|data_ref| !data_ref.access && vtables.alone.contains_key(&data_ref.to)).flat_map(|data_ref| graph.functions_at(data_ref.from));
    let starts: Vec<u64> = methods.chain(constructors).filter(|&start| is_entry(start)).collect();
    let (members, live, puts) = {
        let _phase = phase::scope("virtual calls/reach");
        reach::<A>(&vtables, &seeds, &mut graph, &mut bodies, starts, &is_entry)
    };
    let _phase = phase::scope("virtual calls/solve");
    solve(&mut vtables, &seeds, &bodies, &members, &live, puts, &is_entry)
}

/// The functions objects can get into from those at `starts`, the places that may hold an
/// object, and what each of those functions puts where.
///
/// Each function is followed with a place that may hold an object holding one of no vtable yet,
/// and any other place what nothing is known of. A place may hold an object where something puts
/// one there and every function that puts something there puts one of the same kind or a null
/// pointer; the functions that take from it are followed in turn. A function that is not
/// followed puts what nothing is known of. Where only such functions keep a place from holding
/// an object, those that an object may pass from only optimistically are followed too: the other
/// writers of a global, and functions that call and are called by one that takes from the place.
fn reach<A: Arch>(vtables: &Vtables, seeds: &FxHashMap<Key, Value>, graph: &mut Graph, bodies: &mut Bodies, starts: Vec<u64>, is_entry: &(impl Fn(u64) -> bool + Sync)) -> (FxHashSet<u64>, FxHashSet<Key>, Puts) {
    let mut members: FxHashSet<u64> = starts.iter().copied().collect();
    // What each place that may hold an object holds as far as reach goes: an object, or a
    // vtable, of no vtable yet. `this` in a method no direct call reaches is one.
    let mut live: FxHashMap<Key, Value> = FxHashMap::default();
    for &start in &members {
        if seeds.contains_key(&Key::This(start)) && graph.callers(start).is_empty() {
            live.insert(Key::This(start), Value::Object(NONE_YET));
        }
    }
    let mut puts = Puts::default();
    let mut due: Vec<u64> = members.iter().copied().collect();
    due.sort_unstable();
    while !due.is_empty() {
        let found: Vec<(u64, Option<Body>, Followed)> = due
            .par_iter()
            .map(|&start| {
                let built = (!bodies.bodies.contains_key(&start)).then(|| bodies.build::<A>(start));
                let body = built.as_ref().unwrap_or_else(|| &bodies.bodies[&start]);
                let found = follow(vtables, body, |key| live.get(&key).copied().unwrap_or_default(), is_entry);
                (start, built, found)
            })
            .collect();
        let mut touched: FxHashSet<Key> = FxHashSet::default();
        for (start, built, found) in found {
            bodies.bodies.extend(built.map(|body| (start, body)));
            puts.record(start, &found, &mut touched);
        }
        let mut next: Vec<u64> = Vec::new();
        for key in touched {
            if live.contains_key(&key) {
                continue;
            }
            let values: Vec<Value> = puts.values(key).chain(seeds.get(&key).copied()).collect();
            let held = kind(&values);
            if held == Value::Unknown {
                continue;
            }
            // A function that passes `this` on to itself puts there only what others pass, and
            // what a function returns only it puts.
            let unfollowed: Vec<u64> = match key {
                Key::This(callee) => graph.callers(callee).iter().copied().filter(|&caller| caller != callee && !puts.followed(caller)).collect(),
                Key::Result(_) => Vec::new(),
                Key::Global(addr) => graph.writers::<A>(addr).iter().copied().filter(|&writer| !puts.followed(writer)).collect(),
            };
            if !unfollowed.is_empty() {
                let mut takers = puts.takers(key).to_vec();
                if let Key::This(callee) = key
                    && members.contains(&callee)
                {
                    takers.push(callee);
                }
                for putter in unfollowed {
                    let added = matches!(key, Key::Global(_)) || takers.iter().any(|&taker| graph.mutual(putter, taker));
                    if added && is_entry(putter) && members.insert(putter) {
                        next.push(putter);
                    }
                }
                continue;
            }
            live.insert(key, held);
            let takers = match key {
                Key::This(callee) => vec![callee],
                Key::Result(callee) => graph.callers(callee).to_vec(),
                Key::Global(addr) => graph.accessors(addr),
            };
            for taker in takers.into_iter().filter(|&taker| is_entry(taker)) {
                members.insert(taker);
                next.push(taker);
            }
        }
        next.sort_unstable();
        next.dedup();
        due = next;
    }
    (members, live.into_keys().collect(), puts)
}

/// What a place holds as far as [`reach`] goes, where each of `values` is put there: an object,
/// or a vtable, of no vtable yet, where every value is one of the same kind or a null pointer.
fn kind(values: &[Value]) -> Value {
    let mut kind = Value::Unknown;
    for &value in values {
        let this = match value {
            Value::Constant(0) => continue,
            Value::Object(_) => Value::Object(NONE_YET),
            Value::Vtable(_) => Value::Vtable(NONE_YET),
            Value::Constant(_) | Value::Unknown => return Value::Unknown,
        };
        if kind != Value::Unknown && kind != this {
            return Value::Unknown;
        }
        kind = this;
    }
    kind
}

/// What the functions in `members` call through vtables, with what each place that `live` says
/// may hold an object holds worked out to a fixed point among them. Any other place holds
/// nothing known: `reach` found that what is put there with any place that may hold an object
/// holding one is not an object, or that a function outside the members puts something there.
fn solve(vtables: &mut Vtables, seeds: &FxHashMap<Key, Value>, bodies: &Bodies, members: &FxHashSet<u64>, live: &FxHashSet<Key>, mut puts: Puts, is_entry: &(impl Fn(u64) -> bool + Sync)) -> Vec<VirtualCall> {
    // What each place holds as last worked out. A place that may hold an object and is missing
    // here has had nothing put in it yet. `this` in a method that no direct call reaches is only
    // ever what its vtables say, so the first round need not start it from nothing and go round
    // again.
    let mut held: FxHashMap<Key, Value> = FxHashMap::default();
    for &key in live {
        if let Some(&seed) = seeds.get(&key)
            && puts.values(key).next().is_none()
        {
            held.insert(key, seed);
        }
    }
    let value = |held: &FxHashMap<Key, Value>, key: Key| match held.get(&key) {
        Some(&value) => value,
        None if live.contains(&key) => Value::Object(NONE_YET),
        None => Value::Unknown,
    };
    let mut touched: FxHashSet<Key> = live.clone();
    let mut due: Vec<u64> = members.iter().copied().collect();
    due.sort_unstable();
    let mut followed: FxHashMap<u64, Followed> = FxHashMap::default();
    while !due.is_empty() {
        let found: Vec<(u64, Followed)> = due.par_iter().map(|&start| (start, follow(vtables, &bodies.bodies[&start], |key| value(&held, key), is_entry))).collect();
        for (start, found) in found {
            puts.record(start, &found, &mut touched);
            // Only what it found and whether that used places with nothing in them yet are
            // needed again.
            followed.insert(start, Followed { puts: Vec::new(), takes: Vec::new(), ..found });
        }
        // A function goes round again where a place it takes from now holds something else,
        // unless that place held nothing yet and what it found did not depend on that.
        let mut next: Vec<u64> = Vec::new();
        for key in touched.drain().filter(|key| live.contains(key)) {
            let now = vtables.sets.join(&puts.values(key).chain(seeds.get(&key).copied()).collect::<Vec<_>>());
            let before = value(&held, key);
            if before == now {
                continue;
            }
            held.insert(key, now);
            let this = match key {
                Key::This(start) => Some(start).filter(|start| members.contains(start)),
                _ => None,
            };
            next.extend(puts.takers(key).iter().copied().chain(this).filter(|start| !none_yet(before) || followed[start].uses_none_yet));
        }
        next.sort_unstable();
        next.dedup();
        due = next;
    }
    let mut calls: Vec<VirtualCall> = followed.into_values().flat_map(|followed| followed.calls).collect();
    calls.sort_unstable_by_key(|call| call.at);
    calls.dedup_by_key(|call| call.at);
    calls
}
