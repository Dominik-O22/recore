//! The architecture-specific parts of analysis: decoding, control-flow classification, and the
//! register tracking that resolves jump tables. Discovery and analysis are written once against
//! this trait.

use std::collections::HashMap;

use crate::image::Image;

/// What a control-flow instruction does. Instructions that only fall through have no `Flow`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Flow {
    Call(u64),
    /// Call through a pointer, with the address of the slot holding it when that is known.
    CallIndirect(Option<u64>),
    Jump(u64),
    Branch(u64),
    /// Jump through a pointer, with the address of the slot holding it when that is known.
    JumpIndirect(Option<u64>),
    Return,
    /// A trap or halt: execution does not continue.
    Halt,
}

/// One decoding step: the bytes at `addr` either form an instruction or do not.
pub struct Decoded<I> {
    pub addr: u64,
    pub len: u8,
    /// `None` when the bytes are not a valid instruction.
    pub insn: Option<I>,
}

impl<I> Decoded<I> {
    pub fn next_addr(&self) -> u64 {
        self.addr + u64::from(self.len)
    }
}

/// A jump table as read from the image.
pub struct Table {
    pub address: u64,
    /// Size of one entry in bytes.
    pub entry_size: u64,
    /// Targets in table order, one per entry.
    pub entries: Vec<u64>,
    /// Whether the entry count is known. Otherwise `entries` runs to the first value that is not
    /// a plausible target and may overshoot into the next table.
    pub bounded: bool,
}

pub trait Arch: 'static {
    type Insn: Copy;
    /// Register contents tracked along control-flow edges to resolve jump tables and address
    /// computations that span several instructions.
    type State: Copy + Default + Send + Sync;

    /// Usual alignment of function entry points in optimised compiler output.
    const FUNCTION_ALIGN: u64;

    /// Whether that alignment is coarser than a single instruction, so that unreferenced code
    /// sitting on an aligned address is likelier to be a function than a block inside one.
    const ALIGNMENT_IS_EVIDENCE: bool;

    /// Decodes consecutive instructions from `bytes`, which are loaded at `addr`.
    fn decode(bytes: &[u8], addr: u64) -> impl Iterator<Item = Decoded<Self::Insn>>;

    /// The control-flow effect of `insn`, given the state before it.
    fn flow(insn: &Self::Insn, state: &Self::State) -> Option<Flow>;

    /// The address `insn` materialises in a register, if it computes one: how code takes the
    /// address of a function or of data.
    fn address_taken(insn: &Self::Insn, state: &Self::State) -> Option<u64>;

    /// Filler the toolchain inserts between functions.
    fn is_padding(insn: &Self::Insn) -> bool;

    /// An instruction compilers place at entry points that can be reached indirectly, such as
    /// `endbr64` or `bti c`.
    fn is_entry_marker(insn: &Self::Insn) -> bool;

    /// Whether the first real instruction of a block shows it is an exception landing pad.
    fn opens_landing_pad(insn: &Self::Insn) -> bool;

    /// Updates `state` for an instruction that falls through.
    fn step(state: &mut Self::State, insn: &Self::Insn);

    /// States on the two edges of a conditional branch: `(taken, not taken)`.
    fn branch(state: Self::State, insn: &Self::Insn) -> (Self::State, Self::State);

    /// The state at the targets of an indirect jump.
    fn after_jump(state: Self::State, jump: &Self::Insn) -> Self::State;

    /// Reads the table behind an indirect jump, if the state identifies one. `pointer_slots`
    /// maps data slots holding relocated pointers to their targets, and `is_target` says whether
    /// an address can be a case target of this jump.
    fn resolve_table(
        state: &Self::State,
        image: &Image,
        pointer_slots: &HashMap<u64, u64>,
        jump: &Self::Insn,
        is_target: &dyn Fn(u64) -> bool,
    ) -> Option<Table>;

    /// Whether the code at `target` is marked as reachable by an indirect jump, when the image is
    /// built so that every such target carries a marker. `None` when the image has no such marking,
    /// so nothing can be concluded.
    fn marked_jump_target(_image: &Image, _target: u64) -> Option<bool> {
        None
    }

    /// Maps each PLT stub's address to the slot it jumps through.
    fn plt_stubs(image: &Image) -> HashMap<u64, u64>;
}
