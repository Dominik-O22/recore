//! The architecture-specific parts of analysis: decoding, control-flow classification, and the
//! register tracking that resolves jump tables. Discovery and analysis are written once against
//! this trait.

use std::num::NonZeroU16;

use rustc_hash::FxHashMap;

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

/// What an instruction does with memory it reaches at an offset from a register.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FieldUse {
    Read,
    Write,
    /// It forms the address and neither reads nor writes there.
    Address,
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

/// An address the code may be forming of text that lies among the code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct TextPointer {
    /// The instruction that completes the address.
    pub from: u64,
    pub to: u64,
    /// The code also says that the address is one in the code space: it reads from there, or
    /// passes the address on with the mark its compiler gives a pointer to code. An address
    /// without that is two numbers that may mean anything.
    pub marked: bool,
}

/// Upper bound on the entries read from one table.
pub const MAX_ENTRIES: usize = 4096;

/// How many entries of a table a bounds check on its index allows, at most [`MAX_ENTRIES`].
/// Two bytes, because every tracked register carries one along every path that is followed.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Limit(NonZeroU16);

impl Limit {
    /// For an index proven to be at most `max_index`.
    pub fn of(max_index: u64) -> Limit {
        let entries = (max_index as usize).saturating_add(1).min(MAX_ENTRIES);
        Limit(NonZeroU16::new(entries as u16).expect("at least one entry"))
    }

    /// How many entries to read: `limit`'s, or as many as any table may have.
    pub fn entries(limit: Option<Limit>) -> usize {
        limit.map_or(MAX_ENTRIES, |limit| usize::from(limit.0.get()))
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
    /// For a table that lies in the code straight after its jump: the address after its last
    /// byte, where the code goes on. Nothing from `address` to there is an instruction.
    pub inline_end: Option<u64>,
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

    /// Whether code embeds absolute addresses that the loader relocates. If so, a value only
    /// counts as an address when some relocation carries it, which rules out constants that
    /// merely look like one.
    const ADDRESSES_ARE_RELOCATED: bool = false;

    /// Whether a function may run on into the one after it, which then returns for both: how
    /// hand-written code and code a linker has factored share their endings. Elsewhere code
    /// that runs off the end of its function is code that never returns.
    const RUNS_ON: bool = false;

    /// Whether unreached code counts as functions on the strength of dividing into them with
    /// nothing left over, for a machine whose code shows no other sign of where one starts:
    /// no alignment, no padding between functions, no common opening.
    const TILES_GAPS: bool = false;

    /// Whether the program keeps its text among the code, as a machine does whose code space
    /// is the only memory that holds anything when it starts.
    const TEXT_IN_CODE: bool = false;

    /// Whether [`Arch::flow`] reads the state: whether what a call or jump goes through can
    /// depend on earlier instructions. A pass that only classifies control flow need not
    /// track registers where it cannot.
    const FLOW_READS_STATE: bool = true;

    /// Decodes consecutive instructions from `bytes`, which are loaded at `addr`.
    fn decode(bytes: &[u8], addr: u64) -> impl Iterator<Item = Decoded<Self::Insn>>;

    /// A decoder over a whole section, for decoding from many places in it: moving one is
    /// cheaper than making one. It holds the instruction it decoded last and lends it out, so
    /// that no instruction is copied on its way to whoever reads it.
    type Decoder<'a>;

    /// A decoder over `bytes`, which are loaded at `addr`.
    fn decoder(bytes: &[u8], addr: u64) -> Self::Decoder<'_>;

    /// Moves the decoder to `offset` into its bytes.
    fn seek(decoder: &mut Self::Decoder<'_>, offset: usize);

    /// Decodes the instruction the decoder is at and moves past it. `None` at the end of the
    /// bytes.
    fn decode_next<'d>(decoder: &'d mut Self::Decoder<'_>) -> Option<Decoded<&'d Self::Insn>>;

    /// The control-flow effect of `insn`, given the state before it. The image says where a
    /// target really lies when the instruction alone does not, as in banked code.
    fn flow(insn: &Self::Insn, state: &Self::State, image: &Image) -> Option<Flow>;

    /// The address `insn` materialises in a register, if it computes one: how code takes the
    /// address of a function or of data.
    fn address_taken(insn: &Self::Insn, state: &Self::State) -> Option<u64>;

    /// Data that `insn` reads at an offset from a base register whose value is tracked, as
    /// `(base, address)`. When the base is the image base this is how a table is reached, which
    /// tells where the table before it ends. Never treated as code.
    fn based_data_address(_insn: &Self::Insn, _state: &Self::State) -> Option<(u64, u64)> {
        None
    }

    /// The fixed address of data `insn` reads or writes, as opposed to taking its address: a
    /// global variable or a constant table. The address is in the instruction itself, or is
    /// an offset from a register whose value the state knows.
    fn memory_reference(_insn: &Self::Insn, _state: &Self::State) -> Option<u64> {
        None
    }

    /// The address `insn` forms by adding to a complete address a register holds: a place
    /// further into an object, such as a field or an element. Unlike [`Arch::address_taken`]
    /// this says nothing about code: the sum of a function's address and a number is not
    /// where another function starts.
    fn offset_address(_insn: &Self::Insn, _state: &Self::State) -> Option<u64> {
        None
    }

    /// Data that `insn` reaches through a pointer the state knows was loaded from a fixed slot,
    /// such as a global offset table entry: `(slot, offset from the pointer, whether the data
    /// is read or written)`. With the pointer the loader puts in the slot, that is a reference
    /// to a global of another module or of this one.
    fn through_pointer(_insn: &Self::Insn, _state: &Self::State) -> Option<(u64, u64, bool)> {
        None
    }

    /// The slot the register of the first (`index` 0) or second argument was loaded from, when
    /// the state knows. At an Objective-C message send the first holds the receiver, which is a
    /// class when the slot is a class reference, and the second holds the selector.
    fn argument_slot(_state: &Self::State, _index: usize) -> Option<u64> {
        None
    }

    /// The number another pass gave what the register of the first (`index` 0) or second
    /// argument holds, with [`Arch::set_argument_object`] or [`Arch::set_result_object`], when
    /// the value has only been moved since: between registers, or to the stack and back.
    fn argument_object(_state: &Self::State, _index: usize) -> Option<u32> {
        None
    }

    /// Says what the register of argument `index` holds, by a number of the caller's choosing:
    /// how the Objective-C pass follows a class or an object from where it is made to where a
    /// message is sent to it.
    fn set_argument_object(_state: &mut Self::State, _index: usize, _object: u32) {}

    /// [`Arch::step`] for the pass that follows objects, which may take more care that an
    /// instruction which leaves a register alone leaves the object in it known.
    fn step_following(state: &mut Self::State, insn: &Self::Insn) {
        Self::step(state, insn);
    }

    /// Says what the register Swift passes `self` to a method in holds, at the method's entry.
    fn set_self_object(_state: &mut Self::State, _object: u32) {}

    /// Says what the register a call returns its result in holds, after the call.
    fn set_result_object(_state: &mut Self::State, _object: u32) {}

    /// Filler the toolchain inserts between functions.
    fn is_padding(insn: &Self::Insn) -> bool;

    /// An instruction compilers place at entry points that can be reached indirectly, such as
    /// `endbr64` or `bti c`.
    fn is_entry_marker(insn: &Self::Insn) -> bool;

    /// Whether two consecutive instructions look like the opening of a function: setting up a
    /// frame or saving registers. Used where neither alignment nor padding settles it.
    fn opens_function(_first: &Self::Insn, _second: Option<&Self::Insn>) -> bool {
        false
    }

    /// Whether code beginning with `insns` uses a stack frame it did not set up, which marks a
    /// block inside a function, such as an exception filter or handler, and not a function.
    fn borrows_frame(_insns: &[Self::Insn]) -> bool {
        false
    }

    /// Whether a short function beginning with `insns` is the compiler's stack-cookie check,
    /// which every protected function calls just before it returns.
    fn checks_stack_cookie(_insns: &[Self::Insn]) -> bool {
        false
    }

    /// The register argument `insn` writes, by its position among the arguments, and the address
    /// it puts there when it puts a fixed one: how a call's string arguments are told before
    /// the function is decompiled.
    fn argument_write(_insn: &Self::Insn) -> Option<(usize, Option<u64>)> {
        None
    }

    /// Whether a function beginning with `insns` sets up to read a variable number of
    /// arguments: it saves the registers arguments arrive in where `va_arg` will look for them.
    fn takes_variable_arguments(_insns: &[Self::Insn]) -> bool {
        false
    }

    /// The offset at which `insn` reaches memory from a register that is not the stack's, and
    /// what it does there: how code uses a field of the structure the register points to.
    fn field_use(_insn: &Self::Insn) -> Option<(u64, FieldUse)> {
        None
    }

    /// The addresses the code in `[start, end)` may be forming of text that lies among the code.
    /// Nothing but the text itself says that such an address is one, so each is only a
    /// candidate until text is found there.
    fn text_pointers(_image: &Image, _start: u64, _end: u64) -> Vec<TextPointer> {
        Vec::new()
    }

    /// Whether the first real instruction of a block shows it is an exception landing pad.
    fn opens_landing_pad(insn: &Self::Insn) -> bool;

    /// Updates `state` for an instruction that falls through.
    fn step(state: &mut Self::State, insn: &Self::Insn);

    /// Splits the state at a conditional branch: returns the state on the taken edge and leaves
    /// `state` as it is when the branch is not taken.
    fn branch(state: &mut Self::State, insn: &Self::Insn) -> Self::State;

    /// The state at the targets of an indirect jump.
    fn after_jump(state: Self::State, jump: &Self::Insn) -> Self::State;

    /// Reads the table behind an indirect jump, if the state identifies one. `pointer_slots`
    /// maps data slots holding relocated pointers to their targets. `is_target` says whether an
    /// address is a likely case target of this jump, which ends a table of unknown length;
    /// `is_code` only says whether it is code at all, which is all a table of known length
    /// needs, since its cases may sit in cold code far from the function.
    fn resolve_table(
        state: &Self::State,
        image: &Image,
        pointer_slots: &FxHashMap<u64, u64>,
        jump: &Self::Insn,
        is_target: &dyn Fn(u64) -> bool,
        is_code: &dyn Fn(u64) -> bool,
    ) -> Option<Table>;

    /// Whether the code at `target` is marked as reachable by an indirect jump, when the image is
    /// built so that every such target carries a marker. `None` when the image has no such marking,
    /// so nothing can be concluded.
    fn marked_jump_target(_image: &Image, _target: u64) -> Option<bool> {
        None
    }

    /// Maps each PLT stub's address to the slot it jumps through.
    fn plt_stubs(image: &Image) -> FxHashMap<u64, u64>;
}
