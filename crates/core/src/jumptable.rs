//! Jump-table recovery for x86-64 switch dispatch.
//!
//! Position-independent x86-64 code dispatches a dense switch like this:
//!
//! ```text
//! cmp    idx, N            ; bounds check, absent when the range is proven
//! ja     default
//! lea    base, [rip+table] ; may be hoisted far above the dispatch
//! movsxd entry, [base+idx*4]
//! add    entry, base
//! jmp    entry
//! ```
//!
//! The table holds 4-byte signed offsets relative to its own address. `State` follows which
//! registers hold a table base, a bounded index, a loaded entry, or the final target. It is
//! carried along control-flow edges during discovery, so the pieces may sit in different blocks.

use rustc_hash::FxHashMap;

use iced_x86::{ConditionCode, Instruction, Mnemonic, OpKind, Register};

use crate::arch::{Limit, Table};
use crate::image::Image;

/// How many spilled values are tracked per path.
const SPILL_SLOTS: usize = 4;

/// What a register is known to hold.
#[derive(Clone, Copy, PartialEq, Debug, Default)]
enum Value {
    #[default]
    Unknown,
    /// Address of a jump table.
    Base(u64),
    /// An index proven to be at most this value by an unsigned bounds check.
    Bounded(u64),
    /// A sign-extended entry loaded from a table, with the limit on its index if known.
    /// `anchor` is the address the entry is an offset from: the table itself in GCC and Clang
    /// output, the image base in MSVC output.
    Entry { table: u64, anchor: u64, limit: Option<Limit> },
    /// Entry plus base: the jump target.
    Target { table: u64, anchor: u64, limit: Option<Limit> },
    /// An entry loaded through a base register whose value is not known. If the same register
    /// is then added to it, the register holds the image base: that is the only way MSVC forms
    /// a jump target, and it often sets the base far from the dispatch.
    BasedEntry { base_register: u8, table_offset: u64, limit: Option<Limit> },
    /// A `BasedEntry` plus its base register.
    BasedTarget { table_offset: u64, limit: Option<Limit> },
    /// A code pointer loaded from a table of absolute addresses, as computed goto uses.
    Pointer { table: u64, limit: Option<Limit> },
    /// A pointer loaded from the slot at this address.
    Slot(u64),
}

// A state is copied at every branch that is followed, so its size is part of the analysis time.
const _: () = assert!(size_of::<Value>() == 24);

/// Register contents relevant to jump tables at one program point.
#[derive(Clone, Copy, Default)]
pub struct State {
    registers: [Value; 16],
    /// Table values spilled to the stack, as `(offset from rsp, value)`.
    spills: [(u64, Value); SPILL_SLOTS],
    /// Register and immediate of a `cmp` whose flags the next instruction may branch on.
    compare: Option<(usize, u64)>,
}

fn index_of(register: Register) -> Option<usize> {
    let full = register.full_register();
    full.is_gpr64().then(|| full.number())
}

impl State {
    fn get(&self, register: Register) -> Value {
        index_of(register).map_or(Value::Unknown, |i| self.registers[i])
    }

    /// The slot `register` was loaded from, if it holds a pointer read from a fixed address.
    pub fn loaded_from(&self, register: Register) -> Option<u64> {
        match self.get(register) {
            Value::Slot(slot) => Some(slot),
            _ => None,
        }
    }

    fn clear(&mut self, registers: &[Register]) {
        for &register in registers {
            if let Some(i) = index_of(register) {
                self.registers[i] = Value::Unknown;
            }
        }
    }

    /// Updates the state for one instruction that falls through.
    /// `caller_saved` lists the registers a call may overwrite under the calling convention.
    pub fn step(&mut self, instr: &Instruction, caller_saved: &[Register]) {
        self.compare = None;
        let dest = (instr.op0_kind() == OpKind::Register).then(|| instr.op0_register());
        let source = (instr.op1_kind() == OpKind::Register).then(|| instr.op1_register());

        // Anything that moves the stack pointer shifts every spill offset.
        let moves_stack = matches!(instr.mnemonic(), Mnemonic::Push | Mnemonic::Pop)
            || dest.is_some_and(|d| d.full_register() == Register::RSP);
        if moves_stack {
            self.spills = Default::default();
        }
        if instr.mnemonic() == Mnemonic::Mov {
            if let (Some(offset), Some(source)) = (stack_slot(instr, 0), source) {
                self.spill(offset, self.get(source));
                return;
            }
            if let (Some(offset), Some(dest)) = (stack_slot(instr, 1), dest.and_then(index_of)) {
                self.registers[dest] = self.spilled(offset);
                return;
            }
        }

        let value = match instr.mnemonic() {
            Mnemonic::Cmp => {
                if let (Some(register), true) = (dest.and_then(index_of), is_immediate(instr.op1_kind())) {
                    self.compare = Some((register, instr.immediate(1)));
                }
                return;
            }
            Mnemonic::Test | Mnemonic::Push | Mnemonic::Bt | Mnemonic::Nop | Mnemonic::Endbr64 => return,
            Mnemonic::Lea if instr.is_ip_rel_memory_operand() => Value::Base(instr.ip_rel_memory_address()),
            // A 32-bit move zero-extends, which keeps an unsigned bound intact.
            Mnemonic::Mov if source.is_some() => source.map_or(Value::Unknown, |s| self.get(s)),
            // MSVC loads the 32-bit entry with a plain `mov`.
            Mnemonic::Mov if instr.op1_kind() == OpKind::Memory && instr.memory_index_scale() == 4 && instr.op0_register().is_gpr32() => {
                self.load(instr)
            }
            Mnemonic::Mov if instr.op1_kind() == OpKind::Memory && instr.memory_index_scale() == 8 => {
                match self.absolute_table(instr) {
                    Some(table) => Value::Pointer { table, limit: self.bound_of(instr.memory_index()) },
                    None => Value::Unknown,
                }
            }
            Mnemonic::Mov if instr.op1_kind() == OpKind::Memory && instr.is_ip_rel_memory_operand() && instr.op0_register().is_gpr64() => {
                Value::Slot(instr.ip_rel_memory_address())
            }
            Mnemonic::Movsxd if instr.op1_kind() == OpKind::Memory => self.load(instr),
            Mnemonic::Add => match (dest.map(|d| self.get(d)), source.map(|s| self.get(s))) {
                (Some(Value::BasedEntry { base_register, table_offset, limit }), _)
                    if source.and_then(index_of) == Some(usize::from(base_register)) =>
                {
                    Value::BasedTarget { table_offset, limit }
                }
                (Some(Value::Entry { table, anchor, limit }), Some(Value::Base(base)))
                | (Some(Value::Base(base)), Some(Value::Entry { table, anchor, limit }))
                    if anchor == base =>
                {
                    Value::Target { table, anchor, limit }
                }
                _ => Value::Unknown,
            },
            Mnemonic::Call => {
                self.clear(caller_saved);
                return;
            }
            Mnemonic::Mul | Mnemonic::Div | Mnemonic::Idiv | Mnemonic::Cdq | Mnemonic::Cqo | Mnemonic::Cwd | Mnemonic::Rdtsc => {
                self.clear(&[Register::RAX, Register::RDX]);
                Value::Unknown
            }
            Mnemonic::Imul if instr.op_count() == 1 => {
                self.clear(&[Register::RAX, Register::RDX]);
                Value::Unknown
            }
            Mnemonic::Cpuid | Mnemonic::Syscall => {
                self.clear(&[Register::RAX, Register::RBX, Register::RCX, Register::RDX, Register::R11]);
                Value::Unknown
            }
            Mnemonic::Xchg | Mnemonic::Xadd | Mnemonic::Cmpxchg => {
                self.clear(&[Register::RAX]);
                if let Some(source) = source {
                    self.clear(&[source]);
                }
                Value::Unknown
            }
            Mnemonic::Movsb | Mnemonic::Movsw | Mnemonic::Movsd | Mnemonic::Movsq | Mnemonic::Stosb | Mnemonic::Stosw
            | Mnemonic::Stosd | Mnemonic::Stosq | Mnemonic::Lodsb | Mnemonic::Lodsw | Mnemonic::Lodsd | Mnemonic::Lodsq
            | Mnemonic::Scasb | Mnemonic::Cmpsb
                if instr.op0_kind() != OpKind::Register =>
            {
                self.clear(&[Register::RAX, Register::RCX, Register::RSI, Register::RDI]);
                return;
            }
            _ => Value::Unknown,
        };
        if let Some(i) = dest.and_then(index_of) {
            self.registers[i] = value;
        }
    }

    /// The value produced by loading a 4-byte entry from `[base + index*4 + offset]`. With no
    /// offset the base is the table. With one, the base is the image base and the offset is
    /// the table's address relative to it, which is how MSVC addresses its tables.
    fn load(&self, instr: &Instruction) -> Value {
        if instr.memory_index_scale() != 4 || instr.memory_index() == Register::None {
            return Value::Unknown;
        }
        match self.get(instr.memory_base()) {
            Value::Base(anchor) => {
                let limit = self.bound_of(instr.memory_index());
                Value::Entry { table: anchor.wrapping_add(instr.memory_displacement64()), anchor, limit }
            }
            // An unknown base with a non-zero offset: possibly the image base.
            _ => match (index_of(instr.memory_base()), instr.memory_displacement64()) {
                (Some(base_register), table_offset) if table_offset != 0 => {
                    Value::BasedEntry { base_register: base_register as u8, table_offset, limit: self.bound_of(instr.memory_index()) }
                }
                _ => Value::Unknown,
            },
        }
    }

    /// Remembers a table value stored to the stack, or forgets the slot if it is overwritten
    /// with anything else.
    fn spill(&mut self, offset: u64, value: Value) {
        let keep = matches!(
            value,
            Value::Base(_) | Value::Entry { .. } | Value::Target { .. } | Value::BasedTarget { .. } | Value::Pointer { .. }
        );
        match (self.spills.iter().position(|(at, v)| *at == offset && *v != Value::Unknown), keep) {
            (Some(slot), _) => self.spills[slot] = (offset, value),
            (None, true) => {
                self.spills.rotate_right(1);
                self.spills[0] = (offset, value);
            }
            (None, false) => {}
        }
    }

    fn spilled(&self, offset: u64) -> Value {
        self.spills.iter().find(|(at, _)| *at == offset).map_or(Value::Unknown, |&(_, value)| value)
    }

    /// The base and address of a `[base + index + offset]` operand whose base register holds a
    /// known address: how MSVC reaches its jump tables and the byte tables that index them.
    pub fn based_address(&self, instr: &Instruction) -> Option<(u64, u64)> {
        if instr.memory_displacement64() == 0 {
            return None;
        }
        // Unscaled, the two registers of the operand are interchangeable, and the compiler
        // puts the base in either place.
        let unscaled = (instr.memory_index_scale() == 1).then(|| instr.memory_index());
        let based = std::iter::once(instr.memory_base()).chain(unscaled).find_map(|register| match self.get(register) {
            Value::Base(base) => Some((base, base.wrapping_add(instr.memory_displacement64()))),
            _ => None,
        });
        // Asked last: few registers hold a base, and going through the operands costs more.
        based.filter(|_| instr.op_kinds().any(|kind| kind == OpKind::Memory))
    }

    /// How many entries an index register can reach, when a bounds check established that.
    fn bound_of(&self, index: Register) -> Option<Limit> {
        match self.get(index) {
            Value::Bounded(max) => Some(Limit::of(max)),
            _ => None,
        }
    }

    /// The table address in a `[base + index*8]` operand whose base register holds one.
    fn absolute_table(&self, instr: &Instruction) -> Option<u64> {
        if instr.memory_index() == Register::None || instr.memory_displacement64() != 0 {
            return None;
        }
        match self.get(instr.memory_base()) {
            Value::Base(table) => Some(table),
            _ => None,
        }
    }

    /// States on the two edges of a conditional branch: `(taken, not taken)`. An unsigned
    /// compare against an immediate bounds the compared register on one of them.
    pub fn branch(&mut self, instr: &Instruction) -> State {
        let compare = self.compare.take();
        let mut taken = *self;
        if let Some((register, immediate)) = compare {
            match instr.condition_code() {
                // `ja default`: falling through means index <= immediate.
                ConditionCode::a => self.registers[register] = Value::Bounded(immediate),
                // `jae default`: falling through means index < immediate.
                ConditionCode::ae if immediate > 0 => self.registers[register] = Value::Bounded(immediate - 1),
                ConditionCode::be => taken.registers[register] = Value::Bounded(immediate),
                ConditionCode::b if immediate > 0 => taken.registers[register] = Value::Bounded(immediate - 1),
                _ => {}
            }
        }
        taken
    }

    /// The state at a case target: everything survives the jump except the target register.
    /// A table base hoisted into a callee-saved register stays valid across cases, which is how
    /// interpreter loops reuse one base for many dispatches.
    pub fn after_jump(mut self, jump: &Instruction) -> State {
        self.compare = None;
        if jump.op0_kind() == OpKind::Register {
            self.clear(&[jump.op0_register()]);
        }
        self
    }

    /// Reads the table behind an indirect jump, if the state identifies one. `pointer_slots`
    /// maps data slots holding relocated pointers to their targets, and `is_target` says whether
    /// an address can be a case target of this jump.
    pub fn resolve(
        &self,
        image: &Image,
        pointer_slots: &FxHashMap<u64, u64>,
        jump: &Instruction,
        is_target: &dyn Fn(u64) -> bool,
        is_code: &dyn Fn(u64) -> bool,
        pointer_size: u64,
    ) -> Option<Table> {
        let value = match jump.op0_kind() {
            OpKind::Register => self.get(jump.op0_register()),
            // `jmp [index*4 + table]`: 32-bit code indexes a table of absolute addresses that
            // sits at a fixed address, usually right after the function.
            OpKind::Memory
                if jump.memory_base() == Register::None
                    && jump.memory_index() != Register::None
                    && u64::from(jump.memory_index_scale()) == pointer_size
                    && jump.memory_displacement64() != 0 =>
            {
                Value::Pointer { table: jump.memory_displacement64(), limit: self.bound_of(jump.memory_index()) }
            }
            // `jmp [base + index*8]` dispatches through absolute pointers directly.
            OpKind::Memory if stack_slot(jump, 0).is_some() => stack_slot(jump, 0).map_or(Value::Unknown, |at| self.spilled(at)),
            OpKind::Memory if jump.memory_index_scale() == 8 => {
                self.absolute_table(jump)
                    .map_or(Value::Unknown, |table| Value::Pointer { table, limit: self.bound_of(jump.memory_index()) })
            }
            _ => Value::Unknown,
        };
        match value {
            // Only images that have a base to be relative to.
            Value::BasedTarget { table_offset, limit } if image.base != 0 => {
                read_relative(image, image.base.wrapping_add(table_offset), image.base, limit, is_target)
            }
            Value::Target { table, anchor, limit } => {
                read_relative(image, table, anchor, limit, if limit.is_some() { is_code } else { is_target })
            }
            Value::Pointer { table, limit: bound } => {
                // Without a bounds check, the table runs for as long as consecutive slots hold
                // relocated code pointers.
                let limit = Limit::entries(bound);
                let entries: Vec<u64> = (0..limit as u64)
                    .map_while(|i| pointer_slots.get(&(table + pointer_size * i)).copied())
                    .take_while(|&target| if bound.is_some() { is_code(target) } else { is_target(target) })
                    .collect();
                // A bounded table that stops short was misread.
                let complete = bound.is_none() || entries.len() == limit;
                (!entries.is_empty() && complete).then_some(Table {
                    address: table,
                    entry_size: pointer_size,
                    entries,
                    bounded: bound.is_some(),
                })
            }
            _ => None,
        }
    }
}

/// Reads a table of 4-byte offsets relative to `anchor`.
fn read_relative(image: &Image, table: u64, anchor: u64, limit: Option<Limit>, is_target: &dyn Fn(u64) -> bool) -> Option<Table> {
    let bytes = image.bytes_from(table)?;
    let mut entries = Vec::new();
    for entry in bytes.chunks_exact(4).take(Limit::entries(limit)) {
        let offset = i32::from_le_bytes(entry.try_into().unwrap());
        let target = anchor.wrapping_add_signed(offset as i64);
        if !is_target(target) {
            // A bounded table with an impossible entry is a misread, not a short table.
            if limit.is_some() {
                return None;
            }
            break;
        }
        entries.push(target);
    }
    (!entries.is_empty()).then_some(Table { address: table, entry_size: 4, entries, bounded: limit.is_some() })
}

/// The offset of a plain `[rsp + disp]` memory operand in position `operand`.
fn stack_slot(instr: &Instruction, operand: u32) -> Option<u64> {
    (instr.op_kind(operand) == OpKind::Memory && instr.memory_base() == Register::RSP && instr.memory_index() == Register::None)
        .then(|| instr.memory_displacement64())
}

fn is_immediate(kind: OpKind) -> bool {
    matches!(
        kind,
        OpKind::Immediate8
            | OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate64
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate32to64
    )
}
