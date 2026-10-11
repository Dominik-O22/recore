//! x86-64 instruction classification on top of the iced decoder.

use iced_x86::{FlowControl, Instruction, Mnemonic, OpKind, Register};

/// What a control-flow instruction does. Instructions that only fall through have no `Flow`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Flow {
    Call(u64),
    /// Call through a memory slot, with the slot address when it is RIP-relative.
    CallIndirect(Option<u64>),
    Jump(u64),
    Branch(u64),
    JumpIndirect(Option<u64>),
    Return,
    /// `ud2`, `int3`, `hlt`: execution does not continue.
    Halt,
}

pub fn classify(instr: &Instruction) -> Option<Flow> {
    match instr.flow_control() {
        FlowControl::Next | FlowControl::XbeginXabortXend => (instr.mnemonic() == Mnemonic::Hlt).then_some(Flow::Halt),
        FlowControl::UnconditionalBranch => Some(Flow::Jump(instr.near_branch_target())),
        FlowControl::ConditionalBranch => Some(Flow::Branch(instr.near_branch_target())),
        FlowControl::IndirectBranch => Some(Flow::JumpIndirect(rip_slot(instr))),
        FlowControl::Call => match instr.mnemonic() {
            Mnemonic::Syscall | Mnemonic::Sysenter => None,
            _ => Some(Flow::Call(instr.near_branch_target())),
        },
        FlowControl::IndirectCall => Some(Flow::CallIndirect(rip_slot(instr))),
        FlowControl::Return => Some(Flow::Return),
        FlowControl::Exception => Some(Flow::Halt),
        FlowControl::Interrupt => (instr.mnemonic() == Mnemonic::Int3).then_some(Flow::Halt),
    }
}

fn rip_slot(instr: &Instruction) -> Option<u64> {
    instr.is_ip_rel_memory_operand().then(|| instr.ip_rel_memory_address())
}

/// The address a `lea reg, [rip+disp]` computes, which is how position-independent code takes
/// the address of a function or of data.
pub fn lea_target(instr: &Instruction) -> Option<u64> {
    (instr.mnemonic() == Mnemonic::Lea && instr.is_ip_rel_memory_operand()).then(|| instr.ip_rel_memory_address())
}

/// Bytes the compiler or linker inserts between functions: `int3`, and every form of `nop`.
pub fn is_padding(instr: &Instruction) -> bool {
    match instr.mnemonic() {
        Mnemonic::Nop | Mnemonic::Int3 => true,
        // `xchg ax, ax` is the two-byte nop.
        Mnemonic::Xchg => instr.op0_kind() == OpKind::Register && instr.op0_register() == instr.op1_register(),
        // `lea rsi, [rsi+0]` style fillers from older assemblers.
        Mnemonic::Lea => {
            instr.memory_displacement64() == 0
                && instr.memory_index() == Register::None
                && instr.memory_base() == instr.op0_register()
        }
        _ => false,
    }
}

/// `endbr64`, which CET-enabled compilers place at every indirectly callable entry point.
pub fn is_endbr(instr: &Instruction) -> bool {
    instr.mnemonic() == Mnemonic::Endbr64
}

/// Whether the instruction after an `endbr64` shows the pad is an exception landing pad and not
/// a function entry. The unwinder enters a landing pad with the exception object in `rax`, so
/// the pad reads `rax` or jumps straight to cleanup code; a function entry does neither, since
/// `rax` carries no argument.
pub fn opens_landing_pad(after_endbr: &Instruction) -> bool {
    let reads_rax = after_endbr.mnemonic() == Mnemonic::Mov
        && after_endbr.op1_kind() == OpKind::Register
        && after_endbr.op1_register().full_register() == Register::RAX;
    reads_rax || after_endbr.flow_control() == FlowControl::UnconditionalBranch
}
