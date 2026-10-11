//! x86-64 support on top of the iced decoder.

use std::collections::HashMap;

use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic, OpKind, Register};

use crate::arch::{Arch, Decoded, Flow, Table};
use crate::image::Image;
use crate::jumptable::State;

pub struct X86;

impl Arch for X86 {
    type Insn = Instruction;
    type State = State;

    /// GCC, Clang and rustc all align functions to 16 bytes at `-O2`.
    const FUNCTION_ALIGN: u64 = 16;

    fn decode(bytes: &[u8], addr: u64) -> impl Iterator<Item = Decoded<Instruction>> {
        let mut decoder = Decoder::with_ip(64, bytes, addr, DecoderOptions::NONE);
        std::iter::from_fn(move || {
            decoder.can_decode().then(|| {
                let instr = decoder.decode();
                Decoded { addr: instr.ip(), len: instr.len().max(1) as u8, insn: (!instr.is_invalid()).then_some(instr) }
            })
        })
    }

    fn flow(insn: &Instruction, _: &State) -> Option<Flow> {
        classify(insn)
    }

    fn address_taken(insn: &Instruction, _: &State) -> Option<u64> {
        lea_target(insn)
    }

    fn is_padding(insn: &Instruction) -> bool {
        is_padding(insn)
    }

    fn is_entry_marker(insn: &Instruction) -> bool {
        insn.mnemonic() == Mnemonic::Endbr64
    }

    fn opens_landing_pad(insn: &Instruction) -> bool {
        opens_landing_pad(insn)
    }

    fn step(state: &mut State, insn: &Instruction) {
        state.step(insn);
    }

    fn branch(state: State, insn: &Instruction) -> (State, State) {
        state.branch(insn)
    }

    fn after_jump(state: State, jump: &Instruction) -> State {
        state.after_jump(jump)
    }

    fn resolve_table(
        state: &State,
        image: &Image,
        pointer_slots: &HashMap<u64, u64>,
        jump: &Instruction,
        is_target: &dyn Fn(u64) -> bool,
    ) -> Option<Table> {
        state.resolve(image, pointer_slots, jump, is_target)
    }

    fn plt_stubs(image: &Image) -> HashMap<u64, u64> {
        let mut stubs = HashMap::new();
        for section in image.sections.iter().filter(|s| s.executable && s.name.starts_with(".plt")) {
            let mut stub_start = section.addr;
            for decoded in Self::decode(&section.data, section.addr) {
                if let Some(Flow::JumpIndirect(Some(slot))) = decoded.insn.as_ref().and_then(classify) {
                    if image.import_slots.contains_key(&slot) {
                        stubs.insert(stub_start, slot);
                    }
                }
                // Stubs are padded to 16 bytes; the next one starts at the next boundary.
                if decoded.next_addr() % 16 == 0 {
                    stub_start = decoded.next_addr();
                }
            }
        }
        stubs
    }
}

fn classify(instr: &Instruction) -> Option<Flow> {
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
fn lea_target(instr: &Instruction) -> Option<u64> {
    (instr.mnemonic() == Mnemonic::Lea && instr.is_ip_rel_memory_operand()).then(|| instr.ip_rel_memory_address())
}

/// Bytes the compiler or linker inserts between functions: `int3`, and every form of `nop`.
fn is_padding(instr: &Instruction) -> bool {
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

/// Whether the instruction after an `endbr64` shows the pad is an exception landing pad and not
/// a function entry. The unwinder enters a landing pad with the exception object in `rax`, so
/// the pad reads `rax` or jumps straight to cleanup code; a function entry does neither, since
/// `rax` carries no argument.
fn opens_landing_pad(after_endbr: &Instruction) -> bool {
    let reads_rax = after_endbr.mnemonic() == Mnemonic::Mov
        && after_endbr.op1_kind() == OpKind::Register
        && after_endbr.op1_register().full_register() == Register::RAX;
    reads_rax || after_endbr.flow_control() == FlowControl::UnconditionalBranch
}
