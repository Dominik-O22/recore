//! x86 support, 64-bit and 32-bit, on top of the iced decoder.

use rustc_hash::FxHashMap;

use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic, OpKind, Register};

use crate::arch::{Arch, Decoded, Flow, Table};
use crate::image::{Format, Image};
use crate::jumptable::State;

/// x86 in 64-bit or 32-bit mode, under the Windows or the System V calling convention.
///
/// The modes differ in how code refers to addresses: 64-bit code is RIP-relative, 32-bit code
/// embeds absolute addresses that the loader relocates. The conventions differ in which
/// registers survive a call, which decides whether a table base set before a call is still
/// there after it.
pub struct X86<const BITS: u32, const WINDOWS: bool>;

impl<const BITS: u32, const WINDOWS: bool> X86<BITS, WINDOWS> {
    /// Registers a call may overwrite.
    const CALLER_SAVED: &'static [Register] = match (BITS, WINDOWS) {
        (32, _) => &[Register::RAX, Register::RCX, Register::RDX],
        (_, true) => &[Register::RAX, Register::RCX, Register::RDX, Register::R8, Register::R9, Register::R10, Register::R11],
        (_, false) => &[
            Register::RAX,
            Register::RCX,
            Register::RDX,
            Register::RSI,
            Register::RDI,
            Register::R8,
            Register::R9,
            Register::R10,
            Register::R11,
        ],
    };
}

impl<const BITS: u32, const WINDOWS: bool> Arch for X86<BITS, WINDOWS> {
    type Insn = Instruction;
    type State = State;

    /// GCC, Clang and rustc all align functions to 16 bytes at `-O2`.
    const FUNCTION_ALIGN: u64 = 16;
    const ALIGNMENT_IS_EVIDENCE: bool = true;
    const ADDRESSES_ARE_RELOCATED: bool = BITS == 32;

    fn decode(bytes: &[u8], addr: u64) -> impl Iterator<Item = Decoded<Instruction>> {
        let mut decoder = Decoder::with_ip(BITS, bytes, addr, DecoderOptions::NONE);
        std::iter::from_fn(move || {
            decoder.can_decode().then(|| {
                let instr = decoder.decode();
                Decoded { addr: instr.ip(), len: instr.len().max(1) as u8, insn: (!instr.is_invalid()).then_some(instr) }
            })
        })
    }

    type Decoder<'a> = (Decoder<'a>, u64);

    fn decoder(bytes: &[u8], addr: u64) -> Self::Decoder<'_> {
        (Decoder::with_ip(BITS, bytes, addr, DecoderOptions::NONE), addr)
    }

    fn decode_from<'d>((decoder, base): &'d mut Self::Decoder<'_>, offset: usize) -> impl Iterator<Item = Decoded<Instruction>> + 'd {
        decoder.set_position(offset).expect("an offset into the section");
        decoder.set_ip(*base + offset as u64);
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
        if BITS == 64 { lea_target(insn) } else { immediate_address(insn) }
    }

    fn based_data_address(insn: &Instruction, state: &State) -> Option<(u64, u64)> {
        state.based_address(insn)
    }

    /// A RIP-relative operand in 64-bit code; in 32-bit code a displacement, which the caller
    /// checks against relocations since any constant offset looks the same.
    fn memory_reference(insn: &Instruction) -> Option<u64> {
        if !insn.op_kinds().any(|kind| kind == OpKind::Memory) || insn.mnemonic() == Mnemonic::Lea {
            return None;
        }
        if insn.is_ip_rel_memory_operand() {
            return Some(insn.ip_rel_memory_address());
        }
        (BITS == 32 && insn.memory_displacement64() != 0).then(|| insn.memory_displacement64())
    }

    fn second_argument_slot(state: &State) -> Option<u64> {
        state.loaded_from(if WINDOWS { Register::RDX } else { Register::RSI })
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

    fn opens_function(first: &Instruction, second: Option<&Instruction>) -> bool {
        opens_function(first, second)
    }

    /// The frame pointer is callee-saved, so a function must save it and set it before
    /// addressing anything through it. Code that reads through it straight away is running in
    /// some other function's frame.
    fn borrows_frame(insns: &[Instruction]) -> bool {
        for instr in insns {
            if instr.op_kinds().any(|kind| kind == OpKind::Memory) && instr.memory_base().full_register() == Register::RBP {
                return true;
            }
            let writes_frame_pointer = instr.op0_kind() == OpKind::Register
                && instr.op0_register().full_register() == Register::RBP
                && !matches!(instr.mnemonic(), Mnemonic::Push | Mnemonic::Cmp | Mnemonic::Test);
            // Any control flow, or saving the frame pointer, ends the part worth judging.
            if writes_frame_pointer || instr.mnemonic() == Mnemonic::Push || instr.flow_control() != FlowControl::Next {
                return false;
            }
        }
        false
    }

    /// MSVC's `__security_check_cookie`: compare the cookie passed in `ecx` or `rcx` with the
    /// global one, and leave for the failure report if they differ.
    fn checks_stack_cookie(insns: &[Instruction]) -> bool {
        let [first, second, ..] = insns else { return false };
        let compares_global = first.mnemonic() == Mnemonic::Cmp
            && first.op0_kind() == OpKind::Register
            && first.op0_register().full_register() == Register::RCX
            && first.op1_kind() == OpKind::Memory
            && (first.is_ip_rel_memory_operand() || (first.memory_base() == Register::None && first.memory_index() == Register::None));
        compares_global && second.mnemonic() == Mnemonic::Jne
    }

    fn step(state: &mut State, insn: &Instruction) {
        state.step(insn, Self::CALLER_SAVED);
    }

    fn branch(state: &mut State, insn: &Instruction) -> State {
        state.branch(insn)
    }

    fn after_jump(state: State, jump: &Instruction) -> State {
        state.after_jump(jump)
    }

    fn resolve_table(
        state: &State,
        image: &Image,
        pointer_slots: &FxHashMap<u64, u64>,
        jump: &Instruction,
        is_target: &dyn Fn(u64) -> bool,
        is_code: &dyn Fn(u64) -> bool,
    ) -> Option<Table> {
        state.resolve(image, pointer_slots, jump, is_target, is_code, u64::from(BITS / 8))
    }

    fn plt_stubs(image: &Image) -> FxHashMap<u64, u64> {
        let mut stubs = FxHashMap::default();
        for section in image.sections.iter().filter(|s| s.is_stubs()) {
            let mut stub_start = section.addr;
            for decoded in Self::decode(&section.data, section.addr) {
                let flow = decoded.insn.as_ref().and_then(classify);
                if let Some(Flow::JumpIndirect(Some(slot))) = flow {
                    if image.import_slots.contains_key(&slot) {
                        stubs.insert(stub_start, slot);
                    }
                }
                // ELF pads stubs to 16 bytes, so the next one starts at the next boundary.
                // Mach-O packs them, each ending with its jump.
                let ends_stub = image.format == Format::MachO && matches!(flow, Some(Flow::Jump(_) | Flow::JumpIndirect(_)));
                if ends_stub || decoded.next_addr() % 16 == 0 {
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
        // `int3`, and `int 0x29`, which is how Windows code fails fast.
        FlowControl::Interrupt => {
            (instr.mnemonic() == Mnemonic::Int3 || (instr.mnemonic() == Mnemonic::Int && instr.immediate8() == 0x29)).then_some(Flow::Halt)
        }
    }
}

/// The address of the memory slot an indirect call or jump reads its target from, when the
/// operand names one outright: RIP-relative in 64-bit code, a bare absolute address in 32-bit.
fn rip_slot(instr: &Instruction) -> Option<u64> {
    if instr.is_ip_rel_memory_operand() {
        return Some(instr.ip_rel_memory_address());
    }
    let absolute = instr.op0_kind() == OpKind::Memory
        && instr.memory_base() == Register::None
        && instr.memory_index() == Register::None
        && instr.code_size() == iced_x86::CodeSize::Code32;
    absolute.then(|| instr.memory_displacement64())
}

/// The 32-bit immediate of `push imm32` or `mov dest, imm32`, which is how 32-bit code takes
/// an address. Whether it really is an address is for the caller to check against relocations.
fn immediate_address(instr: &Instruction) -> Option<u64> {
    let operand = match instr.mnemonic() {
        Mnemonic::Push => 0,
        Mnemonic::Mov => 1,
        _ => return None,
    };
    (instr.op_kind(operand) == OpKind::Immediate32).then(|| u64::from(instr.immediate32()))
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

/// The usual ways compiled x86 functions begin: `push ebp; mov ebp, esp`, the hot-patch
/// `mov edi, edi`, reserving stack with `sub esp, N`, or saving callee-saved registers.
fn opens_function(first: &Instruction, second: Option<&Instruction>) -> bool {
    let register = |instr: &Instruction, operand: u32| {
        (instr.op_kind(operand) == OpKind::Register).then(|| instr.op_register(operand).full_register())
    };
    let is_callee_saved = |reg: Option<Register>| matches!(reg, Some(Register::RBX | Register::RSI | Register::RDI | Register::RBP));
    let reserves_stack = |instr: &Instruction| instr.mnemonic() == Mnemonic::Sub && register(instr, 0) == Some(Register::RSP);
    let saves = |instr: &Instruction| instr.mnemonic() == Mnemonic::Push && is_callee_saved(register(instr, 0));

    match first.mnemonic() {
        Mnemonic::Mov => register(first, 0) == Some(Register::RDI) && register(first, 1) == Some(Register::RDI),
        Mnemonic::Sub => reserves_stack(first),
        Mnemonic::Push if register(first, 0) == Some(Register::RBP) => second.is_some_and(|next| {
            next.mnemonic() == Mnemonic::Mov && register(next, 0) == Some(Register::RBP) && register(next, 1) == Some(Register::RSP)
        }),
        Mnemonic::Push if saves(first) => second.is_some_and(|next| saves(next) || reserves_stack(next)),
        _ => false,
    }
}
