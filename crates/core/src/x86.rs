//! x86 support, 64-bit and 32-bit, on top of the iced decoder.

use rustc_hash::FxHashMap;

use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic, OpKind, Register};

use crate::arch::{Arch, Decoded, Effect, FieldUse, Flow, Operand, Place, Table};
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
    /// An operand names the slot outright, except in a call through a register. Discovery
    /// follows the paths to those with the registers tracked, and the decoding of a function
    /// takes where they go from it, so it need not track registers itself.
    const FLOW_READS_STATE: bool = false;

    fn decode<'a>(_: &'a Image, bytes: &'a [u8], addr: u64) -> impl Iterator<Item = Decoded<Instruction>> + 'a {
        let mut decoder = Decoder::with_ip(BITS, bytes, addr, DecoderOptions::NONE);
        let mut instr = Instruction::default();
        std::iter::from_fn(move || {
            decoder.can_decode().then(|| {
                decoder.decode_out(&mut instr);
                Decoded { addr: instr.ip(), len: instr.len().max(1) as u8, insn: (!instr.is_invalid()).then_some(instr) }
            })
        })
    }

    /// The decoder, the address its bytes are loaded at, and the instruction decoded last.
    type Decoder<'a> = (Decoder<'a>, u64, Instruction);

    fn decoder<'a>(_: &'a Image, bytes: &'a [u8], addr: u64) -> Self::Decoder<'a> {
        (Decoder::with_ip(BITS, bytes, addr, DecoderOptions::NONE), addr, Instruction::default())
    }

    fn seek((decoder, base, _): &mut Self::Decoder<'_>, offset: usize) {
        decoder.set_position(offset).expect("an offset into the section");
        decoder.set_ip(*base + offset as u64);
    }

    fn decode_next<'d>((decoder, _, instr): &'d mut Self::Decoder<'_>) -> Option<Decoded<&'d Instruction>> {
        decoder.can_decode().then(|| {
            decoder.decode_out(instr);
            Decoded { addr: instr.ip(), len: instr.len().max(1) as u8, insn: (!instr.is_invalid()).then_some(&*instr) }
        })
    }

    /// A call through a register loaded from an import's slot calls the import: MSVC loads an
    /// import it calls more than once into a register a call preserves. A register loaded from
    /// any other global holds whatever the program put there last, not what the file holds.
    fn flow(insn: &Instruction, state: &State, image: &Image) -> Option<Flow> {
        match classify(insn) {
            Some(Flow::CallIndirect(None)) if insn.op0_kind() == OpKind::Register => {
                Some(Flow::CallIndirect(state.loaded_from(insn.op0_register()).filter(|slot| image.import_slots.contains_key(slot))))
            }
            flow => flow,
        }
    }

    fn address_taken(insn: &Instruction, _: &State, _: &Image) -> Option<u64> {
        if BITS == 64 { lea_target(insn) } else { immediate_address(insn) }
    }

    fn based_data_address(insn: &Instruction, state: &State) -> Option<(u64, u64)> {
        state.based_address(insn)
    }

    /// A RIP-relative operand in 64-bit code; in 32-bit code a displacement, which the caller
    /// checks against relocations since any constant offset looks the same.
    fn memory_reference(insn: &Instruction, _: &State) -> Option<u64> {
        // The address first: most instructions have none, and going through the operands to see
        // whether one is memory costs more.
        let address = if insn.is_ip_rel_memory_operand() {
            insn.ip_rel_memory_address()
        } else if BITS == 32 && insn.memory_displacement64() != 0 {
            insn.memory_displacement64()
        } else {
            return None;
        };
        (insn.mnemonic() != Mnemonic::Lea && insn.op_kinds().any(|kind| kind == OpKind::Memory)).then_some(address)
    }

    fn through_pointer(insn: &Instruction, state: &State) -> Option<(u64, u64, bool)> {
        // `[register + offset]` with nothing else in the operand. Few registers hold a loaded
        // pointer, so that is asked first. A 32-bit slot is a global that the program may point
        // elsewhere as it runs, not an entry of a global offset table.
        let base = insn.memory_base();
        if BITS == 32 || base == Register::None || insn.memory_index() != Register::None {
            return None;
        }
        let slot = state.loaded_from(base).filter(|_| insn.op_kinds().any(|kind| kind == OpKind::Memory))?;
        Some((slot, insn.memory_displacement64(), insn.mnemonic() != Mnemonic::Lea))
    }

    /// MSVC's thiscall passes `this` in `ecx`, its x64 convention in `rcx`, and System V's in
    /// `rdi`. 32-bit System V code passes it on the stack.
    const THIS: Option<crate::arch::Register> = match (BITS, WINDOWS) {
        (32, false) => None,
        (_, true) => Some(1),
        (_, false) => Some(7),
    };

    fn object_effect(insn: &Instruction) -> Effect {
        object_effect(insn, BITS, Self::CALLER_SAVED)
    }

    fn argument_slot(state: &State, index: usize) -> Option<u64> {
        let registers = if WINDOWS { [Register::RCX, Register::RDX] } else { [Register::RDI, Register::RSI] };
        state.loaded_from(registers[index])
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

    fn argument_write(insn: &Instruction, _: &State) -> Option<(usize, Option<u64>)> {
        const WINDOWS_ORDER: [Register; 4] = [Register::RCX, Register::RDX, Register::R8, Register::R9];
        const SYSTEM_V_ORDER: [Register; 6] = [Register::RDI, Register::RSI, Register::RDX, Register::RCX, Register::R8, Register::R9];
        let order: &[Register] = if WINDOWS { &WINDOWS_ORDER } else { &SYSTEM_V_ORDER };
        // These read their first operand and leave it as it was.
        if BITS != 64 || insn.op0_kind() != OpKind::Register || matches!(insn.mnemonic(), Mnemonic::Cmp | Mnemonic::Test | Mnemonic::Push) {
            return None;
        }
        let position = order.iter().position(|&register| register == insn.op0_register().full_register())?;
        let address = match insn.mnemonic() {
            Mnemonic::Lea if insn.is_ip_rel_memory_operand() => Some(insn.ip_rel_memory_address()),
            Mnemonic::Mov if matches!(insn.op1_kind(), OpKind::Immediate32 | OpKind::Immediate64 | OpKind::Immediate32to64) => Some(insn.immediate(1)),
            _ => None,
        };
        Some((position, address))
    }

    fn takes_variable_arguments(insns: &[Instruction]) -> bool {
        let stored = |insn: &Instruction, registers: &[Register]| insn.mnemonic() == Mnemonic::Mov && insn.op0_kind() == OpKind::Memory && insn.op1_kind() == OpKind::Register && registers.contains(&insn.op1_register());
        // System V: `al` says how many vector registers carry arguments, and the function
        // saves them all unless it is zero.
        let tests_al = insns.iter().any(|insn| insn.mnemonic() == Mnemonic::Test && insn.op0_register() == Register::AL && insn.op1_register() == Register::AL);
        let saves_vectors = insns.iter().filter(|insn| matches!(insn.mnemonic(), Mnemonic::Movaps | Mnemonic::Movups) && insn.op0_kind() == OpKind::Memory && matches!(insn.op1_register(), Register::XMM4 | Register::XMM5 | Register::XMM6 | Register::XMM7)).count() == 4;
        if tests_al && saves_vectors {
            return true;
        }
        // Microsoft x64: the last register arguments go to the slots the caller left for them,
        // and the function takes the address of one, which is where `va_start` begins.
        let stack = |insn: &Instruction| insn.memory_base() == Register::RSP && insn.memory_index() == Register::None;
        // The first store of each: the register is free for other use once it is saved.
        let home = |register: Register| insns.iter().find(|insn| stored(insn, &[register]) && stack(insn)).map(|insn| insn.memory_displacement64());
        let (Some(third), Some(fourth)) = (home(Register::R8), home(Register::R9)) else { return false };
        fourth == third + 8 && insns.iter().any(|insn| insn.mnemonic() == Mnemonic::Lea && stack(insn) && insn.memory_displacement64() <= third && third - insn.memory_displacement64() <= 16)
    }

    fn field_use(insn: &Instruction) -> Option<(u64, FieldUse)> {
        let base = insn.memory_base();
        // A frame pointer reaches the function's own variables below it. Code built without
        // one uses the register as any other, and then with offsets that are not negative.
        let below_frame = base.full_register() == Register::RBP && (insn.memory_displacement64() as i64) < 0;
        let stack = below_frame || matches!(base.full_register(), Register::RSP | Register::RIP | Register::None);
        if stack || insn.memory_index() != Register::None || !insn.op_kinds().any(|kind| kind == OpKind::Memory) {
            return None;
        }
        let use_ = match insn.mnemonic() {
            Mnemonic::Lea => FieldUse::Address,
            // These read their first operand and leave it as it was.
            Mnemonic::Cmp | Mnemonic::Test | Mnemonic::Push | Mnemonic::Call | Mnemonic::Jmp => FieldUse::Read,
            _ if insn.op0_kind() == OpKind::Memory => FieldUse::Write,
            _ => FieldUse::Read,
        };
        Some((insn.memory_displacement64(), use_))
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
            for decoded in Self::decode(image, &section.data, section.addr) {
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

/// The number [`Effect`] gives a general-purpose register: `rax` 0, `rcx` 1, up to `r15` 15,
/// whatever part of it the instruction names.
fn gpr(register: Register) -> Option<crate::arch::Register> {
    let full = register.full_register();
    full.is_gpr64().then(|| full.number() as u8)
}

/// [`Arch::object_effect`] in code of `bits`, where a call may change the registers in
/// `caller_saved`.
fn object_effect(insn: &Instruction, bits: u32, caller_saved: &[Register]) -> Effect {
    let mask = |registers: &[Register]| registers.iter().filter_map(|&register| gpr(register)).fold(0, |mask, register| mask | 1 << register);
    let pointer = (bits / 8) as usize;
    let pointer_register = |operand: u32| (insn.op_kind(operand) == OpKind::Register && insn.op_register(operand).size() == pointer).then(|| gpr(insn.op_register(operand))).flatten();
    // `[register + offset]` or a fixed address, and nothing else.
    let place = || {
        if insn.memory_index() != Register::None || insn.segment_prefix() != Register::None {
            return None;
        }
        if insn.is_ip_rel_memory_operand() {
            return Some(Place::Global(insn.ip_rel_memory_address()));
        }
        if bits == 32 {
            let offset = insn.memory_displacement32();
            return Some(match insn.memory_base() {
                Register::None => Place::Global(u64::from(offset)),
                base => Place::Field { base: gpr(base)?, offset: i64::from(offset as i32) },
            });
        }
        Some(Place::Field { base: gpr(insn.memory_base())?, offset: insn.memory_displacement64() as i64 })
    };
    let operand = |index: u32| match insn.op_kind(index) {
        OpKind::Immediate32 | OpKind::Immediate32to64 | OpKind::Immediate64 => Some(Operand::Constant(insn.immediate(index))),
        _ => pointer_register(index).map(Operand::Register),
    };
    let written = || if insn.op0_kind() == OpKind::Register { mask(&[insn.op0_register()]) } else { 0 };
    match insn.mnemonic() {
        Mnemonic::Mov | Mnemonic::Lea => {
            let to = pointer_register(0);
            let effect = match (insn.mnemonic(), insn.op0_kind(), insn.op1_kind()) {
                (Mnemonic::Lea, _, _) if insn.is_ip_rel_memory_operand() => to.map(|to| Effect::Set { to, from: Operand::Constant(insn.ip_rel_memory_address()) }),
                (Mnemonic::Lea, _, _) => None,
                (_, OpKind::Register, OpKind::Memory) => to.zip(place()).map(|(to, from)| Effect::Load { to, from }),
                (_, OpKind::Register, _) => to.zip(operand(1)).map(|(to, from)| Effect::Set { to, from }),
                (_, OpKind::Memory, _) if insn.memory_size().size() == pointer => place().zip(operand(1)).map(|(to, from)| Effect::Store { to, from }),
                _ => None,
            };
            effect.unwrap_or_else(|| Effect::Clobbers(written()))
        }
        // `xor eax, eax` is how a register is set to zero.
        Mnemonic::Xor if insn.op0_kind() == OpKind::Register && insn.op1_kind() == OpKind::Register && insn.op0_register() == insn.op1_register() => match pointer_register(0) {
            Some(to) => Effect::Set { to, from: Operand::Constant(0) },
            None => Effect::Clobbers(written()),
        },
        Mnemonic::Call => match place().filter(|_| insn.op0_kind() == OpKind::Memory) {
            Some(slot) => Effect::Through { slot, clobbers: mask(caller_saved) },
            None => Effect::Clobbers(mask(caller_saved)),
        },
        Mnemonic::Jmp => place().filter(|_| insn.op0_kind() == OpKind::Memory).map_or(Effect::Clobbers(0), |slot| Effect::Through { slot, clobbers: 0 }),
        // These read their first operand and leave it as it was.
        Mnemonic::Push | Mnemonic::Cmp | Mnemonic::Test | Mnemonic::Bt => Effect::Clobbers(0),
        Mnemonic::Mul | Mnemonic::Div | Mnemonic::Idiv | Mnemonic::Cdq | Mnemonic::Cqo | Mnemonic::Cwd | Mnemonic::Rdtsc => Effect::Clobbers(mask(&[Register::RAX, Register::RDX])),
        Mnemonic::Imul if insn.op_count() == 1 => Effect::Clobbers(mask(&[Register::RAX, Register::RDX])),
        Mnemonic::Cpuid => Effect::Clobbers(mask(&[Register::RAX, Register::RBX, Register::RCX, Register::RDX])),
        Mnemonic::Xchg | Mnemonic::Xadd | Mnemonic::Cmpxchg => {
            let second = if insn.op1_kind() == OpKind::Register { mask(&[insn.op1_register()]) } else { 0 };
            Effect::Clobbers(written() | second | mask(&[Register::RAX]))
        }
        Mnemonic::Loop | Mnemonic::Loope | Mnemonic::Loopne => Effect::Clobbers(mask(&[Register::RCX])),
        Mnemonic::Leave => Effect::Clobbers(mask(&[Register::RSP, Register::RBP])),
        // A string instruction steps the registers that point into its strings and count them.
        _ if insn.op_kinds().any(|kind| {
            matches!(kind, OpKind::MemorySegSI | OpKind::MemorySegESI | OpKind::MemorySegRSI | OpKind::MemoryESDI | OpKind::MemoryESEDI | OpKind::MemoryESRDI)
        }) =>
        {
            Effect::Clobbers(mask(&[Register::RAX, Register::RCX, Register::RSI, Register::RDI]))
        }
        _ => Effect::Clobbers(written()),
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
pub(crate) fn is_padding(instr: &Instruction) -> bool {
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
