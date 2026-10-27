//! A trap after a call says the compiler knows the code after it can't run. That is how clang
//! marks a call that never returns, and also how it marks a call followed by undefined
//! behavior, such as a use of a null pointer, where the callee returns as usual. Each call
//! site of a callee votes, and these pin what counts as a vote.

use recore::image::{Format, Image, InstructionSet, Machine, Section};
use recore::report::Analysis;

const BASE: u64 = 0x401000;

/// x86 code laid out from [`BASE`], with the few instructions these tests need.
#[derive(Default)]
struct X86(Vec<u8>);

impl X86 {
    fn here(&self) -> u64 {
        BASE + self.0.len() as u64
    }

    fn rel32(&mut self, opcode: &[u8], to: u64) -> &mut Self {
        self.0.extend(opcode);
        let next = self.here() + 4;
        self.0.extend(((to as i64 - next as i64) as i32).to_le_bytes());
        self
    }

    fn call(&mut self, to: u64) -> &mut Self {
        self.rel32(&[0xe8], to)
    }

    fn jmp(&mut self, to: u64) -> &mut Self {
        self.rel32(&[0xe9], to)
    }

    fn jnz(&mut self, to: u64) -> &mut Self {
        self.rel32(&[0x0f, 0x85], to)
    }

    fn bytes(&mut self, bytes: &[u8]) -> &mut Self {
        self.0.extend(bytes);
        self
    }

    /// `int3` up to `addr`, as linkers pad between functions.
    fn pad_to(&mut self, addr: u64) -> &mut Self {
        while self.here() < addr {
            self.0.push(INT3);
        }
        self
    }

    fn image(&self, format: Format, machine: Machine) -> Image {
        let text = Section { name: ".text".into(), addr: BASE, data: self.0.clone(), file_offset: None, executable: true, writable: false };
        Image { base: 0x400000, ..Image::bare("traps".into(), format, machine, BASE, vec![text]) }
    }
}

const INT3: u8 = 0xcc;
const RET: u8 = 0xc3;
const XOR_EAX_EAX: [u8; 2] = [0x31, 0xc0];
const TEST_ECX_ECX: [u8; 2] = [0x85, 0xc9];

fn noreturn(analysis: &Analysis, addr: u64) -> bool {
    analysis.functions.iter().find(|function| function.addr == addr).unwrap().noreturn
}

/// `callers` functions at 0x401020, 0x401040 and on that each call 0x401200 and go on, one at
/// 0x401180 whose call a trap follows, and an entry that calls them all.
fn calls_that_go_on_and_one_trap(callers: u64) -> Analysis {
    let (callee, trapping) = (0x401200, 0x401180);
    let mut code = X86::default();
    for caller in 0..callers {
        code.call(0x401020 + caller * 0x20);
    }
    code.call(trapping).bytes(&[RET]);
    for caller in 0..callers {
        code.pad_to(0x401020 + caller * 0x20).call(callee).bytes(&XOR_EAX_EAX).bytes(&[RET]);
    }
    // What follows uses a null pointer.
    code.pad_to(trapping).call(callee).bytes(&[INT3]);
    code.pad_to(callee).bytes(&XOR_EAX_EAX).bytes(&[RET]);
    recore::analyze(&code.image(Format::Pe, Machine::X86))
}

#[test]
fn a_callee_that_three_callers_go_on_from_returns_though_one_call_is_followed_by_a_trap() {
    assert!(!noreturn(&calls_that_go_on_and_one_trap(3), 0x401200));
}

/// MSVC leaves code after a call to `exit` when nothing told it `exit` never returns, so code
/// after a call is weaker evidence than a trap.
#[test]
fn a_trap_after_one_call_outweighs_two_callers_that_go_on() {
    assert!(noreturn(&calls_that_go_on_and_one_trap(2), 0x401200));
}

#[test]
fn a_callee_whose_only_call_is_followed_by_a_trap_never_returns_though_it_has_a_return() {
    let mut code = X86::default();
    code.call(0x401010).bytes(&[INT3]);
    code.pad_to(0x401010).bytes(&XOR_EAX_EAX).bytes(&[RET]);

    assert!(noreturn(&recore::analyze(&code.image(Format::Pe, Machine::X86)), 0x401010));
}

/// Three functions that each branch past their call, so a jump also leads to the code after
/// it, as MSVC's cold block after `__report_rangecheckfailure` is reached.
#[test]
fn code_after_a_call_that_a_jump_in_the_same_function_leads_to_casts_no_vote() {
    let (callee, trapping) = (0x401200, 0x401180);
    let mut code = X86::default();
    for caller in 0..3 {
        code.call(0x401020 + caller * 0x20);
    }
    code.call(trapping).bytes(&[RET]);
    for caller in 0..3 {
        code.pad_to(0x401020 + caller * 0x20).bytes(&TEST_ECX_ECX);
        let after = code.here() + 6 + 5;
        code.jnz(after).call(callee).bytes(&XOR_EAX_EAX).bytes(&[RET]);
    }
    code.pad_to(trapping).call(callee).bytes(&[INT3]);
    code.pad_to(callee).bytes(&XOR_EAX_EAX).bytes(&[RET]);

    assert!(noreturn(&recore::analyze(&code.image(Format::Pe, Machine::X86)), callee));
}

/// GCC moves a function's cold path into a `.cold` part with a frame of its own, which jumps
/// back to the code after a call in the hot part, as the landing pads that call
/// `_Unwind_Resume` do. A jump from another function counts as much as one from the caller.
#[test]
fn code_after_a_call_that_a_jump_from_another_function_leads_to_casts_no_vote() {
    let (callee, trapping) = (0x401200, 0x401180);
    let hot = |caller: u64| 0x401020 + caller * 0x20;
    let cold = |caller: u64| 0x401300 + caller * 0x10;
    let mut code = X86::default();
    let mut frames = Vec::new();
    for caller in 0..3 {
        code.call(hot(caller));
    }
    code.call(trapping).bytes(&[RET]);
    frames.push((BASE, code.here()));
    let mut after_calls = Vec::new();
    for caller in 0..3 {
        code.pad_to(hot(caller)).bytes(&TEST_ECX_ECX).jnz(cold(caller)).call(callee);
        after_calls.push(code.here());
        code.bytes(&[RET]);
        frames.push((hot(caller), code.here()));
    }
    code.pad_to(trapping).call(callee).bytes(&[INT3]);
    frames.push((trapping, code.here()));
    code.pad_to(callee).bytes(&XOR_EAX_EAX).bytes(&[RET]);
    frames.push((callee, code.here()));
    for (caller, &after_call) in after_calls.iter().enumerate() {
        code.pad_to(cold(caller as u64)).jmp(after_call);
        frames.push((cold(caller as u64), code.here()));
    }
    let image = Image { frames, ..code.image(Format::Elf, Machine::X86_64) };

    assert!(noreturn(&recore::analyze(&image), callee));
}

/// A32 code laid out from [`BASE`].
#[derive(Default)]
struct A32(Vec<u32>);

impl A32 {
    fn here(&self) -> u64 {
        BASE + 4 * self.0.len() as u64
    }

    /// A branch with the given condition and link bits, whose offset counts from 8 bytes on.
    fn branch(&mut self, opcode: u32, to: u64) -> &mut Self {
        let offset = (to as i64 - (self.here() as i64 + 8)) / 4;
        self.0.push(opcode | (offset as u32 & 0x00ff_ffff));
        self
    }

    fn bl(&mut self, to: u64) -> &mut Self {
        self.branch(0xeb00_0000, to)
    }

    fn beq(&mut self, to: u64) -> &mut Self {
        self.branch(0x0a00_0000, to)
    }

    fn word(&mut self, word: u32) -> &mut Self {
        self.0.push(word);
        self
    }
}

const BX_LR: u32 = 0xe12f_ff1e;
const MOV_R0_0: u32 = 0xe3a0_0000;
const NOP: u32 = 0xe320_f000;
const CMP_R0_0: u32 = 0xe350_0000;
const UDF: u32 = 0xe7f0_00f0;
/// `ldr r1, [pc]`, which loads the word 8 bytes on.
const LDR_R1_PC: u32 = 0xe59f_1000;

/// GCC places a literal pool after a call that never returns, as no code runs on into it there.
/// Its words decode as instructions, but they are data, and say nothing about the callee.
#[test]
fn a_literal_pool_after_a_call_casts_no_vote() {
    let (callee, trapping) = (0x401100, 0x4010f0);
    let caller = |caller: u64| 0x401020 + caller * 0x20;
    let mut code = A32::default();
    for n in 0..3 {
        code.bl(caller(n));
    }
    code.bl(trapping).word(BX_LR);
    for n in 0..3 {
        while code.here() < caller(n) {
            code.word(NOP);
        }
        let skip = code.here() + 20;
        code.word(CMP_R0_0).beq(skip).word(LDR_R1_PC).bl(callee).word(0x1234_5678).word(BX_LR);
    }
    while code.here() < trapping {
        code.word(NOP);
    }
    code.bl(callee).word(UDF);
    while code.here() < callee {
        code.word(NOP);
    }
    code.word(MOV_R0_0).word(BX_LR);
    let data = code.0.iter().flat_map(|word| word.to_le_bytes()).collect();
    let text = Section { name: ".text".into(), addr: BASE, data, file_offset: None, executable: true, writable: false };
    let mut image = Image::bare("traps".into(), Format::Elf, Machine::Arm, BASE, vec![text]);
    image.instruction_sets = vec![(BASE, InstructionSet::A32)];
    image.data_in_code = true;

    assert!(noreturn(&recore::analyze(&image), callee));
}
