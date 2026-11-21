//! An ELF function symbol with a size bounds its function: inside it, a symbol or an unwind frame
//! starts a function, and so does a call from outside the symbol. These pin what the inside of a
//! sized symbol still lets through.

use recore::image::{Format, Image, Machine, Section};
use recore::report::{Analysis, AnalyzedFunction, CallTarget};

const BASE: u64 = 0x401000;

const MOV_RAX_RDI: [u8; 3] = [0x48, 0x89, 0xf8];
const ADD_RAX_RSI: [u8; 3] = [0x48, 0x01, 0xf0];
const IMUL_RAX_RDX: [u8; 4] = [0x48, 0x0f, 0xaf, 0xc2];
const ADD_RAX_1: [u8; 4] = [0x48, 0x83, 0xc0, 0x01];
const PAUSE: [u8; 2] = [0xf3, 0x90];
const JMP_BACK_2: [u8; 2] = [0xeb, 0xfc];
const MOV_EAX_1: [u8; 5] = [0xb8, 1, 0, 0, 0];
const PUSH_RBX: u8 = 0x53;
const POP_RBX: u8 = 0x5b;
const RET: u8 = 0xc3;

/// x86-64 code laid out from [`BASE`], with sized exported functions.
#[derive(Default)]
struct Code {
    bytes: Vec<u8>,
    symbols: Vec<(u64, u64)>,
}

impl Code {
    fn here(&self) -> u64 {
        BASE + self.bytes.len() as u64
    }

    fn bytes(&mut self, bytes: &[u8]) -> &mut Self {
        self.bytes.extend(bytes);
        self
    }

    fn call(&mut self, to: u64) -> &mut Self {
        let next = self.here() + 5;
        self.bytes.push(0xe8);
        self.bytes.extend(((to as i64 - next as i64) as i32).to_le_bytes());
        self
    }

    fn symbol(&mut self, start: u64, end: u64) -> &mut Self {
        self.symbols.push((start, end));
        self
    }

    fn analyze(&self) -> Analysis {
        let text = Section { name: ".text".into(), addr: BASE, data: self.bytes.clone(), file_offset: None, executable: true, writable: false };
        let mut image = Image::bare("symbols".into(), Format::Elf, Machine::X86_64, BASE, vec![text]);
        image.exports = self.symbols.iter().map(|&(start, _)| start).collect();
        image.symbol_extents = self.symbols.clone();
        recore::analyze(&image)
    }
}

fn function(analysis: &Analysis, addr: u64) -> Option<&AnalyzedFunction> {
    analysis.functions.iter().find(|function| function.addr == addr)
}

fn callers(analysis: &Analysis, callee: u64) -> Vec<u64> {
    analysis.calls.iter().filter(|call| call.target == CallTarget::Function(callee)).map(|call| call.at).collect()
}

/// `outer` computes a value and falls into `inner`, whose symbol lies inside its own. `outer`
/// ends where `inner` starts, short of its symbol's end, and still runs on into it.
#[test]
fn a_function_runs_on_into_a_symbol_nested_in_its_own() {
    let mut code = Code::default();
    let outer = code.here();
    code.bytes(&MOV_RAX_RDI).bytes(&ADD_RAX_RSI).bytes(&IMUL_RAX_RDX);
    let inner = code.here();
    code.bytes(&ADD_RAX_1).bytes(&[RET]);
    let end = code.here();
    code.symbol(outer, end).symbol(inner, end);

    let analysis = code.analyze();
    assert_eq!(function(&analysis, outer).and_then(|f| f.runs_on), Some(inner));
}

/// `outer` calls `sub` at its own inside, as a retpoline calls past its trap, and `user`, laid
/// out before it, calls the same address from outside. Discovery asks about `sub` from `outer`
/// first.
fn calls_into_a_symbol(from_outside: bool) -> (Analysis, u64, [u64; 2]) {
    let mut code = Code::default();
    let user = code.here();
    let outer = user + 8;
    let sub = outer + 5 + PAUSE.len() as u64 + JMP_BACK_2.len() as u64;
    code.bytes(&[PUSH_RBX]);
    let user_call = code.here();
    if from_outside {
        code.call(sub);
    } else {
        code.bytes(&[0x90; 5]);
    }
    code.bytes(&[POP_RBX, RET]);
    code.symbol(user, code.here());
    assert_eq!(code.here(), outer);
    code.call(sub).bytes(&PAUSE).bytes(&JMP_BACK_2);
    code.bytes(&MOV_EAX_1).bytes(&[RET]);
    code.symbol(outer, code.here());
    (code.analyze(), sub, [user_call, outer])
}

/// Ghidra makes a function at a call's destination. From outside the symbol, a call is evidence
/// enough, and then the call from inside goes to that function too.
#[test]
fn a_call_from_outside_a_symbol_starts_a_function_inside_it() {
    let (analysis, sub, call_sites) = calls_into_a_symbol(true);
    assert!(function(&analysis, sub).is_some(), "the callee is a function");
    assert_eq!(callers(&analysis, sub), call_sites);
}

/// A call within its own symbol is how hand-written code reaches a label, as `call 1f` reads
/// its own address. The code stays its function's.
#[test]
fn a_call_within_a_symbol_starts_no_function() {
    let (analysis, sub, _) = calls_into_a_symbol(false);
    assert!(function(&analysis, sub).is_none());
}

/// `user` calls `alt` inside `outer`'s symbol, which starts a function there. `alt` ends in a
/// call that never returns, and `rest`, which only `outer`'s own branch reaches, follows it.
/// `rest` is still inside the symbol, so the code no path from `alt` reaches is not split off as
/// a function: only past the symbol's end may it be.
#[test]
fn code_after_a_function_a_call_started_stays_inside_the_symbol() {
    const TEST_EDI_EDI: [u8; 2] = [0x85, 0xff];
    const JE_REST: [u8; 2] = [0x74, 12];
    const MOV_EAX_2_RET: [u8; 6] = [0xb8, 2, 0, 0, 0, RET];
    const ADD_EAX_ESI: [u8; 2] = [0x01, 0xf0];
    const JMP_SELF: [u8; 2] = [0xeb, 0xfe];

    let mut code = Code::default();
    let outer = code.here();
    // `rest` is where a function would be laid out, 16 bytes in.
    let (alt, rest, user) = (outer + 10, outer + 16, outer + 24);
    let spin = user + 8;
    code.bytes(&TEST_EDI_EDI).bytes(&JE_REST).bytes(&MOV_EAX_2_RET);
    assert_eq!(code.here(), alt);
    code.bytes(&[PUSH_RBX]).call(spin);
    assert_eq!(code.here(), rest);
    code.bytes(&MOV_EAX_1).bytes(&ADD_EAX_ESI).bytes(&[RET]).symbol(outer, user);
    code.bytes(&[PUSH_RBX]).call(alt).bytes(&[POP_RBX, RET]).symbol(user, spin);
    code.bytes(&JMP_SELF).symbol(spin, spin + 2);

    let analysis = code.analyze();
    assert!(function(&analysis, alt).is_some(), "the call from outside starts a function");
    assert!(function(&analysis, rest).is_none(), "what follows it inside the symbol is no function");
}
