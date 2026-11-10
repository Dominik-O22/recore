//! Raw p-code read into operations: what the decompiler's processor specifications lift each
//! instruction to, as both the lifter and recore-mcp's emulator take it.

use anyhow::{Context, Result, bail};
use recore_machine::ops::Code;
use recore_machine::{sse, x87};

/// A place in one of the processor's spaces: the registers, the memory, the temporaries an
/// instruction's operations pass between them, or the constants operations take.
#[derive(Clone, Copy, Debug)]
pub struct Varnode {
    pub space: Space,
    pub offset: u64,
    pub size: usize,
}

/// A space of the processor by the number the interpreter gave its name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Space(pub u8);

pub const CONST: Space = Space(0);
pub const REGISTER: Space = Space(1);
pub const UNIQUE: Space = Space(2);

/// The names of the spaces in the order they were first seen.
pub struct Spaces(pub Vec<String>);

impl Spaces {
    pub fn new() -> Spaces {
        Spaces(["const", "register", "unique"].map(String::from).to_vec())
    }

    pub fn intern(&mut self, name: &str) -> Space {
        let index = self.0.iter().position(|known| known == name).unwrap_or_else(|| {
            self.0.push(name.to_string());
            self.0.len() - 1
        });
        Space(index as u8)
    }
}

impl Default for Spaces {
    fn default() -> Spaces {
        Spaces::new()
    }
}

/// One p-code operation. A LOAD or STORE reaches the space `space`; what a CALLOTHER does is
/// `userop`, resolved from the name of its processor operation. Neither is among `inputs`.
#[derive(Clone, Debug)]
pub struct Op {
    pub code: Code,
    pub out: Option<Varnode>,
    pub inputs: Vec<Varnode>,
    pub space: Space,
    pub userop: Userop,
}

/// What a CALLOTHER does, resolved from the name of its processor operation when the instruction
/// is lifted: what a run does there and what `coverage` reports agree by being read from here.
#[derive(Clone, Debug)]
pub enum Userop {
    /// One of the MMX and SSE operations of [`sse`].
    Sse(sse::Op),
    /// Nothing a function can observe: see [`HARMLESS`].
    Harmless,
    /// Any other operation, by name: a run stops at it, and the lifter runs a few.
    Other(String),
}

impl Userop {
    fn parse(name: &str, has_out: bool) -> Userop {
        match sse::Op::parse(name) {
            Some(op) if has_out => Userop::Sse(op),
            _ if HARMLESS.iter().any(|harmless| harmless.eq_ignore_ascii_case(name)) => Userop::Harmless,
            _ => Userop::Other(name.into()),
        }
    }
}

/// Processor operations that change nothing a function can observe, as the specifications name
/// them, compared without regard to case. `setISAMode` tells a decompiler which instruction set
/// a branch goes to, and a Cortex-M has one.
const HARMLESS: &[&str] = &[
    "setISAMode", "lock", "unlock", "nop", "sev", "SendEvent", "Yield", "Hint_Prefetch", "DataMemoryBarrier", "DataSynchronizationBarrier", "InstructionSynchronizationBarrier",
];

pub enum Semantics {
    /// The p-code of the processor specification, or why it is not known. An operation the
    /// interpreter lacks fails the run only if the run gets to it.
    Pcode(Result<Vec<Op>, String>),
    /// An x87 instruction run whole, which the specification leaves opaque or approximate.
    X87(x87::Instruction),
}

impl Semantics {
    /// What `instruction` does: on x86 an x87 instruction runs whole, anything else as its p-code.
    pub fn of(spaces: &mut Spaces, instruction: &recore_decomp::Instruction, x86: bool) -> Semantics {
        match instruction.text.split(' ').next().and_then(x87::Instruction::parse) {
            Some(whole) if x86 => Semantics::X87(whole),
            _ => Semantics::Pcode(instruction.pcode.iter().map(|line| parse_op(spaces, line)).collect::<Result<Vec<_>>>().map_err(|error| format!("{error:#}"))),
        }
    }
}

fn operand(spaces: &mut Spaces, text: &str) -> Result<Varnode> {
    let mut parts = text.split(':');
    let (Some(space), Some(offset), Some(size), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
        bail!("`{text}` is not an operand");
    };
    Ok(Varnode { space: spaces.intern(space), offset: u64::from_str_radix(offset, 16)?, size: size.parse()? })
}

/// Reads one line of raw p-code: see [`recore_decomp::Session::lift`].
pub fn parse_op(spaces: &mut Spaces, line: &str) -> Result<Op> {
    let mut words = line.split(' ');
    let name = words.next().unwrap_or_default();
    let code = Code::parse(name).with_context(|| format!("the p-code operation {name} is not known"))?;
    let out = match words.next() {
        Some("-") | None => None,
        Some(word) => Some(operand(spaces, word)?),
    };
    let mut op = Op { code, out, inputs: Vec::new(), space: CONST, userop: Userop::Harmless };
    let mut userop = "";
    for (index, word) in words.enumerate() {
        match (index, code) {
            (0, Code::Load | Code::Store) => op.space = spaces.intern(word),
            (0, Code::CallOther) if !word.contains(':') => userop = word,
            _ => op.inputs.push(operand(spaces, word)?),
        }
    }
    if code == Code::CallOther {
        op.userop = Userop::parse(userop, out.is_some());
    }
    Ok(op)
}
