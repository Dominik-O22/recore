//! Runs a function of the binary as its processor would, on arguments the caller gives, by
//! interpreting the raw p-code the decompiler's processor specifications lift each instruction
//! to. One interpreter serves every machine recore reads. Functions the binary imports run as
//! small stand-ins written here; a call to any other stops the run and says so, and so does an
//! instruction or a processor operation the specifications give no semantics.
//!
//! This is the oracle: what the original does on chosen inputs, for a rewrite to be checked
//! against, or for a finding to be shown with. It runs one function and what it calls, not the
//! program: memory the run has not written and the file does not hold reads as zero, and the run
//! says how many reads of that it made, since on a chip those are its peripherals.

use std::collections::BTreeMap;
use std::fmt::Write;
use std::rc::Rc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use recore::FxHashMap;
use recore::image::{Compiler, Format, Image, Machine};
use recore::program::parse_addr;
use recore::report::CallTarget;
use recore::thumb;
use serde::Deserialize;

use crate::binary::Binary;

mod x87;

/// Bytes in a page of the sparse memory each space keeps.
const PAGE: usize = 4096;
/// Bytes lifted at a time from where execution goes next.
const WINDOW: u64 = 512;
/// Bytes of stack the run gets.
const STACK: u64 = 1 << 20;
/// Bytes of scratch memory for buffers passed in and for what `malloc` hands out.
const SCRATCH: u64 = 16 << 20;
/// Operations run unless the caller sets `steps`.
const DEFAULT_STEPS: u64 = 10_000_000;
/// Bytes of a buffer or a write shown before the rest is cut.
const SHOWN: usize = 64;
/// Ranges of memory the run wrote that are listed.
const RANGES_SHOWN: usize = 16;
/// The stack pointer of an 8051 function unless the caller sets it and the startup code does not
/// say: above the register banks and the bits.
const INITIAL_SP: u128 = 0x40;
/// The longest a run goes before it stops, whatever `steps` allows.
const TIMEOUT: Duration = Duration::from_secs(30);
/// The most memory a buffer, a dump or a stand-in moves at once.
const LARGEST_BLOCK: u64 = SCRATCH;
/// Addresses of reads of unwritten memory that are remembered.
const UNWRITTEN_SHOWN: usize = 4;

/// A place in one of the processor's spaces: the registers, the memory, the temporaries an
/// instruction's operations pass between them, or the constants operations take.
#[derive(Clone, Copy, Debug)]
struct Varnode {
    space: Space,
    offset: u64,
    size: usize,
}

/// A space of the processor by the number the interpreter gave its name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct Space(u8);

const CONST: Space = Space(0);
const REGISTER: Space = Space(1);
const UNIQUE: Space = Space(2);

/// The names of the spaces in the order they were first seen.
struct Spaces(Vec<String>);

impl Spaces {
    fn new() -> Spaces {
        Spaces(["const", "register", "unique"].map(String::from).to_vec())
    }

    fn intern(&mut self, name: &str) -> Space {
        let index = self.0.iter().position(|known| known == name).unwrap_or_else(|| {
            self.0.push(name.to_string());
            self.0.len() - 1
        });
        Space(index as u8)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Code {
    Copy, Load, Store, Branch, CBranch, BranchInd, Call, CallInd, CallOther, Return,
    Piece, SubPiece, Equal, NotEqual, SLess, SLessEqual, Less, LessEqual, ZExt, SExt,
    Add, Sub, Carry, SCarry, SBorrow, TwoComp, Negate, Xor, And, Or, Left, Right, SRight,
    Mult, Div, Rem, SDiv, SRem, BoolNegate, BoolXor, BoolAnd, BoolOr,
    FEqual, FNotEqual, FLess, FLessEqual, FNan, FAdd, FDiv, FMult, FSub, FNeg, FAbs, FSqrt,
    Int2Float, Float2Float, Trunc, Ceil, Floor, Round, PopCount, LzCount,
    /// An instruction the processor specification gives no semantics: see `rd_listing`.
    Unimplemented,
}

impl Code {
    fn parse(name: &str) -> Option<Code> {
        use Code::*;
        Some(match name {
            "COPY" => Copy, "LOAD" => Load, "STORE" => Store, "BRANCH" => Branch, "CBRANCH" => CBranch,
            "BRANCHIND" => BranchInd, "CALL" => Call, "CALLIND" => CallInd, "CALLOTHER" => CallOther, "RETURN" => Return,
            "PIECE" => Piece, "SUBPIECE" => SubPiece, "INT_EQUAL" => Equal, "INT_NOTEQUAL" => NotEqual,
            "INT_SLESS" => SLess, "INT_SLESSEQUAL" => SLessEqual, "INT_LESS" => Less, "INT_LESSEQUAL" => LessEqual,
            "INT_ZEXT" => ZExt, "INT_SEXT" => SExt, "INT_ADD" => Add, "INT_SUB" => Sub, "INT_CARRY" => Carry,
            "INT_SCARRY" => SCarry, "INT_SBORROW" => SBorrow, "INT_2COMP" => TwoComp, "INT_NEGATE" => Negate,
            "INT_XOR" => Xor, "INT_AND" => And, "INT_OR" => Or, "INT_LEFT" => Left, "INT_RIGHT" => Right,
            "INT_SRIGHT" => SRight, "INT_MULT" => Mult, "INT_DIV" => Div, "INT_REM" => Rem, "INT_SDIV" => SDiv,
            "INT_SREM" => SRem, "BOOL_NEGATE" => BoolNegate, "BOOL_XOR" => BoolXor, "BOOL_AND" => BoolAnd, "BOOL_OR" => BoolOr,
            "FLOAT_EQUAL" => FEqual, "FLOAT_NOTEQUAL" => FNotEqual, "FLOAT_LESS" => FLess, "FLOAT_LESSEQUAL" => FLessEqual,
            "FLOAT_NAN" => FNan, "FLOAT_ADD" => FAdd, "FLOAT_DIV" => FDiv, "FLOAT_MULT" => FMult, "FLOAT_SUB" => FSub,
            "FLOAT_NEG" => FNeg, "FLOAT_ABS" => FAbs, "FLOAT_SQRT" => FSqrt, "INT2FLOAT" => Int2Float,
            "FLOAT2FLOAT" => Float2Float, "TRUNC" => Trunc, "CEIL" => Ceil, "FLOOR" => Floor,
            "ROUND" => Round, "POPCOUNT" => PopCount, "LZCOUNT" => LzCount, "UNIMPLEMENTED" => Unimplemented,
            _ => return None,
        })
    }
}

/// One p-code operation. A LOAD or STORE reaches the space `space`; a CALLOTHER is the
/// processor operation called `userop`. Neither is among `inputs`.
#[derive(Clone, Debug)]
struct Op {
    code: Code,
    out: Option<Varnode>,
    inputs: Vec<Varnode>,
    space: Space,
    userop: String,
}

/// One instruction: its length and what it does.
struct Lifted {
    len: u64,
    semantics: Semantics,
}

enum Semantics {
    /// The p-code of the processor specification, or why it is not known. An operation the
    /// interpreter lacks fails the run only if the run gets to it.
    Pcode(Result<Vec<Op>, String>),
    /// An x87 instruction run whole, which the specification leaves opaque or approximate.
    X87(x87::Instruction),
}

fn operand(spaces: &mut Spaces, text: &str) -> Result<Varnode> {
    let mut parts = text.split(':');
    let (Some(space), Some(offset), Some(size), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
        bail!("`{text}` is not an operand");
    };
    Ok(Varnode { space: spaces.intern(space), offset: u64::from_str_radix(offset, 16)?, size: size.parse()? })
}

/// Reads one line of raw p-code: see [`recore_decomp::Session::lift`].
fn parse_op(spaces: &mut Spaces, line: &str) -> Result<Op> {
    let mut words = line.split(' ');
    let name = words.next().unwrap_or_default();
    let code = Code::parse(name).with_context(|| format!("the p-code operation {name} is not known"))?;
    let out = match words.next() {
        Some("-") | None => None,
        Some(word) => Some(operand(spaces, word)?),
    };
    let mut op = Op { code, out, inputs: Vec::new(), space: CONST, userop: String::new() };
    for (index, word) in words.enumerate() {
        match (index, code) {
            (0, Code::Load | Code::Store) => op.space = spaces.intern(word),
            (0, Code::CallOther) if !word.contains(':') => op.userop = word.to_string(),
            _ => op.inputs.push(operand(spaces, word)?),
        }
    }
    Ok(op)
}

/// Where a call leaves the address the function returns to.
#[derive(Clone, Copy)]
enum Returns {
    /// On the stack, a pointer wide, where the call pushes it.
    Pushed,
    /// In a register.
    Link(&'static str),
    /// As two bytes, low first, on the internal stack of an 8051, where `SP` points.
    Internal,
}

/// How a machine passes arguments and returns, by register names of its processor specification.
struct Abi {
    args: &'static [&'static str],
    result: &'static str,
    stack: &'static str,
    returns: Returns,
    /// Bytes the caller leaves free on the stack above the return address, as Windows x64 does.
    shadow: u64,
    /// Bits of a return address the processor ignores: the Thumb bit of a link register.
    mode_bit: u64,
    /// Whether integer division and float to integer conversion behave as on ARM: a zero divisor
    /// gives zero, and a float out of range saturates. On x86 a zero divisor stops the run, as the
    /// processor traps, and a float out of range gives the lowest integer.
    arm_arithmetic: bool,
    /// Bytes a stack pointer is aligned to at a call.
    alignment: u64,
    pointer: u64,
    /// The space the image's bytes are in.
    code: &'static str,
    /// The spaces of the processor besides the registers, which a caller can name.
    spaces: &'static [&'static str],
    /// Registers that hold the rest of a result wider than `result`, the lowest first.
    result_rest: &'static [&'static str],
    big_endian: bool,
    /// Registers that take float arguments, in order, and after them the stack; `None` where it
    /// depends on how the binary was built, as on 32-bit ARM.
    floats: Option<&'static [&'static str]>,
    /// Whether an argument goes in the register of its position among all the arguments, as on
    /// Windows x64, rather than in the next free one of its kind.
    positional: bool,
    /// The x87 control word a thread starts with, and the system that sets it.
    control_word: Option<(u128, &'static str)>,
}

const SYSTEM_V: Abi = Abi { args: &[], result: "", stack: "", returns: Returns::Pushed, shadow: 0, mode_bit: 0, arm_arithmetic: false, alignment: 16, pointer: 0, code: "ram", spaces: &["ram"], result_rest: &[], big_endian: false, floats: None, positional: false, control_word: None };

const XMM: [&str; 8] = ["XMM0", "XMM1", "XMM2", "XMM3", "XMM4", "XMM5", "XMM6", "XMM7"];
/// Windows rounds x87 results to 53 bits, as a double has, and Linux and macOS to 64.
const WINDOWS_X87: Option<(u128, &str)> = Some((0x27f, "Windows"));
const UNIX_X87: Option<(u128, &str)> = Some((0x37f, "Linux and macOS"));

/// The memories of an 8051 and the bits in them.
const EIGHT051: [&str; 5] = ["CODE", "INTMEM", "EXTMEM", "SFR", "BITS"];

fn abi(image: &Image) -> Result<Abi> {
    let pointer = image.machine.pointer_size();
    let abi = match image.machine {
        Machine::X86_64 if image.format == Format::Pe => Abi { args: &["RCX", "RDX", "R8", "R9"], result: "RAX", stack: "RSP", shadow: 32, floats: Some(&XMM[..4]), positional: true, control_word: WINDOWS_X87, ..SYSTEM_V },
        Machine::X86_64 => Abi { args: &["RDI", "RSI", "RDX", "RCX", "R8", "R9"], result: "RAX", stack: "RSP", floats: Some(&XMM), control_word: UNIX_X87, ..SYSTEM_V },
        Machine::X86 => Abi { result: "EAX", stack: "ESP", floats: Some(&[]), control_word: if image.format == Format::Pe { WINDOWS_X87 } else { UNIX_X87 }, ..SYSTEM_V },
        Machine::Aarch64 => Abi { args: &["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"], result: "x0", stack: "sp", returns: Returns::Link("x30"), arm_arithmetic: true, floats: Some(&["d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7"]), ..SYSTEM_V },
        Machine::Thumb | Machine::Arm => Abi { args: &["r0", "r1", "r2", "r3"], result: "r0", stack: "sp", returns: Returns::Link("lr"), mode_bit: 1, arm_arithmetic: true, alignment: 8, ..SYSTEM_V },
        // Arguments of an 8051 function are in places that depend on its compiler and on the
        // function, so the caller sets them. The first byte of a result is in DPL for SDCC and
        // in R7 for Keil, and a wider result goes on in the registers after it.
        Machine::I8051 if image.compiler == Some(Compiler::Sdcc) => Abi { result: "DPL", result_rest: &["DPH", "B", "ACC"], stack: "SP", returns: Returns::Internal, code: "CODE", spaces: &EIGHT051, big_endian: true, ..SYSTEM_V },
        Machine::I8051 => Abi { result: "R7", result_rest: &["R6", "R5", "R4"], stack: "SP", returns: Returns::Internal, code: "CODE", spaces: &EIGHT051, big_endian: true, ..SYSTEM_V },
    };
    Ok(Abi { pointer, ..abi })
}

fn mask(size: usize) -> u128 {
    if size >= 16 { u128::MAX } else { (1u128 << (8 * size)) - 1 }
}

fn signed(value: u128, size: usize) -> i128 {
    if size == 0 {
        return 0;
    }
    let spare = 128u32.saturating_sub(8 * size as u32);
    ((value << spare) as i128) >> spare
}

/// Whether the signed `value` fits `size` bytes.
fn fits(value: i128, size: usize) -> bool {
    size >= 16 || signed(value as u128 & mask(size), size) == value
}

/// The lowest signed integer of `size` bytes.
fn signed_min(size: usize) -> i128 {
    if size >= 16 { i128::MIN } else { -(1i128 << (8 * size - 1)) }
}

/// A float cut toward zero to a signed integer of `size` bytes. Out of range or not a number,
/// ARM saturates and gives zero for not a number, and x86 gives the lowest integer.
fn float_to_int(value: f64, size: usize, arm: bool) -> u128 {
    let cut = value.trunc();
    let lowest = signed_min(size);
    let (below, above) = (cut < lowest as f64, cut >= -(lowest as f64));
    let integer = match (value.is_nan(), below, above, arm) {
        (false, false, false, _) => cut as i128,
        (true, _, _, true) => 0,
        (false, false, true, true) => -(lowest + 1),
        _ => lowest,
    };
    integer as u128
}

fn float(value: u128, size: usize) -> Result<f64, String> {
    match size {
        4 => Ok(f64::from(f32::from_bits(value as u32))),
        8 => Ok(f64::from_bits(value as u64)),
        _ => Err(format!("floating point of {size} bytes is not run")),
    }
}

fn float_bits(value: f64, size: usize) -> Result<u128, String> {
    match size {
        4 => Ok(u128::from((value as f32).to_bits())),
        8 => Ok(u128::from(value.to_bits())),
        _ => Err(format!("floating point of {size} bytes is not run")),
    }
}

/// The result of an operation that computes a value from its inputs, each as its bits and its
/// size in bytes, in a place `size` bytes wide.
fn compute(code: Code, size: usize, inputs: &[(u128, usize)], arm: bool) -> Result<u128, String> {
    use Code::*;
    let input = |index: usize| inputs.get(index).copied().unwrap_or((0, 0));
    let ((a, a_size), (b, b_size)) = (input(0), input(1));
    let (sa, sb) = (signed(a, a_size), signed(b, b_size));
    let amount = |bits: usize| if b >= bits as u128 { None } else { Some(b as u32) };
    let result = match code {
        Copy | ZExt => a,
        SExt => sa as u128,
        Piece => a.checked_shl(8 * b_size as u32).unwrap_or(0) | b,
        SubPiece => a.checked_shr(8 * b as u32).unwrap_or(0),
        Equal => (a == b).into(),
        NotEqual => (a != b).into(),
        SLess => (sa < sb).into(),
        SLessEqual => (sa <= sb).into(),
        Less => (a < b).into(),
        LessEqual => (a <= b).into(),
        Add => a.wrapping_add(b),
        Sub => a.wrapping_sub(b),
        Carry => {
            let (sum, wrapped) = a.overflowing_add(b);
            (wrapped || sum > mask(a_size)).into()
        }
        SCarry => {
            let (sum, wrapped) = sa.overflowing_add(sb);
            (wrapped || !fits(sum, a_size)).into()
        }
        SBorrow => {
            let (difference, wrapped) = sa.overflowing_sub(sb);
            (wrapped || !fits(difference, a_size)).into()
        }
        TwoComp => 0u128.wrapping_sub(a),
        Negate => !a,
        Xor => a ^ b,
        And => a & b,
        Or => a | b,
        Left => amount(8 * a_size).map_or(0, |by| a << by),
        Right => amount(8 * a_size).map_or(0, |by| a >> by),
        SRight => (sa >> amount(8 * a_size).unwrap_or(127).min(127)) as u128,
        Mult => a.wrapping_mul(b),
        Div | Rem | SDiv | SRem if b == 0 => return if arm { Ok(0) } else { Err("division by zero".into()) },
        Div => a / b,
        Rem => a % b,
        SDiv => sa.wrapping_div(sb) as u128,
        SRem => sa.wrapping_rem(sb) as u128,
        BoolNegate => (a & 1) ^ 1,
        BoolXor => (a ^ b) & 1,
        BoolAnd => a & b & 1,
        BoolOr => (a | b) & 1,
        PopCount => a.count_ones().into(),
        LzCount => u128::from(a.leading_zeros() - (128 - 8 * a_size as u32)),
        FEqual => (float(a, a_size)? == float(b, b_size)?).into(),
        FNotEqual => (float(a, a_size)? != float(b, b_size)?).into(),
        FLess => (float(a, a_size)? < float(b, b_size)?).into(),
        FLessEqual => (float(a, a_size)? <= float(b, b_size)?).into(),
        FNan => float(a, a_size)?.is_nan().into(),
        FAdd => float_bits(float(a, a_size)? + float(b, b_size)?, size)?,
        FSub => float_bits(float(a, a_size)? - float(b, b_size)?, size)?,
        FMult => float_bits(float(a, a_size)? * float(b, b_size)?, size)?,
        FDiv => float_bits(float(a, a_size)? / float(b, b_size)?, size)?,
        FNeg => float_bits(-float(a, a_size)?, size)?,
        FAbs => float_bits(float(a, a_size)?.abs(), size)?,
        FSqrt => float_bits(float(a, a_size)?.sqrt(), size)?,
        // An integer of 64 bits to a float of 32 rounds once, not through a double.
        Int2Float if size == 4 => u128::from((sa as f32).to_bits()),
        Int2Float => float_bits(sa as f64, size)?,
        Float2Float => float_bits(float(a, a_size)?, size)?,
        Trunc => float_to_int(float(a, a_size)?, size, arm),
        Ceil => float_bits(float(a, a_size)?.ceil(), size)?,
        Floor => float_bits(float(a, a_size)?.floor(), size)?,
        Round => float_bits((float(a, a_size)? + 0.5).floor(), size)?,
        Load | Store | Branch | CBranch | BranchInd | Call | CallInd | CallOther | Return | Unimplemented => unreachable!("{code:?} is not a computation"),
    };
    Ok(result & mask(size))
}

/// Processor operations that change nothing a function can observe, as the specifications name
/// them, compared without regard to case. `setISAMode` tells a decompiler which instruction set
/// a branch goes to, and a Cortex-M has one.
const HARMLESS: &[&str] = &[
    "setISAMode", "lock", "unlock", "nop", "sev", "SendEvent", "Yield", "Hint_Prefetch", "DataMemoryBarrier", "DataSynchronizationBarrier", "InstructionSynchronizationBarrier",
];

struct Page {
    bytes: [u8; PAGE],
    /// Whether the byte has a value that is not just zero: the file holds it or the run wrote it.
    known: [bool; PAGE],
    /// Whether the run wrote the byte.
    dirty: [bool; PAGE],
}

/// The memory of every space but the constants, a page at a time.
struct Memory {
    pages: FxHashMap<(Space, u64), Box<Page>>,
    /// The space the image's bytes are in.
    code: Space,
    big_endian: bool,
    /// How many reads touched memory that nothing had written, and the first few addresses.
    unwritten: u64,
    unwritten_first: Vec<(Space, u64)>,
}

impl Memory {
    fn page(&mut self, image: &Image, space: Space, index: u64) -> &mut Page {
        let code = self.code;
        self.pages.entry((space, index)).or_insert_with(|| {
            let mut page = Box::new(Page { bytes: [0; PAGE], known: [false; PAGE], dirty: [false; PAGE] });
            if space == code {
                let start = index * PAGE as u64;
                for offset in 0..PAGE {
                    let addr = start + offset as u64;
                    match image.section_at(addr) {
                        Some(section) => {
                            page.bytes[offset] = section.data[(addr - section.addr) as usize];
                            page.known[offset] = true;
                        }
                        // A raw image's zero-filled memory is only where its processor has memory: nothing says what is in it.
                        None => page.known[offset] = image.format != Format::Raw && image.is_zero_filled(addr),
                    }
                }
            }
            page
        })
    }

    fn read_byte(&mut self, image: &Image, space: Space, addr: u64) -> (u8, bool) {
        let (page, at) = (self.page(image, space, addr / PAGE as u64), (addr % PAGE as u64) as usize);
        (page.bytes[at], page.known[at] || space == REGISTER || space == UNIQUE)
    }

    fn write_byte(&mut self, image: &Image, space: Space, addr: u64, byte: u8, mark: bool) {
        let (page, at) = (self.page(image, space, addr / PAGE as u64), (addr % PAGE as u64) as usize);
        page.bytes[at] = byte;
        page.known[at] = true;
        page.dirty[at] |= mark;
    }

    /// Reads `size` bytes. A read of any byte nothing has written counts as one read of
    /// unwritten memory.
    fn read(&mut self, image: &Image, space: Space, addr: u64, size: usize) -> u128 {
        let mut value = 0u128;
        let mut known = true;
        for index in 0..size {
            let (byte, byte_known) = self.read_byte(image, space, addr.wrapping_add(index as u64));
            known &= byte_known;
            let byte = u128::from(byte);
            value |= if self.big_endian { byte << (8 * (size - 1 - index)) } else { byte << (8 * index) };
        }
        if !known {
            self.unwritten += 1;
            if self.unwritten_first.len() < UNWRITTEN_SHOWN {
                self.unwritten_first.push((space, addr));
            }
        }
        value
    }

    fn write(&mut self, image: &Image, space: Space, addr: u64, size: usize, value: u128, mark: bool) {
        for index in 0..size {
            let shift = if self.big_endian { 8 * (size - 1 - index) } else { 8 * index };
            self.write_byte(image, space, addr.wrapping_add(index as u64), (value >> shift) as u8, mark);
        }
    }

    /// The bytes at `addr` as the run left them.
    fn peek(&mut self, image: &Image, space: Space, addr: u64, len: usize) -> Vec<u8> {
        (0..len as u64).map(|index| self.read_byte(image, space, addr + index).0).collect()
    }
}

/// Why a run ended.
#[derive(Debug, PartialEq, Eq)]
pub enum Stop {
    /// The function returned to its caller.
    Returned,
    /// The run reached the limit on operations.
    Steps,
    /// The run cannot go on, and why.
    Fault(String),
}

/// A number given for an argument or a register: an integer, or the bits of a float of 4 or 8
/// bytes. A float argument goes where the platform passes floats, and a float put in a 10-byte
/// x87 register becomes the extended float of the same value.
#[derive(Debug, Clone, Copy)]
pub enum Scalar {
    Int(u128),
    Float { bits: u128, size: usize },
}

/// An argument of the call.
#[derive(Debug, Clone)]
pub enum Arg {
    Value(Scalar),
    /// Bytes put in scratch memory, whose address is passed.
    Buffer(Vec<u8>),
}

/// What to run.
#[derive(Debug)]
pub struct Call {
    pub entry: u64,
    pub args: Vec<Arg>,
    /// Registers set before the run, which comes after the arguments are placed.
    pub registers: Vec<(String, Scalar)>,
    /// Memory written before the run.
    pub memory: Vec<(Option<String>, u64, Vec<u8>)>,
    /// Registers read after the run, besides the one that holds the result, each as it is or with
    /// `:f32` or `:f64` as a float of that size.
    pub read: Vec<String>,
    /// Memory read after the run: address and length.
    pub dump: Vec<(Option<String>, u64, usize)>,
    pub steps: u64,
}

/// A buffer passed in, and how it was left.
pub struct Buffer {
    pub arg: usize,
    pub addr: u64,
    pub before: Vec<u8>,
    pub after: Vec<u8>,
}

/// A register as the answer shows it.
pub struct Reading {
    pub name: String,
    pub bits: u128,
    pub size: usize,
    /// Whether the bits are a float, shown in decimal.
    pub float: bool,
}

/// What a run did.
pub struct Outcome {
    pub stop: Stop,
    /// Instructions run, and what the stand-ins charged for the bytes they moved.
    pub steps: u64,
    /// What the oracle chose or found that changes how to read the run.
    pub notes: Vec<String>,
    /// The register that holds the result, and what it held.
    pub result: Reading,
    pub registers: Vec<Reading>,
    pub dumps: Vec<(Option<String>, u64, Vec<u8>)>,
    pub buffers: Vec<Buffer>,
    /// Memory the run wrote besides its stack and its buffers: space, address and bytes, in runs.
    pub writes: Vec<(Option<String>, u64, Vec<u8>)>,
    /// How many reads the run made of memory that nothing had written and the file does not
    /// hold, and the addresses of the first few.
    pub unwritten: (u64, Vec<(Option<String>, u64)>),
    /// Imports whose stand-in ran, with how often.
    pub stand_ins: BTreeMap<String, u64>,
}

struct Emulator<'a> {
    binary: &'a mut Binary,
    abi: Abi,
    spaces: Spaces,
    memory: Memory,
    lifted: FxHashMap<u64, Rc<Lifted>>,
    registers: FxHashMap<String, Varnode>,
    /// The address of each call or tail call of an import, to its name and whether it is a tail call.
    imports: FxHashMap<u64, (String, bool)>,
    stack: (u64, u64),
    scratch: (u64, u64),
    /// The address the function returns to, which no code is at.
    sentinel: u64,
    /// Where the internal stack of an 8051 begins and the highest the stack pointer has been,
    /// whose bytes between are the stack's. The place of the stack pointer is the third.
    internal_stack: Option<(u64, Varnode)>,
    stack_high: u64,
    /// The internal memory of an 8051, where its register banks are.
    register_banks: Option<Space>,
    /// The blocks of scratch memory given out, as address and size.
    blocks: Vec<(u64, u64)>,
    /// Instructions run, and what the stand-ins charge for the bytes they move.
    steps: u64,
    notes: Vec<String>,
    /// Where the next allocation in scratch memory goes.
    heap: u64,
    stand_ins: BTreeMap<String, u64>,
    /// Whether the run did x87 arithmetic, which the control word rounds.
    x87: bool,
}

/// A region of `size` bytes below `top` that no section of the image is in.
fn free_region(image: &Image, top: u64, size: u64) -> (u64, u64) {
    let mut top = top;
    loop {
        let start = top - size;
        if image.sections.iter().all(|section| section.end() <= start || section.addr >= top) {
            return (start, top);
        }
        top = start;
    }
}

impl<'a> Emulator<'a> {
    fn new(binary: &'a mut Binary) -> Result<Emulator<'a>> {
        let image = &binary.program.image;
        let abi = abi(image)?;
        let imports = binary
            .program
            .analysis
            .calls
            .iter()
            .filter_map(|call| match call.target {
                CallTarget::Import(slot) => Some((call.at, (binary.program.import_name(slot)?.to_string(), call.tail))),
                CallTarget::Function(_) => None,
            })
            .collect();
        let stack = free_region(image, 0x7ff0_0000, STACK);
        let scratch = free_region(image, stack.0, SCRATCH);
        // The first page of scratch memory is where the function returns to. An 8051 has 16-bit
        // code addresses, and the last that no section holds will do.
        let sentinel = match image.machine {
            Machine::I8051 => (0..0x1_0000u64).rev().find(|&addr| image.section_at(addr).is_none()).context("the code fills the 64 KB of code memory")?,
            _ => scratch.0,
        };
        let mut spaces = Spaces::new();
        for name in abi.spaces {
            spaces.intern(name);
        }
        let register_banks = (image.machine == Machine::I8051).then(|| spaces.intern("INTMEM"));
        let memory = Memory { pages: FxHashMap::default(), code: spaces.intern(abi.code), big_endian: abi.big_endian, unwritten: 0, unwritten_first: Vec::new() };
        Ok(Emulator { binary, abi, spaces, memory, lifted: FxHashMap::default(), registers: FxHashMap::default(), imports, stack, scratch, sentinel, internal_stack: None, stack_high: 0, register_banks, blocks: Vec::new(), steps: 0, notes: Vec::new(), heap: scratch.0 + PAGE as u64, stand_ins: BTreeMap::new(), x87: false })
    }

    fn register(&mut self, name: &str) -> Result<Varnode, String> {
        if let Some(&found) = self.registers.get(name) {
            return Ok(found);
        }
        let (space, offset, size) = self.binary.register(name).map_err(|error| format!("no register {name}: {error}"))?;
        let found = Varnode { space: self.spaces.intern(&space), offset, size: size as usize };
        self.registers.insert(name.to_string(), found);
        Ok(found)
    }

    /// Where `place` is in the memory of the processor. The specification of the 8051 keeps `R0`
    /// to `R7` in a register file of their own, as the first register bank; on the chip they
    /// are eight bytes of internal memory, the bank that `RS1` and `RS0` select, and `@R0` and a
    /// direct address reach the same bytes.
    fn banked(&mut self, place: Varnode) -> Result<Varnode, String> {
        let Some(internal) = self.register_banks else { return Ok(place) };
        if place.space != REGISTER || place.offset + place.size as u64 > 8 {
            return Ok(place);
        }
        let (rs1, rs0) = (self.register("RS1")?, self.register("RS0")?);
        let bank = (self.get(rs1)? << 1 | self.get(rs0)?) as u64 & 3;
        Ok(Varnode { space: internal, offset: place.offset + 8 * bank, size: place.size })
    }

    fn get(&mut self, place: Varnode) -> Result<u128, String> {
        if place.size > 16 {
            return Err(format!("an operand of {} bytes is not run", place.size));
        }
        let place = self.banked(place)?;
        Ok(if place.space == CONST { u128::from(place.offset) } else { self.memory.read(&self.binary.program.image, place.space, place.offset, place.size) })
    }

    fn put(&mut self, place: Varnode, value: u128) -> Result<(), String> {
        if place.size > 16 {
            return Err(format!("an operand of {} bytes is not run", place.size));
        }
        let place = self.banked(place)?;
        let value = value & mask(place.size);
        if self.internal_stack.is_some_and(|(_, sp)| place.space == sp.space && place.offset == sp.offset) {
            self.stack_high = self.stack_high.max(value as u64);
        }
        self.memory.write(&self.binary.program.image, place.space, place.offset, place.size, value, true);
        Ok(())
    }

    fn read_register(&mut self, name: &str) -> Result<u128, String> {
        let place = self.register(name)?;
        self.get(place)
    }

    fn write_register(&mut self, name: &str, value: u128) -> Result<(), String> {
        let place = self.register(name)?;
        self.put(place, value)
    }

    fn write_scalar(&mut self, name: &str, value: Scalar) -> Result<(), String> {
        let place = self.register(name)?;
        let bits = match value {
            Scalar::Float { bits, size } if place.size == 10 => x87::widen(bits, size)?,
            Scalar::Float { size, .. } if size > place.size => return Err(format!("{name} has {} bytes, too few for a float of {size}", place.size)),
            Scalar::Int(bits) | Scalar::Float { bits, .. } => bits,
        };
        self.put(place, bits)
    }

    /// How the x87 rounds now, as its control word says.
    fn control(&mut self) -> Result<x87::Control, String> {
        Ok(x87::Control::from_word(self.read_register("FPUControlWord")?))
    }

    /// Runs an x87 instruction on the register stack, and sets the condition bits it defines in
    /// their registers and in the status word, which the specification keeps apart.
    fn x87_instruction(&mut self, instruction: x87::Instruction) -> Result<(), String> {
        self.x87 = true;
        let control = self.control()?;
        let outcome = x87::execute(instruction, self.read_register("ST0")?, self.read_register("ST1")?, control);
        let mut stack = [0; 8];
        for (index, held) in stack.iter_mut().enumerate() {
            *held = self.read_register(&format!("ST{index}"))?;
        }
        match outcome.stack {
            x87::Stack::Replace(top) => stack[0] = top,
            x87::Stack::Pop(top) => {
                // The specification pops by moving each register up, and leaves ST7 as it was.
                stack.copy_within(1.., 0);
                stack[0] = top;
            }
            x87::Stack::ReplacePush(top, pushed) => {
                stack.copy_within(..7, 1);
                stack[1] = top;
                stack[0] = pushed;
            }
            x87::Stack::Push(pushed) => {
                stack.copy_within(..7, 1);
                stack[0] = pushed;
            }
        }
        for (index, value) in stack.into_iter().enumerate() {
            self.write_register(&format!("ST{index}"), value)?;
        }
        let mut status = self.read_register("FPUStatusWord")?;
        for (index, (condition, bit)) in outcome.conditions.into_iter().zip([8, 9, 10, 14]).enumerate() {
            if let Some(set) = condition {
                self.write_register(&format!("C{index}"), u128::from(set))?;
                status = status & !(1 << bit) | u128::from(set) << bit;
            }
        }
        self.write_register("FPUStatusWord", status)
    }

    fn read_pointer(&mut self, addr: u64) -> u64 {
        self.memory.read(&self.binary.program.image, self.memory.code, addr, self.abi.pointer as usize) as u64
    }

    fn write_memory(&mut self, addr: u64, bytes: &[u8], mark: bool) {
        for (index, &byte) in bytes.iter().enumerate() {
            self.memory.write_byte(&self.binary.program.image, self.memory.code, addr + index as u64, byte, mark);
        }
    }

    /// The instruction at `pc`, lifting the code from there if it has not been.
    fn fetch(&mut self, pc: u64) -> Result<Rc<Lifted>, String> {
        if let Some(found) = self.lifted.get(&pc) {
            return Ok(found.clone());
        }
        let mut window = WINDOW;
        let instructions = loop {
            match self.binary.lift(pc, pc + window) {
                Ok(instructions) => break instructions,
                Err(error) if window <= 16 => return Err(format!("cannot decode the instruction at {pc:#x}: {error}")),
                Err(_) => window /= 2,
            }
        };
        for instruction in instructions {
            if instruction.text == "(bad)" {
                break;
            }
            let x86 = matches!(self.binary.program.image.machine, Machine::X86 | Machine::X86_64);
            let semantics = match instruction.text.split(' ').next().and_then(x87::Instruction::parse) {
                Some(whole) if x86 => Semantics::X87(whole),
                _ => Semantics::Pcode(instruction.pcode.iter().map(|line| parse_op(&mut self.spaces, line)).collect::<Result<Vec<_>>>().map_err(|error| format!("{error:#}"))),
            };
            self.lifted.entry(instruction.addr).or_insert_with(|| Rc::new(Lifted { len: instruction.len, semantics }));
        }
        self.lifted.get(&pc).cloned().ok_or_else(|| format!("no instruction decodes at {pc:#x}"))
    }

    /// Runs the operations of the instruction at `pc`: where execution goes next, or `None` for
    /// the instruction after it.
    fn execute(&mut self, lifted: &Lifted) -> Result<Option<u64>, String> {
        let ops = match &lifted.semantics {
            Semantics::Pcode(ops) => ops.as_ref().map_err(Clone::clone)?,
            &Semantics::X87(instruction) => {
                self.x87_instruction(instruction)?;
                return Ok(None);
            }
        };
        let mut index = 0;
        while let Some(op) = ops.get(index) {
            let here = index;
            index += 1;
            match op.code {
                Code::Branch | Code::CBranch => {
                    if op.code == Code::CBranch && self.get(op.inputs[1])? == 0 {
                        continue;
                    }
                    let place = op.inputs[0];
                    if place.space != CONST {
                        return Ok(Some(place.offset));
                    }
                    // A branch to a constant goes to another operation of the instruction, by
                    // how far from this one.
                    let to = here as i64 + signed(u128::from(place.offset), place.size) as i64;
                    if to < 0 || to as usize > ops.len() {
                        return Err("a branch leaves its instruction".into());
                    }
                    index = to as usize;
                }
                Code::Call => return Ok(Some(op.inputs[0].offset)),
                Code::BranchInd | Code::CallInd | Code::Return => return Ok(Some(self.get(op.inputs[0])? as u64)),
                Code::Load => {
                    let addr = self.get(op.inputs[0])? as u64;
                    let out = op.out.ok_or("a LOAD with no output")?;
                    let value = self.memory.read(&self.binary.program.image, op.space, addr, out.size);
                    self.put(out, value)?;
                }
                Code::Store => {
                    let addr = self.get(op.inputs[0])? as u64;
                    let value = self.get(op.inputs[1])?;
                    self.memory.write(&self.binary.program.image, op.space, addr, op.inputs[1].size, value, true);
                }
                Code::CallOther => {
                    if !HARMLESS.iter().any(|harmless| harmless.eq_ignore_ascii_case(&op.userop)) {
                        let name = if op.userop.is_empty() { "an unnamed operation" } else { &op.userop };
                        return Err(format!("the processor operation {name} is not run"));
                    }
                }
                Code::Unimplemented => return Err("the processor specification gives this instruction no semantics".into()),
                code => {
                    let mut inputs = Vec::with_capacity(op.inputs.len());
                    for &input in &op.inputs {
                        inputs.push((self.get(input)?, input.size));
                    }
                    let out = op.out.ok_or_else(|| format!("{code:?} with no output"))?;
                    let value = if x87::applies(code, out.size, &inputs) {
                        self.x87 = true;
                        let control = self.control()?;
                        x87::compute(code, out.size, &inputs, control)?
                    } else {
                        compute(code, out.size, &inputs, self.abi.arm_arithmetic)?
                    };
                    self.put(out, value)?;
                }
            }
        }
        Ok(None)
    }

    /// The `n`th argument of a call that is about to be made, or of a tail call that has been.
    fn argument(&mut self, n: usize, tail: bool) -> Result<u64, String> {
        if let Some(name) = self.abi.args.get(n) {
            return Ok(self.read_register(name)? as u64);
        }
        let sp = self.read_register(self.abi.stack)? as u64;
        let returns_on_stack = if tail && matches!(self.abi.returns, Returns::Pushed) { self.abi.pointer } else { 0 };
        let slot = (n - self.abi.args.len()) as u64;
        Ok(self.read_pointer(sp + returns_on_stack + self.abi.shadow + slot * self.abi.pointer))
    }

    /// Returns to the caller of a function that was tail-called: the return address is where
    /// the processor keeps it.
    fn return_from_tail(&mut self) -> Result<u64, String> {
        match self.abi.returns {
            Returns::Link(link) => Ok(self.read_register(link)? as u64 & !self.abi.mode_bit),
            Returns::Pushed => {
                let sp = self.read_register(self.abi.stack)? as u64;
                let to = self.read_pointer(sp);
                self.write_register(self.abi.stack, u128::from(sp + self.abi.pointer))?;
                Ok(to)
            }
            Returns::Internal => Err("an 8051 program has no imports to return from".into()),
        }
    }

    /// A block of scratch memory, or none when it has run out, as `malloc` has it.
    fn allocate(&mut self, size: u64) -> Option<u64> {
        let addr = (self.heap + 15) & !15;
        let end = addr.checked_add(size).filter(|&end| end <= self.scratch.1)?;
        self.heap = end;
        self.blocks.push((addr, size));
        Some(addr)
    }

    /// A length a stand-in is asked to move, which costs steps as the instructions that move it
    /// would, and may be no more than a block of scratch memory.
    fn length(&mut self, len: u64) -> Result<u64, String> {
        if len > LARGEST_BLOCK {
            return Err(format!("the run asked a stand-in to move {len} bytes, more than the {LARGEST_BLOCK} the oracle gives a block"));
        }
        self.steps += len / 16;
        Ok(len)
    }

    fn byte_at(&mut self, addr: u64) -> u8 {
        self.memory.read(&self.binary.program.image, self.memory.code, addr, 1) as u8
    }

    /// Runs the stand-in for the import `name` and gives the value it returns, if it does.
    fn stand_in(&mut self, name: &str, tail: bool) -> Result<Option<u64>, String> {
        let plain = name.trim_start_matches('_').trim_end_matches("_chk");
        Ok(match plain {
            "memcpy" | "memmove" => {
                let (to, from, len) = (self.argument(0, tail)?, self.argument(1, tail)?, self.argument(2, tail)?);
                let len = self.length(len)?;
                let bytes: Vec<u8> = (0..len).map(|index| self.byte_at(from + index)).collect();
                self.write_memory(to, &bytes, true);
                Some(to)
            }
            "memset" => {
                let (to, byte, len) = (self.argument(0, tail)?, self.argument(1, tail)?, self.argument(2, tail)?);
                let len = self.length(len)?;
                self.write_memory(to, &vec![byte as u8; len as usize], true);
                Some(to)
            }
            "memcmp" | "strncmp" | "strcmp" => {
                let (a, b) = (self.argument(0, tail)?, self.argument(1, tail)?);
                let limit = match plain {
                    "strcmp" => u64::MAX,
                    "memcmp" => {
                        let len = self.argument(2, tail)?;
                        self.length(len)?
                    }
                    _ => self.argument(2, tail)?,
                };
                let mut order = 0i64;
                for index in 0..limit {
                    let (x, y) = (self.byte_at(a + index), self.byte_at(b + index));
                    if x != y {
                        order = i64::from(x) - i64::from(y);
                        break;
                    }
                    if plain != "memcmp" && x == 0 {
                        break;
                    }
                }
                Some(order as u64)
            }
            "strlen" => {
                let at = self.argument(0, tail)?;
                let mut len = 0;
                while self.byte_at(at + len) != 0 {
                    len += 1;
                }
                Some(len)
            }
            "strcpy" => {
                let (to, from) = (self.argument(0, tail)?, self.argument(1, tail)?);
                let mut bytes = Vec::new();
                loop {
                    let byte = self.byte_at(from + bytes.len() as u64);
                    bytes.push(byte);
                    if byte == 0 {
                        break;
                    }
                }
                self.write_memory(to, &bytes, true);
                Some(to)
            }
            "abs" => Some(u64::from((self.argument(0, tail)? as i32).unsigned_abs())),
            "malloc" => {
                let size = self.argument(0, tail)?;
                Some(self.allocate(size).unwrap_or(0))
            }
            "calloc" => {
                let size = self.argument(0, tail)?.saturating_mul(self.argument(1, tail)?);
                Some(self.allocate(size).unwrap_or(0))
            }
            "free" => None,
            "abort" | "exit" | "Exit" | "stack_chk_fail" | "assert_fail" => return Err(format!("the run called {name}")),
            _ => return Err(format!("the run called {name}, an import with no stand-in")),
        })
    }

    /// The space called `name`, in any case, or the one the image is in when there is no name.
    fn space_named(&mut self, name: Option<&str>) -> Result<Space, String> {
        let Some(name) = name else { return Ok(self.memory.code) };
        match self.abi.spaces.iter().position(|known| known.eq_ignore_ascii_case(name)) {
            Some(index) => Ok(self.spaces.intern(self.abi.spaces[index])),
            None => Err(format!("this processor has no memory called {name}; it has {}", self.abi.spaces.join(", "))),
        }
    }

    /// Puts the arguments where the function finds them. Gives the buffers passed.
    fn start(&mut self, call: &Call) -> Result<Vec<Buffer>, String> {
        if let Some((word, _)) = self.abi.control_word {
            self.write_register("FPUControlWord", word)?;
        }
        let mut values = Vec::new();
        let mut buffers = Vec::new();
        for (index, arg) in call.args.iter().enumerate() {
            match arg {
                Arg::Value(value) => values.push(*value),
                Arg::Buffer(bytes) => {
                    let addr = self.allocate(bytes.len() as u64).ok_or("scratch memory ran out")?;
                    self.write_memory(addr, bytes, false);
                    buffers.push(Buffer { arg: index + 1, addr, before: bytes.clone(), after: Vec::new() });
                    values.push(Scalar::Int(u128::from(addr)));
                }
            }
        }
        if matches!(self.abi.returns, Returns::Internal) {
            if !values.is_empty() {
                return Err("an 8051 function takes its arguments in registers and memory that depend on its compiler: put them there with `set`".into());
            }
            self.start_internal(call)?;
        } else {
            self.start_on_stack(&values)?;
            for (name, value) in &call.registers {
                self.write_scalar(name, *value)?;
            }
        }
        for (space, _, _) in &call.dump {
            self.space_named(space.as_deref())?;
        }
        for (space, addr, bytes) in &call.memory {
            let space = self.space_named(space.as_deref())?;
            for (index, &byte) in bytes.iter().enumerate() {
                self.memory.write_byte(&self.binary.program.image, space, addr + index as u64, byte, false);
            }
        }
        Ok(buffers)
    }

    /// Arguments and the return address for a machine with a stack in memory or a link register.
    fn start_on_stack(&mut self, values: &[Scalar]) -> Result<(), String> {
        let pointer = self.abi.pointer;
        let (mut ints, mut floats) = (0, 0);
        let mut on_stack = Vec::new();
        for (index, &value) in values.iter().enumerate() {
            let (registers, taken, bits) = match value {
                Scalar::Int(bits) => (self.abi.args, &mut ints, bits),
                Scalar::Float { bits, .. } => (self.abi.floats.ok_or("where a float argument goes on 32-bit ARM depends on how the binary was built: pass its bits as an integer, or set its register")?, &mut floats, bits),
            };
            match registers.get(if self.abi.positional { index } else { *taken }) {
                Some(name) => {
                    *taken += 1;
                    self.write_register(name, bits)?;
                }
                None => on_stack.push(value),
            }
        }
        // A slot of the stack is a pointer wide, and a double takes two on x86.
        let slot = |value: &Scalar| match value {
            Scalar::Float { size, .. } => (*size as u64).max(pointer),
            Scalar::Int(_) => pointer,
        };
        let args_size: u64 = on_stack.iter().map(slot).sum();
        let base = (self.stack.1 - self.abi.shadow - args_size) & !(self.abi.alignment - 1);
        let mut at = base + self.abi.shadow;
        for value in &on_stack {
            let (Scalar::Int(bits) | Scalar::Float { bits, .. }) = *value;
            self.memory.write(&self.binary.program.image, self.memory.code, at, slot(value) as usize, bits, false);
            at += slot(value);
        }
        let sentinel = u128::from(self.sentinel);
        let sp = match self.abi.returns {
            Returns::Link(link) => {
                self.write_register(link, sentinel | u128::from(self.abi.mode_bit))?;
                base
            }
            _ => {
                self.memory.write(&self.binary.program.image, self.memory.code, base - pointer, pointer as usize, sentinel, false);
                base - pointer
            }
        };
        self.write_register(self.abi.stack, u128::from(sp))
    }

    /// The stack pointer the startup code of an 8051 image sets: `MOV SP,#n` within the first 64
    /// bytes at the reset vector, or where the reset vector's `LJMP` goes.
    fn startup_stack_pointer(&self) -> Option<u8> {
        let image = &self.binary.program.image;
        let mut start = image.bytes_from(image.entry)?;
        if let [0x02, high, low, ..] = *start {
            start = image.bytes_from(u64::from(high) << 8 | u64::from(low))?;
        }
        start.get(..64.min(start.len()))?.windows(3).find(|window| window[..2] == [0x75, 0x81]).map(|window| window[2])
    }

    /// The return address on the internal stack of an 8051, above the stack pointer the caller
    /// sets, or the one the startup code sets, or `INITIAL_SP`.
    fn start_internal(&mut self, call: &Call) -> Result<(), String> {
        for (name, value) in &call.registers {
            self.write_scalar(name, *value)?;
        }
        if call.registers.iter().any(|(name, _)| name.eq_ignore_ascii_case(self.abi.stack)) {
            self.notes.push("the internal stack began where the caller set SP".into());
        } else if let Some(found) = self.startup_stack_pointer() {
            self.write_register(self.abi.stack, u128::from(found))?;
            self.notes.push(format!("the internal stack began at SP = {found:#x}, as the startup code sets it"));
        } else {
            self.write_register(self.abi.stack, INITIAL_SP)?;
            self.notes.push(format!("the internal stack began at SP = {INITIAL_SP:#x}, which the oracle chose: set SP to put it elsewhere"));
        }
        let internal = self.space_named(Some("INTMEM"))?;
        let place = self.register(self.abi.stack)?;
        let mut sp = self.read_register(self.abi.stack)? as u64;
        self.internal_stack = Some((sp, place));
        self.stack_high = sp;
        for byte in [self.sentinel as u8, (self.sentinel >> 8) as u8] {
            sp = (sp + 1) & 0xff;
            self.memory.write_byte(&self.binary.program.image, internal, sp, byte, false);
        }
        self.write_register(self.abi.stack, u128::from(sp))
    }

    fn run(&mut self, entry: u64, steps: u64) -> Stop {
        let mut pc = entry;
        let started = Instant::now();
        let mut turns = 0u64;
        loop {
            if pc == self.sentinel {
                return Stop::Returned;
            }
            if self.steps >= steps {
                return Stop::Steps;
            }
            turns += 1;
            if turns.is_multiple_of(4096) && started.elapsed() > TIMEOUT {
                return Stop::Fault(format!("the run took more than {} seconds", TIMEOUT.as_secs()));
            }
            self.steps += 1;
            let lifted = match self.fetch(pc) {
                Ok(lifted) => lifted,
                Err(fault) => return Stop::Fault(fault),
            };
            let next = if let Some((name, tail)) = self.imports.get(&pc).cloned() {
                *self.stand_ins.entry(name.clone()).or_default() += 1;
                self.stand_in(&name, tail).and_then(|value| {
                    if let Some(value) = value {
                        self.write_register(self.abi.result, u128::from(value))?;
                    }
                    if tail { self.return_from_tail().map(Some) } else { Ok(None) }
                })
            } else {
                self.execute(&lifted)
            };
            match next {
                Ok(to) => pc = to.unwrap_or(pc + lifted.len),
                Err(fault) => return Stop::Fault(format!("{fault} at {pc:#x}")),
            }
        }
    }

    /// The bytes the run wrote outside its stack and the blocks of scratch memory, in runs, each
    /// with the name of its space unless that is the one the image is in.
    fn writes(&self) -> Vec<(Option<String>, u64, Vec<u8>)> {
        let mut pages: Vec<_> = self.memory.pages.iter().filter(|((space, _), _)| *space != REGISTER && *space != UNIQUE).collect();
        pages.sort_by_key(|(key, _)| **key);
        let mut runs: Vec<(Space, u64, Vec<u8>)> = Vec::new();
        for (&(space, index), page) in pages {
            for at in (0..PAGE).filter(|&at| page.dirty[at]) {
                let addr = index * PAGE as u64 + at as u64;
                if self.is_private(space, addr) {
                    continue;
                }
                match runs.last_mut() {
                    Some((last, start, bytes)) if *last == space && *start + bytes.len() as u64 == addr => bytes.push(page.bytes[at]),
                    _ => runs.push((space, addr, vec![page.bytes[at]])),
                }
            }
        }
        runs.into_iter().map(|(space, addr, bytes)| (self.space_label(space), addr, bytes)).collect()
    }

    /// The name of `space`, unless it is the one the image is in.
    fn space_label(&self, space: Space) -> Option<String> {
        (space != self.memory.code).then(|| self.spaces.0[space.0 as usize].clone())
    }

    /// Whether the run's own stack, or a block of scratch memory it was given, is at `addr` of
    /// `space`. A write that runs past a block lands outside it, and is reported.
    fn is_private(&self, space: Space, addr: u64) -> bool {
        match self.internal_stack {
            // The first register bank is registers, which the answer does not list as memory.
            Some((base, _)) => self.spaces.0[space.0 as usize] == "INTMEM" && (addr < 8 || addr > base && addr <= self.stack_high),
            None => space == self.memory.code && (addr >= self.stack.0 && addr < self.stack.1 || self.blocks.iter().any(|&(start, size)| addr >= start && addr - start < size)),
        }
    }

    /// A register as the caller asked to read it: `ST0`, or `XMM0:f64` for a float in its low
    /// bytes. A 10-byte register is an x87 one, which holds a float, and a float read from it
    /// is rounded as a store of it would be.
    fn reading(&mut self, name: String) -> Result<Reading, String> {
        let (register, view) = match name.split_once(':') {
            None => (name.as_str(), None),
            Some((register, "f32")) => (register, Some(4)),
            Some((register, "f64")) => (register, Some(8)),
            Some(_) => return Err(format!("`{name}`: a register reads as it is, or as a float with `:f32` or `:f64`")),
        };
        let place = self.register(register)?;
        let held = self.get(place)?;
        let (bits, size) = match view {
            None => (held, place.size),
            Some(size) if place.size == 10 => {
                let control = self.control()?;
                (x87::narrow(held, size, control)?, size)
            }
            Some(size) if size > place.size => return Err(format!("{register} has {} bytes, too few for a float of {size}", place.size)),
            Some(size) => (held & mask(size), size),
        };
        Ok(Reading { name, bits, size, float: view.is_some() || place.size == 10 })
    }

    fn outcome(&mut self, call: &Call, stop: Stop, mut buffers: Vec<Buffer>) -> Result<Outcome, String> {
        let code = self.memory.code;
        for buffer in &mut buffers {
            buffer.after = self.memory.peek(&self.binary.program.image, code, buffer.addr, buffer.before.len());
        }
        let mut registers = Vec::new();
        for name in self.abi.result_rest.iter().map(|name| name.to_string()).chain(call.read.iter().cloned()) {
            registers.push(self.reading(name)?);
        }
        if let Some((word, system)) = self.abi.control_word.filter(|_| self.x87 && !call.registers.iter().any(|(name, _)| name.eq_ignore_ascii_case("FPUControlWord"))) {
            let x87::Control { precision, .. } = x87::Control::from_word(word);
            self.notes.push(format!("the x87 began with control word {word:#x}, which a thread starts with on {system}: {precision}-bit precision, rounding to nearest. Set FPUControlWord to change it"));
        }
        let mut dumps = Vec::new();
        for (space, addr, len) in &call.dump {
            let space = self.space_named(space.as_deref())?;
            dumps.push((self.space_label(space), *addr, self.memory.peek(&self.binary.program.image, space, *addr, *len)));
        }
        let result = self.reading(self.abi.result.to_string())?;
        let unwritten = (self.memory.unwritten, self.memory.unwritten_first.iter().map(|&(space, addr)| (self.space_label(space), addr)).collect());
        Ok(Outcome { stop, steps: self.steps, notes: std::mem::take(&mut self.notes), result, registers, dumps, buffers, writes: self.writes(), unwritten, stand_ins: std::mem::take(&mut self.stand_ins) })
    }
}

/// Runs `call` on the binary. The run, not the call, can fail: see [`Stop`]; an `Err` is a call
/// that cannot be set up.
pub fn emulate(binary: &mut Binary, call: &Call) -> Result<Outcome> {
    let mut emulator = Emulator::new(binary)?;
    let buffers = emulator.start(call).map_err(anyhow::Error::msg)?;
    // What the setup wrote is not the function's doing.
    for page in emulator.memory.pages.values_mut() {
        page.dirty = [false; PAGE];
    }
    let stop = emulator.run(call.entry, call.steps);
    emulator.outcome(call, stop, buffers).map_err(anyhow::Error::msg)
}

/// The arguments of the `run` tool.
#[derive(Deserialize)]
pub struct Run {
    function: String,
    #[serde(default)]
    args: Vec<Given>,
    #[serde(default)]
    set: Vec<String>,
    #[serde(default)]
    read: Vec<String>,
    #[serde(default)]
    dump: Vec<String>,
    steps: Option<u64>,
    bits: Option<u32>,
}

/// A number or a text, as JSON has it.
#[derive(Deserialize)]
#[serde(untagged)]
enum Given {
    Signed(i64),
    Unsigned(u64),
    Text(String),
}

fn number(text: &str) -> Result<u128> {
    let text = text.trim();
    let (negative, digits) = text.strip_prefix('-').map_or((false, text), |digits| (true, digits));
    let value = match digits.strip_prefix("0x").or_else(|| digits.strip_prefix("0X")) {
        Some(hex) => u128::from_str_radix(hex, 16),
        None => digits.parse(),
    }
    .with_context(|| format!("`{text}` is not a number: write decimal, or hex as 0x1f"))?;
    Ok(if negative { value.wrapping_neg() } else { value })
}

/// A count of bytes that fits a block of scratch memory.
fn size(text: &str) -> Result<usize> {
    let count = number(text)?;
    ensure!(count <= u128::from(LARGEST_BLOCK), "`{text}` bytes is more than the {LARGEST_BLOCK} that fit a block");
    Ok(count as usize)
}

fn hex_bytes(text: &str) -> Result<Vec<u8>> {
    let digits: Vec<u8> = text.bytes().filter(|byte| !byte.is_ascii_whitespace()).collect();
    ensure!(digits.len().is_multiple_of(2), "`{text}` has an odd number of hex digits");
    digits.chunks(2).map(|pair| u8::from_str_radix(std::str::from_utf8(pair)?, 16).with_context(|| format!("`{text}` is not hex"))).collect()
}

/// A number, or `f32:` or `f64:` and a float in decimal.
fn scalar(text: &str) -> Result<Scalar> {
    let not_a_float = || format!("`{text}` is not a float: write a decimal, as 1.5, -2e-3 or inf");
    Ok(match text.split_once(':') {
        Some(("f32", value)) => Scalar::Float { bits: u128::from(value.trim().parse::<f32>().with_context(not_a_float)?.to_bits()), size: 4 },
        Some(("f64", value)) => Scalar::Float { bits: u128::from(value.trim().parse::<f64>().with_context(not_a_float)?.to_bits()), size: 8 },
        _ => Scalar::Int(number(text)?),
    })
}

/// An argument given as text: a number or a float, or `hex:` bytes, `str:` text with its end, or
/// `buf:` a count of zero bytes, each of which is put in memory and passed by its address.
fn arg(given: &Given) -> Result<Arg> {
    Ok(match given {
        Given::Signed(value) => Arg::Value(Scalar::Int(*value as u128)),
        Given::Unsigned(value) => Arg::Value(Scalar::Int(u128::from(*value))),
        Given::Text(text) => match text.split_once(':') {
            Some(("hex", bytes)) => Arg::Buffer(hex_bytes(bytes)?),
            Some(("str", text)) => Arg::Buffer(text.bytes().chain([0]).collect()),
            Some(("buf", count)) => Arg::Buffer(vec![0; size(count)?]),
            _ => Arg::Value(scalar(text)?),
        },
    })
}

/// An address as written, after the name of its space unless it is in the image's.
fn place(space: &Option<String>, addr: u64) -> String {
    match space {
        Some(space) => format!("{space}:{addr:#x}"),
        None => format!("{addr:#x}"),
    }
}

fn count(n: usize, noun: &str) -> String {
    format!("{n} {noun}{}", if n == 1 { "" } else { "s" })
}

fn hex(bytes: &[u8]) -> String {
    let shown: Vec<String> = bytes.iter().take(SHOWN).map(|byte| format!("{byte:02x}")).collect();
    let more = if bytes.len() > SHOWN { format!(" ... ({} bytes)", bytes.len()) } else { String::new() };
    format!("{}{more}", shown.join(" "))
}

/// A register's value as hex and decimal: a float's in decimal, and an integer's as unsigned and,
/// if its top bit is set, as signed, of the low `bits` bits of it when the caller says the
/// function returns fewer than it holds.
fn value(reading: &Reading, bits: Option<u32>) -> String {
    let &Reading { ref name, bits: held, size, float } = reading;
    if float {
        return format!("{name} = {held:#x} ({})", x87::decimal(held, size));
    }
    let width = bits.map_or(8 * size, |bits| (bits as usize).clamp(1, 8 * size));
    let held = if width >= 128 { held } else { held & ((1u128 << width) - 1) };
    let mut text = format!("{name} = {held:#x} ({held}");
    if held >> (width - 1) & 1 == 1 {
        let spare = 128 - width as u32;
        write!(text, ", {} signed", ((held << spare) as i128) >> spare).expect("writing to a string");
    }
    text.push(')');
    text
}

/// The `run` tool.
pub fn run(binary: &mut Binary, args: Run) -> Result<String> {
    ensure!(args.bits != Some(0), "`bits` is at least 1");
    // A name, or else exactly the address: the function the address is in may start before it.
    let entry = match binary.program.function_named(&args.function) {
        Ok(entry) => entry,
        Err(_) => parse_addr(&args.function).filter(|&addr| binary.program.image.is_code(addr)).with_context(|| format!("`{}` is neither a function of the binary nor an address in its code", args.function))?,
    };
    let mut dump = Vec::new();
    for range in &args.dump {
        let parts: Vec<&str> = range.split(':').collect();
        let (space, addr, len) = match parts.as_slice() {
            [addr, len] => (None, *addr, *len),
            [space, addr, len] => (Some(space.to_string()), *addr, *len),
            _ => bail!("`{range}` is not ADDRESS:LENGTH or SPACE:ADDRESS:LENGTH"),
        };
        dump.push((space, parse_addr(addr).with_context(|| format!("`{addr}` is not an address"))?, size(len)?));
    }
    let mut call = Call { entry, args: args.args.iter().map(arg).collect::<Result<_>>()?, registers: Vec::new(), memory: Vec::new(), read: args.read, dump, steps: args.steps.unwrap_or(DEFAULT_STEPS) };
    for setting in &args.set {
        let (place, what) = setting.split_once('=').with_context(|| format!("`{setting}` is not REGISTER=number, 0xADDRESS=hex:bytes or SPACE:0xADDRESS=hex:bytes"))?;
        let (space, addr) = place.rsplit_once(':').map_or((None, place), |(space, addr)| (Some(space.to_string()), addr));
        if addr.starts_with("0x") {
            let bytes = what.strip_prefix("hex:").map(hex_bytes).with_context(|| format!("`{setting}`: memory takes `hex:` bytes"))??;
            call.memory.push((space, parse_addr(addr).with_context(|| format!("`{addr}` is not an address"))?, bytes));
        } else {
            call.registers.push((place.to_string(), scalar(what)?));
        }
    }
    let outcome = emulate(binary, &call)?;
    let label = binary.program.label(entry);
    let mut out = String::new();
    let result = &outcome.result;
    match &outcome.stop {
        Stop::Returned => writeln!(out, "{label} returned {} after {} instructions", value(result, args.bits), outcome.steps)?,
        Stop::Steps => writeln!(out, "{label} did not return in {} instructions; {} holds {:#x}", outcome.steps, result.name, result.bits)?,
        Stop::Fault(fault) => writeln!(out, "{label} stopped after {} instructions: {fault}", outcome.steps)?,
    }
    for reading in &outcome.registers {
        writeln!(out, "{}", value(reading, None))?;
    }
    for (space, addr, bytes) in &outcome.dumps {
        writeln!(out, "{} at {}: {}", count(bytes.len(), "byte"), place(space, *addr), hex(bytes))?;
    }
    for buffer in &outcome.buffers {
        let state = if buffer.before == buffer.after { "unchanged" } else { "now" };
        writeln!(out, "argument {}, a buffer at {:#x}, {state}: {}", buffer.arg, buffer.addr, hex(&buffer.after))?;
    }
    for (space, addr, bytes) in outcome.writes.iter().take(RANGES_SHOWN) {
        writeln!(out, "wrote {} at {}: {}", count(bytes.len(), "byte"), place(space, *addr), hex(bytes))?;
    }
    if outcome.writes.len() > RANGES_SHOWN {
        writeln!(out, "... and {} more ranges", outcome.writes.len() - RANGES_SHOWN)?;
    }
    for note in &outcome.notes {
        writeln!(out, "{note}")?;
    }
    if !outcome.stand_ins.is_empty() {
        let used: Vec<String> = outcome.stand_ins.iter().map(|(name, count)| format!("{name} x{count}")).collect();
        writeln!(out, "ran stand-ins for: {}", used.join(", "))?;
    }
    let (count, first) = &outcome.unwritten;
    if *count > 0 {
        let image = &binary.program.image;
        let first: Vec<String> = first
            .iter()
            .map(|(space, addr)| match thumb::MEMORY.iter().find(|&&(start, end, _)| image.machine == Machine::Thumb && *addr >= start && *addr < end) {
                Some((_, _, region)) => format!("{} ({region})", place(space, *addr)),
                None => place(space, *addr),
            })
            .collect();
        writeln!(out, "read memory that nothing had written and the file does not hold {count}x, as zeros: the first at {}", first.join(", "))?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(code: Code, size: usize, inputs: &[(u128, usize)]) -> u128 {
        compute(code, size, inputs, false).unwrap()
    }

    #[test]
    fn arithmetic_flags_are_those_of_the_sized_operands() {
        assert_eq!(run(Code::Carry, 1, &[(0xff, 1), (1, 1)]), 1);
        assert_eq!(run(Code::Carry, 1, &[(0x7f, 1), (1, 1)]), 0);
        assert_eq!(run(Code::SCarry, 1, &[(0x7f, 1), (1, 1)]), 1);
        assert_eq!(run(Code::SCarry, 1, &[(0xff, 1), (1, 1)]), 0);
        assert_eq!(run(Code::SBorrow, 1, &[(0x80, 1), (1, 1)]), 1);
        assert_eq!(run(Code::SBorrow, 1, &[(0, 1), (1, 1)]), 0);
        assert_eq!(run(Code::Carry, 16, &[(u128::MAX, 16), (1, 16)]), 1);
    }

    #[test]
    fn shifts_past_the_width_clear_or_fill() {
        assert_eq!(run(Code::Left, 4, &[(1, 4), (32, 1)]), 0);
        assert_eq!(run(Code::Left, 4, &[(1, 4), (31, 1)]), 0x8000_0000);
        assert_eq!(run(Code::Right, 4, &[(0x8000_0000, 4), (40, 1)]), 0);
        assert_eq!(run(Code::SRight, 4, &[(0x8000_0000, 4), (40, 1)]), 0xffff_ffff);
        assert_eq!(run(Code::SRight, 4, &[(0x8000_0000, 4), (4, 1)]), 0xf800_0000);
    }

    #[test]
    fn pieces_join_and_cut_by_bytes() {
        assert_eq!(run(Code::Piece, 4, &[(0x1234, 2), (0xabcd, 2)]), 0x1234_abcd);
        assert_eq!(run(Code::SubPiece, 1, &[(0x1234_abcd, 4), (2, 4)]), 0x34);
        assert_eq!(run(Code::SExt, 8, &[(0xfe, 1)]), 0xffff_ffff_ffff_fffe);
        assert_eq!(run(Code::ZExt, 8, &[(0xfe, 1)]), 0xfe);
    }

    #[test]
    fn signed_division_rounds_toward_zero_and_a_zero_divisor_is_the_machines() {
        assert_eq!(run(Code::SDiv, 4, &[(0xffff_fff9, 4), (2, 4)]), 0xffff_fffd);
        assert_eq!(run(Code::SRem, 4, &[(0xffff_fff9, 4), (2, 4)]), 0xffff_ffff);
        assert_eq!(compute(Code::Div, 4, &[(1, 4), (0, 4)], false), Err("division by zero".into()));
        assert_eq!(compute(Code::Div, 4, &[(1, 4), (0, 4)], true), Ok(0));
    }

    #[test]
    fn floats_compute_in_the_width_of_their_operands() {
        let (one, two) = (u128::from(1.0f32.to_bits()), u128::from(2.0f32.to_bits()));
        assert_eq!(run(Code::FAdd, 4, &[(one, 4), (one, 4)]), two);
        assert_eq!(run(Code::Trunc, 4, &[(u128::from((-2.5f32).to_bits()), 4)]), 0xffff_fffe);
        assert_eq!(compute(Code::FAdd, 2, &[(0, 2), (0, 2)], false), Err("floating point of 2 bytes is not run".into()));
    }

    #[test]
    fn every_operation_the_lifter_can_write_is_known_or_deliberately_not() {
        // Placeholders of the sleigh compiler and operations of the decompiler's own graphs, which no
        // instruction lifts to.
        let internal = ["BLANK", "BUILD", "DELAY_SLOT", "LABEL", "CROSSBUILD", "CAST", "SEGMENTOP", "CPOOLREF", "NEW", "INSERT", "EXTRACT", "UNUSED1"];
        let source = include_str!("../../../third_party/ghidra-decompiler/cpp/opcodes.cc");
        let table = source.split_once("opcode_name[] = {").and_then(|(_, rest)| rest.split_once("};")).expect("the table of names").0;
        let names: Vec<&str> = table.split('"').skip(1).step_by(2).collect();
        assert!(names.contains(&"INT2FLOAT") && names.len() > 60, "{names:?}");
        for name in names.into_iter().filter(|name| !name.is_empty() && !internal.contains(name)) {
            assert!(Code::parse(name).is_some(), "{name} is a p-code operation the interpreter does not know");
        }
    }

    #[test]
    fn a_float_out_of_range_is_the_machines() {
        let (nan, big) = (f64::NAN, 1e10);
        let word = |value: u128| value & mask(4);
        assert_eq!(word(float_to_int(-2.9, 4, false)), 0xffff_fffe);
        assert_eq!(word(float_to_int(nan, 4, false)), 0x8000_0000);
        assert_eq!(word(float_to_int(big, 4, false)), 0x8000_0000);
        assert_eq!(word(float_to_int(nan, 4, true)), 0);
        assert_eq!(word(float_to_int(big, 4, true)), 0x7fff_ffff);
        assert_eq!(word(float_to_int(-big, 4, true)), 0x8000_0000);
        assert_eq!(float_to_int(1e19, 8, false) & mask(8), 0x8000_0000_0000_0000);
    }

    #[test]
    fn a_wide_integer_becomes_a_narrow_float_by_one_rounding() {
        let wide = (1u128 << 60) + (1 << 36) + 1;
        assert_eq!(run(Code::Int2Float, 4, &[(wide, 8)]), 0x5d80_0001);
    }
}
