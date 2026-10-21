//! Writes Rust source that does what the functions reachable from some roots do, one Rust
//! function per function, each instruction's raw p-code as statements. The source runs on
//! `recore-machine` (crates/machine): `Cpu`, `dispatch`, and the p-code and x87 semantics the
//! emulator runs too. [`super::workspace`] writes it out as a cargo workspace.

use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
};

use super::*;

struct Insn {
    addr: u64,
    len: u64,
    semantics: Semantics,
    /// What the instruction does to the depth of the x87 stack, by its mnemonic.
    x87: Step,
}

/// What an instruction does to the depth of the x87 stack.
#[derive(Clone, Copy, PartialEq)]
enum Step {
    /// Pushes this many values, less those it pops.
    By(i32),
    /// Empties the stack (FNINIT).
    Empty,
    /// Sets the stack from memory, or stores every register, empty ones too (FRSTOR, FSAVE), or
    /// uses the x87 registers as MMX registers, which keep values across calls.
    Whole,
}

/// The x87 stack step of an instruction, by its mnemonic and operands as Ghidra prints them.
fn x87_step(text: &str) -> Step {
    if text.split([' ', ',']).any(|word| word.len() == 3 && word.starts_with("MM") && word.as_bytes()[2].is_ascii_digit()) || matches!(text.split(' ').next(), Some("EMMS" | "FEMMS")) {
        return Step::Whole;
    }
    Step::By(match text.split(' ').next().unwrap_or("") {
        "FLD" | "FILD" | "FBLD" | "FLD1" | "FLDZ" | "FLDPI" | "FLDL2E" | "FLDL2T" | "FLDLG2" | "FLDLN2" | "FDECSTP" | "FXTRACT" | "FPTAN" | "FSINCOS" => 1,
        "FSTP" | "FISTP" | "FISTTP" | "FBSTP" | "FCOMP" | "FUCOMP" | "FICOMP" | "FCOMIP" | "FUCOMIP" | "FADDP" | "FSUBP" | "FSUBRP" | "FMULP" | "FDIVP" | "FDIVRP" | "FPATAN" | "FYL2X" | "FYL2XP1" | "FINCSTP" | "FFREEP" => -1,
        "FCOMPP" | "FUCOMPP" => -2,
        "FNINIT" | "FINIT" => return Step::Empty,
        "FNSAVE" | "FSAVE" | "FRSTOR" | "FLDENV" | "FXSAVE" | "FXRSTOR" => return Step::Whole,
        _ => 0,
    })
}

fn lift_range(binary: &mut Binary, spaces: &mut Spaces, start: u64, end: u64, out: &mut Vec<Insn>) -> Result<()> {
    let mut pc = start;
    while pc < end {
        let mut window = WINDOW.min(end - pc).max(16);
        let instructions = loop {
            match binary.lift(pc, pc + window) {
                Ok(found) if !found.is_empty() => break found,
                Ok(_) | Err(_) if window <= 16 => bail!("cannot decode at {pc:#x}"),
                _ => window /= 2,
            }
        };
        let before = pc;
        for instruction in instructions {
            if instruction.addr != pc || instruction.text == "(bad)" || pc >= end {
                break;
            }
            let semantics = match instruction.text.split(' ').next().and_then(x87::Instruction::parse) {
                Some(whole) => Semantics::X87(whole),
                None => Semantics::Pcode(instruction.pcode.iter().map(|line| parse_op(spaces, line)).collect::<Result<Vec<_>>>().map_err(|e| format!("{e:#}"))),
            };
            out.push(Insn { addr: pc, len: instruction.len, semantics, x87: x87_step(&instruction.text) });
            pc += instruction.len;
        }
        if pc == before {
            bail!("no progress at {pc:#x}");
        }
    }
    Ok(())
}

fn mask_of(size: usize) -> String {
    if size >= 16 { "u128::MAX".into() } else { format!("{:#x}u128", (1u128 << (8 * size)) - 1) }
}

/// The Rust type a value of `size` bytes is kept in: the unsigned integer of its width, and
/// u128 for the odd sizes, which `fit` cuts to their bytes.
fn ty(size: usize) -> &'static str {
    match size {
        1 => "u8",
        2 => "u16",
        4 => "u32",
        8 => "u64",
        _ => "u128",
    }
}

/// The signed type of `ty`'s width.
fn sty(size: usize) -> &'static str {
    match size {
        1 => "i8",
        2 => "i16",
        4 => "i32",
        8 => "i64",
        _ => "i128",
    }
}

/// Whether a value of `size` bytes fills its type, so its arithmetic wraps by itself.
fn whole(size: usize) -> bool {
    matches!(size, 1 | 2 | 4 | 8 | 16)
}

/// `expr` cut to `size` bytes, for the sizes that do not fill their type.
fn fit(expr: String, size: usize) -> String {
    if whole(size) { expr } else { format!("({expr} & {})", mask_of(size)) }
}

/// `expr`, a value of `from` bytes, as one of `to` bytes: zero-extended or cut.
fn cast(expr: String, from: usize, to: usize) -> String {
    if ty(from) == ty(to) { if from > to { fit(expr, to) } else { expr } } else { fit(format!("({} as {})", typed(expr, from), ty(to)), to) }
}

/// `expr`, a value of `size` bytes, as a signed integer of its width (i128 for the odd sizes).
fn signed_of(expr: &str, size: usize) -> String {
    let expr = typed(expr.to_string(), size);
    if whole(size) {
        format!("({expr} as {})", sty(size))
    } else {
        let shift = 128 - 8 * size;
        format!("((({expr}) as i128) << {shift} >> {shift})")
    }
}

/// A constant of `size` bytes, without a type: Rust infers it from where it is used, and
/// `typed` gives it one where nothing does.
fn lit(value: u64, size: usize) -> String {
    let value = if size < 8 { value & ((1 << (8 * size)) - 1) } else { value };
    format!("{value:#x}")
}

/// `expr`, a value of `size` bytes, with its type written out if it is a bare constant: as the
/// receiver of a method, the operand of a cast, or the left of an operator.
fn typed(expr: String, size: usize) -> String {
    if expr.starts_with("0x") && expr[2..].bytes().all(|b| b.is_ascii_hexdigit()) { format!("{expr}{}", ty(size)) } else { expr }
}

/// `c.<name>(args)`. An argument that calls into `c` itself is bound first, since a call
/// cannot borrow `c` while one of its arguments does.
fn call(name: &str, args: &[String]) -> String {
    let args: Vec<String> = args.iter().map(|a| bare(a).to_string()).collect();
    if args.iter().any(|a| a.contains("c.")) {
        let lets: String = args.iter().enumerate().map(|(i, a)| format!("let a{i} = {a}; ")).collect();
        let names: Vec<String> = (0..args.len()).map(|i| format!("a{i}")).collect();
        format!("({{ {lets}c.{name}({}) }})", names.join(", "))
    } else {
        format!("c.{name}({})", args.join(", "))
    }
}

/// `expr` without the parentheses around all of it, which an argument does not need.
fn bare(expr: &str) -> &str {
    let Some(inner) = expr.strip_prefix('(').and_then(|e| e.strip_suffix(')')) else { return expr };
    let mut depth = 0i32;
    for b in inner.bytes() {
        depth += match b {
            b'(' => 1,
            b')' => -1,
            _ => 0,
        };
        if depth < 0 {
            return expr;
        }
    }
    if depth == 0 { inner } else { expr }
}

/// A load of `size` bytes from the address `addr`, a u32.
fn load(addr: String, size: usize) -> String {
    if matches!(size, 1 | 2 | 4 | 8) { call(&format!("ld_{}", ty(size)), &[addr]) } else { cast(call("ld", &[addr, size.to_string()]), 16, size) }
}

/// A store of `value`, of `size` bytes, at the address `addr`.
fn store(addr: String, value: String, size: usize) -> String {
    let statement = if matches!(size, 1 | 2 | 4 | 8) { call(&format!("st_{}", ty(size)), &[addr, value]) } else { call("st", &[addr, size.to_string(), cast(value, size, 16)]) };
    format!("{statement};")
}

/// The registers kept in locals: the general registers as `r0` to `r7` (u32), the flag bytes
/// 0x200 to 0x20f as `f[0]` to `f[15]` (u8), and the x87 stack as `st0` to `st7`: u128 in the
/// extended format, or f64 in a fast body (`fast`), which these read and write as extended bits.
/// A read is a value of the type of its size (`ty`).
fn local_read(off: u64, size: usize, fast: bool) -> Option<String> {
    let end = off + size as u64;
    if end <= 0x20 {
        let (slot, byte) = (off / 4, off % 4);
        if byte + size as u64 <= 4 {
            return Some(match (byte, size) {
                (0, 4) => format!("r{slot}"),
                (0, _) => fit(format!("(r{slot} as {})", ty(size)), size),
                _ => fit(format!("((r{slot} >> {}) as {})", 8 * byte, ty(size)), size),
            });
        }
        let parts: Vec<String> = (0..size as u64).map(|i| { let o = off + i; format!("((((r{} >> {}) & 0xff) as u128) << {})", o / 4, 8 * (o % 4), 8 * i) }).collect();
        return Some(cast(format!("({})", parts.join(" | ")), 16, size));
    }
    if (0x200..0x210).contains(&off) && end <= 0x210 {
        if size == 1 {
            return Some(format!("f[{}]", off - 0x200));
        }
        let parts: Vec<String> = (0..size as u64).map(|i| format!("((f[{}] as u128) << {})", off + i - 0x200, 8 * i)).collect();
        return Some(cast(format!("({})", parts.join(" | ")), 16, size));
    }
    if (0x1100..0x1180).contains(&off) && (off - 0x1100) % 16 + size as u64 <= 10 {
        let (slot, byte) = ((off - 0x1100) / 16, (off - 0x1100) % 16);
        let st = if fast { format!("f64_to_f80(st{slot})") } else { format!("st{slot}") };
        return Some(if byte == 0 && size == 10 { st } else { cast(format!("({st} >> {})", 8 * byte), 16, size) });
    }
    None
}

/// The statement that writes `value`, of the type of `size`, to a register kept in a local.
fn local_write(off: u64, size: usize, fast: bool, value: &str) -> Option<String> {
    let end = off + size as u64;
    if end <= 0x20 {
        let (slot, byte) = (off / 4, off % 4);
        if byte == 0 && size == 4 {
            return Some(format!("r{slot} = {value};"));
        }
        if byte + size as u64 <= 4 {
            let m = (((1u64 << (8 * size)) - 1) << (8 * byte)) as u32;
            let shift = if byte == 0 { String::new() } else { format!(" << {}", 8 * byte) };
            return Some(format!("r{slot} = (r{slot} & {:#x}) | ({} as u32){shift};", !m, typed(value.to_string(), size)));
        }
        let parts: Vec<String> = (0..size as u64).map(|i| { let o = off + i; let sh = 8 * (o % 4); format!("r{0} = (r{0} & !(0xffu32 << {sh})) | ((((v >> {1}) & 0xff) as u32) << {sh});", o / 4, 8 * i) }).collect();
        return Some(format!("{{ let v = {} as u128; {} }}", typed(value.to_string(), size), parts.join(" ")));
    }
    if (0x200..0x210).contains(&off) && end <= 0x210 {
        if size == 1 {
            return Some(format!("f[{}] = {value};", off - 0x200));
        }
        let parts: Vec<String> = (0..size as u64).map(|i| format!("f[{}] = (v >> {}) as u8;", off + i - 0x200, 8 * i)).collect();
        return Some(format!("{{ let v = {} as u128; {} }}", typed(value.to_string(), size), parts.join(" ")));
    }
    if (0x1100..0x1180).contains(&off) && (off - 0x1100) % 16 + size as u64 <= 10 {
        let (slot, byte) = ((off - 0x1100) / 16, (off - 0x1100) % 16);
        let (m, sh) = (mask_of(size), 8 * byte);
        return Some(match (fast, byte == 0 && size == 10) {
            (true, true) => format!("st{slot} = f80_to_f64({value});"),
            (true, false) => format!("{{ let v = {} as u128; st{slot} = f80_to_f64((f64_to_f80(st{slot}) & !({m} << {sh})) | ((v & {m}) << {sh})); }}", typed(value.to_string(), size)),
            (false, true) => format!("st{slot} = ({value}) & {};", mask_of(10)),
            (false, false) => format!("{{ let v = {} as u128; st{slot} = (st{slot} & !({m} << {sh})) | ((v & {m}) << {sh}); }}", typed(value.to_string(), size)),
        });
    }
    None
}

fn touches_locals(off: u64, size: usize) -> bool {
    let end = off + size as u64;
    off < 0x20 || (off < 0x210 && end > 0x200) || (off < 0x1180 && end > 0x1100)
}

/// The registers the runtime reads and writes by name, which lift() writes to regs.rs.
const RUNTIME_REGISTERS: [&str; 23] = ["EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI", "FS_OFFSET", "FPUControlWord", "FPUStatusWord", "ST0", "ST1", "ST2", "ST3", "ST4", "ST5", "ST6", "ST7", "C0", "C1", "C2", "C3"];

const GPR: &str = "[r0, r1, r2, r3, r4, r5, r6, r7]";
/// The flag bytes 0x200 to 0x20f, as one array: `f[6]` is the byte at 0x206, the zero flag.
const FLAGS: &str = "f";
const ST: &str = "[st0, st1, st2, st3, st4, st5, st6, st7]";

fn mutable(pattern: &str) -> String {
    pattern.replace('[', "[mut ").replace(", ", ", mut ")
}

fn save(fast: bool) -> String {
    if fast { format!("c.save_g({GPR}); c.save_f({FLAGS}); c.save_st64({ST});") } else { format!("c.save({GPR}, {FLAGS}, {ST});") }
}


/// The instructions reachable from `entry` by falling through and branching, for a call target
/// the analysis did not make a function.
fn discover(binary: &mut Binary, spaces: &mut Spaces, entry: u64) -> Result<Vec<Insn>> {
    let mut seen: BTreeMap<u64, Insn> = BTreeMap::new();
    let mut work = vec![entry];
    while let Some(pc) = work.pop() {
        if seen.contains_key(&pc) {
            continue;
        }
        ensure!(seen.len() < 20000, "more than 20000 instructions from {entry:#x}");
        let mut one = Vec::new();
        let instructions = binary.lift(pc, pc + 16)?;
        let instruction = instructions.into_iter().find(|i| i.addr == pc).with_context(|| format!("nothing decodes at {pc:#x}"))?;
        let semantics = match instruction.text.split(' ').next().and_then(x87::Instruction::parse) {
            Some(whole) => Semantics::X87(whole),
            None => Semantics::Pcode(instruction.pcode.iter().map(|line| parse_op(spaces, line)).collect::<Result<Vec<_>>>().map_err(|e| format!("{e:#}"))),
        };
        let mut falls = true;
        if let Semantics::Pcode(Ok(ops)) = &semantics {
            for op in ops {
                match op.code {
                    Code::Branch | Code::CBranch if op.inputs[0].space != CONST => {
                        work.push(op.inputs[0].offset);
                        falls &= op.code == Code::CBranch;
                    }
                    Code::Return | Code::BranchInd => falls = false,
                    _ => {}
                }
            }
        }
        if falls {
            work.push(pc + instruction.len);
        }
        one.push(Insn { addr: pc, len: instruction.len, semantics, x87: x87_step(&instruction.text) });
        seen.insert(pc, one.pop().unwrap());
    }
    Ok(seen.into_values().collect())
}

/// The x87 register a 10-byte register varnode is, if it is one whole.
fn st_slot(v: Varnode) -> Option<u64> {
    (v.space == REGISTER && v.size == 10 && (0x1100..0x1180).contains(&v.offset) && (v.offset - 0x1100) % 16 == 0).then(|| (v.offset - 0x1100) / 16)
}

/// How one instruction's ops read and write their values, each of the Rust type of its size
/// (`ty`): registers in the body's locals, temporaries in locals of their offset and size
/// (`u<offset>_<size>`, and `x<offset>` for a fast body's 10-byte floats), or folded into the
/// one op that reads them (`folds`).
struct Values<'a> {
    /// The temporaries the instruction uses at one size.
    uniques: &'a BTreeMap<u64, usize>,
    /// Whether the body keeps the x87 registers as f64 (`native_float`).
    fast: bool,
    /// The temporaries to fold, by offset and size.
    folds: &'a BTreeSet<(u64, usize)>,
    /// A folded temporary's expression until its reader takes it, and whether it is an f64.
    pending: RefCell<BTreeMap<(u64, usize), (String, bool)>>,
    /// The body's temporaries in locals, to declare: offset, size, and whether an f64.
    used: &'a RefCell<BTreeSet<(u64, usize, bool)>>,
    /// The register bytes outside the locals that anything reads: lifted code or the runtime.
    read: &'a BTreeSet<u64>,
}

impl Values<'_> {
    fn local(&self, v: Varnode) -> bool {
        v.space == UNIQUE && self.uniques.get(&v.offset) == Some(&v.size)
    }

    /// A temporary's folded expression, taken by its one reader.
    fn take(&self, v: Varnode) -> Option<(String, bool)> {
        self.pending.borrow_mut().remove(&(v.offset, v.size))
    }

    /// A value as its bits.
    fn read(&self, v: Varnode) -> String {
        match v.space {
            CONST => lit(v.offset, v.size),
            REGISTER => local_read(v.offset, v.size, self.fast).unwrap_or_else(|| cast(format!("c.rg({:#x}, {})", v.offset, v.size), 16, v.size)),
            UNIQUE if self.local(v) => match self.take(v) {
                Some((expr, true)) => format!("f64_to_f80({expr})"),
                Some((expr, false)) => expr,
                None if self.fast && v.size == 10 => {
                    self.used.borrow_mut().insert((v.offset, 10, true));
                    format!("f64_to_f80(x{:x})", v.offset)
                }
                None => {
                    self.used.borrow_mut().insert((v.offset, v.size, false));
                    format!("u{:x}_{}", v.offset, v.size)
                }
            },
            UNIQUE => cast(format!("c.uq({:#x}, {})", v.offset, v.size), 16, v.size),
            _ => load(lit(v.offset, 4), v.size),
        }
    }

    /// The statement that writes `value`, of the type of the varnode's size.
    fn write(&self, v: Varnode, value: String) -> String {
        match v.space {
            REGISTER => match local_write(v.offset, v.size, self.fast, &value) {
                Some(statement) => statement,
                // Nothing reads it, as the FPU instruction pointer every x87 instruction sets.
                None if !(v.offset..v.offset + v.size as u64).any(|b| self.read.contains(&b)) => String::new(),
                None => format!("{};", call("wg", &[format!("{:#x}", v.offset), v.size.to_string(), cast(value, v.size, 16)])),
            },
            UNIQUE if self.local(v) && self.folds.contains(&(v.offset, v.size)) => {
                self.pending.borrow_mut().insert((v.offset, v.size), (value, false));
                String::new()
            }
            UNIQUE if self.local(v) && self.fast && v.size == 10 => {
                self.used.borrow_mut().insert((v.offset, 10, true));
                format!("x{:x} = f80_to_f64({value});", v.offset)
            }
            UNIQUE if self.local(v) => {
                self.used.borrow_mut().insert((v.offset, v.size, false));
                format!("u{:x}_{} = {};", v.offset, v.size, fit(value, v.size))
            }
            UNIQUE => format!("{};", call("wuq", &[format!("{:#x}", v.offset), v.size.to_string(), cast(value, v.size, 16)])),
            _ => store(lit(v.offset, 4), value, v.size),
        }
    }

    /// A 10-byte value as an f64.
    fn read_f(&self, v: Varnode) -> String {
        if self.fast && self.local(v) {
            return match self.take(v) {
                Some((expr, true)) => expr,
                Some((expr, false)) => format!("f80_to_f64({expr})"),
                None => {
                    self.used.borrow_mut().insert((v.offset, 10, true));
                    format!("x{:x}", v.offset)
                }
            };
        }
        match st_slot(v) {
            Some(slot) if self.fast => format!("st{slot}"),
            _ => format!("f80_to_f64({})", self.read(v)),
        }
    }

    /// The statement that writes an f64 to a 10-byte value.
    fn write_f(&self, v: Varnode, value: String) -> String {
        if self.fast && self.local(v) {
            if self.folds.contains(&(v.offset, v.size)) {
                self.pending.borrow_mut().insert((v.offset, v.size), (value, true));
                return String::new();
            }
            self.used.borrow_mut().insert((v.offset, 10, true));
            return format!("x{:x} = {value};", v.offset);
        }
        match st_slot(v) {
            Some(slot) if self.fast => format!("st{slot} = {value};"),
            _ => self.write(v, format!("f64_to_f80({value})")),
        }
    }
}

/// A float op of a fast body as Rust on `f64`, which computes what the x87 does with the
/// control word the game keeps outside the bodies that load one: 53 bits, to nearest (0x27f;
/// docs/design/lifting.md). `f` reads an input as an f64, `i` as bits. Answers the expression
/// and whether it is an f64.
fn native_float(op: &Op, f: &dyn Fn(usize) -> String, i: &dyn Fn(usize) -> String) -> Option<(String, bool)> {
    let sizes: Vec<usize> = op.inputs.iter().map(|v| v.size).collect();
    let binary = |sign: &str| format!("({} {sign} {})", f(0), f(1));
    let compare = |sign: &str| format!("(({} {sign} {}) as u8)", f(0), f(1));
    Some(match (op.code, sizes.as_slice(), op.out?.size) {
        (Code::FAdd, [10, 10], 10) => (binary("+"), true),
        (Code::FSub, [10, 10], 10) => (binary("-"), true),
        (Code::FMult, [10, 10], 10) => (binary("*"), true),
        (Code::FDiv, [10, 10], 10) => (binary("/"), true),
        (Code::FSqrt, [10], 10) => (format!("{}.sqrt()", f(0)), true),
        (Code::FNeg, [10], 10) => (format!("(-{})", f(0)), true),
        (Code::FAbs, [10], 10) => (format!("{}.abs()", f(0)), true),
        (Code::FEqual, [10, 10], 1) => (compare("=="), false),
        (Code::FNotEqual, [10, 10], 1) => (compare("!="), false),
        (Code::FLess, [10, 10], 1) => (compare("<"), false),
        (Code::FLessEqual, [10, 10], 1) => (compare("<="), false),
        (Code::FNan, [10], 1) => (format!("({}.is_nan() as u8)", f(0)), false),
        (Code::Copy | Code::Float2Float, [10], 10) => (f(0), true),
        (Code::Float2Float, [4], 10) => (format!("f64::from(f32::from_bits({}))", i(0)), true),
        (Code::Float2Float, [8], 10) => (format!("f64::from_bits({})", i(0)), true),
        (Code::Float2Float, [10], 4) => (format!("({} as f32).to_bits()", f(0)), false),
        (Code::Float2Float, [10], 8) => (format!("{}.to_bits()", f(0)), false),
        (Code::Int2Float, [n @ (1 | 2 | 4 | 8)], 10) => (format!("({} as f64)", signed_of(&i(0), *n)), true),
        (Code::Round, [10], 10) => (format!("{}.round_ties_even()", f(0)), true),
        (Code::Trunc, [10], 10) => (format!("{}.trunc()", f(0)), true),
        (Code::Ceil, [10], 10) => (format!("{}.ceil()", f(0)), true),
        (Code::Floor, [10], 10) => (format!("{}.floor()", f(0)), true),
        // Toward zero; a value out of range, or not a number, gives the integer indefinite.
        (Code::Trunc, [10], n @ (2 | 4 | 8)) => {
            let limit = 2f64.powi(8 * n as i32 - 1);
            (format!("({{ let x = {}.trunc(); if x >= {:?} && x < {limit:?} {{ x as i64 as {} }} else {{ {:#x}{} }} }})", f(0), -limit, ty(n), 1u64 << (8 * n - 1), ty(n)), false)
        }
        _ => return None,
    })
}

/// The temporaries of a straight-line instruction to fold into their one reader: each written
/// by a pure op or a load and read whole by exactly one later op, with no op between them that
/// writes what its expression reads, calls, or stores while the expression reads memory.
fn folds(ops: &[Op], dead: &[bool], uniques: &BTreeMap<u64, usize>) -> BTreeSet<(u64, usize)> {
    let overlaps = |a: &Varnode, b: &Varnode| a.space == b.space && a.offset < b.offset + b.size as u64 && b.offset < a.offset + a.size as u64;
    let live: Vec<usize> = (0..ops.len()).filter(|i| !dead[*i]).collect();
    // A folded temporary's expression: what it reads, and whether it reads memory.
    let mut folded: BTreeMap<(u64, usize), (Vec<Varnode>, bool)> = BTreeMap::new();
    for (position, &i) in live.iter().enumerate() {
        let op = &ops[i];
        let Some(out) = op.out else { continue };
        let pure = !matches!(op.code, Code::Store | Code::Branch | Code::CBranch | Code::BranchInd | Code::Call | Code::CallInd | Code::CallOther | Code::Return | Code::Unimplemented);
        if !pure || out.space != UNIQUE || uniques.get(&out.offset) != Some(&out.size) {
            continue;
        }
        let later = &live[position + 1..];
        let readers: Vec<usize> = later.iter().copied().filter(|&j| ops[j].inputs.iter().any(|v| overlaps(v, &out))).collect();
        let [reader] = readers.as_slice() else { continue };
        let reads: Vec<&Varnode> = ops[*reader].inputs.iter().filter(|v| overlaps(v, &out)).collect();
        if reads.len() != 1 || (reads[0].offset, reads[0].size) != (out.offset, out.size) {
            continue;
        }
        let between: Vec<usize> = later.iter().copied().take_while(|j| j != reader).collect();
        let mut deps = Vec::new();
        let mut memory = op.code == Code::Load;
        for v in &op.inputs {
            match folded.get(&(v.offset, v.size)) {
                Some((inner, m)) if v.space == UNIQUE => {
                    deps.extend(inner.iter().copied());
                    memory |= *m;
                }
                _ if v.space == CONST => {}
                _ => {
                    memory |= !matches!(v.space, REGISTER | UNIQUE);
                    deps.push(*v);
                }
            }
        }
        let clobbered = between.iter().any(|&k| {
            let other = &ops[k];
            other.out.is_some_and(|w| overlaps(&w, &out) || deps.iter().any(|d| overlaps(&w, d)))
                || matches!(other.code, Code::Call | Code::CallInd | Code::CallOther)
                || memory && other.code == Code::Store
        });
        if !clobbered {
            folded.insert((out.offset, out.size), (deps, memory));
        }
    }
    folded.into_keys().collect()
}

/// The machine's own function for a common x87 operation with these operand and result sizes
/// (`recore_machine::Cpu::f_add` and its kin), called in place of the generic `c.op`.
fn typed_float(code: Code, inputs: &[usize], out: usize) -> Option<&'static str> {
    Some(match (code, inputs, out) {
        (Code::FAdd, [10, 10], 10) => "f_add",
        (Code::FSub, [10, 10], 10) => "f_sub",
        (Code::FMult, [10, 10], 10) => "f_mult",
        (Code::FDiv, [10, 10], 10) => "f_div",
        (Code::FSqrt, [10], 10) => "f_sqrt",
        (Code::FEqual, [10, 10], 1) => "f_equal",
        (Code::FNotEqual, [10, 10], 1) => "f_not_equal",
        (Code::FLess, [10, 10], 1) => "f_less",
        (Code::FLessEqual, [10, 10], 1) => "f_less_equal",
        (Code::FNan, [10], 1) => "f_nan",
        (Code::Float2Float, [4], 10) => "f_4_10",
        (Code::Float2Float, [8], 10) => "f_8_10",
        (Code::Float2Float, [10], 4) => "f_10_4",
        (Code::Float2Float, [10], 8) => "f_10_8",
        (Code::Int2Float, [2], 10) => "i_2_10",
        (Code::Int2Float, [4], 10) => "i_4_10",
        (Code::Int2Float, [8], 10) => "i_8_10",
        _ => return None,
    })
}

/// What the whole-program summaries say about the calls and returns of the body being emitted.
struct CallCtx<'a> {
    /// The flags and x87 registers a function reads at its entry, through its callees.
    reads: &'a dyn Fn(u64) -> Live,
    /// What a function does with the x87 registers, through its callees.
    kind: &'a dyn Fn(u64) -> X87,
    /// The flags and x87 registers this body's callers read after it returns.
    returned: Live,
    touches_x87: bool,
    /// Whether this body keeps the x87 registers as `f64` (`native_float`).
    fast: bool,
    /// The names the binary's edits give functions, for a comment at each call.
    names: &'a BTreeMap<u64, String>,
}

impl CallCtx<'_> {
    /// The registers saved before a call to `target` (or any code when `None`), and loaded after
    /// it, when the caller reads `after` of the flags and x87 registers afterwards. The x87
    /// registers are saved when the callee takes values on the stack and reads one at its entry,
    /// and loaded when it touches them and the caller reads one afterwards.
    fn around(&self, target: Option<u64>, after: Live) -> (String, String) {
        let st_after = after & ST_BITS != 0;
        let after = after & CALL_FLAGS & FLAG_BITS;
        // An indirect callee is a method or a callback: by the ABI the x87 stack is empty when it
        // is called, and it leaves nothing there but a float it returns in ST0.
        let (flags, save_x87, load_x87) = match target {
            Some(t) => (((self.reads)(t) | after) & FLAG_BITS, matches!((self.kind)(t), X87::Helper | X87::Runtime) && (self.reads)(t) & ST_BITS != 0, (self.kind)(t) != X87::Untouched && st_after),
            None => (CALL_FLAGS & FLAG_BITS, false, st_after),
        };
        let mut save = format!("c.save_g({GPR});");
        let mut load = format!("{GPR} = c.gpr();");
        if flags != 0 {
            save += &format!(" c.save_f({FLAGS});");
        }
        if after != 0 || target.is_none() {
            load += &format!(" {FLAGS} = c.flags();");
        }
        let (save_st, sts) = if self.fast { ("save_st64", "sts64") } else { ("save_st", "sts") };
        if save_x87 {
            save += &format!(" c.{save_st}({ST});");
        }
        if load_x87 {
            load += &format!(" {ST} = c.{sts}();");
        }
        (save, load)
    }

    /// The registers written back at a return, where `live` of the x87 registers hold what the
    /// callers read.
    fn leaving(&self, live: Live) -> String {
        let mut save = format!("c.save_g({GPR});");
        if self.returned & CALL_FLAGS & FLAG_BITS != 0 {
            save += &format!(" c.save_f({FLAGS});");
        }
        if self.touches_x87 && live & ST_BITS != 0 {
            save += &format!(" c.{}({ST});", if self.fast { "save_st64" } else { "save_st" });
        }
        save
    }
}

impl Values<'_> {
    /// The Rust statements of one op.
    fn op(&self, op: &Op, here: usize, local: &BTreeSet<u64>, calls: &CallCtx, after: Live) -> String {
        let fast = self.fast;
        let r = |i: usize| self.read(op.inputs[i]);
        let goto = |target: u64| if local.contains(&target) { format!("{{ pc = {target:#x}; continue 'f; }}") } else { format!("{{ {} dispatch(c, {target:#x}); return; }}", save(fast)) };
        match op.code {
            Code::Branch | Code::CBranch => {
                let place = op.inputs[0];
                let target = if place.space == CONST {
                    let to = here as i64 + signed(u128::from(place.offset), place.size) as i64;
                    format!("{{ i = {to}; continue 'ops; }}")
                } else {
                    goto(place.offset)
                };
                if op.code == Code::CBranch { format!("if {} != 0 {target}", r(1)) } else { target }
            }
            Code::Call => {
                let target = op.inputs[0].offset;
                let (save, load) = calls.around(Some(target), after);
                let named = calls.names.get(&target).map_or_else(String::new, |name| format!(" /* {} */", name.replace("*/", "")));
                format!("{save} f_{target:x}(c);{named} {load}")
            }
            Code::CallInd => {
                let (save, load) = calls.around(None, after);
                format!("{{ let t = {} as u32; {save} dispatch(c, t); {load} }}", typed(r(0), op.inputs[0].size))
            }
            Code::BranchInd => format!("{{ pc = {} as u32; continue 'f; }}", typed(r(0), op.inputs[0].size)),
            Code::Return => format!("{} return;", calls.leaving(after)),
            Code::Load => {
                let out = op.out.expect("load out");
                self.write(out, load(r(0), out.size))
            }
            Code::Store => store(r(0), r(1), op.inputs[1].size),
            Code::CallOther => {
                if HARMLESS.iter().any(|h| h.eq_ignore_ascii_case(&op.userop)) || op.userop == "ffree" {
                    String::new()
                } else if let (Some(out), true) = (op.out, op.userop.starts_with("cpuid") || op.userop == "rdtsc") {
                    let input = if op.inputs.is_empty() { "0u128".to_string() } else { cast(r(0), op.inputs[0].size, 16) };
                    self.write(out, cast(call("callother", &[format!("\"{}\"", op.userop), input]), 16, out.size))
                } else {
                    format!("panic!(\"callother {}\");", op.userop)
                }
            }
            Code::Unimplemented => "panic!(\"unimplemented instruction\");".into(),
            code => {
                let out = op.out.expect("op out");
                if fast {
                    let f = |i: usize| self.read_f(op.inputs[i]);
                    if let Some((value, float)) = native_float(op, &f, &r) {
                        return if float { self.write_f(out, value) } else { self.write(out, value) };
                    }
                }
                let size = |i: usize| op.inputs.get(i).map_or(0, |v| v.size);
                let (s0, w) = (size(0), out.size);
                // The first input with its type written out if it is a constant, for the left of
                // an operator or the receiver of a method; Rust infers the rest.
                let t0 = || typed(r(0), s0);
                let bits = 8 * s0;
                // A shift by `n`, a value of `size(1)` bytes: nothing is left past the width.
                let shift = |x: String, sign: &str, checked: &str| {
                    if whole(s0) && size(1) <= 4 {
                        format!("{x}.{checked}({} as u32).unwrap_or(0)", typed(r(1), size(1)))
                    } else {
                        fit(format!("({{ let (x, n) = ({x}, {} as u64); if n >= {bits} {{ 0 }} else {{ x {sign} n }} }})", typed(r(1), size(1))), s0)
                    }
                };
                let value = match code {
                    Code::Copy => r(0),
                    Code::ZExt => cast(r(0), s0, w),
                    Code::SExt if whole(s0) && whole(w) => format!("({} as {} as {} as {})", t0(), sty(s0), sty(w), ty(w)),
                    Code::SExt => cast(format!("({} as u128)", signed_of(&r(0), s0)), 16, w),
                    // The lifted crates build without overflow checks, so the operators wrap.
                    Code::Add => fit(format!("({} + {})", t0(), r(1)), w),
                    Code::Sub => fit(format!("({} - {})", t0(), r(1)), w),
                    Code::Mult => fit(format!("({} * {})", t0(), r(1)), w),
                    Code::TwoComp => fit(format!("{}.wrapping_neg()", t0()), w),
                    Code::Negate => fit(format!("(!{})", t0()), w),
                    Code::And => format!("({} & {})", t0(), r(1)),
                    Code::Or => format!("({} | {})", t0(), r(1)),
                    Code::Xor => format!("({} ^ {})", t0(), r(1)),
                    Code::Equal => format!("(({} == {}) as u8)", t0(), r(1)),
                    Code::NotEqual => format!("(({} != {}) as u8)", t0(), r(1)),
                    Code::Less => format!("(({} < {}) as u8)", t0(), r(1)),
                    Code::LessEqual => format!("(({} <= {}) as u8)", t0(), r(1)),
                    Code::SLess => format!("(({} < {}) as u8)", signed_of(&r(0), s0), signed_of(&r(1), s0)),
                    Code::SLessEqual => format!("(({} <= {}) as u8)", signed_of(&r(0), s0), signed_of(&r(1), s0)),
                    // Division by zero panics, as the runtime's compute does for x86.
                    Code::Div if whole(s0) => format!("({} / {})", t0(), r(1)),
                    Code::Rem if whole(s0) => format!("({} % {})", t0(), r(1)),
                    Code::SDiv if whole(s0) => format!("({}.wrapping_div({}) as {})", signed_of(&r(0), s0), signed_of(&r(1), s0), ty(s0)),
                    Code::SRem if whole(s0) => format!("({}.wrapping_rem({}) as {})", signed_of(&r(0), s0), signed_of(&r(1), s0), ty(s0)),
                    Code::Carry if whole(s0) => format!("({}.overflowing_add({}).1 as u8)", t0(), r(1)),
                    Code::Carry => format!("(((({} + {}) >> {bits}) != 0) as u8)", t0(), r(1)),
                    Code::SCarry | Code::SBorrow if whole(s0) => {
                        let name = if code == Code::SCarry { "add" } else { "sub" };
                        format!("({}.overflowing_{name}({}).1 as u8)", signed_of(&r(0), s0), signed_of(&r(1), s0))
                    }
                    Code::SCarry | Code::SBorrow => {
                        let sign = if code == Code::SCarry { "+" } else { "-" };
                        let shift = 128 - bits;
                        format!("({{ let x: i128 = {} {sign} {}; (((x << {shift}) >> {shift}) != x) as u8 }})", signed_of(&r(0), s0), signed_of(&r(1), s0))
                    }
                    Code::Left => shift(t0(), "<<", "checked_shl"),
                    Code::Right => shift(t0(), ">>", "checked_shr"),
                    Code::SRight if whole(s0) && size(1) <= 4 => format!("(({} >> ({} as u32).min({})) as {})", signed_of(&r(0), s0), typed(r(1), size(1)), bits - 1, ty(s0)),
                    Code::SRight => fit(format!("({{ let (x, n) = ({}, {} as u64); (x >> n.min({})) as u128 }})", signed_of(&r(0), s0), typed(r(1), size(1)), bits - 1), s0),
                    Code::PopCount => cast(format!("{}.count_ones()", t0()), 4, w),
                    Code::BoolNegate => format!("(({} & 1) ^ 1)", t0()),
                    Code::BoolAnd => format!("({} & {} & 1)", t0(), r(1)),
                    Code::BoolOr => format!("(({} | {}) & 1)", t0(), r(1)),
                    Code::BoolXor => format!("(({} ^ {}) & 1)", t0(), r(1)),
                    Code::Piece => fit(format!("(({} << {}) | {})", cast(r(0), s0, w), 8 * size(1), cast(r(1), size(1), w)), w),
                    Code::SubPiece if 8 * op.inputs[1].offset < bits as u64 => {
                        let by = 8 * op.inputs[1].offset;
                        cast(if by == 0 { r(0) } else { format!("({} >> {by})", t0()) }, s0, w)
                    }
                    Code::SubPiece => lit(0, w),
                    _ => {
                        let sizes: Vec<usize> = op.inputs.iter().map(|v| v.size).collect();
                        let args: Vec<String> = (0..op.inputs.len()).map(|i| cast(r(i), size(i), 16)).collect();
                        let result = match typed_float(code, &sizes, w) {
                            Some(name) => call(name, &args),
                            None => {
                                let lets: String = args.iter().enumerate().map(|(i, a)| format!("let i{i} = {a}; ")).collect();
                                let inputs: Vec<String> = (0..args.len()).map(|i| format!("(i{i}, {})", size(i))).collect();
                                format!("({{ {lets}c.op(Code::{code:?}, {w}, &[{}]) }})", inputs.join(", "))
                            }
                        };
                        cast(result, 16, w)
                    }
                };
                self.write(out, value)
            }
        }
    }
}

/// The registers whose liveness the lifter follows across instructions, one bit each: the flag
/// bytes 0x200 to 0x20f (bits 0 to 15) and the x87 registers ST0 to ST7 (bits 24 to 31), which
/// are locals, and the FPU instruction pointer 0x10ac to 0x10af (bits 16 to 19), which stays in
/// `Cpu`. Every x87 instruction sets the pointer and only FNSTENV and FSAVE read it, so its write
/// is kept only where one of them may see it. A write to an x87 register that nothing reads is
/// dropped too, which takes out most of the moves p-code makes to push and pop the stack, and a
/// call saves and loads the x87 registers only where the callee or the caller reads them.
type Live = u32;

/// The flag and FPU instruction pointer bytes of `Live` a register varnode covers, as bits.
fn flag_bits(v: &Varnode) -> Live {
    if v.space != REGISTER {
        return 0;
    }
    (0..v.size as u64).map(|i| v.offset + i).fold(0, |m, o| match o {
        0x200..0x210 => m | 1 << (o - 0x200),
        0x10ac..0x10b0 => m | 1 << (16 + o - 0x10ac),
        _ => m,
    })
}

/// The x87 registers of `Live` a register varnode touches, or with `whole` the ones it covers
/// whole. ST0 to ST7 are the 10 bytes at 0x1100, 0x1110 and on.
fn st_bits(v: &Varnode, whole: bool) -> Live {
    if v.space != REGISTER {
        return 0;
    }
    let (lo, hi) = (v.offset, v.offset + v.size as u64);
    (0..8u64).filter(|k| {
        let (start, end) = (0x1100 + 16 * k, 0x1100 + 16 * k + 10);
        if whole { lo <= start && end <= hi } else { lo < end && start < hi }
    }).fold(0, |m, k| m | 1 << (24 + k))
}

const ALL_FLAGS: Live = 0xff0f_ffff;

/// The bits of `Live` that are flags, which a call or a return saves and loads with the locals.
const FLAG_BITS: Live = 0xffff;

/// The bits of `Live` that are the x87 registers.
const ST_BITS: Live = 0xff00_0000;

/// ST0, where a function returns a float.
const ST0_BIT: Live = 1 << 24;

/// The bits that may carry a value across a call or a return. Of the flags, carry, parity, zero,
/// sign and overflow: the Windows ABI keeps the direction flag clear at every call and return,
/// and the system flags (trap, interrupt, privilege) do not change in a program, so a call
/// carries none of them: compiled code reads them only after setting them, or as the constants
/// they are. The adjust flag is left out too: the instructions that leave it undefined keep it in
/// p-code, which reads like a use, but only BCD arithmetic and LAHF or PUSHF use it, never across
/// a call. The FPU instruction pointer carries across both, to a FNSTENV in the callee or after
/// it, and so do the x87 registers, as arguments of the C runtime's helpers and results.
const CALL_FLAGS: Live = 0xff0f_08c5;

/// What a function does with the x87 registers, through its callees.
#[derive(Clone, Copy, PartialEq, Debug)]
enum X87 {
    /// It leaves them alone.
    Untouched,
    /// By the ABI it finds the stack empty and leaves nothing there, or the float it returns in
    /// ST0: code outside the C runtime, and runtime code that code outside calls. The runtime
    /// too is taken to call code outside it, its callbacks, with the stack empty.
    Empty,
    /// A function of the C runtime that `X87Abi::helpers` describes: the registers it takes on the
    /// stack and how it changes the depth.
    Helper,
    /// Code of the C runtime that the runtime calls, which may keep values on the stack across
    /// its calls and take arguments there; a body outside it that pops below its entry; or code
    /// that is not lifted.
    Runtime,
}

/// What one op reads of `Live` before writing it, and what it writes whole. A part of a register
/// that an op writes counts as read, since the rest of the register stays. A call reads what its
/// callee reads at its entry (`reads`), of the x87 registers only when the callee takes values
/// on the stack (`kind`). A call to code that touches the x87 registers, and an indirect call,
/// end the values the caller holds in them, since what the caller reads of them afterwards is
/// loaded from `Cpu` (`CallCtx::around`).
fn op_effect(op: &Op, reads: &dyn Fn(u64) -> Live, kind: &dyn Fn(u64) -> X87) -> (Live, Live) {
    match op.code {
        Code::Call => {
            let target = op.inputs[0].offset;
            match kind(target) {
                X87::Untouched => (reads(target) & !ST_BITS, 0),
                X87::Empty => (reads(target) & !ST_BITS, ST_BITS),
                X87::Helper | X87::Runtime => (reads(target), ST_BITS),
            }
        }
        // By the ABI the x87 stack is empty at an indirect call, as `CallCtx::around` has it.
        Code::CallInd => (ALL_FLAGS & !ST_BITS, ST_BITS),
        _ => {
            let whole = op.out.as_ref().map_or(0, |v| flag_bits(v) | st_bits(v, true));
            let part = op.out.as_ref().map_or(0, |v| st_bits(v, false)) & !whole;
            (op.inputs.iter().map(|v| flag_bits(v) | st_bits(v, false)).fold(part, |a, b| a | b), whole)
        }
    }
}

/// What of `Live` is live before an instruction, given `live` after it. An op whose only result
/// nothing reads reads nothing either (`walk_ops`), so a push or pop moves only the registers
/// read later. An instruction this pass does not look into reads everything; an x87 instruction
/// the runtime runs whole reads every x87 register; an instruction with branches inside it
/// writes nothing for sure.
fn live_before(insn: &Insn, imported: bool, live: Live, reads: &dyn Fn(u64) -> Live, kind: &dyn Fn(u64) -> X87) -> Live {
    let Semantics::Pcode(Ok(ops)) = &insn.semantics else {
        return if matches!(insn.semantics, Semantics::X87(_)) { live | ST_BITS } else { ALL_FLAGS };
    };
    // An import is host code, which neither reads nor changes the game's flags or x87 registers.
    if imported {
        return live;
    }
    if ops.iter().any(|op| matches!(op.code, Code::Branch | Code::CBranch) && op.inputs[0].space == CONST) {
        return ops.iter().fold(live, |l, op| l | op_effect(op, reads, kind).0);
    }
    walk_ops(ops, live, reads, kind).0
}

/// Where control goes after an instruction inside the function, and whether it may leave the
/// function there, where every flag counts as read.
/// Where control goes after an instruction inside the function, and the flags read where it
/// leaves the function there: what callers read after a return (`returned`), every flag where
/// it jumps out. `import` is the tail flag of an import called there.
fn successors(insn: &Insn, local: &BTreeSet<u64>, import: Option<bool>, returned: Live) -> (Vec<u64>, Live) {
    let next = insn.addr + insn.len;
    let fall = |v: &mut Vec<u64>, exits: &mut Live| if local.contains(&next) { v.push(next) } else { *exits |= ALL_FLAGS };
    let (mut out, mut exits) = (Vec::new(), 0);
    match (&insn.semantics, import) {
        (_, Some(true)) => exits = returned,
        (_, Some(false)) => fall(&mut out, &mut exits),
        (Semantics::Pcode(Ok(ops)), None) => {
            let mut falls = true;
            for op in ops {
                match op.code {
                    Code::Branch | Code::CBranch if op.inputs[0].space != CONST => {
                        let target = op.inputs[0].offset;
                        if local.contains(&target) { out.push(target) } else { exits |= ALL_FLAGS }
                        if op.code == Code::Branch {
                            falls = false;
                        }
                    }
                    Code::Return => {
                        exits |= returned;
                        falls = false;
                    }
                    Code::BranchInd => {
                        exits |= ALL_FLAGS;
                        falls = false;
                    }
                    _ => {}
                }
            }
            if falls {
                fall(&mut out, &mut exits);
            }
        }
        _ => fall(&mut out, &mut exits),
    }
    (out, exits)
}

/// The bits of `Live` live before and after each instruction of a body, given what each callee
/// reads at its entry and what the body's callers read after it returns. `keep` holds, for each
/// instruction, the bits that may be live before and after it: of the x87 registers, those that
/// hold a value there by `x87_depths`.
fn flag_liveness(insns: &[Insn], local: &BTreeSet<u64>, imports: &FxHashMap<u64, (String, bool)>, reads: &dyn Fn(u64) -> Live, kind: &dyn Fn(u64) -> X87, returned: Live, keep: Option<&[(Live, Live)]>) -> (Vec<Live>, Vec<Live>) {
    let index: BTreeMap<u64, usize> = insns.iter().enumerate().map(|(i, insn)| (insn.addr, i)).collect();
    let keep = |i: usize| keep.map_or((ALL_FLAGS, ALL_FLAGS), |k| k[i]);
    let flow: Vec<(Vec<u64>, Live)> = insns.iter().map(|insn| successors(insn, local, imports.get(&insn.addr).map(|(_, tail)| *tail), returned)).collect();
    let mut live_in = vec![0; insns.len()];
    let mut live_out = vec![0; insns.len()];
    loop {
        let mut changed = false;
        for i in (0..insns.len()).rev() {
            let (succ, exits) = &flow[i];
            let (keep_in, keep_out) = keep(i);
            let out = succ.iter().map(|t| live_in[index[t]]).fold(*exits & keep_out, |a, b| a | b);
            let inn = live_before(&insns[i], imports.contains_key(&insns[i].addr), out, reads, kind) & keep_in;
            if out != live_out[i] || inn != live_in[i] {
                live_out[i] = out;
                live_in[i] = inn;
                changed = true;
            }
        }
        if !changed {
            return (live_in, live_out);
        }
    }
}

/// The depth of the x87 stack: the fewest and the most values it may hold.
type Depth = (i32, i32);

fn join(a: Option<Depth>, b: Depth) -> Depth {
    a.map_or(b, |a| (a.0.min(b.0), a.1.max(b.1)))
}

/// The x87 stack depth of a body before and after each of its instructions (`None` where nothing
/// reaches), counted from its entry, and where it returns.
struct Depths {
    before: Vec<Option<Depth>>,
    after: Vec<Option<Depth>>,
    returns: Option<Depth>,
    /// Each direct call and the depth before it.
    calls: Vec<(u64, Depth)>,
    /// Whether the body pops below its entry, which only a helper does.
    below: bool,
}

/// What the x87 analysis knows of the calls a body makes.
struct Callees<'a> {
    kind: &'a dyn Fn(u64) -> X87,
    /// For a helper, the x87 registers it reads at its entry (ST0 in bit 0) and how many values
    /// it leaves on the stack less those it found (`X87Abi::helpers`).
    effect: &'a dyn Fn(u64) -> (u8, i32),
    /// Whether an address is the entry of a lifted body. A jump elsewhere outside the body
    /// enters code that another body shares, which returns for it.
    entry: &'a dyn Fn(u64) -> bool,
}

/// The x87 registers, ST0 in bit 0, that a body outside the C runtime reads after each
/// instruction before writing them, where its callers read ST0 after it returns when
/// `returns_float`. By the ABI the stack is empty at a call to anything but a helper, so such a
/// call, an indirect one and an import read none of the caller's and end them all. A call to a
/// helper reads what it takes and passes the rest through, moved by what it leaves; one to
/// other runtime code may read any. A jump to code outside the body returns for it, as a return
/// does, unless it enters the runtime; every register counts as read there.
fn st_liveness(insns: &[Insn], imports: &FxHashMap<u64, (String, bool)>, tables: &BTreeSet<u64>, callees: &Callees, returns_float: bool) -> (Vec<u8>, Vec<u8>) {
    let index: BTreeMap<u64, usize> = insns.iter().enumerate().map(|(i, insn)| (insn.addr, i)).collect();
    let bits = |v: &Varnode, whole: bool| (st_bits(v, whole) >> 24) as u8;
    // What is read before a step of `by`, from what is read after it: after a push ST1 is the
    // ST0 before, after a pop ST0 is the ST1 before.
    let moved = |live: u8, by: i32| if by >= 0 { live >> by } else { ((live as u16) << -by) as u8 };
    let exit = returns_float as u8;
    // Each instruction's successors in the body, and the registers read where it leaves.
    let flow: Vec<(Vec<usize>, u8)> = insns.iter().map(|insn| {
        let next = insn.addr + insn.len;
        let tail = imports.get(&insn.addr).map(|(_, tail)| *tail);
        let mut out = Vec::new();
        let mut leaves = 0u8;
        let mut falls = tail != Some(true);
        if tail == Some(true) {
            leaves = exit;
        } else if let (Semantics::Pcode(Ok(ops)), None) = (&insn.semantics, tail) {
            for op in ops {
                match op.code {
                    Code::Branch | Code::CBranch if op.inputs[0].space != CONST => {
                        match index.get(&op.inputs[0].offset) {
                            Some(&t) => out.push(t),
                            None if (callees.entry)(op.inputs[0].offset) && matches!((callees.kind)(op.inputs[0].offset), X87::Helper | X87::Runtime) => leaves = 0xff,
                            None => leaves |= exit,
                        }
                        falls &= op.code == Code::CBranch;
                    }
                    Code::BranchInd => {
                        out.extend(tables.iter().filter_map(|t| index.get(t).copied()));
                        leaves |= exit;
                        falls = false;
                    }
                    Code::Return => {
                        leaves |= exit;
                        falls = false;
                    }
                    _ => {}
                }
            }
        } else if matches!(insn.semantics, Semantics::Pcode(Err(_))) {
            leaves = 0xff;
            falls = false;
        }
        if falls {
            match index.get(&next) {
                Some(&t) => out.push(t),
                None => leaves |= exit,
            }
        }
        (out, leaves)
    }).collect();
    // An instruction that pops reads what it pops, if only to drop it (FSTP ST0): popping an
    // empty slot is a stack fault, so a pop tells that the slot held a value.
    let popped = |insn: &Insn| match insn.x87 {
        Step::By(k) if k < 0 => ((1u16 << -k) - 1) as u8,
        _ => 0,
    };
    let pass = |i: usize, mut live: u8| -> u8 {
        let insn = &insns[i];
        if imports.contains_key(&insn.addr) {
            return 0;
        }
        match &insn.semantics {
            Semantics::Pcode(Ok(ops)) => {
                let inner = ops.iter().any(|op| matches!(op.code, Code::Branch | Code::CBranch) && op.inputs[0].space == CONST);
                // The temporaries read later in the instruction, so that a move into a register
                // nothing reads reads nothing, as in `walk_ops`.
                let mut temps: BTreeSet<(u64, usize)> = BTreeSet::new();
                for op in ops.iter().rev() {
                    let pure = !matches!(op.code, Code::Store | Code::Branch | Code::CBranch | Code::BranchInd | Code::Call | Code::CallInd | Code::CallOther | Code::Return | Code::Unimplemented);
                    if let Some(out) = op.out.filter(|_| pure && !inner) {
                        let unread = match out.space {
                            UNIQUE => !temps.iter().any(|&(o, n)| o < out.offset + out.size as u64 && out.offset < o + n as u64),
                            REGISTER => out.size == 10 && bits(&out, true).count_ones() == 1 && bits(&out, true) & live == 0,
                            _ => false,
                        };
                        if unread {
                            continue;
                        }
                    }
                    temps.extend(op.inputs.iter().filter(|v| v.space == UNIQUE).map(|v| (v.offset, v.size)));
                    live = match op.code {
                        Code::Call => match (callees.kind)(op.inputs[0].offset) {
                            X87::Untouched | X87::Empty => 0,
                            X87::Helper => {
                                let (takes, net) = (callees.effect)(op.inputs[0].offset);
                                takes | moved(live, net)
                            }
                            X87::Runtime => 0xff,
                        },
                        Code::CallInd => 0,
                        _ => {
                            let (whole, part) = op.out.as_ref().map_or((0, 0), |v| (bits(v, true), bits(v, false)));
                            let kept = if inner { live } else { live & !whole };
                            kept | (part & !whole) | op.inputs.iter().map(|v| bits(v, false)).fold(0, |a, b| a | b)
                        }
                    };
                }
                live
            }
            // An x87 instruction the runtime runs whole reads its operands, ST0 or ST0 and ST1,
            // and moves the rest by its step.
            Semantics::X87(instruction) => {
                use x87::Instruction::*;
                let operands = match instruction {
                    Fyl2x | Fyl2xp1 | Fscale | Fpatan | Fprem | Fprem1 => 0b11,
                    Fldpi | Fldl2e | Fldl2t | Fldlg2 | Fldln2 => 0,
                    F2xm1 | Fsin | Fcos | Fsincos | Fptan | Fxtract | Fxam => 0b1,
                };
                match insn.x87 {
                    Step::By(k) => operands | moved(live, k),
                    _ => 0xff,
                }
            }
            Semantics::Pcode(Err(_)) => 0xff,
        }
    };
    let transfer = |i: usize, live: u8| -> u8 { pass(i, live) | popped(&insns[i]) };
    let mut live_in = vec![0u8; insns.len()];
    let mut live_out = vec![0u8; insns.len()];
    loop {
        let mut changed = false;
        for i in (0..insns.len()).rev() {
            let (succ, leaves) = &flow[i];
            let out = succ.iter().fold(*leaves, |a, t| a | live_in[*t]);
            let inn = transfer(i, out);
            if out != live_out[i] || inn != live_in[i] {
                live_out[i] = out;
                live_in[i] = inn;
                changed = true;
            }
        }
        if !changed {
            return (live_in, live_out);
        }
    }
}

/// The x87 stack depths of a body outside the C runtime (`Depths`), from each instruction's
/// step, or `None` for an entry that is not one of its instructions, which leaves for `dispatch`
/// at once. By the ABI the body finds the stack empty at its entry, so its depth is never below
/// 0. A call to a helper adds what the helper leaves; after other runtime code any depth may
/// follow. By the ABI a call to any other body, and an indirect one, leaves the stack holding
/// the float the callee returns or nothing, and a caller reads a float it is returned, if only
/// to pop it: so one value where the body reads ST0 after the call, and none or one where ST0
/// only reaches a return of a body that may return a float (`st0_after`, by instruction: what
/// the body reads, and what it reads or returns). A jump to another body
/// returns for this one, with a float where `returns_float`; one through a table goes to the
/// body's table targets.
fn x87_depths(entry: u64, insns: &[Insn], tables: &BTreeSet<u64>, imports: &FxHashMap<u64, (String, bool)>, returns_float: bool, callees: &Callees, st0_after: &dyn Fn(usize) -> (bool, bool)) -> Option<Depths> {
    let index: BTreeMap<u64, usize> = insns.iter().enumerate().map(|(i, insn)| (insn.addr, i)).collect();
    let mut d = Depths { before: vec![None; insns.len()], after: vec![None; insns.len()], returns: None, calls: Vec::new(), below: false };
    let start = *index.get(&entry)?;
    let mut below = false;
    let mut clamp = |(lo, hi): Depth| -> Depth {
        below |= hi < 0;
        (lo.clamp(0, 8), hi.clamp(0, 8))
    };
    let result = |(read, returned): (bool, bool)| (read as i32, (read || returned) as i32);
    let call = |target: u64, at: Depth, float: (bool, bool)| match (callees.kind)(target) {
        X87::Untouched => at,
        X87::Empty => result(float),
        X87::Helper => {
            let net = (callees.effect)(target).1;
            (at.0 + net, at.1 + net)
        }
        X87::Runtime => (0, 8),
    };
    d.before[start] = Some((0, 0));
    let mut work = vec![start];
    while let Some(i) = work.pop() {
        let insn = &insns[i];
        let Some(mut at) = d.before[i] else { continue };
        at = match insn.x87 {
            Step::By(k) => clamp((at.0 + k, at.1 + k)),
            Step::Empty => (0, 0),
            Step::Whole => clamp((-8, 8)),
        };
        let tail = imports.get(&insn.addr).map(|(_, tail)| *tail);
        let (mut next, mut returns) = (Vec::new(), tail == Some(true));
        match (&insn.semantics, tail) {
            (Semantics::Pcode(Ok(ops)), None) => {
                let mut falls = true;
                for op in ops {
                    match op.code {
                        Code::Call => {
                            d.calls.push((op.inputs[0].offset, at));
                            at = clamp(call(op.inputs[0].offset, at, st0_after(i)));
                        }
                        Code::CallInd => {
                            at = result(st0_after(i));
                        }
                        Code::Branch | Code::CBranch if op.inputs[0].space != CONST => {
                            let target = op.inputs[0].offset;
                            if index.contains_key(&target) {
                                next.push(target);
                            } else if !(callees.entry)(target) {
                                d.returns = Some(join(d.returns, (0, returns_float as i32)));
                            } else {
                                d.returns = Some(join(d.returns, clamp(call(target, at, (false, returns_float)))));
                            }
                            falls &= op.code == Code::CBranch;
                        }
                        Code::BranchInd => {
                            next.extend(tables.iter().copied().filter(|t| index.contains_key(t)));
                            falls = false;
                        }
                        Code::Return => {
                            returns = true;
                            falls = false;
                        }
                        _ => {}
                    }
                }
                if falls {
                    next.push(insn.addr + insn.len);
                }
            }
            (_, Some(true)) => {}
            _ => next.push(insn.addr + insn.len),
        }
        d.after[i] = Some(join(d.after[i], at));
        if returns {
            d.returns = Some(join(d.returns, at));
        }
        for target in next {
            let Some(&t) = index.get(&target) else { continue };
            let joined = join(d.before[t], at);
            if d.before[t] != Some(joined) {
                d.before[t] = Some(joined);
                work.push(t);
            }
        }
    }
    d.below = below;
    Some(d)
}

/// Which ops of a straight-line instruction write only flags, x87 registers or temporaries that
/// nothing reads before they are written again, and what of `Live` is live before the first,
/// given `live_out` after the last.
fn walk_ops(ops: &[Op], live_out: Live, reads: &dyn Fn(u64) -> Live, kind: &dyn Fn(u64) -> X87) -> (Live, Vec<bool>) {
    let mut live = live_out;
    let mut temps: BTreeSet<u64> = BTreeSet::new();
    let mut dead = vec![false; ops.len()];
    fn bytes(v: &Varnode) -> impl Iterator<Item = u64> + use<> {
        let (offset, size) = (v.offset, v.size as u64);
        (0..size).map(move |i| offset + i)
    }
    for (index, op) in ops.iter().enumerate().rev() {
        let pure = !matches!(op.code, Code::Store | Code::Branch | Code::CBranch | Code::BranchInd | Code::Call | Code::CallInd | Code::CallOther | Code::Return | Code::Unimplemented);
        if let Some(out) = op.out.filter(|_| pure) {
            // Whether the op writes nothing but bits of `Live`: flag bytes, or one x87 register whole.
            let tracked = out.space == REGISTER && (flag_bits(&out).count_ones() as usize == out.size || out.size == 10 && st_bits(&out, true).count_ones() == 1);
            let unread = if out.space == UNIQUE { bytes(&out).all(|b| !temps.contains(&b)) } else { tracked && (flag_bits(&out) | st_bits(&out, true)) & live == 0 };
            if (out.space == UNIQUE || tracked) && unread {
                dead[index] = true;
                continue;
            }
            if out.space == UNIQUE {
                for b in bytes(&out) {
                    temps.remove(&b);
                }
            }
        }
        let (used, written) = op_effect(op, reads, kind);
        live = (live & !written) | used;
        for v in op.inputs.iter().filter(|v| v.space == UNIQUE) {
            temps.extend(bytes(v));
        }
    }
    (live, dead)
}

/// The x87 ABI of a program with a statically linked C runtime: the runtime starts at `runtime`,
/// and `helpers` describes the runtime functions other code calls with values on the x87 stack,
/// by address: the registers each reads at its entry (ST0 in bit 0) and how many values it leaves
/// on the stack less those it found. Without it (`runtime` 0), all code counts as runtime code.
#[derive(Default)]
pub struct X87Abi {
    pub runtime: u64,
    pub helpers: FxHashMap<u64, (u8, i32)>,
}

/// A lifted program: its functions in the order they were lifted, and the report of what was
/// lifted.
pub struct Program {
    pub functions: Vec<Function>,
    pub report: String,
}

/// One lifted function: its entry, the doc attribute that names it (empty when it has no name),
/// and its Rust, the doc included.
pub struct Function {
    pub entry: u64,
    pub doc: String,
    pub text: String,
}

/// Lifts every function `roots` reach by direct calls, and every root.
pub fn lift(binary: &mut Binary, roots: &[u64], abi: &X87Abi) -> Result<Program> {
    let mut spaces = Spaces::new();
    spaces.intern("ram");
    let functions: FxHashMap<u64, Vec<(u64, u64)>> = binary.program.analysis.functions.iter().map(|f| (f.addr, f.ranges.clone())).collect();
    let imports: FxHashMap<u64, (String, bool)> = binary
        .program
        .analysis
        .calls
        .iter()
        .filter_map(|call| match call.target {
            CallTarget::Import(slot) => Some((call.at, (binary.program.import_name(slot)?.to_string(), call.tail))),
            CallTarget::Function(_) => None,
        })
        .collect();
    // The names and comments the binary's edits give functions (recore's `rename` and `comment`),
    // as each lifted function's doc: identifiers stay `f_<address>`, which never collide.
    let names = binary.edits.names.clone();
    let notes = binary.edits.comments.clone();
    let doc = |entry: u64| match (names.get(&entry), notes.get(&entry)) {
        (Some(name), Some(note)) => format!("#[doc = {:?}] ", format!("{name} ({entry:#x}): {note}")),
        (Some(name), None) => format!("#[doc = {:?}] ", format!("{name} ({entry:#x})")),
        (None, _) => String::new(),
    };
    let mut queue: Vec<u64> = roots.to_vec();
    let mut done = BTreeSet::new();
    // Where each function's text starts in `code`, and its entry.
    let mut starts: Vec<(usize, u64)> = Vec::new();
    let mut code = String::from("use crate::*;\n");
    let mut insn_count = 0usize;
    let mut failed = Vec::new();
    let mut bodies: Vec<(u64, Vec<Insn>, BTreeSet<u64>)> = Vec::new();
    while let Some(entry) = queue.pop() {
        if !done.insert(entry) {
            continue;
        }
        let mut insns = Vec::new();
        let mut error = None;
        match functions.get(&entry).cloned() {
            Some(ranges) => {
                for (start, end) in ranges {
                    if let Err(e) = lift_range(binary, &mut spaces, start, end, &mut insns) {
                        error = Some(format!("{e:#}"));
                        break;
                    }
                }
            }
            // An entry inside a known function, as a method or a switch case reached from a
            // table: that function's whole body, entered here.
            None if functions.values().any(|r| r.iter().any(|&(lo, hi)| (lo..hi).contains(&entry))) => {
                let ranges = functions.values().find(|r| r.iter().any(|&(lo, hi)| (lo..hi).contains(&entry))).cloned().unwrap_or_default();
                for (start, end) in ranges {
                    if let Err(e) = lift_range(binary, &mut spaces, start, end, &mut insns) {
                        error = Some(format!("{e:#}"));
                        break;
                    }
                }
            }
            None => match discover(binary, &mut spaces, entry) {
                Ok(found) => {
                    failed.push(format!("{entry:#x}: not a function, {} instructions found by following it", found.len()));
                    insns = found;
                }
                Err(e) => error = Some(format!("{e:#}")),
            },
        }
        // Jump tables: an indirect jump through `[reg*4 + table]` goes to the table's entries,
        // read while they point near the function.
        let mut scanned: BTreeSet<u64> = BTreeSet::new();
        let mut tables: BTreeSet<u64> = BTreeSet::new();
        while error.is_none() && !insns.is_empty() {
            let before = insns.len();
            let (low, high) = (insns.iter().map(|i| i.addr).min().unwrap_or(0).saturating_sub(0x1000), insns.iter().map(|i| i.addr).max().unwrap_or(0) + 0x1000);
            let mut extra = Vec::new();
            let known: BTreeSet<u64> = insns.iter().map(|i| i.addr).collect();
            for insn in &insns {
                let Semantics::Pcode(Ok(ops)) = &insn.semantics else { continue };
                // The analysis ends some functions after a call followed by an alignment NOP
                // (0x538f10 at 0x538faa), though the call returns: the code after it is the body.
                let next = insn.addr + insn.len;
                if ops.iter().any(|op| matches!(op.code, Code::Call | Code::CallInd))
                    && !known.contains(&next)
                    && binary.program.image.bytes_from(next).and_then(|b| b.first().copied()) == Some(0x90)
                {
                    extra.push(next);
                }
                if !ops.iter().any(|op| op.code == Code::BranchInd) || !scanned.insert(insn.addr) {
                    continue;
                }
                let text = binary.lift(insn.addr, insn.addr + insn.len).ok().and_then(|found| found.into_iter().next()).map(|i| i.text).unwrap_or_default();
                let Some(table) = text.split("*0x4 + 0x").nth(1).and_then(|rest| u64::from_str_radix(rest.trim_end_matches(']').split(|c: char| !c.is_ascii_hexdigit()).next()?, 16).ok()) else { continue };
                // MSVC's memcpy also indexes a table backwards, after `NEG ECX`.
                for step in [4i64, -4] {
                    for n in 0..256i64 {
                        let Some(bytes) = binary.program.image.bytes_from((table as i64 + step * n) as u64) else { break };
                        let Some(word) = bytes.get(..4) else { break };
                        let target = u64::from(u32::from_le_bytes(word.try_into().unwrap()));
                        // An index that starts at 1 leaves a word of something else first.
                        if !(low..high).contains(&target) {
                            if n == 0 {
                                continue;
                            }
                            break;
                        }
                        extra.push(target);
                        tables.insert(target);
                    }
                }
            }
            let mut have: BTreeSet<u64> = insns.iter().map(|i| i.addr).collect();
            for target in extra {
                if have.contains(&target) {
                    continue;
                }
                if let Ok(found) = discover(binary, &mut spaces, target) {
                    for insn in found {
                        if have.insert(insn.addr) {
                            insns.push(insn);
                        }
                    }
                }
            }
            insns.sort_by_key(|i| i.addr);
            if insns.len() == before {
                break;
            }
        }
        if let Some(e) = error {
            starts.push((code.len(), entry));
            writeln!(code, "#[allow(unused)] {}pub fn f_{entry:x}(c: &mut Cpu) {{ panic!(\"cannot lift {entry:#x}: {}\") }}", doc(entry), e.replace('"', "'"))?;
            failed.push(format!("{entry:#x}: {e}"));
            continue;
        }
        insn_count += insns.len();
        let local: BTreeSet<u64> = insns.iter().map(|i| i.addr).collect();
        for insn in &insns {
            let Semantics::Pcode(Ok(ops)) = &insn.semantics else { continue };
            for op in ops {
                if op.code == Code::Call {
                    queue.push(op.inputs[0].offset);
                }
                if matches!(op.code, Code::Branch | Code::CBranch) && op.inputs[0].space != CONST && !local.contains(&op.inputs[0].offset) {
                    queue.push(op.inputs[0].offset);
                }
            }
        }
        bodies.push((entry, insns, tables));
    }
    // The whole program, to a fixed point: the flags each function reads at its entry, the
    // flags its callers read after it returns, and whether it touches the x87 registers, each
    // through its callees. A call then saves the flags only when the callee reads them or the
    // caller reads them after, and the x87 registers only when the callee touches them. A
    // caller the program does not show (an indirect call, the host) relies on no flags across a
    // call, as the ABI has it. Copies of one body share their group's summary, so they are
    // emitted alike.
    let mut group_of: FxHashMap<u64, usize> = FxHashMap::default();
    let mut groups: BTreeMap<(u64, u64, usize), usize> = BTreeMap::new();
    let body_group: Vec<usize> = bodies
        .iter()
        .map(|(_, insns, _)| {
            let key = (insns.first().map_or(0, |i| i.addr), insns.last().map_or(0, |i| i.addr), insns.len());
            let next = groups.len();
            *groups.entry(key).or_insert(next)
        })
        .collect();
    for ((entry, _, _), g) in bodies.iter().zip(&body_group) {
        group_of.insert(*entry, *g);
    }
    // A body touches the x87 registers where it uses one, through any callee or body it jumps to
    // that does, and through code that is not lifted, which a call or a jump may enter.
    let mut touches_x87 = vec![false; groups.len()];
    let mut onward: Vec<Vec<u64>> = vec![Vec::new(); bodies.len()];
    for (((_, insns, _), g), onward) in bodies.iter().zip(&body_group).zip(&mut onward) {
        let local: BTreeSet<u64> = insns.iter().map(|i| i.addr).collect();
        for insn in insns {
            match &insn.semantics {
                Semantics::X87(_) => touches_x87[*g] = true,
                Semantics::Pcode(Ok(ops)) => {
                    for op in ops {
                        for v in op.inputs.iter().chain(op.out.iter()) {
                            if v.space == REGISTER && (0x1100..0x1180).contains(&v.offset) {
                                touches_x87[*g] = true;
                            }
                        }
                        match op.code {
                            Code::Call => onward.push(op.inputs[0].offset),
                            Code::Branch | Code::CBranch if op.inputs[0].space != CONST && !local.contains(&op.inputs[0].offset) => onward.push(op.inputs[0].offset),
                            _ => {}
                        }
                    }
                }
                Semantics::Pcode(Err(_)) => {}
            }
        }
    }
    loop {
        let mut changed = false;
        for (g, onward) in body_group.iter().zip(&onward) {
            if !touches_x87[*g] && onward.iter().any(|t| group_of.get(t).is_none_or(|t| touches_x87[*t])) {
                touches_x87[*g] = true;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    // Bodies that callers outside the lifted calls may reach: one no call names, called
    // indirectly as a method or a callback, and one a jump enters, which returns for the body
    // that jumped.
    let mut named: BTreeSet<u64> = BTreeSet::new();
    let mut jumped: BTreeSet<u64> = BTreeSet::new();
    for (_, insns, _) in &bodies {
        let local: BTreeSet<u64> = insns.iter().map(|i| i.addr).collect();
        for insn in insns {
            let Semantics::Pcode(Ok(ops)) = &insn.semantics else { continue };
            for op in ops {
                match op.code {
                    Code::Call => {
                        named.insert(op.inputs[0].offset);
                    }
                    Code::Branch | Code::CBranch if op.inputs[0].space != CONST && !local.contains(&op.inputs[0].offset) => {
                        jumped.insert(op.inputs[0].offset);
                    }
                    _ => {}
                }
            }
        }
    }
    let mut open = vec![false; groups.len()];
    for ((entry, _, _), g) in bodies.iter().zip(&body_group) {
        open[*g] |= !named.contains(entry) || jumped.contains(entry);
    }
    // The C runtime starts at `abi.runtime`; without it, all code counts as runtime code. The
    // runtime may keep values on the x87 stack across its calls and take arguments there, so its
    // bodies keep every x87 register they may read. `abi.helpers` describes the runtime functions
    // other code calls (`X87Abi`). Code outside the runtime follows the ABI: the stack is empty at
    // its entry and at each call it makes to anything but a helper (X87::Empty).
    let runtime_start = abi.runtime;
    let x87_table = &abi.helpers;
    // A body that sets the stack whole or uses MMX is treated as runtime code too.
    let mut runtime = vec![false; groups.len()];
    for ((entry, insns, _), g) in bodies.iter().zip(&body_group) {
        runtime[*g] |= *entry >= runtime_start || insns.iter().any(|i| i.x87 == Step::Whole);
    }
    // Bodies outside the runtime that do not follow the ABI as far as their depths tell: one
    // that pops below its entry takes values on the stack. They are treated as runtime code that
    // every caller treats as such, and found with the depths.
    // This goes by entry, not by group: an address from data may enter a function's code in the
    // middle of its work on the stack.
    let odd: Vec<std::cell::Cell<bool>> = vec![std::cell::Cell::new(false); bodies.len()];
    let body_of: FxHashMap<u64, usize> = bodies.iter().enumerate().map(|(b, (entry, _, _))| (*entry, b)).collect();
    // What a call does with the x87 registers, by whether the caller is runtime code.
    let kind_from = |caller_runtime: bool, t: u64| match group_of.get(&t) {
        None => X87::Runtime,
        Some(&g) if !touches_x87[g] => X87::Untouched,
        Some(_) if x87_table.contains_key(&t) => X87::Helper,
        Some(&g) if body_of.get(&t).is_some_and(|b| odd[*b].get()) || runtime[g] && caller_runtime => X87::Runtime,
        Some(_) => X87::Empty,
    };
    let kind_of = |t: u64| kind_from(false, t);
    let kind_in_runtime = |t: u64| kind_from(true, t);
    let effect = |t: u64| x87_table.get(&t).copied().unwrap_or((0xff, 0));
    let entry_of = |t: u64| group_of.contains_key(&t);
    let callees = Callees { kind: &kind_of, effect: &effect, entry: &entry_of };
    // The x87 stack depths of the bodies outside the runtime (`x87_depths`). A body returns a
    // float when a caller reads ST0 after calling it, or it may return with a value on the stack;
    // one that callers outside the lifted calls may reach counts as one that does. These grow
    // together until they settle.
    let mut float = open.clone();
    let depths: Vec<Option<Depths>> = loop {
        let depths: Vec<Option<Depths>> = loop {
        let mut found: Vec<(Option<Depths>, Vec<u64>)> = Vec::new();
        for (b, ((entry, insns, tables), g)) in bodies.iter().zip(&body_group).enumerate() {
            if !touches_x87[*g] || runtime[*g] || odd[b].get() {
                found.push((None, Vec::new()));
                continue;
            }
            // ST0 read after an instruction before it is written, by the body itself or also by
            // its callers after it returns.
            let (_, returned_out) = st_liveness(insns, &imports, tables, &callees, float[*g]);
            let read_out = if float[*g] { st_liveness(insns, &imports, tables, &callees, false).1 } else { returned_out.clone() };
            let st0 = |i: usize| (read_out[i] & 1 != 0, returned_out[i] & 1 != 0);
            let mut reading = Vec::new();
            for (i, insn) in insns.iter().enumerate() {
                let Semantics::Pcode(Ok(ops)) = &insn.semantics else { continue };
                for op in ops {
                    let target = op.inputs.first().map(|v| v.offset);
                    match op.code {
                        Code::Call if st0(i).1 => reading.extend(target),
                        Code::Branch | Code::CBranch if float[*g] && op.inputs[0].space != CONST && !insns.iter().any(|x| Some(x.addr) == target) => reading.extend(target),
                        _ => {}
                    }
                }
            }
            let d = x87_depths(*entry, insns, tables, &imports, float[*g], &callees, &st0);
            found.push((d, reading));
        }
        let mut changed = false;
        for (g, (d, reading)) in body_group.iter().zip(&found) {
            for target in reading {
                if let Some(&t) = group_of.get(target)
                    && kind_of(*target) == X87::Empty
                    && !runtime[t]
                    && !float[t]
                {
                    float[t] = true;
                    changed = true;
                }
            }
            if !float[*g] && d.as_ref().is_some_and(|d| d.returns.is_some_and(|r| r.1 > 0)) {
                float[*g] = true;
                changed = true;
            }
        }
        if !changed {
            break found.into_iter().map(|(d, _)| d).collect();
        }
    };
        let mut grew = false;
        for (b, d) in depths.iter().enumerate() {
            if d.as_ref().is_some_and(|d| d.below) && !odd[b].get() {
                odd[b].set(true);
                grew = true;
            }
        }
        if !grew {
            break depths;
        }
    };
    // The bits that may be live before and after each instruction of a body outside the runtime:
    // of the x87 registers, the slots below the most values the stack may hold there. A group's
    // bodies share their instructions, so the group keeps what any of its entries keeps and
    // emits them once; an odd entry keeps every register and is emitted apart.
    let slots = |depth: Option<Depth>| depth.map_or(ALL_FLAGS, |(_, hi)| !ST_BITS | ((1u32 << hi.clamp(0, 8)) - 1) << 24);
    let mut group_masks: Vec<Option<Vec<(Live, Live)>>> = vec![None; groups.len()];
    for ((g, d), odd) in body_group.iter().zip(&depths).zip(&odd) {
        let Some(d) = d.as_ref().filter(|_| !odd.get()) else { continue };
        let keep: Vec<(Live, Live)> = d.before.iter().zip(&d.after).map(|(b, a)| (slots(*b), slots(*a))).collect();
        group_masks[*g] = Some(match group_masks[*g].take() {
            Some(old) => old.iter().zip(&keep).map(|(o, k)| (o.0 | k.0, o.1 | k.1)).collect(),
            None => keep,
        });
    }
    let masks: Vec<Option<Vec<(Live, Live)>>> = body_group.iter().zip(&odd).map(|(g, odd)| if odd.get() { None } else { group_masks[*g].clone() }).collect();
    // A call made with values on the x87 stack to a function `X87Abi::helpers` does not describe breaks
    // the ABI as the lifter has it: LIFT_DEBUG_ST lists them, to add to the table.
    if std::env::var_os("LIFT_DEBUG_ST").is_some() {
        for ((entry, _, _), d) in bodies.iter().zip(&depths) {
            for (t, at) in d.iter().flat_map(|d| &d.calls) {
                if at.0 > 0 && kind_of(*t) == X87::Empty {
                    eprintln!("x87: {entry:#x} calls {t:#x} with {} values on the stack", at.0);
                }
            }
        }
    }
    // What callers read after a body returns, from its direct calls, and ST0 from a body that
    // returns a float to callers that may not be lifted calls.
    let mut returned = vec![0; groups.len()];
    for g in &body_group {
        if float[*g] {
            returned[*g] |= ST0_BIT;
        }
    }
    let mut reads: FxHashMap<u64, Live> = bodies.iter().map(|(entry, _, _)| (*entry, 0)).collect();
    loop {
        let mut changed = false;
        for (b, ((entry, insns, _), g)) in bodies.iter().zip(&body_group).enumerate() {
            let local: BTreeSet<u64> = insns.iter().map(|i| i.addr).collect();
            let read_of = |t: u64| reads.get(&t).copied().unwrap_or(ALL_FLAGS);
            let kind_here: &dyn Fn(u64) -> X87 = if runtime[*g] || odd[b].get() { &kind_in_runtime } else { &kind_of };
            let (live_in, live_out) = flag_liveness(insns, &local, &imports, &read_of, kind_here, returned[*g], masks[b].as_deref());
            // A body that leaves the x87 registers alone passes what its callers hold in them
            // through, and reads none of them.
            let carried = if touches_x87[*g] { CALL_FLAGS } else { CALL_FLAGS & !ST_BITS };
            let at_entry = insns.iter().position(|i| i.addr == *entry).map_or(ALL_FLAGS, |i| live_in[i]) & carried;
            let mut calls = Vec::new();
            for (i, insn) in insns.iter().enumerate() {
                let Semantics::Pcode(Ok(ops)) = &insn.semantics else { continue };
                for op in ops.iter().filter(|op| op.code == Code::Call) {
                    calls.push((op.inputs[0].offset, live_out[i] & CALL_FLAGS));
                }
            }
            if reads[entry] | at_entry != reads[entry] {
                *reads.get_mut(entry).expect("an entry") |= at_entry;
                changed = true;
            }
            for (target, after) in calls {
                if let Some(&t) = group_of.get(&target)
                    && returned[t] | after != returned[t]
                {
                    returned[t] |= after;
                    changed = true;
                }
            }
        }
        if !changed {
            break;
        }
    }
    let read_of = |t: u64| reads.get(&t).copied().unwrap_or(ALL_FLAGS);
    // The register bytes outside the locals that lifted code reads, and those the runtime
    // reads by name (regs.rs): a write to any other register is dropped. A return's input is
    // not a read: the lifted return leaves by Rust's `return`, so the EIP that RET loads is
    // never used.
    let mut read: BTreeSet<u64> = BTreeSet::new();
    for (_, insns, _) in &bodies {
        for insn in insns {
            let Semantics::Pcode(Ok(ops)) = &insn.semantics else { continue };
            for v in ops.iter().filter(|op| op.code != Code::Return).flat_map(|op| op.inputs.iter()).filter(|v| v.space == REGISTER && !touches_locals(v.offset, v.size)) {
                read.extend(v.offset..v.offset + v.size as u64);
            }
        }
    }
    for name in RUNTIME_REGISTERS {
        let (_, offset, size) = binary.register(name)?;
        read.extend(offset..offset + size as u64);
    }
    // A body keeps the x87 registers as f64 unless it loads the control word, as the C
    // runtime's math functions do around their extended-precision work; LIFT_X87_EXACT keeps
    // every body extended, to compare.
    let (_, control, _) = binary.register("FPUControlWord")?;
    let exact_everywhere = std::env::var_os("LIFT_X87_EXACT").is_some();
    // With every entry known, each body is emitted with an arm of its `match` at each place
    // control can enter it from outside the straight line: an entry, a branch target, a jump
    // table's target, and the instruction after one that does not fall through. The rest of a
    // basic block follows in the same arm, without going around the loop. Every copy of a body
    // gets the same arms, so the workspace writes them once.
    for (b, ((entry, insns, tables), group)) in bodies.into_iter().zip(body_group).enumerate() {
        let local: BTreeSet<u64> = insns.iter().map(|i| i.addr).collect();
        let mut leaders: BTreeSet<u64> = done.iter().copied().filter(|a| local.contains(a)).collect();
        leaders.extend(tables.iter().copied().filter(|a| local.contains(a)));
        for insn in &insns {
            let Semantics::Pcode(Ok(ops)) = &insn.semantics else { continue };
            for op in ops {
                if matches!(op.code, Code::Branch | Code::CBranch) && op.inputs[0].space != CONST && local.contains(&op.inputs[0].offset) {
                    leaders.insert(op.inputs[0].offset);
                }
            }
        }
        let kind_here: &dyn Fn(u64) -> X87 = if runtime[group] || odd[b].get() { &kind_in_runtime } else { &kind_of };
        let (_, live_out) = flag_liveness(&insns, &local, &imports, &read_of, kind_here, returned[group], masks[b].as_deref());
        let loads_control = insns.iter().any(|insn| match &insn.semantics {
            Semantics::Pcode(Ok(ops)) => ops.iter().any(|op| op.out.is_some_and(|o| o.space == REGISTER && (o.offset..o.offset + o.size as u64).contains(&control))),
            _ => false,
        });
        let fast = !exact_everywhere && !loads_control;
        let calls = CallCtx { reads: &read_of, kind: kind_here, returned: returned[group], touches_x87: touches_x87[group], fast, names: &names };
        let mut body = String::new();
        let used: RefCell<BTreeSet<(u64, usize, bool)>> = RefCell::new(BTreeSet::new());
        let mut bad_register = None;
        // Whether an arm is open and the last instruction falls into the next.
        let mut open = false;
        for (position, insn) in insns.iter().enumerate() {
            let next = insn.addr + insn.len;
            if !open || leaders.contains(&insn.addr) {
                if open {
                    writeln!(body, " pc = {:#x}; }}", insn.addr)?;
                }
                write!(body, "            {:#x} => {{", insn.addr)?;
            }
            let falls = if let Some((name, tail)) = imports.get(&insn.addr) {
                // Host code reads and writes only the general registers and memory.
                if *tail {
                    write!(body, " {} c.import(\"{name}\", true); return;", calls.leaving(live_out[position]))?;
                } else {
                    write!(body, " c.save_g({GPR}); c.import(\"{name}\", false); {GPR} = c.gpr();")?;
                }
                !*tail
            } else {
            match &insn.semantics {
                Semantics::X87(instruction) => {
                    let (save_st, sts) = if fast { ("save_st64", "sts64") } else { ("save_st", "sts") };
                    write!(body, " c.{save_st}({ST}); c.x87(x87::Instruction::{instruction:?}); {ST} = c.{sts}();")?;
                    true
                }
                Semantics::Pcode(Err(e)) => {
                    write!(body, " panic!(\"{}\");", e.replace('"', "'"))?;
                    false
                }
                Semantics::Pcode(Ok(ops)) => {
                    for op in ops {
                        for v in op.inputs.iter().chain(op.out.iter()) {
                            if v.space == REGISTER && touches_locals(v.offset, v.size) && local_read(v.offset, v.size, false).is_none() {
                                bad_register = Some(format!("register {:#x}:{} at {:#x}", v.offset, v.size, insn.addr));
                            }
                        }
                    }
                    let mut sizes: BTreeMap<u64, BTreeSet<usize>> = BTreeMap::new();
                    for op in ops {
                        for v in op.inputs.iter().chain(op.out.iter()) {
                            if v.space == UNIQUE {
                                sizes.entry(v.offset).or_default().insert(v.size);
                            }
                        }
                    }
                    let uniques: BTreeMap<u64, usize> = sizes.iter().filter(|(_, s)| s.len() == 1).map(|(o, s)| (*o, *s.iter().next().unwrap())).collect();
                    let inner = ops.iter().any(|op| matches!(op.code, Code::Branch | Code::CBranch) && op.inputs[0].space == CONST);
                    let none = BTreeSet::new();
                    let dead = if inner { vec![false; ops.len()] } else { walk_ops(ops, live_out[position], &read_of, kind_here).1 };
                    let folded = if inner { none } else { folds(ops, &dead, &uniques) };
                    let values = Values { uniques: &uniques, fast, folds: &folded, pending: RefCell::new(BTreeMap::new()), used: &used, read: &read };
                    if inner {
                        write!(body, " {{ let mut i: i64 = 0; 'ops: loop {{ match i {{")?;
                        for (here, op) in ops.iter().enumerate() {
                            write!(body, " {here} => {{ i = {}; {} }}", here + 1, values.op(op, here, &local, &calls, live_out[position]))?;
                        }
                        write!(body, " _ => break 'ops, }} }} }}")?;
                    } else {
                        for (here, op) in ops.iter().enumerate().filter(|(here, _)| !dead[*here]) {
                            let statement = values.op(op, here, &local, &calls, live_out[position]);
                            if !statement.is_empty() {
                                write!(body, " {statement}")?;
                            }
                        }
                    }
                    // Control goes on to the next instruction unless the last op leaves.
                    !ops.iter().any(|op| matches!(op.code, Code::Return | Code::BranchInd) || op.code == Code::Branch && op.inputs[0].space != CONST)
                }
            }
            };
            if falls && insns.get(position + 1).map(|i| i.addr) == Some(next) {
                open = true;
            } else {
                if falls {
                    write!(body, " pc = {next:#x};")?;
                }
                writeln!(body, " }}")?;
                open = false;
            }
        }
        starts.push((code.len(), entry));
        if let Some(why) = bad_register {
            writeln!(code, "#[allow(unused)] {}pub fn f_{entry:x}(c: &mut Cpu) {{ panic!(\"cannot lift {entry:#x}: {why}\") }}", doc(entry))?;
            failed.push(format!("{entry:#x}: {why}"));
            continue;
        }
        let declared: String = used.borrow().iter().map(|&(o, size, float)| if float { format!(" let mut x{o:x}: f64 = 0.0;") } else { format!(" let mut u{o:x}_{size}: {} = 0;", ty(size)) }).collect();
        writeln!(code, "#[allow(unused, unused_mut, unused_assignments, unreachable_code, unused_labels, unused_parens)]\n{}pub fn f_{entry:x}(c: &mut Cpu) {{\n    let mut pc: u32 = {entry:#x};{declared}\n    let {} = c.gpr(); let mut {FLAGS} = c.flags(); let {} = c.{}();\n    'f: loop {{\n        match pc {{", doc(entry), mutable(GPR), mutable(ST), if fast { "sts64" } else { "sts" })?;
        code.push_str(&body);
        writeln!(code, "            _ => {{ {} dispatch(c, pc); return; }}\n        }}\n    }}\n}}", save(fast))?;
    }
    let functions = starts.iter().enumerate().map(|(i, &(at, entry))| Function { entry, doc: doc(entry), text: code[at..starts.get(i + 1).map_or(code.len(), |next| next.0)].to_string() }).collect();
    Ok(Program { functions, report: format!("lifted {} functions, {insn_count} instructions; {} failed\n{}", done.len(), failed.len(), failed.join("\n")) })
}
