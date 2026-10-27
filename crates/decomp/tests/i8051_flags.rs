//! The 8051 language's flags against the processor's own rules.
//!
//! The language keeps each flag in a register of its own and puts the status word together
//! only where code reads it. Here the p-code of every instruction that reads or writes a flag
//! is run from every value of the accumulator, of its operand and of the flags it reads, and
//! the outcome compared with a model of the processor written from its manual.

use std::collections::HashMap;

use recore_decomp::{Section, Session, Target, vendored_spec_dir};

/// What the instructions under test can see and change. `ac` is carried along but no
/// instruction's effect on it is modelled, here or in the language.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Cpu {
    a: u8,
    b: u8,
    cy: bool,
    ac: bool,
    f0: bool,
    rs1: bool,
    rs0: bool,
    ov: bool,
    f1: bool,
    sp: u8,
    /// The byte at 0x30, which the instructions with an operand in memory name.
    operand: u8,
    /// The byte at 0x41: where a push from `SP` of 0x40 goes.
    pushed: u8,
    /// Whether the instruction jumped.
    jumped: bool,
}

impl Cpu {
    fn psw(&self) -> u8 {
        let bit = |flag: bool, at: u8| u8::from(flag) << at;
        bit(self.cy, 7) | bit(self.ac, 6) | bit(self.f0, 5) | bit(self.rs1, 4) | bit(self.rs0, 3) | bit(self.ov, 2) | bit(self.f1, 1) | (self.a.count_ones() as u8 & 1)
    }

    fn set_psw(&mut self, psw: u8) {
        let bit = |at: u8| psw >> at & 1 == 1;
        (self.cy, self.ac, self.f0, self.rs1, self.rs0, self.ov, self.f1) = (bit(7), bit(6), bit(5), bit(4), bit(3), bit(2), bit(1));
    }

    /// A bit by its address: one of `PSW` or of `A`.
    fn bit(&self, addr: u8) -> bool {
        let byte = if addr & 0xf8 == 0xd0 { self.psw() } else { self.a };
        byte >> (addr & 7) & 1 == 1
    }

    fn set_bit(&mut self, addr: u8, value: bool) {
        let mask = 1 << (addr & 7);
        let byte = if addr & 0xf8 == 0xd0 { self.psw() } else { self.a };
        let byte = if value { byte | mask } else { byte & !mask };
        if addr & 0xf8 == 0xd0 { self.set_psw(byte) } else { self.a = byte }
    }

    /// The processor's rules for the instruction in `code`, whose operand in memory is 0x30.
    fn step(mut self, code: [u8; 3]) -> Cpu {
        let (a, operand, carry) = (self.a, self.operand, u8::from(self.cy));
        let signed = |value: i16| !(-128..=127).contains(&value);
        match code[0] {
            // ADD and ADDC A, direct
            0x25 | 0x35 => {
                let carry = if code[0] == 0x35 { carry } else { 0 };
                self.a = a.wrapping_add(operand).wrapping_add(carry);
                self.cy = u16::from(a) + u16::from(operand) + u16::from(carry) > 0xff;
                self.ov = signed(i16::from(a as i8) + i16::from(operand as i8) + i16::from(carry));
            }
            // SUBB A, direct
            0x95 => {
                self.a = a.wrapping_sub(operand).wrapping_sub(carry);
                self.cy = u16::from(a) < u16::from(operand) + u16::from(carry);
                self.ov = signed(i16::from(a as i8) - i16::from(operand as i8) - i16::from(carry));
            }
            // CJNE A, direct, rel
            0xb5 => (self.cy, self.jumped) = (a < operand, a != operand),
            // RLC A and RRC A
            0x33 => (self.a, self.cy) = (a << 1 | carry, a & 0x80 != 0),
            0x13 => (self.a, self.cy) = (a >> 1 | carry << 7, a & 1 != 0),
            // MUL AB
            0xa4 => {
                let product = u16::from(a) * u16::from(self.b);
                (self.a, self.b, self.cy, self.ov) = (product as u8, (product >> 8) as u8, false, product > 0xff);
            }
            // DIV AB, which leaves A and B as they were when it divides by zero
            0x84 => {
                (self.cy, self.ov) = (false, self.b == 0);
                if let Some(quotient) = a.checked_div(self.b) {
                    (self.a, self.b) = (quotient, a % self.b);
                }
            }
            // JC, JNC
            0x40 => self.jumped = self.cy,
            0x50 => self.jumped = !self.cy,
            // SETB, CLR, CPL bit
            0xd2 => self.set_bit(code[1], true),
            0xc2 => self.set_bit(code[1], false),
            0xb2 => self.set_bit(code[1], !self.bit(code[1])),
            // SETB C, CLR C, CPL C
            0xd3 => self.cy = true,
            0xc3 => self.cy = false,
            0xb3 => self.cy = !self.cy,
            // JB, JNB, JBC bit, rel
            0x20 => self.jumped = self.bit(code[1]),
            0x30 => self.jumped = !self.bit(code[1]),
            0x10 => {
                self.jumped = self.bit(code[1]);
                if self.jumped {
                    self.set_bit(code[1], false);
                }
            }
            // MOV C, bit; MOV bit, C; ANL and ORL C, bit and C, /bit
            0xa2 => self.cy = self.bit(code[1]),
            0x92 => self.set_bit(code[1], self.cy),
            0x82 => self.cy &= self.bit(code[1]),
            0xb0 => self.cy &= !self.bit(code[1]),
            0x72 => self.cy |= self.bit(code[1]),
            0xa0 => self.cy |= !self.bit(code[1]),
            // PUSH PSW, POP PSW
            0xc0 => (self.sp, self.pushed) = (self.sp + 1, self.psw()),
            0xd0 => {
                self.set_psw(self.pushed);
                self.sp -= 1;
            }
            // MOV A, PSW; MOV PSW, A; MOV 0x30, PSW; MOV PSW, 0x30
            0xe5 => self.a = self.psw(),
            0xf5 => self.set_psw(a),
            0x85 if code[1] == 0xd0 => self.operand = self.psw(),
            0x85 => self.set_psw(operand),
            // ANL, ORL, XRL PSW, A; INC PSW; XCH A, PSW; ADD A, PSW
            0x52 => self.set_psw(self.psw() & a),
            0x42 => self.set_psw(self.psw() | a),
            0x62 => self.set_psw(self.psw() ^ a),
            0x05 => self.set_psw(self.psw().wrapping_add(1)),
            0xc5 => {
                self.a = self.psw();
                self.set_psw(a);
            }
            other => panic!("no rule for opcode {other:#04x}"),
        }
        self
    }
}

/// Where a p-code operation reads or writes.
#[derive(Clone, Copy)]
enum Place {
    Constant(u64),
    /// A register or a temporary, by its number among the ones the instruction uses.
    Register(usize, u32),
    /// A byte of internal memory at a fixed address.
    Memory(u8),
    /// A jump's destination.
    Code(u64),
    /// The name of an address space.
    Space,
}

struct Operation {
    name: String,
    output: Option<Place>,
    inputs: Vec<Place>,
}

/// An instruction's p-code, as [`Session::listing`] prints it, ready to run.
struct Program {
    operations: Vec<Operation>,
    registers: Vec<String>,
    /// Where the instruction after this one starts.
    next: u64,
}

impl Program {
    fn of(code: [u8; 3]) -> Program {
        let mut session = Session::new(&vendored_spec_dir().unwrap(), Target::I8051, &[Section { addr: 0x100, data: &code, readonly: true, code: true }]).unwrap();
        let listed = session.listing(0x100, 0x101, true).unwrap().remove(0);
        let mut registers: Vec<String> = Vec::new();
        let mut place = |text: &str| {
            if let Some(constant) = text.strip_prefix("0x") {
                return Place::Constant(u64::from_str_radix(constant, 16).unwrap());
            }
            if let Some(addr) = text.strip_prefix("INTMEM[0x") {
                return Place::Memory(u8::from_str_radix(addr.split(']').next().unwrap(), 16).unwrap());
            }
            if let Some(addr) = text.strip_prefix("CODE[0x") {
                return Place::Code(u64::from_str_radix(addr.split(']').next().unwrap(), 16).unwrap());
            }
            if text == "INTMEM" {
                return Place::Space;
            }
            let (name, size) = text.split_once(':').map_or((text, 1), |(name, size)| (name, size.parse().unwrap()));
            let index = registers.iter().position(|known| known == name).unwrap_or_else(|| {
                registers.push(name.to_string());
                registers.len() - 1
            });
            Place::Register(index, size)
        };
        let operations = listed
            .pcode
            .iter()
            .map(|line| {
                let (output, rest) = line.split_once(" = ").map_or((None, line.as_str()), |(output, rest)| (Some(place(output)), rest));
                let (name, inputs) = rest.split_once(' ').unwrap_or((rest, ""));
                Operation { name: name.to_string(), output, inputs: inputs.split(", ").filter(|input| !input.is_empty()).map(&mut place).collect() }
            })
            .collect();
        Program { operations, registers, next: listed.addr + listed.len }
    }

    /// Runs the p-code from `cpu` and gives the state it leaves.
    fn run(&self, cpu: Cpu) -> Cpu {
        let flags = [("CY", cpu.cy), ("AC", cpu.ac), ("F0", cpu.f0), ("RS1", cpu.rs1), ("RS0", cpu.rs0), ("OV", cpu.ov), ("F1", cpu.f1)];
        let named: HashMap<&str, u64> = flags.iter().map(|&(name, flag)| (name, u64::from(flag))).chain([("ACC", cpu.a.into()), ("B", cpu.b.into()), ("SP", cpu.sp.into())]).collect();
        let mut values: Vec<u64> = self.registers.iter().map(|name| named.get(name.as_str()).copied().unwrap_or(0)).collect();
        let mut memory = [0u8; 256];
        (memory[0x30], memory[0x41]) = (cpu.operand, cpu.pushed);
        let mut jumped = false;
        for operation in &self.operations {
            let read = |place: Place, values: &[u64], memory: &[u8; 256]| match place {
                Place::Constant(value) => value,
                Place::Register(index, _) => values[index],
                Place::Memory(addr) => memory[addr as usize].into(),
                Place::Code(_) | Place::Space => unreachable!("neither is a value"),
            };
            let input = |at: usize| read(operation.inputs[at], &values, &memory);
            let size = |place: Place| if let Place::Register(_, size) = place { size } else { 1 };
            let (bits, sign) = (8 * size(operation.inputs.first().copied().unwrap_or(Place::Space)), |value: u64, bits: u32| ((value << (64 - bits)) as i64) >> (64 - bits));
            let result = match operation.name.as_str() {
                "COPY" | "INT_ZEXT" => input(0),
                "INT_ADD" => input(0).wrapping_add(input(1)),
                "INT_SUB" => input(0).wrapping_sub(input(1)),
                "INT_MULT" => input(0) * input(1),
                "INT_DIV" => input(0) / input(1),
                "INT_REM" => input(0) % input(1),
                "INT_AND" => input(0) & input(1),
                "INT_OR" | "BOOL_OR" => input(0) | input(1),
                "INT_XOR" | "BOOL_XOR" => input(0) ^ input(1),
                "INT_NEGATE" => !input(0),
                "INT_LEFT" => input(0) << input(1),
                "INT_RIGHT" => input(0) >> input(1),
                "INT_EQUAL" => (input(0) == input(1)).into(),
                "INT_NOTEQUAL" => (input(0) != input(1)).into(),
                "INT_LESS" => (input(0) < input(1)).into(),
                "INT_CARRY" => ((input(0) + input(1)) >> bits != 0).into(),
                "INT_SCARRY" => (sign(input(0), bits) + sign(input(1), bits) != sign(input(0).wrapping_add(input(1)), bits)).into(),
                "INT_SBORROW" => (sign(input(0), bits) - sign(input(1), bits) != sign(input(0).wrapping_sub(input(1)), bits)).into(),
                "POPCOUNT" => input(0).count_ones().into(),
                "SUBPIECE" => input(0) >> (8 * input(1)),
                "LOAD" => memory[input(1) as usize].into(),
                "STORE" => {
                    memory[input(1) as usize] = input(2) as u8;
                    continue;
                }
                "BRANCH" | "CBRANCH" => {
                    if operation.name == "BRANCH" || input(1) != 0 {
                        // One to the next instruction only gives up half way, as DIV does.
                        jumped = !matches!(operation.inputs[0], Place::Code(addr) if addr == self.next);
                        break;
                    }
                    continue;
                }
                other => panic!("no rule for {other}"),
            };
            match operation.output.expect("an operation with a result") {
                Place::Register(index, size) => values[index] = result & (u64::MAX >> (64 - 8 * size)),
                Place::Memory(addr) => memory[addr as usize] = result as u8,
                Place::Constant(_) | Place::Code(_) | Place::Space => panic!("a result with nowhere to go"),
            }
        }
        let value = |name: &str| self.registers.iter().position(|known| known == name).map_or(named[name], |index| values[index]);
        Cpu {
            a: value("ACC") as u8,
            b: value("B") as u8,
            cy: value("CY") == 1,
            ac: value("AC") == 1,
            f0: value("F0") == 1,
            rs1: value("RS1") == 1,
            rs0: value("RS0") == 1,
            ov: value("OV") == 1,
            f1: value("F1") == 1,
            sp: value("SP") as u8,
            operand: memory[0x30],
            pushed: memory[0x41],
            jumped,
        }
    }
}

/// Runs `code` from every accumulator and carry and each of `operands`, with the other flags
/// as `flags` packs them, and holds the p-code to the model.
fn check(code: [u8; 3], flags: u8, operands: impl Iterator<Item = u8> + Clone) {
    let program = Program::of(code);
    for a in 0..=255u8 {
        for operand in operands.clone() {
            for cy in [false, true] {
                let mut cpu = Cpu { a, b: operand, cy, ac: false, f0: false, rs1: false, rs0: false, ov: false, f1: false, sp: 0x40, operand, pushed: operand, jumped: false };
                cpu.set_psw(flags & 0x7f | u8::from(cy) << 7);
                // A pop takes the byte a push would have left.
                if code[0] == 0xd0 {
                    cpu.sp = 0x41;
                }
                let (expected, found) = (cpu.step(code), program.run(cpu));
                assert_eq!(found, expected, "{code:02x?} from {cpu:?}");
            }
        }
    }
}

#[test]
fn arithmetic_sets_carry_and_overflow_as_the_processor_does() {
    for opcode in [0x25, 0x35, 0x95, 0x33, 0x13, 0xa4, 0x84] {
        check([opcode, 0x30, 0x00], 0, 0..=255);
    }
}

#[test]
fn a_jump_on_a_flag_goes_where_the_processor_goes() {
    for code in [[0xb5, 0x30, 0x10], [0x40, 0x10, 0x00], [0x50, 0x10, 0x00]] {
        check(code, 0, 0..=255);
    }
}

#[test]
fn a_bit_of_the_status_word_is_its_flag() {
    // Each bit of PSW, the parity bit among them, and a bit of the accumulator beside them.
    for bit in (0xd0..=0xd7).chain([0xe3]) {
        for opcode in [0xd2, 0xc2, 0xb2, 0x20, 0x30, 0x10, 0xa2, 0x92, 0x82, 0xb0, 0x72, 0xa0] {
            for flags in [0x00, 0x7e, 0x24, 0x5a] {
                check([opcode, bit, 0x10], flags, [0x5a].into_iter());
            }
        }
    }
    for opcode in [0xd3, 0xc3, 0xb3] {
        check([opcode, 0x00, 0x00], 0, [0x5a].into_iter());
    }
}

#[test]
fn the_status_word_read_or_written_whole_is_its_flags() {
    for code in [[0xc0, 0xd0, 0], [0xd0, 0xd0, 0], [0xe5, 0xd0, 0], [0xf5, 0xd0, 0], [0x85, 0xd0, 0x30], [0x85, 0x30, 0xd0], [0x52, 0xd0, 0], [0x42, 0xd0, 0], [0x62, 0xd0, 0], [0x05, 0xd0, 0], [0xc5, 0xd0, 0]] {
        for flags in [0x00, 0x7e, 0x24, 0x5a] {
            check(code, flags, (0..=255).step_by(7));
        }
    }
}
