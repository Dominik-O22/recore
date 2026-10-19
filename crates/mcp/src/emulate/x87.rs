//! The x87's floats, computed in software as the processor computes them. Its registers hold the
//! 80-bit extended format: a sign, 15 bits of exponent biased by 16383, and 64 bits of significand
//! whose top bit is the integer bit. A sum, difference, product, quotient or square root is rounded
//! once, to the precision and in the direction the control word asks for, within the exponent range
//! of the extended format, and a store to a 4- or 8-byte float rounds once more, in that direction.
//! Exceptions are masked, as they are when a program starts: an invalid operation gives the
//! processor's own not-a-number, a division by zero an infinity, and nothing traps.
//!
//! The processor specification lifts each x87 instruction to the float operations of p-code on
//! the 10-byte registers `ST0` to `ST7`, and moves the registers to push and pop, so the stack needs
//! no top pointer here. What is computed here is any float operation with a 10-byte operand, and
//! in `instructions` the x87 instructions the specification leaves opaque or approximate.

use std::cmp::Ordering;

use super::{Code, fits, mask, signed, signed_min};

mod instructions;
mod wide;

pub use instructions::{Instruction, Stack, execute};

/// How results are rounded, as the control word says: to how many bits of significand, and which
/// way.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Control {
    pub precision: u32,
    pub rounding: Rounding,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rounding {
    Nearest,
    Down,
    Up,
    Zero,
}

impl Control {
    /// The precision is bits 8 and 9 of the word, the rounding bits 10 and 11. The precision field's
    /// value 1 is reserved, and the processor rounds to 64 bits for it as for 3.
    pub fn from_word(word: u128) -> Control {
        let precision = match word >> 8 & 3 {
            0 => 24,
            2 => 53,
            _ => 64,
        };
        let rounding = match word >> 10 & 3 {
            0 => Rounding::Nearest,
            1 => Rounding::Down,
            2 => Rounding::Up,
            _ => Rounding::Zero,
        };
        Control { precision, rounding }
    }
}

/// A binary format a value is rounded into.
struct Format {
    /// Bytes of a value.
    size: usize,
    /// Bits of significand, the integer bit among them.
    precision: u32,
    /// The exponent of the least normal number and of the greatest.
    min_exp: i32,
    max_exp: i32,
}

const SINGLE: Format = Format { size: 4, precision: 24, min_exp: -126, max_exp: 127 };
const DOUBLE: Format = Format { size: 8, precision: 53, min_exp: -1022, max_exp: 1023 };
const EXTENDED: Format = Format { size: 10, precision: 64, min_exp: -16382, max_exp: 16383 };

impl Format {
    fn of(size: usize) -> Result<&'static Format, String> {
        match size {
            4 => Ok(&SINGLE),
            8 => Ok(&DOUBLE),
            10 => Ok(&EXTENDED),
            _ => Err(format!("floating point of {size} bytes is not run")),
        }
    }

    /// Bits that hold the significand: all of it in the extended format, which writes its integer
    /// bit, and all but the integer bit in the others.
    fn field(&self) -> u32 {
        if self.size == 10 { 64 } else { self.precision - 1 }
    }

    fn exponent_mask(&self) -> u128 {
        (1 << (8 * self.size as u32 - 1 - self.field())) - 1
    }

    fn pack(&self, negative: bool, exponent: u128, significand: u128) -> u128 {
        u128::from(negative) << (8 * self.size - 1) | exponent << self.field() | significand & ((1 << self.field()) - 1)
    }
}

/// A value taken apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Value {
    Zero { negative: bool },
    /// `significand` times two to the `exp - 63`, with the top bit of the significand set.
    Finite { negative: bool, exp: i32, significand: u64 },
    Infinite { negative: bool },
    /// Not a number, with its significand as the extended format holds it: integer bit set, and
    /// the bit below it set if it is quiet.
    Nan { negative: bool, significand: u64 },
}

use Value::{Finite, Infinite, Nan, Zero};

const QUIET: u64 = 1 << 62;
const INTEGER_BIT: u64 = 1 << 63;

/// What an invalid operation gives: the negative quiet not-a-number with no payload.
const INDEFINITE: Value = Nan { negative: true, significand: INTEGER_BIT | QUIET };

impl Value {
    fn negative(self) -> bool {
        match self {
            Zero { negative } | Finite { negative, .. } | Infinite { negative } | Nan { negative, .. } => negative,
        }
    }

    fn negate(self) -> Value {
        match self {
            Zero { negative } => Zero { negative: !negative },
            Finite { negative, exp, significand } => Finite { negative: !negative, exp, significand },
            Infinite { negative } => Infinite { negative: !negative },
            nan => nan,
        }
    }
}

/// Whether an extended float is one the processor no longer supports, which the format can hold
/// because it writes its integer bit: one whose integer bit contradicts its exponent. An
/// operation on it is invalid.
fn unsupported(bits: u128) -> bool {
    bits >> 64 & 0x7fff != 0 && bits & u128::from(INTEGER_BIT) == 0
}

fn decode(bits: u128, format: &Format) -> Value {
    let negative = bits >> (8 * format.size - 1) & 1 == 1;
    let exponent = bits >> format.field() & format.exponent_mask();
    let field = bits & ((1 << format.field()) - 1);
    let extended = format.size == 10;
    // As the extended format holds it, with the integer bit at the top.
    let significand = if extended { field as u64 } else { (field as u64) << (64 - format.precision) | u64::from(exponent != 0) << 63 };
    let bias = format.max_exp as u128;
    if extended && unsupported(bits) {
        INDEFINITE
    } else if exponent == format.exponent_mask() {
        if significand << 1 == 0 { Infinite { negative } } else { Nan { negative, significand: significand | INTEGER_BIT } }
    } else if significand == 0 {
        Zero { negative }
    } else {
        // A subnormal has the exponent of the least normal number.
        let exp = if exponent == 0 { format.min_exp } else { exponent as i32 - bias as i32 };
        let shift = significand.leading_zeros();
        Finite { negative, exp: exp - shift as i32, significand: significand << shift }
    }
}

/// A value the format holds exactly as it is: a zero, an infinity, or a not-a-number made quiet.
fn encode(value: Value, format: &Format) -> u128 {
    let all = format.exponent_mask();
    let integer = if format.size == 10 { u128::from(INTEGER_BIT) } else { 0 };
    match value {
        Zero { negative } => format.pack(negative, 0, 0),
        Infinite { negative } => format.pack(negative, all, integer),
        Nan { negative, significand } => format.pack(negative, all, u128::from(significand | QUIET) >> (64 - format.precision) | integer),
        Finite { negative, exp, significand } => round(negative, exp - 63, u128::from(significand), false, format, format.precision, Rounding::Nearest),
    }
}

/// Whether a value cut to `kept` rounds away from zero, given the first bit cut, whether any bit
/// below that is set, and its sign.
fn rounds_up(kept: u128, half: bool, sticky: bool, negative: bool, rounding: Rounding) -> bool {
    let inexact = half || sticky;
    match rounding {
        Rounding::Nearest => half && (sticky || kept & 1 == 1),
        Rounding::Zero => false,
        Rounding::Up => inexact && !negative,
        Rounding::Down => inexact && negative,
    }
}

/// `significand` times two to the `exp`, plus a little more if `sticky`, rounded to `precision`
/// bits of significand in `format`. The significand is not zero.
fn round(negative: bool, exp: i32, significand: u128, sticky: bool, format: &Format, precision: u32, rounding: Rounding) -> u128 {
    let shift = significand.leading_zeros();
    let (significand, exp) = (significand << shift, exp - shift as i32);
    // The bit that is kept last: `precision` bits below the top one, or below the top one of the
    // least normal number when the value is less. The processor keeps no more bits of a subnormal
    // than the precision allows a normal number.
    let lsb = (exp + 127).max(format.min_exp) - (precision as i32 - 1);
    let drop = (lsb - exp) as u32;
    let (kept, half, below) = match drop {
        0..128 => (significand >> drop, significand >> (drop - 1) & 1 == 1, significand.checked_shl(129 - drop).unwrap_or(0) != 0),
        128 => (0, significand >> 127 == 1, significand << 1 != 0),
        _ => (0, false, true),
    };
    let kept = kept + u128::from(rounds_up(kept, half, below || sticky, negative, rounding));
    if kept == 0 {
        return format.pack(negative, 0, 0);
    }
    let width = 128 - kept.leading_zeros();
    let top = lsb + width as i32 - 1;
    if top > format.max_exp {
        let to_infinity = match rounding {
            Rounding::Nearest => true,
            Rounding::Zero => false,
            Rounding::Up => !negative,
            Rounding::Down => negative,
        };
        if to_infinity {
            return encode(Infinite { negative }, format);
        }
        let largest = ((1 << precision) - 1) << (format.precision - precision);
        return format.pack(negative, (format.max_exp * 2) as u128, largest);
    }
    if top < format.min_exp {
        return format.pack(negative, 0, kept << (format.precision - precision));
    }
    let aligned = if width <= format.precision { kept << (format.precision - width) } else { kept >> (width - format.precision) };
    format.pack(negative, (top + format.max_exp) as u128, aligned)
}

/// A result before it is rounded.
#[derive(Clone, Copy, Debug)]
enum Exact {
    /// One the format holds as it is.
    Special(Value),
    /// `significand` times two to the `exp`, plus a little more if `sticky`.
    Number { negative: bool, exp: i32, significand: u128, sticky: bool },
}

use Exact::{Number, Special};

fn exact(value: Value) -> Exact {
    match value {
        Finite { negative, exp, significand } => Number { negative, exp: exp - 63, significand: u128::from(significand), sticky: false },
        other => Special(other),
    }
}

fn finish(result: Exact, format: &Format, precision: u32, rounding: Rounding) -> u128 {
    match result {
        Special(value) => encode(value, format),
        Number { negative, exp, significand, sticky } => round(negative, exp, significand, sticky, format, precision, rounding),
    }
}

/// The not-a-number an operation on these gives, if any is one: a quiet one before a signalling
/// one, else the one with the larger significand, else the first. It comes out quiet.
fn propagate(operands: &[Value]) -> Option<Value> {
    let mut chosen: Option<(bool, u64)> = None;
    for &operand in operands {
        if let Nan { negative, significand } = operand {
            let rank = |significand: u64| (significand & QUIET != 0, significand);
            if chosen.is_none_or(|(_, best)| rank(significand) > rank(best)) {
                chosen = Some((negative, significand));
            }
        }
    }
    chosen.map(|(negative, significand)| Nan { negative, significand: significand | QUIET })
}

/// Bits shifted out to the right, and whether any that fell off were set.
fn shift_right(value: u128, by: u32) -> (u128, bool) {
    match by {
        0 => (value, false),
        1..128 => (value >> by, value << (128 - by) != 0),
        _ => (0, value != 0),
    }
}

fn add(a: Value, b: Value, rounding: Rounding) -> Exact {
    if let Some(nan) = propagate(&[a, b]) {
        return Special(nan);
    }
    match (a, b) {
        (Infinite { negative: x }, Infinite { negative: y }) => Special(if x == y { a } else { INDEFINITE }),
        (Infinite { .. }, _) => Special(a),
        (_, Infinite { .. }) => Special(b),
        // Zeros of opposite signs sum to a positive one, unless the rounding is down.
        (Zero { negative: x }, Zero { negative: y }) => Special(Zero { negative: if x == y { x } else { rounding == Rounding::Down } }),
        (Zero { .. }, number) | (number, Zero { .. }) => exact(number),
        (Finite { negative: na, exp: ea, significand: sa }, Finite { negative: nb, exp: eb, significand: sb }) => {
            let ((negative, exp, big), (other, small_exp, small)) = if (ea, sa) >= (eb, sb) { ((na, ea, sa), (nb, eb, sb)) } else { ((nb, eb, sb), (na, ea, sa)) };
            // Room above for a carry and 62 bits below to round from.
            let big = u128::from(big) << 62;
            let (small, sticky) = shift_right(u128::from(small) << 62, (exp - small_exp) as u32);
            // What fell off the smaller makes the difference a little less than this.
            let significand = if negative == other { big + small } else { big - small - u128::from(sticky) };
            if significand == 0 {
                return Special(Zero { negative: rounding == Rounding::Down });
            }
            Number { negative, exp: exp - 63 - 62, significand, sticky }
        }
        (Nan { .. }, _) | (_, Nan { .. }) => unreachable!("propagated"),
    }
}

fn multiply(a: Value, b: Value) -> Exact {
    if let Some(nan) = propagate(&[a, b]) {
        return Special(nan);
    }
    let negative = a.negative() != b.negative();
    match (a, b) {
        (Infinite { .. }, Zero { .. }) | (Zero { .. }, Infinite { .. }) => Special(INDEFINITE),
        (Infinite { .. }, _) | (_, Infinite { .. }) => Special(Infinite { negative }),
        (Zero { .. }, _) | (_, Zero { .. }) => Special(Zero { negative }),
        (Finite { exp: ea, significand: sa, .. }, Finite { exp: eb, significand: sb, .. }) => Number { negative, exp: ea + eb - 126, significand: u128::from(sa) * u128::from(sb), sticky: false },
        (Nan { .. }, _) | (_, Nan { .. }) => unreachable!("propagated"),
    }
}

fn divide(a: Value, b: Value) -> Exact {
    if let Some(nan) = propagate(&[a, b]) {
        return Special(nan);
    }
    let negative = a.negative() != b.negative();
    match (a, b) {
        (Infinite { .. }, Infinite { .. }) | (Zero { .. }, Zero { .. }) => Special(INDEFINITE),
        (Infinite { .. }, _) | (_, Zero { .. }) => Special(Infinite { negative }),
        (Zero { .. }, _) | (_, Infinite { .. }) => Special(Zero { negative }),
        (Finite { exp: ea, significand: sa, .. }, Finite { exp: eb, significand: sb, .. }) => {
            let (numerator, divisor) = (u128::from(sa) << 64, u128::from(sb));
            let (quotient, remainder) = (numerator / divisor, numerator % divisor);
            // One bit more than the quotient of the significands has when the first is the smaller.
            let (bit, remainder) = if remainder << 1 >= divisor { (1, (remainder << 1) - divisor) } else { (0, remainder << 1) };
            Number { negative, exp: ea - eb - 65, significand: quotient << 1 | bit, sticky: remainder != 0 }
        }
        (Nan { .. }, _) | (_, Nan { .. }) => unreachable!("propagated"),
    }
}

fn square_root(a: Value) -> Exact {
    match a {
        Nan { .. } => Special(propagate(&[a]).expect("a not-a-number")),
        Zero { .. } | Infinite { negative: false } => Special(a),
        Infinite { negative: true } | Finite { negative: true, .. } => Special(INDEFINITE),
        Finite { negative: false, exp, significand } => {
            // An even power of two, and as many bits as fit to take the root of.
            let power = exp - 63;
            let shift = if power.rem_euclid(2) == 0 { 64 } else { 63 };
            let n = u128::from(significand) << shift;
            let root = n.isqrt();
            let remainder = n - root * root;
            // The root is at least halfway to the next integer exactly when the remainder is more
            // than the root, and it is never exactly halfway.
            Number { negative: false, exp: (power - shift) / 2 - 1, significand: root << 1 | u128::from(remainder > root), sticky: remainder != 0 }
        }
    }
}

/// The value rounded to an integer, as `FRNDINT` rounds it, held as a float.
fn integral(a: Value, rounding: Rounding) -> Exact {
    match a {
        Nan { .. } => Special(propagate(&[a]).expect("a not-a-number")),
        Finite { negative, exp, significand } if exp < 63 => {
            let drop = (63 - exp) as u32;
            let significand = u128::from(significand);
            let (kept, half, sticky) = if drop > 64 { (0, false, true) } else { (significand >> drop, significand >> (drop - 1) & 1 == 1, significand & ((1 << (drop - 1)) - 1) != 0) };
            let kept = kept + u128::from(rounds_up(kept, half, sticky, negative, rounding));
            if kept == 0 { Special(Zero { negative }) } else { Number { negative, exp: 0, significand: kept, sticky: false } }
        }
        other => exact(other),
    }
}

/// The value cut toward zero to a signed integer of `size` bytes. Out of range, an infinity or a
/// not-a-number gives the lowest integer, as the processor stores it.
fn to_integer(a: Value, size: usize) -> u128 {
    let integer = match a {
        Zero { .. } => Some(0),
        Finite { exp, .. } if exp < 0 => Some(0),
        Finite { negative, exp, significand } if exp <= 126 => {
            let magnitude = if exp <= 63 { i128::from(significand >> (63 - exp)) } else { i128::from(significand) << (exp - 63) };
            Some(if negative { -magnitude } else { magnitude })
        }
        _ => None,
    };
    integer.filter(|&integer| fits(integer, size)).unwrap_or_else(|| signed_min(size)) as u128 & mask(size)
}

fn compare(a: Value, b: Value) -> Option<Ordering> {
    // How far from zero, in an order that holds within a sign. Both zeros are the same.
    let magnitude = |value: Value| match value {
        Finite { exp, significand, .. } => (1, exp, significand),
        Infinite { .. } => (2, 0, 0),
        _ => (0, 0, 0),
    };
    let below_zero = |value: Value| value.negative() && !matches!(value, Zero { .. });
    match (a, b) {
        (Nan { .. }, _) | (_, Nan { .. }) => None,
        _ => Some(match (below_zero(a), below_zero(b)) {
            (false, false) => magnitude(a).cmp(&magnitude(b)),
            (true, true) => magnitude(b).cmp(&magnitude(a)),
            (false, true) => Ordering::Greater,
            (true, false) => Ordering::Less,
        }),
    }
}

/// Whether the operation is one of the floats of the x87: a float operation with a 10-byte operand.
pub fn applies(code: Code, size: usize, inputs: &[(u128, usize)]) -> bool {
    use Code::*;
    let float = matches!(code, FEqual | FNotEqual | FLess | FLessEqual | FNan | FAdd | FDiv | FMult | FSub | FNeg | FAbs | FSqrt | Int2Float | Float2Float | Trunc | Ceil | Floor | Round);
    float && (size == 10 || inputs.iter().any(|&(_, size)| size == 10))
}

/// The result of a float operation of p-code with an extended operand, in a place `size` bytes
/// wide. An integer of 10 bytes, which `ROUND` and `TRUNC` make for an x87 register, is held as a
/// float there.
pub fn compute(code: Code, size: usize, inputs: &[(u128, usize)], control: Control) -> Result<u128, String> {
    use Code::*;
    let operand = |index: usize| -> Result<Value, String> {
        let (bits, size) = inputs.get(index).copied().ok_or_else(|| format!("{code:?} without its operand"))?;
        Ok(decode(bits, Format::of(size)?))
    };
    let order = || -> Result<Option<Ordering>, String> { Ok(compare(operand(0)?, operand(1)?)) };
    let out = || Format::of(size);
    // The arithmetic rounds to the precision the control word asks for, a conversion to the
    // precision of its format, and an integer is exact.
    let arithmetic = |result: Exact| -> Result<u128, String> {
        let format = out()?;
        Ok(finish(result, format, control.precision.min(format.precision), control.rounding))
    };
    let converted = |result: Exact| -> Result<u128, String> {
        let format = out()?;
        Ok(finish(result, format, format.precision, control.rounding))
    };
    let flip = |bits: u128, clear: bool| -> Result<u128, String> {
        let sign = 1u128 << (8 * size - 1);
        Ok(if clear { bits & !sign } else { bits ^ sign })
    };
    match code {
        FEqual => Ok(u128::from(order()? == Some(Ordering::Equal))),
        FNotEqual => Ok(u128::from(order()? != Some(Ordering::Equal))),
        FLess => Ok(u128::from(order()? == Some(Ordering::Less))),
        FLessEqual => Ok(u128::from(matches!(order()?, Some(Ordering::Less | Ordering::Equal)))),
        FNan => Ok(u128::from(matches!(operand(0)?, Nan { .. }))),
        FAdd => arithmetic(add(operand(0)?, operand(1)?, control.rounding)),
        FSub => arithmetic(add(operand(0)?, operand(1)?.negate(), control.rounding)),
        FMult => arithmetic(multiply(operand(0)?, operand(1)?)),
        FDiv => arithmetic(divide(operand(0)?, operand(1)?)),
        FSqrt => arithmetic(square_root(operand(0)?)),
        // A change of sign touches only the sign bit, of a not-a-number too.
        FNeg | FAbs => {
            let (bits, from) = inputs[0];
            let bits = if from == size { bits } else { converted(exact(operand(0)?))? };
            flip(bits, code == FAbs)
        }
        Float2Float => converted(exact(operand(0)?)),
        Int2Float => {
            let (bits, from) = inputs[0];
            let integer = signed(bits, from);
            converted(if integer == 0 { Special(Zero { negative: false }) } else { Number { negative: integer < 0, exp: 0, significand: integer.unsigned_abs(), sticky: false } })
        }
        Round | Trunc | Ceil | Floor => {
            let rounding = match code {
                Round => control.rounding,
                Trunc => Rounding::Zero,
                Ceil => Rounding::Up,
                _ => Rounding::Down,
            };
            if code == Trunc && size != 10 {
                return Ok(to_integer(operand(0)?, size));
            }
            converted(integral(operand(0)?, rounding))
        }
        _ => unreachable!("{code:?} is not a float operation"),
    }
}

/// A natural number of any size, as 32-bit digits, the lowest first: enough arithmetic to print a
/// float exactly.
struct Natural(Vec<u32>);

impl Natural {
    fn multiply(&mut self, factor: u32) {
        let mut carry = 0u64;
        for digit in &mut self.0 {
            let product = u64::from(*digit) * u64::from(factor) + carry;
            *digit = product as u32;
            carry = product >> 32;
        }
        if carry > 0 {
            self.0.push(carry as u32);
        }
    }

    fn shift_left(&mut self, bits: u32) {
        for _ in 0..bits / 32 {
            self.0.insert(0, 0);
        }
        let bits = bits % 32;
        if bits > 0 {
            let mut carry = 0;
            for digit in &mut self.0 {
                let shifted = u64::from(*digit) << bits | carry;
                *digit = shifted as u32;
                carry = shifted >> 32;
            }
            if carry > 0 {
                self.0.push(carry as u32);
            }
        }
    }

    /// Divides in place and gives the remainder.
    fn divide(&mut self, divisor: u32) -> u32 {
        let mut remainder = 0u64;
        for digit in self.0.iter_mut().rev() {
            let current = remainder << 32 | u64::from(*digit);
            *digit = (current / u64::from(divisor)) as u32;
            remainder = current % u64::from(divisor);
        }
        while self.0.last() == Some(&0) {
            self.0.pop();
        }
        remainder as u32
    }

    fn decimal(mut self) -> String {
        let mut groups = Vec::new();
        while !self.0.is_empty() {
            groups.push(self.divide(1_000_000_000));
        }
        let mut text = groups.pop().map_or_else(|| "0".to_string(), |first| first.to_string());
        for group in groups.iter().rev() {
            text.push_str(&format!("{group:09}"));
        }
        text
    }
}

/// Significant digits shown of an extended float: enough to tell any two apart.
const DIGITS: usize = 21;

/// Digits and where the decimal point goes among them, from the left, as decimal text: written
/// out between 1e-5 and 1e21, else with an exponent, as `shortest` writes a narrower float.
fn place_point(digits: &str, point: i32) -> String {
    let len = digits.len() as i32;
    if point > -5 && point <= 21 {
        if point <= 0 {
            format!("0.{}{digits}", "0".repeat(-point as usize))
        } else if point >= len {
            format!("{digits}{}", "0".repeat((point - len) as usize))
        } else {
            format!("{}.{}", &digits[..point as usize], &digits[point as usize..])
        }
    } else {
        let rest = if len > 1 { format!(".{}", &digits[1..]) } else { String::new() };
        format!("{}{rest}e{}", &digits[..1], point - 1)
    }
}

/// A float as Rust writes it, with an exponent outside 1e-5 to 1e21.
fn shortest<T: std::fmt::Display + std::fmt::LowerExp>(value: T, magnitude: f64) -> String {
    if magnitude == 0.0 || !magnitude.is_finite() || (1e-5..1e21).contains(&magnitude.abs()) { value.to_string() } else { format!("{value:e}") }
}

/// A float of `size` bytes in decimal: an extended one to 21 significant digits, enough to tell
/// any two apart, and a narrower one in the fewest digits that read back as it.
pub fn decimal(bits: u128, size: usize) -> String {
    match size {
        4 => return shortest(f32::from_bits(bits as u32), f64::from(f32::from_bits(bits as u32))),
        8 => return shortest(f64::from_bits(bits as u64), f64::from_bits(bits as u64)),
        _ => {}
    }
    let (negative, exp, significand) = match decode(bits, &EXTENDED) {
        Zero { negative } => return if negative { "-0".into() } else { "0".into() },
        Infinite { negative } => return if negative { "-inf".into() } else { "inf".into() },
        Nan { .. } => return "NaN".into(),
        Finite { negative, exp, significand } => (negative, exp, significand),
    };
    // The value is a natural number over a power of ten.
    let mut natural = Natural(vec![significand as u32, (significand >> 32) as u32]);
    let power = exp - 63;
    let scale = if power >= 0 {
        natural.shift_left(power as u32);
        0
    } else {
        // Times five to the power, thirteen fives at a time.
        let fives = -power as u32;
        for _ in 0..fives / 13 {
            natural.multiply(5u32.pow(13));
        }
        natural.multiply(5u32.pow(fives % 13));
        -power
    };
    let mut digits: Vec<u8> = natural.decimal().into_bytes();
    let mut point = digits.len() as i32 - scale;
    if digits.len() > DIGITS {
        let rest = digits.split_off(DIGITS);
        let beyond = rest[1..].iter().any(|&digit| digit != b'0');
        let odd = digits[DIGITS - 1] % 2 == 1;
        if rest[0] > b'5' || rest[0] == b'5' && (beyond || odd) {
            let mut at = DIGITS;
            loop {
                if at == 0 {
                    digits.insert(0, b'1');
                    digits.pop();
                    point += 1;
                    break;
                }
                at -= 1;
                if digits[at] == b'9' {
                    digits[at] = b'0';
                } else {
                    digits[at] += 1;
                    break;
                }
            }
        }
    }
    while digits.len() > 1 && digits.last() == Some(&b'0') {
        digits.pop();
    }
    let text = place_point(std::str::from_utf8(&digits).expect("digits"), point);
    if negative { format!("-{text}") } else { text }
}

/// A float of `size` bytes, 4 or 8, as an extended one, which holds it exactly.
pub fn widen(bits: u128, size: usize) -> Result<u128, String> {
    Ok(encode(decode(bits, Format::of(size)?), &EXTENDED))
}

/// An extended float as a float of `size` bytes, rounded as the control word says.
pub fn narrow(bits: u128, size: usize, control: Control) -> Result<u128, String> {
    let format = Format::of(size)?;
    Ok(finish(exact(decode(bits, &EXTENDED)), format, format.precision, control.rounding))
}

#[cfg(test)]
mod tests {
    use super::*;

    const NEAREST_53: Control = Control { precision: 53, rounding: Rounding::Nearest };
    const NEAREST_64: Control = Control { precision: 64, rounding: Rounding::Nearest };

    fn ext(value: f64) -> u128 {
        widen(u128::from(value.to_bits()), 8).unwrap()
    }

    #[test]
    fn a_third_is_rounded_to_the_precision_the_control_word_asks_for() {
        let third = |control| compute(Code::FDiv, 10, &[(ext(1.0), 10), (ext(3.0), 10)], control).unwrap();
        assert_eq!(third(NEAREST_64), 0x3ffd_aaaa_aaaa_aaaa_aaab);
        assert_eq!(third(NEAREST_53), 0x3ffd_aaaa_aaaa_aaaa_a800);
        assert_eq!(third(Control { precision: 24, rounding: Rounding::Zero }), 0x3ffd_aaaa_aa00_0000_0000);
        assert_eq!(Control::from_word(0x27f), NEAREST_53);
        assert_eq!(Control::from_word(0xc7f), Control { precision: 24, rounding: Rounding::Zero });
    }

    #[test]
    fn an_integer_store_rounds_as_the_control_word_says_and_cuts_toward_zero() {
        let round = |value: f64, word: u128| {
            let rounded = compute(Code::Round, 10, &[(ext(value), 10)], Control::from_word(word)).unwrap();
            compute(Code::Trunc, 4, &[(rounded, 10)], Control::from_word(word)).unwrap() as u32 as i32
        };
        assert_eq!([round(2.5, 0x37f), round(3.5, 0x37f), round(-2.5, 0x37f), round(-2.7, 0xf7f)], [2, 4, -2, -2]);
        assert_eq!([round(2.5, 0x77f), round(2.5, 0xb7f), round(-2.5, 0x77f)], [2, 3, -3]);
        assert_eq!(compute(Code::Trunc, 4, &[(ext(3e9), 10)], NEAREST_64).unwrap(), 0x8000_0000);
    }

    #[test]
    fn a_comparison_with_a_not_a_number_is_unordered() {
        let nan = ext(f64::NAN);
        assert_eq!(compute(Code::FLess, 1, &[(nan, 10), (ext(1.0), 10)], NEAREST_64), Ok(0));
        assert_eq!(compute(Code::FNotEqual, 1, &[(nan, 10), (nan, 10)], NEAREST_64), Ok(1));
        assert_eq!(compute(Code::FEqual, 1, &[(ext(0.0), 10), (ext(-0.0), 10)], NEAREST_64), Ok(1));
        assert_eq!(compute(Code::FLess, 1, &[(ext(-2.0), 10), (ext(-1.0), 10)], NEAREST_64), Ok(1));
    }

    #[test]
    fn floats_print_in_decimal() {
        assert_eq!(decimal(ext(130.0), 10), "130");
        assert_eq!(decimal(ext(-0.0), 10), "-0");
        assert_eq!(decimal(0x3ffd_aaaa_aaaa_aaaa_aaab, 10), "0.333333333333333333342");
        assert_eq!(decimal(ext(0.1), 10), "0.100000000000000005551");
        assert_eq!(decimal(0x7ffe_ffff_ffff_ffff_ffff, 10), "1.18973149535723176502e4932");
        assert_eq!(decimal(0x0000_0000_0000_0000_0001, 10), "3.64519953188247460253e-4951");
        assert_eq!(decimal(ext(1e23), 10), "9.99999999999999916114e22");
        assert_eq!(decimal(u128::from(0.1f32.to_bits()), 4), "0.1");
        assert_eq!(decimal(u128::from(1e-7f64.to_bits()), 8), "1e-7");
    }

    /// The same operations run on this machine's own x87.
    #[cfg(target_arch = "x86_64")]
    mod hardware {
        use std::arch::asm;

        use super::*;

        /// Runs `$op` with `a` in ST0 and `b` in ST1 under the control word, and stores ST0 as
        /// `$store` writes it.
        macro_rules! x87 {
            ($op:literal, $store:literal) => {
                |a: u128, b: u128, word: u16| -> u128 {
                    let (a, b, mut out, mut saved) = (a.to_le_bytes(), b.to_le_bytes(), [0u8; 16], 0u16);
                    // SAFETY: the operands are 16 bytes each, and the stack is left empty and the
                    // control word as it was.
                    unsafe {
                        asm!(
                            "fnstcw word ptr [{saved}]",
                            "fldcw word ptr [{word}]",
                            "fld tbyte ptr [{b}]",
                            "fld tbyte ptr [{a}]",
                            $op,
                            $store,
                            "fstp st(0)",
                            "fldcw word ptr [{saved}]",
                            saved = in(reg) &raw mut saved,
                            word = in(reg) &raw const word,
                            a = in(reg) a.as_ptr(),
                            b = in(reg) b.as_ptr(),
                            out = in(reg) out.as_mut_ptr(),
                            out("st(0)") _, out("st(1)") _, out("st(2)") _, out("st(3)") _,
                            out("st(4)") _, out("st(5)") _, out("st(6)") _, out("st(7)") _,
                            options(nostack),
                        );
                    }
                    u128::from_le_bytes(out)
                }
            };
        }

        struct Rng(u64);

        impl Rng {
            fn next(&mut self) -> u64 {
                self.0 ^= self.0 << 13;
                self.0 ^= self.0 >> 7;
                self.0 ^= self.0 << 17;
                self.0
            }
        }

        /// An extended float that is likely to round in an interesting way: near the other
        /// operand, at the ends of the range, a double, or one of the special values.
        fn generate(rng: &mut Rng, near: Option<u128>) -> u128 {
            let sign = u128::from(rng.next() & 1) << 79;
            let significand = rng.next() | 1 << 63;
            let exponent = match rng.next() % 10 {
                0 => rng.next() % 0x7fff,
                1 => rng.next() % 70,
                2 => 0x7ffe - rng.next() % 70,
                _ => 0x3fff - 70 + rng.next() % 140,
            };
            let value = sign | u128::from(exponent) << 64 | u128::from(significand);
            let chosen = match (rng.next() % 16, near) {
                (0, _) => [0, 1 << 79, 0x7fff_8000_0000_0000_0000, 0xffff_8000_0000_0000_0000][rng.next() as usize % 4],
                (1, _) => 0x7fff_8000_0000_0000_0000 | u128::from(rng.next() >> 2) | u128::from(rng.next() & 1) << 62 | sign,
                (2, _) => sign | u128::from(rng.next() >> 1),
                (3 | 4, _) => value & !0x7ff,
                (5..=7, Some(near)) => near ^ u128::from(rng.next() % 4) << 79 ^ u128::from(rng.next() & 0xfff),
                (8, Some(near)) => near ^ 1 << 64,
                _ => value,
            };
            chosen & mask(10)
        }

        type Operation = (&'static str, Code, usize, fn(u128, u128, u16) -> u128);

        /// Inputs tried on each instruction under each control word.
        const CASES: usize = 2000;

        /// How far apart two extended floats of the same sign are, in units in the last place of
        /// the 64-bit significand. The format writes its integer bit, so the count goes by value
        /// and not by the bits: a normal number's exponent field counts from 1.
        fn ulps(a: u128, b: u128) -> u128 {
            let magnitude = |bits: u128| match bits >> 64 & 0x7fff {
                0 => bits & u128::from(u64::MAX),
                exponent => (exponent - 1) << 63 | bits & ((1 << 63) - 1),
            };
            if a >> 79 != b >> 79 { u128::MAX } else { magnitude(a).abs_diff(magnitude(b)) }
        }

        #[test]
        fn every_rounding_is_the_processors() {
            let operations: [Operation; 10] = [
                ("add", Code::FAdd, 10, x87!("fadd st, st(1)", "fstp tbyte ptr [{out}]")),
                ("sub", Code::FSub, 10, x87!("fsub st, st(1)", "fstp tbyte ptr [{out}]")),
                ("mul", Code::FMult, 10, x87!("fmul st, st(1)", "fstp tbyte ptr [{out}]")),
                ("div", Code::FDiv, 10, x87!("fdiv st, st(1)", "fstp tbyte ptr [{out}]")),
                ("sqrt", Code::FSqrt, 10, x87!("fsqrt", "fstp tbyte ptr [{out}]")),
                ("frndint", Code::Round, 10, x87!("frndint", "fstp tbyte ptr [{out}]")),
                ("fst m32", Code::Float2Float, 4, x87!("fnop", "fstp dword ptr [{out}]")),
                ("fst m64", Code::Float2Float, 8, x87!("fnop", "fstp qword ptr [{out}]")),
                ("fistp m64", Code::Trunc, 8, x87!("fnop", "fistp qword ptr [{out}]")),
                ("fistp m16", Code::Trunc, 2, x87!("fnop", "fistp word ptr [{out}]")),
            ];
            let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
            let mut wrong = Vec::new();
            let mut tried = 0;
            for precision in 0..4u16 {
                for rounding in 0..4u16 {
                    let word = 0x7f | precision << 8 | rounding << 10;
                    let control = Control::from_word(u128::from(word));
                    for &(name, code, size, hardware) in &operations {
                        for _ in 0..3000 {
                            let a = generate(&mut rng, None);
                            let b = generate(&mut rng, Some(a));
                            let unary = matches!(code, Code::FSqrt | Code::Round | Code::Float2Float | Code::Trunc);
                            let inputs: &[(u128, usize)] = if unary { &[(a, 10)] } else { &[(a, 10), (b, 10)] };
                            let want = hardware(a, b, word) & mask(size);
                            // The specification lifts an integer store to a rounding, then a cut.
                            let got = if code == Code::Trunc {
                                let rounded = compute(Code::Round, 10, inputs, control).unwrap();
                                compute(Code::Trunc, size, &[(rounded, 10)], control).unwrap()
                            } else {
                                compute(code, size, inputs, control).unwrap()
                            };
                            tried += 1;
                            if got != want {
                                wrong.push(format!("{name} {a:#022x} {b:#022x} under {word:#x}: the processor gives {want:#x}, this {got:#x}"));
                            }
                        }
                    }
                }
            }
            assert!(wrong.is_empty(), "{} of {tried} differ:\n{}", wrong.len(), wrong.iter().take(20).cloned().collect::<Vec<_>>().join("\n"));
        }

        /// The condition bits `FCOM` leaves in the status word: C0 for less, C3 for equal, and all
        /// three of C0, C2 and C3 when the two are unordered.
        fn fcom(a: u128, b: u128) -> u16 {
            let (a, b, mut status) = (a.to_le_bytes(), b.to_le_bytes(), 0u16);
            // SAFETY: as in `x87!`.
            unsafe {
                asm!(
                    "fld tbyte ptr [{b}]",
                    "fld tbyte ptr [{a}]",
                    "fcompp",
                    "fnstsw ax",
                    a = in(reg) a.as_ptr(),
                    b = in(reg) b.as_ptr(),
                    out("ax") status,
                    out("st(0)") _, out("st(1)") _, out("st(2)") _, out("st(3)") _,
                    out("st(4)") _, out("st(5)") _, out("st(6)") _, out("st(7)") _,
                    options(nostack),
                );
            }
            status & 0x4500
        }

        /// A float of 4 or 8 bytes, or with `integer` an integer of 8, loaded into ST0 and
        /// stored as the extended float it became.
        fn load(bits: u64, size: usize, integer: bool) -> u128 {
            let (bits, mut out) = (bits.to_le_bytes(), [0u8; 16]);
            // SAFETY: as in `x87!`.
            unsafe {
                match (size, integer) {
                    (4, _) => asm!("fld dword ptr [{bits}]", "fstp tbyte ptr [{out}]", bits = in(reg) bits.as_ptr(), out = in(reg) out.as_mut_ptr(), out("st(0)") _, options(nostack)),
                    (_, false) => asm!("fld qword ptr [{bits}]", "fstp tbyte ptr [{out}]", bits = in(reg) bits.as_ptr(), out = in(reg) out.as_mut_ptr(), out("st(0)") _, options(nostack)),
                    (_, true) => asm!("fild qword ptr [{bits}]", "fstp tbyte ptr [{out}]", bits = in(reg) bits.as_ptr(), out = in(reg) out.as_mut_ptr(), out("st(0)") _, options(nostack)),
                }
            }
            u128::from_le_bytes(out)
        }

        #[test]
        fn comparisons_and_loads_are_the_processors() {
            let mut rng = Rng(0x2545_f491_4f6c_dd1d);
            let control = Control::from_word(0x37f);
            for _ in 0..20000 {
                let a = generate(&mut rng, None);
                let b = generate(&mut rng, Some(a));
                let bit = |code: Code| compute(code, 1, &[(a, 10), (b, 10)], control).unwrap() as u16;
                let unordered = compute(Code::FNan, 1, &[(a, 10)], control).unwrap() | compute(Code::FNan, 1, &[(b, 10)], control).unwrap();
                let unordered = unordered as u16;
                let got = (unordered | bit(Code::FLess)) << 8 | unordered << 10 | (unordered | bit(Code::FEqual)) << 14;
                assert_eq!(got, fcom(a, b), "{a:#x} against {b:#x}");
            }
            for _ in 0..20000 {
                let (single, double) = (rng.next() as u32, rng.next());
                // Mostly the ends of the range, where the subnormals and the not-a-numbers are.
                let single = if rng.next().is_multiple_of(2) { single | 0x7f80_0000 } else if rng.next().is_multiple_of(2) { single & 0x807f_ffff } else { single };
                let double = if rng.next().is_multiple_of(2) { double | 0x7ff << 52 } else if rng.next().is_multiple_of(2) { double & !(0x7ff << 52) } else { double };
                assert_eq!(widen(u128::from(single), 4).unwrap(), load(u64::from(single), 4, false), "{single:#x}");
                assert_eq!(widen(u128::from(double), 8).unwrap(), load(double, 8, false), "{double:#x}");
                // An integer of any of the sizes FILD loads, sign-extended to 8 bytes.
                let size = [2, 4, 8][rng.next() as usize % 3];
                let integer = signed(u128::from(rng.next()) & mask(size), size) as u64;
                assert_eq!(compute(Code::Int2Float, 10, &[(u128::from(integer), 8)], control).unwrap(), load(integer, 8, true), "{integer:#x}");
            }
        }

        /// Runs `$op` with `a` in ST0 and `b` in ST1 under the control word, from a stack and
        /// status word that are otherwise clear, and gives ST0, ST1 and the status word after it.
        macro_rules! whole {
            ($op:literal) => {
                |a: u128, b: u128, word: u16| -> (u128, u128, u16) {
                    let (a, b, mut st0, mut st1, mut status, mut saved) = (a.to_le_bytes(), b.to_le_bytes(), [0u8; 16], [0u8; 16], 0u16, 0u16);
                    // SAFETY: as in `x87!`. FNINIT empties the stack, and the control word it sets
                    // is set back.
                    unsafe {
                        asm!(
                            "fnstcw word ptr [{saved}]",
                            "fninit",
                            "fldcw word ptr [{word}]",
                            "fld tbyte ptr [{b}]",
                            "fld tbyte ptr [{a}]",
                            $op,
                            "fnstsw word ptr [{status}]",
                            "fstp tbyte ptr [{st0}]",
                            "fstp tbyte ptr [{st1}]",
                            "fninit",
                            "fldcw word ptr [{saved}]",
                            saved = in(reg) &raw mut saved,
                            word = in(reg) &raw const word,
                            status = in(reg) &raw mut status,
                            a = in(reg) a.as_ptr(),
                            b = in(reg) b.as_ptr(),
                            st0 = in(reg) st0.as_mut_ptr(),
                            st1 = in(reg) st1.as_mut_ptr(),
                            out("st(0)") _, out("st(1)") _, out("st(2)") _, out("st(3)") _,
                            out("st(4)") _, out("st(5)") _, out("st(6)") _, out("st(7)") _,
                            options(nostack),
                        );
                    }
                    (u128::from_le_bytes(st0) & mask(10), u128::from_le_bytes(st1) & mask(10), status)
                }
            };
        }

        /// An extended float from 2^`low` up to 2^(`high` + 1), of either sign.
        fn between(rng: &mut Rng, low: i32, high: i32) -> u128 {
            let exponent = (16383 + low + (rng.next() % (high - low + 1) as u64) as i32) as u128;
            u128::from(rng.next() & 1) << 79 | exponent << 64 | u128::from(rng.next() | 1 << 63)
        }

        fn positive(bits: u128) -> u128 {
            bits & !(1 << 79)
        }

        /// A float a few units in the last place from `bits`, which is finite.
        fn nudge(rng: &mut Rng, bits: u128) -> u128 {
            let line = bits as i128 + (rng.next() % 9) as i128 - 4;
            line as u128 & mask(10)
        }

        /// A float near a multiple of half the processor's pi, where the sine or the cosine
        /// cancels.
        fn near_half_pi(rng: &mut Rng) -> u128 {
            let multiple = u128::from(rng.next() >> (rng.next() % 64)) | 1;
            let x = multiple.saturating_mul(instructions::HALF_PI);
            let shift = 128 - x.leading_zeros().min(127);
            let exponent = 16383 + shift as i32 - 1 - 65;
            let significand = if shift >= 64 { x >> (shift - 64) } else { x << (64 - shift) };
            let sign = u128::from(rng.next() & 1) << 79;
            nudge(rng, sign | (exponent as u128) << 64 | significand)
        }

        /// Whether this machine is AMD's, whose way with what the processor leaves undefined is
        /// what this computes.
        fn amd() -> bool {
            let vendor = std::arch::x86_64::__cpuid(0);
            [vendor.ebx, vendor.edx, vendor.ecx].map(u32::to_le_bytes).concat() == b"AuthenticAMD"
        }

        type Whole = (&'static str, Instruction, fn(u128, u128, u16) -> (u128, u128, u16), fn(&mut Rng) -> (u128, u128));

        #[test]
        fn whole_instructions_are_the_processors() {
            let instructions: [Whole; 18] = [
                ("f2xm1", Instruction::F2xm1, whole!("f2xm1"), |rng| (if rng.next().is_multiple_of(4) { generate(rng, None) } else { between(rng, -70, -1) }, 0)),
                ("fyl2x", Instruction::Fyl2x, whole!("fyl2x"), |rng| {
                    let one = 0x3fff_8000_0000_0000_0000u128;
                    let x = match rng.next() % 4 {
                        0 => generate(rng, None),
                        1 => nudge(rng, one) + u128::from(rng.next().is_multiple_of(3)) * 0x7fff_ffff,
                        _ => positive(between(rng, -16000, 16000)),
                    };
                    (x, if rng.next().is_multiple_of(4) { generate(rng, None) } else { between(rng, -8, 8) })
                }),
                ("fyl2xp1", Instruction::Fyl2xp1, whole!("fyl2xp1"), |rng| {
                    let x = if rng.next().is_multiple_of(4) { generate(rng, None) } else { between(rng, -70, -2) };
                    (x, if rng.next().is_multiple_of(4) { generate(rng, None) } else { between(rng, -8, 8) })
                }),
                ("fscale", Instruction::Fscale, whole!("fscale"), |rng| {
                    let power = if rng.next().is_multiple_of(4) { generate(rng, None) } else { between(rng, -1, 15) };
                    (generate(rng, None), power)
                }),
                ("fsin", Instruction::Fsin, whole!("fsin"), trigonometric),
                ("fcos", Instruction::Fcos, whole!("fcos"), trigonometric),
                ("fsincos", Instruction::Fsincos, whole!("fsincos"), trigonometric),
                ("fptan", Instruction::Fptan, whole!("fptan"), trigonometric),
                ("fpatan", Instruction::Fpatan, whole!("fpatan"), |rng| match rng.next() % 3 {
                    0 => operands(rng),
                    _ => (between(rng, -70, 70), between(rng, -70, 70)),
                }),
                ("fxtract", Instruction::Fxtract, whole!("fxtract"), operands),
                ("fprem", Instruction::Fprem, whole!("fprem"), dividend_divisor),
                ("fprem1", Instruction::Fprem1, whole!("fprem1"), dividend_divisor),
                ("fxam", Instruction::Fxam, whole!("fxam"), |rng| (generate(rng, None) & !(u128::from(rng.next().is_multiple_of(4)) << 63), 0)),
                ("fldpi", Instruction::Fldpi, whole!("fldpi"), operands),
                ("fldl2e", Instruction::Fldl2e, whole!("fldl2e"), operands),
                ("fldl2t", Instruction::Fldl2t, whole!("fldl2t"), operands),
                ("fldlg2", Instruction::Fldlg2, whole!("fldlg2"), operands),
                ("fldln2", Instruction::Fldln2, whole!("fldln2"), operands),
            ];
            fn operands(rng: &mut Rng) -> (u128, u128) {
                (generate(rng, None), generate(rng, None))
            }
            fn trigonometric(rng: &mut Rng) -> (u128, u128) {
                let x = match rng.next() % 6 {
                    0 => generate(rng, None),
                    1 => near_half_pi(rng),
                    2 => between(rng, 50, 64),
                    _ => between(rng, -70, 62),
                };
                (x, 0)
            }
            fn dividend_divisor(rng: &mut Rng) -> (u128, u128) {
                if rng.next().is_multiple_of(4) {
                    return (generate(rng, None), generate(rng, None));
                }
                let divisor = between(rng, -16000, 16000);
                let apart = match rng.next() % 3 {
                    0 => (rng.next() % 8) as i32 - 2,
                    1 => (rng.next() % 140) as i32,
                    _ => (rng.next() % 16000) as i32,
                };
                let exponent = ((divisor >> 64 & 0x7fff) as i32 + apart).clamp(1, 0x7ffe) as u128;
                (between(rng, 0, 0) & !(0x7fff << 64) | exponent << 64, divisor)
            }
            let amd = amd();
            // Intel's bound is under 1.5 units in the last place for a directed rounding, so 2 from
            // a correct one; this machine's is within 1.
            let tolerance = |control: Control| if amd || control.rounding == Rounding::Nearest { 1 } else { 2 };
            let exact = |instruction: Instruction| !matches!(instruction, Instruction::F2xm1 | Instruction::Fyl2x | Instruction::Fyl2xp1 | Instruction::Fsin | Instruction::Fcos | Instruction::Fsincos | Instruction::Fptan | Instruction::Fpatan);
            let mut rng = Rng(0x6a09_e667_f3bc_c908);
            let mut wrong = Vec::new();
            let mut report = Vec::new();
            for &(name, instruction, hardware, operands) in &instructions {
                let (mut tried, mut apart, mut largest) = (0, 0, 0);
                for word in (0..16u16).map(|control| 0x7f | control << 8) {
                    let control = Control::from_word(u128::from(word));
                    for _ in 0..CASES {
                        let (a, b) = operands(&mut rng);
                        // What the processor leaves undefined, which only AMD's does as this does.
                        let undefined = match (instruction, decode(a, &EXTENDED), decode(b, &EXTENDED)) {
                            (Instruction::F2xm1, Finite { exp, significand, .. }, _) => exp > 0 || exp == 0 && significand != INTEGER_BIT,
                            (Instruction::F2xm1, Infinite { .. }, _) => true,
                            (Instruction::Fprem | Instruction::Fprem1, Finite { exp: ea, .. }, Finite { exp: eb, .. }) => ea - eb >= 64,
                            // What FPTAN pushes and FPREM's condition bits for a not-a-number.
                            (Instruction::Fptan, Nan { .. } | Infinite { .. }, _) => true,
                            (Instruction::Fprem | Instruction::Fprem1, Nan { .. }, _) | (Instruction::Fprem | Instruction::Fprem1, _, Nan { .. }) => true,
                            // Out of the domain, from 1 - sqrt(2) / 2 on, about 0.29.
                            (Instruction::Fyl2xp1, x, _) => compare(x, decode(0x3ffd_95f6_1998_0c43_3812, &EXTENDED)) != Some(Ordering::Less) || compare(x, decode(0xbffd_95f6_1998_0c43_3812, &EXTENDED)) != Some(Ordering::Greater),
                            _ => false,
                        };
                        if undefined && !amd {
                            continue;
                        }
                        let (st0, st1, status) = hardware(a, b, word);
                        let outcome = execute(instruction, a, b, control);
                        let (got0, got1, top) = match outcome.stack {
                            Stack::Replace(value) => (value, Some(b), 6),
                            Stack::Pop(value) => (value, None, 7),
                            Stack::ReplacePush(value, pushed) => (pushed, Some(value), 5),
                            Stack::Push(pushed) => (pushed, Some(a), 5),
                        };
                        tried += 1;
                        let conditions = outcome.conditions.iter().zip([8, 9, 10, 14]).all(|(&condition, bit)| condition.is_none_or(|set| set == (status >> bit & 1 == 1)));
                        let mut same = conditions && status >> 11 & 7 == top;
                        let mut differs = false;
                        for (got, want) in [(Some(got0), st0), (got1, st1)] {
                            let Some(got) = got.filter(|&got| got != want) else { continue };
                            let units = ulps(got, want);
                            let nan = |bits: u128| bits >> 64 & 0x7fff == 0x7fff;
                            if exact(instruction) || units > tolerance(control) || nan(got) || nan(want) {
                                same = false;
                            }
                            differs = true;
                            largest = largest.max(units);
                        }
                        apart += usize::from(differs);
                        if !same {
                            wrong.push(format!("{name} {a:#x} {b:#x} under {word:#x}: the processor gives {st0:#x} {st1:#x} with status {status:#x}, this {outcome:x?}"));
                        }
                    }
                }
                report.push(format!("{name}: {apart} of {tried} differ, by {largest} units in the last place at most"));
            }
            eprintln!("{}", report.join("\n"));
            let first: Vec<&String> = instructions.iter().flat_map(|(name, ..)| wrong.iter().filter(move |line| line.split(' ').next() == Some(name)).take(3)).collect();
            assert!(wrong.is_empty(), "{} differ, the first of each instruction:\n{}", wrong.len(), first.iter().map(|line| line.as_str()).collect::<Vec<_>>().join("\n"));
        }
    }
}
