//! The x87 instructions the processor specification leaves opaque or approximate, run here as
//! whole instructions on ST0 and ST1. The specification calls an operation it does not define for
//! the transcendental ones, rounds a constant to a double, rounds `log2` before the product, and
//! divides and multiplies back for a remainder. FXAM is here too, since the specification
//! tells neither a not-a-number from an infinity nor -0 from 0.
//!
//! A transcendental result is the exact value rounded once, to 64 bits whatever the precision
//! control, in the direction the control word sets, as the processor rounds it. The processor's
//! own are not rounded correctly, and differ from these by a unit in the last place at most, as
//! the hardware test in `x87.rs` measures. FSIN, FCOS, FSINCOS and FPTAN reduce their argument
//! by the processor's 66-bit pi, not pi, which is what both Intel's and AMD's do, and leave an
//! argument of 2^63 or more as it is with C2 set. A constant is the true one rounded the same way.
//! A remainder is exact.

use std::cmp::Ordering;

use super::wide::{self, Wide};
use super::{Control, EXTENDED, Exact, Finite, INDEFINITE, INTEGER_BIT, Infinite, Nan, Number, Special, Value, Zero, compare, decode, exact, finish, multiply, propagate, unsupported};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Instruction {
    F2xm1,
    Fyl2x,
    Fyl2xp1,
    Fscale,
    Fsin,
    Fcos,
    Fsincos,
    Fptan,
    Fpatan,
    Fxtract,
    Fprem,
    Fprem1,
    Fxam,
    Fldpi,
    Fldl2e,
    Fldl2t,
    Fldlg2,
    Fldln2,
}

impl Instruction {
    /// The instruction of a mnemonic as Ghidra prints it.
    pub fn parse(mnemonic: &str) -> Option<Instruction> {
        use Instruction::*;
        Some(match mnemonic {
            "F2XM1" => F2xm1,
            "FYL2X" => Fyl2x,
            "FYL2XP1" => Fyl2xp1,
            "FSCALE" => Fscale,
            "FSIN" => Fsin,
            "FCOS" => Fcos,
            "FSINCOS" => Fsincos,
            "FPTAN" => Fptan,
            "FPATAN" => Fpatan,
            "FXTRACT" => Fxtract,
            "FPREM" => Fprem,
            "FPREM1" => Fprem1,
            "FXAM" => Fxam,
            "FLDPI" => Fldpi,
            "FLDL2E" => Fldl2e,
            "FLDL2T" => Fldl2t,
            "FLDLG2" => Fldlg2,
            "FLDLN2" => Fldln2,
            _ => return None,
        })
    }
}

/// How an instruction changes the register stack, each value as the 80 bits a register holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stack {
    /// ST0 becomes this.
    Replace(u128),
    /// ST1 becomes this and the stack pops, so that it is ST0.
    Pop(u128),
    /// ST0 becomes the first, and the second is pushed above it.
    ReplacePush(u128, u128),
    Push(u128),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Outcome {
    pub stack: Stack,
    /// The condition bits C0 to C3 the instruction sets. One it leaves undefined is `None` and
    /// keeps what it held.
    pub conditions: [Option<bool>; 4],
}

/// Runs the instruction on ST0 and ST1, the second read only by an instruction that takes two.
pub fn execute(instruction: Instruction, st0: u128, st1: u128, control: Control) -> Outcome {
    use Instruction::*;
    // An unsupported operand makes the result the processor's not-a-number, whatever the other.
    let reads_st1 = matches!(instruction, Fyl2x | Fyl2xp1 | Fpatan | Fscale | Fprem | Fprem1);
    let invalid = unsupported(st0) || reads_st1 && unsupported(st1);
    let (x, y) = if invalid { (INDEFINITE, INDEFINITE) } else { (decode(st0, &EXTENDED), decode(st1, &EXTENDED)) };
    let round = |result: Exact| finish(result, &EXTENDED, 64, control.rounding);
    let stack = match instruction {
        Fldpi => Stack::Push(round(wide::PI.inexact())),
        Fldl2e => Stack::Push(round(wide::LOG2_E.inexact())),
        Fldl2t => Stack::Push(round(wide::LOG2_10.inexact())),
        Fldlg2 => Stack::Push(round(wide::LOG10_2.inexact())),
        Fldln2 => Stack::Push(round(wide::LN2.inexact())),
        F2xm1 => Stack::Replace(round(exp2_m1(x))),
        Fyl2x => Stack::Pop(round(times_log2(y, x, false))),
        Fyl2xp1 => Stack::Pop(round(times_log2(y, x, true))),
        Fpatan => Stack::Pop(round(atan2(y, x))),
        Fscale => Stack::Replace(round(scale(x, y))),
        Fxtract => {
            let (exponent, significand) = extract(x);
            Stack::ReplacePush(round(exponent), round(significand))
        }
        Fprem | Fprem1 => {
            let (result, conditions) = remainder(x, y, instruction == Fprem1);
            return Outcome { stack: Stack::Replace(round(result)), conditions };
        }
        Fxam => return Outcome { stack: Stack::Replace(st0), conditions: examine(st0) },
        Fsin | Fcos | Fsincos | Fptan => {
            let Some(trig) = trigonometry(x) else {
                return Outcome { stack: Stack::Replace(st0), conditions: [None, None, Some(true), None] };
            };
            let stack = match instruction {
                Fsin => Stack::Replace(round(trig.sine())),
                Fcos => Stack::Replace(round(trig.cosine())),
                Fsincos => Stack::ReplacePush(round(trig.sine()), round(trig.cosine())),
                // A not-a-number is pushed in place of the 1.
                _ => {
                    let tangent = trig.tangent();
                    Stack::ReplacePush(round(tangent), round(if matches!(tangent, Special(Nan { .. })) { tangent } else { exact(ONE) }))
                }
            };
            return Outcome { stack, conditions: [None, None, Some(false), None] };
        }
    };
    Outcome { stack, conditions: [None; 4] }
}

const ONE: Value = Finite { negative: false, exp: 0, significand: INTEGER_BIT };

/// An integer as a value.
fn integer(n: i64) -> Value {
    if n == 0 {
        return Zero { negative: false };
    }
    let shift = n.unsigned_abs().leading_zeros();
    Finite { negative: n < 0, exp: 63 - shift as i32, significand: n.unsigned_abs() << shift }
}

/// `2^x - 1`, which the processor defines from -1 to 1 and at the infinities. Elsewhere this
/// machine leaves the operand as it is, and so does this.
fn exp2_m1(x: Value) -> Exact {
    match x {
        Nan { .. } => Special(propagate(&[x]).expect("a not-a-number")),
        Zero { .. } | Infinite { negative: false } => Special(x),
        Infinite { negative: true } => exact(ONE.negate()),
        Finite { negative, exp: 0, significand: INTEGER_BIT } => exact(if negative { Finite { negative, exp: -1, significand: INTEGER_BIT } } else { ONE }),
        Finite { exp, .. } if exp < 0 => wide::exp_m1(Wide::of(x).multiply(wide::LN2)).inexact(),
        _ => exact(x),
    }
}

/// A logarithm, which a register holds exactly or does not.
enum Log {
    Exact(Value),
    Inexact(Wide),
}

/// The base-2 logarithm of `x`, or with `plus_one` of `1 + x`, which is above 0 here.
fn log2(x: Value, plus_one: bool) -> Log {
    match x {
        Nan { .. } => Log::Exact(x),
        Zero { .. } if plus_one => Log::Exact(x),
        Zero { .. } => Log::Exact(Infinite { negative: true }),
        Infinite { negative: false } => Log::Exact(x),
        Infinite { negative: true } => Log::Exact(INDEFINITE),
        Finite { negative: true, .. } if !plus_one => Log::Exact(INDEFINITE),
        // Near zero, the logarithm of 1 + x from x itself, which 1 + x would round away.
        Finite { exp, .. } if plus_one && exp < -2 => Log::Inexact(wide::ln_1p(Wide::of(x)).multiply(wide::LOG2_E)),
        Finite { exp, .. } => {
            let w = if plus_one { Wide::of(x).add(Wide::of(ONE)) } else { Wide::of(x) };
            match w.significand {
                0 => Log::Exact(Infinite { negative: true }),
                // A power of two, when 1 + x was exact.
                bits if bits == 1 << 127 && (!plus_one || exp < 64) => Log::Exact(integer(i64::from(w.exp + 127))),
                _ => Log::Inexact(wide::log2(w.exp + 127, w.times_power_of_two(-127 - w.exp))),
            }
        }
    }
}

/// `y log2(x)`, or with `plus_one` `y log2(1 + x)`, rounded once.
fn times_log2(y: Value, x: Value, plus_one: bool) -> Exact {
    if let Some(nan) = propagate(&[x, y]) {
        return Special(nan);
    }
    // The processor defines 1 + x only from about -0.29 to 0.29. From -1 down, this machine
    // gives y negated when it is a zero or an infinity and x otherwise, and so does this.
    if plus_one && matches!(x, Finite { .. }) && compare(x, ONE.negate()) != Some(Ordering::Greater) {
        return match y {
            Zero { .. } | Infinite { .. } => Special(y.negate()),
            _ => exact(x),
        };
    }
    match (log2(x, plus_one), y) {
        (Log::Exact(log), _) => multiply(y, log),
        (Log::Inexact(log), Zero { negative } | Infinite { negative }) => {
            let negative = negative != log.negative;
            Special(if matches!(y, Zero { .. }) { Zero { negative } } else { Infinite { negative } })
        }
        (Log::Inexact(log), _) => Wide::of(y).multiply(log).inexact(),
    }
}

/// The angle of the point (x, y) from the positive x axis, from -pi to pi.
fn atan2(y: Value, x: Value) -> Exact {
    if let Some(nan) = propagate(&[x, y]) {
        return Special(nan);
    }
    let negative = y.negative();
    let quarters = |n: i64| Wide::integer(n).multiply(wide::PI).times_power_of_two(-2);
    let angle = match (y, x) {
        (Zero { .. }, _) | (Finite { .. }, Infinite { negative: false }) if !x.negative() => return Special(Zero { negative }),
        (Zero { .. }, _) | (Finite { .. }, Infinite { .. }) => quarters(4),
        (Infinite { .. }, Infinite { negative: false }) => quarters(1),
        (Infinite { .. }, Infinite { .. }) => quarters(3),
        (Infinite { .. }, _) | (_, Zero { .. }) => quarters(2),
        _ => {
            let (a, b) = (Wide::of(y), Wide::of(x));
            let (a, b) = (Wide { negative: false, ..a }, Wide { negative: false, ..b });
            let base = if (a.exp, a.significand) <= (b.exp, b.significand) { wide::atan(a.divide(b)) } else { quarters(2).subtract(wide::atan(b.divide(a))) };
            if x.negative() { quarters(4).subtract(base) } else { base }
        }
    };
    Wide { negative, ..angle }.inexact()
}

/// `x` times two to the power of `y` cut toward zero.
fn scale(x: Value, y: Value) -> Exact {
    if let Some(nan) = propagate(&[x, y]) {
        return Special(nan);
    }
    match (x, y) {
        (Zero { .. }, Infinite { negative: false }) | (Infinite { .. }, Infinite { negative: true }) => Special(INDEFINITE),
        (Zero { .. } | Infinite { .. }, _) | (_, Zero { .. }) => Special(x),
        (_, Infinite { negative }) => Special(if negative { Zero { negative: x.negative() } } else { Infinite { negative: x.negative() } }),
        (Finite { negative, exp, significand }, Finite { negative: down, exp: power_exp, significand: power }) => {
            // A power past 2^20 takes any value out of range, as 2^20 does.
            let power = match power_exp {
                ..0 => 0,
                0..=20 => (power >> (63 - power_exp)) as i32,
                _ => 1 << 20,
            };
            Number { negative, exp: exp - 63 + if down { -power } else { power }, significand: u128::from(significand), sticky: false }
        }
        (Nan { .. }, _) | (_, Nan { .. }) => unreachable!("propagated"),
    }
}

/// The exponent and the significand, the significand from 1 up to 2 with the sign of `x`.
fn extract(x: Value) -> (Exact, Exact) {
    match x {
        Nan { .. } => {
            let nan = propagate(&[x]).expect("a not-a-number");
            (Special(nan), Special(nan))
        }
        Zero { .. } => (Special(Infinite { negative: true }), Special(x)),
        Infinite { .. } => (Special(Infinite { negative: false }), Special(x)),
        Finite { negative, exp, significand } => (exact(integer(i64::from(exp))), exact(Finite { negative, exp: 0, significand })),
    }
}

/// The partial remainder of `x` by `y`, and the condition bits: C2 set when it is partial, else
/// C0, C3 and C1 the low three bits of the quotient. The quotient is cut toward zero, or with
/// `nearest` rounded to the nearest integer, an even one from halfway. When the exponents are
/// 64 or more apart, this machine takes off 32 bits of quotient and as many more as the
/// difference has above a multiple of 32, and so does this.
fn remainder(x: Value, y: Value, nearest: bool) -> (Exact, [Option<bool>; 4]) {
    let conditions = |quotient: u128, partial: bool| [Some(quotient & 4 != 0), Some(quotient & 1 != 0), Some(partial), Some(quotient & 2 != 0)];
    if let Some(nan) = propagate(&[x, y]) {
        return (Special(nan), conditions(0, false));
    }
    let (Finite { negative, exp: ex, significand: a }, Finite { exp: ey, significand: b, .. }) = (x, y) else {
        let result = match (x, y) {
            (Infinite { .. }, _) | (_, Zero { .. }) => INDEFINITE,
            _ => x,
        };
        return (Special(result), conditions(0, false));
    };
    let (a, b) = (u128::from(a), u128::from(b));
    let difference = ex - ey;
    if difference >= 64 {
        let bits = 32 + difference % 32;
        let rest = (a << bits) % b;
        let exp = ey - 63 + difference - bits;
        return (if rest == 0 { Special(Zero { negative }) } else { Number { negative, exp, significand: rest, sticky: false } }, conditions(0, true));
    }
    if difference < -1 {
        return (exact(x), conditions(0, false));
    }
    let (numerator, denominator) = (a << difference.max(0), b << (-difference).max(0));
    let (mut quotient, mut rest, mut negative) = (numerator / denominator, numerator % denominator, negative);
    if nearest && match (2 * rest).cmp(&denominator) {
        Ordering::Greater => true,
        Ordering::Equal => quotient & 1 == 1,
        Ordering::Less => false,
    } {
        quotient += 1;
        rest = denominator - rest;
        negative = !negative;
    }
    let exp = ex.min(ey) - 63;
    let result = if rest == 0 { Special(Zero { negative: x.negative() }) } else { Number { negative, exp, significand: rest, sticky: false } };
    (result, conditions(quotient, false))
}

/// What kind of value ST0 holds, as FXAM sets C3, C2 and C0, and its sign in C1. A register is
/// never empty here, since the stack has no tags.
fn examine(bits: u128) -> [Option<bool>; 4] {
    let (c3, c2, c0) = match decode(bits, &EXTENDED) {
        _ if unsupported(bits) => (false, false, false),
        Nan { .. } => (false, false, true),
        Infinite { .. } => (false, true, true),
        Zero { .. } => (true, false, false),
        // A subnormal has a zero exponent field.
        Finite { .. } if bits >> 64 & 0x7fff == 0 => (true, true, false),
        Finite { .. } => (false, true, false),
    };
    [Some(c0), Some(bits >> 79 == 1), Some(c2), Some(c3)]
}

/// The sine, cosine and tangent of an argument: the results of a special argument, or the sine
/// and cosine from the series, which the tangent is divided from only when FPTAN asks for it.
enum Trig {
    Special([Exact; 3]),
    Series(Wide, Wide),
}

impl Trig {
    fn sine(&self) -> Exact {
        match self {
            Trig::Special([sine, ..]) => *sine,
            Trig::Series(sine, _) => sine.inexact(),
        }
    }

    fn cosine(&self) -> Exact {
        match self {
            Trig::Special([_, cosine, _]) => *cosine,
            Trig::Series(_, cosine) => cosine.inexact(),
        }
    }

    fn tangent(&self) -> Exact {
        match self {
            Trig::Special([.., tangent]) => *tangent,
            Trig::Series(sine, cosine) => sine.divide(*cosine).inexact(),
        }
    }
}

/// The sine, cosine and tangent, or none for an argument of 2^63 or more, which the processor
/// does not reduce.
fn trigonometry(x: Value) -> Option<Trig> {
    match x {
        Nan { .. } => Some(Trig::Special([Special(propagate(&[x]).expect("a not-a-number")); 3])),
        Infinite { .. } => Some(Trig::Special([Special(INDEFINITE); 3])),
        Zero { .. } => Some(Trig::Special([Special(x), exact(ONE), Special(x)])),
        Finite { exp, .. } if exp >= 63 => None,
        Finite { negative, exp, significand } => {
            let (quadrant, r) = reduce(exp, significand);
            let (s, c) = wide::sin_cos(r);
            let (sine, cosine) = match quadrant {
                0 => (s, c),
                1 => (c, s.negate()),
                2 => (s.negate(), c.negate()),
                _ => (c.negate(), s),
            };
            let sine = if negative { sine.negate() } else { sine };
            Some(Trig::Series(sine, cosine))
        }
    }
}

/// Half the processor's pi, which is pi to 66 bits, in units of 2^-65.
pub(super) const HALF_PI: u128 = 0x3_243f_6a88_85a3_08d3;

/// The magnitude `significand` times 2^(exp - 63) less the nearest multiple of `HALF_PI`, which
/// is exact, and that multiple's remainder by 4, the quadrant.
fn reduce(exp: i32, significand: u64) -> (u128, Wide) {
    if exp < -1 {
        return (0, Wide::of(Finite { negative: false, exp, significand }));
    }
    let x = u128::from(significand) << (exp + 2);
    let (multiple, rest) = (x / HALF_PI, x % HALF_PI);
    let (multiple, r) = if 2 * rest > HALF_PI { (multiple + 1, Wide::new(true, -65, HALF_PI - rest)) } else { (multiple, Wide::new(false, -65, rest)) };
    (multiple % 4, r)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x87::Rounding;

    /// An extended float as a number that orders as its value does, for finite floats.
    fn ordered(bits: u128) -> i128 {
        let magnitude = match bits >> 64 & 0x7fff {
            0 => bits & u128::from(u64::MAX),
            exponent => (exponent - 1) << 63 | bits & ((1 << 63) - 1),
        } as i128;
        if bits >> 79 == 1 { -magnitude } else { magnitude }
    }

    #[test]
    fn a_transcendental_result_rounds_in_the_direction_the_control_word_sets() {
        let mut state = 0x243f_6a88_85a3_08d3u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let mut inexact = 0;
        let mut tried = 0;
        for instruction in [Instruction::F2xm1, Instruction::Fyl2x, Instruction::Fyl2xp1, Instruction::Fsin, Instruction::Fcos, Instruction::Fsincos, Instruction::Fptan, Instruction::Fpatan] {
            for _ in 0..500 {
                // A magnitude below a quarter, and a positive one for FYL2X.
                let x = u128::from(next() & 1 & u64::from(instruction != Instruction::Fyl2x)) << 79 | u128::from(16380 - next() % 60) << 64 | u128::from(next() | 1 << 63);
                let y = u128::from(next() & 1) << 79 | u128::from(16380 + next() % 8) << 64 | u128::from(next() | 1 << 63);
                let results = [Rounding::Down, Rounding::Nearest, Rounding::Up, Rounding::Zero].map(|rounding| match execute(instruction, x, y, Control { precision: 24, rounding }).stack {
                    Stack::Replace(value) | Stack::Pop(value) | Stack::ReplacePush(value, _) => ordered(value),
                    Stack::Push(_) => unreachable!("not a load"),
                });
                let [down, nearest, up, zero] = results;
                assert!(down <= nearest && nearest <= up && up - down <= 1, "{instruction:?} {x:#x} {y:#x}: {results:?}");
                assert_eq!(zero, if down < 0 { up } else { down }, "{instruction:?} {x:#x} {y:#x} toward zero");
                inexact += usize::from(up != down);
                tried += 1;
            }
        }
        assert!(inexact > tried * 99 / 100, "only {inexact} of {tried} results were inexact");
    }
}
