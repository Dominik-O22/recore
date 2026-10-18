//! Real numbers to 128 bits, and the functions the x87's transcendental instructions compute,
//! evaluated from their series. Each operation keeps about 126 bits, so a result is far closer
//! than a unit in the 64th bit and rounds to the extended format as the exact value would, but
//! for a value within about 2^-120 of halfway between two extended floats.

use super::{Exact, Value};

/// `significand` times two to the `exp`, with the top bit of the significand set, or zero when
/// the significand is.
#[derive(Clone, Copy, Debug)]
pub(super) struct Wide {
    pub negative: bool,
    pub exp: i32,
    pub significand: u128,
}

pub(super) const PI: Wide = Wide { negative: false, exp: -126, significand: 0xc90f_daa2_2168_c234_c4c6_628b_80dc_1cd1 };
pub(super) const LN2: Wide = Wide { negative: false, exp: -128, significand: 0xb172_17f7_d1cf_79ab_c9e3_b398_03f2_f6af };
pub(super) const LOG2_E: Wide = Wide { negative: false, exp: -127, significand: 0xb8aa_3b29_5c17_f0bb_be87_fed0_691d_3e88 };
pub(super) const LOG2_10: Wide = Wide { negative: false, exp: -126, significand: 0xd49a_784b_cd1b_8afe_492b_f6ff_4daf_db4c };
pub(super) const LOG10_2: Wide = Wide { negative: false, exp: -129, significand: 0x9a20_9a84_fbcf_f798_8f89_59ac_0b7c_9178 };
const ONE: Wide = Wide { negative: false, exp: -127, significand: 1 << 127 };

/// The bits of `a * b`, high then low.
fn multiply_wide(a: u128, b: u128) -> (u128, u128) {
    let low = |x: u128| x & u128::from(u64::MAX);
    let (a1, a0, b1, b0) = (a >> 64, low(a), b >> 64, low(b));
    let (p00, p01, p10, p11) = (a0 * b0, a0 * b1, a1 * b0, a1 * b1);
    let middle = (p00 >> 64) + low(p01) + low(p10);
    (p11 + (p01 >> 64) + (p10 >> 64) + (middle >> 64), low(p00) | middle << 64)
}

impl Wide {
    pub fn new(negative: bool, exp: i32, significand: u128) -> Wide {
        let shift = significand.leading_zeros() % 128;
        Wide { negative, exp: exp - shift as i32, significand: significand << shift }
    }

    pub fn integer(n: i64) -> Wide {
        Wide::new(n < 0, 0, u128::from(n.unsigned_abs()))
    }

    /// A finite value exactly, or zero.
    pub fn of(value: Value) -> Wide {
        match value {
            Value::Finite { negative, exp, significand } => Wide { negative, exp: exp - 127, significand: u128::from(significand) << 64 },
            other => Wide { negative: other.negative(), exp: 0, significand: 0 },
        }
    }

    pub fn is_zero(self) -> bool {
        self.significand == 0
    }

    pub fn negate(self) -> Wide {
        Wide { negative: !self.negative, ..self }
    }

    pub fn times_power_of_two(self, power: i32) -> Wide {
        Wide { exp: self.exp + power, ..self }
    }

    pub fn multiply(self, other: Wide) -> Wide {
        let negative = self.negative != other.negative;
        if self.is_zero() || other.is_zero() {
            return Wide { negative, exp: 0, significand: 0 };
        }
        let (high, low) = multiply_wide(self.significand, other.significand);
        Wide::new(negative, self.exp + other.exp + 128, high).with_low(high, low)
    }

    /// The product's top bit is one of the top two of `high`; the bit below `high` fills the
    /// last place when it is the second.
    fn with_low(self, high: u128, low: u128) -> Wide {
        if high >> 127 == 1 { self } else { Wide { significand: self.significand | low >> 127, ..self } }
    }

    pub fn add(self, other: Wide) -> Wide {
        if other.is_zero() {
            return self;
        }
        if self.is_zero() {
            return other;
        }
        if (self.exp, self.significand) == (other.exp, other.significand) && self.negative != other.negative {
            return Wide { negative: false, exp: 0, significand: 0 };
        }
        let (big, small) = if (self.exp, self.significand) >= (other.exp, other.significand) { (self, other) } else { (other, self) };
        // A bit of room above for a carry. What falls off the smaller makes a difference a little
        // less than this, so that it is cut toward zero as a sum is.
        let (small_bits, lost) = match (big.exp - small.exp) as u32 + 1 {
            gap @ ..128 => (small.significand >> gap, small.significand << (128 - gap) != 0),
            _ => (0, true),
        };
        let bits = if big.negative == small.negative { (big.significand >> 1) + small_bits } else { (big.significand >> 1) - small_bits - u128::from(lost) };
        Wide::new(big.negative, big.exp + 1, bits)
    }

    pub fn subtract(self, other: Wide) -> Wide {
        self.add(other.negate())
    }

    /// The quotient, one bit at a time. `other` is not zero.
    pub fn divide(self, other: Wide) -> Wide {
        let negative = self.negative != other.negative;
        let divisor = other.significand;
        let (mut remainder, mut carry, mut quotient) = (self.significand, false, 0u128);
        for _ in 0..128 {
            let bit = carry || remainder >= divisor;
            if bit {
                remainder = remainder.wrapping_sub(divisor);
            }
            quotient = quotient << 1 | u128::from(bit);
            carry = remainder >> 127 == 1;
            remainder <<= 1;
        }
        Wide::new(negative, self.exp - other.exp - 127, quotient)
    }

    /// The value before it is rounded to a register, which is never exactly one.
    pub fn inexact(self) -> Exact {
        if self.is_zero() {
            Exact::Special(Value::Zero { negative: self.negative })
        } else {
            Exact::Number { negative: self.negative, exp: self.exp, significand: self.significand, sticky: true }
        }
    }

    /// Whether the terms of a series have fallen below what a sum this size keeps. The first
    /// that has is still added, to cut the sum toward zero when the rest of the series takes
    /// from it.
    fn negligible(self, sum: Wide) -> bool {
        self.is_zero() || self.exp < sum.exp - 130
    }
}

/// `e^t - 1`, for `t` of at most about 1.
pub(super) fn exp_m1(t: Wide) -> Wide {
    let (mut term, mut sum) = (t, t);
    for n in 2.. {
        term = term.multiply(t).divide(Wide::integer(n));
        sum = sum.add(term);
        if term.negligible(sum) {
            break;
        }
    }
    sum
}

/// `ln((1 + s) / (1 - s))`, twice the inverse hyperbolic tangent, for `s` of at most about 1/5.
fn log_ratio(s: Wide) -> Wide {
    let square = s.multiply(s);
    let (mut power, mut sum) = (s, s);
    for k in 1.. {
        power = power.multiply(square);
        let term = power.divide(Wide::integer(2 * k + 1));
        sum = sum.add(term);
        if term.negligible(sum) {
            break;
        }
    }
    sum.times_power_of_two(1)
}

/// `ln(1 + x)`, for `x` from about -0.3 to 0.42.
pub(super) fn ln_1p(x: Wide) -> Wide {
    log_ratio(x.divide(x.add(Wide::integer(2))))
}

/// `log2(m * 2^exp)` for a significand `m` from 1 up to 2.
pub(super) fn log2(exp: i32, m: Wide) -> Wide {
    // The significand halved past the square root of 2, so that its logarithm is at most a half.
    let (exp, m) = if m.significand > 0xb504_f333_f9de_6484_597d_89b3_754a_be9f { (exp + 1, m.times_power_of_two(-1)) } else { (exp, m) };
    Wide::integer(i64::from(exp)).add(ln_1p(m.subtract(ONE)).multiply(LOG2_E))
}

/// The sine and the cosine of `r`, for `r` of at most about 1.
pub(super) fn sin_cos(r: Wide) -> (Wide, Wide) {
    let square = r.multiply(r).negate();
    let (mut sine, mut sin_term) = (r, r);
    let (mut cosine, mut cos_term) = (ONE, ONE);
    for n in (2..).step_by(2) {
        cos_term = cos_term.multiply(square).divide(Wide::integer((n - 1) * n));
        sin_term = sin_term.multiply(square).divide(Wide::integer(n * (n + 1)));
        cosine = cosine.add(cos_term);
        sine = sine.add(sin_term);
        if cos_term.negligible(cosine) && sin_term.negligible(sine) {
            break;
        }
    }
    (sine, cosine)
}

/// The arctangent of `z`, from 0 to 1.
pub(super) fn atan(z: Wide) -> Wide {
    // From a half up, a quarter of pi and the arctangent of a third at most.
    let (base, w) = if z.exp >= -128 { (PI.times_power_of_two(-2), z.subtract(ONE).divide(z.add(ONE))) } else { (Wide::of(Value::Zero { negative: false }), z) };
    let square = w.multiply(w).negate();
    let (mut power, mut sum) = (w, w);
    for k in 1.. {
        power = power.multiply(square);
        let term = power.divide(Wide::integer(2 * k + 1));
        sum = sum.add(term);
        if term.negligible(sum) {
            break;
        }
    }
    base.add(sum)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The value as an f64, for checks to a double's precision.
    fn approx(w: Wide) -> f64 {
        let value = (w.significand >> 64) as f64 * 2f64.powi(w.exp + 64);
        if w.negative { -value } else { value }
    }

    #[test]
    fn the_series_give_the_functions() {
        let half = Wide::integer(1).times_power_of_two(-1);
        assert_eq!(approx(exp_m1(half)), 0.5f64.exp_m1());
        assert_eq!(approx(log2(3, Wide::integer(3).times_power_of_two(-1))), 12f64.log2());
        let (sine, cosine) = sin_cos(half);
        assert_eq!((approx(sine), approx(cosine)), (0.5f64.sin(), 0.5f64.cos()));
        assert_eq!(approx(atan(Wide::integer(1))), std::f64::consts::FRAC_PI_4);
        assert_eq!(approx(atan(half)), 0.5f64.atan());
    }

    /// How far apart two numbers near each other are, in units of the 128th bit of the first. Each
    /// operation cuts toward zero, so a long series falls short by tens of them.
    fn apart(a: Wide, b: Wide) -> u128 {
        let difference = a.subtract(b);
        match difference.exp - a.exp {
            _ if difference.is_zero() => 0,
            ..=-128 => 0,
            shift @ ..0 => difference.significand >> -shift,
            _ => u128::MAX,
        }
    }

    #[test]
    fn the_constants_and_the_series_agree_to_about_118_bits() {
        let one = Wide::integer(1);
        assert!(apart(exp_m1(LN2), one) <= 1024, "e^ln2 - 1");
        let (sine, cosine) = sin_cos(PI.times_power_of_two(-2));
        assert!(apart(sine, cosine) <= 1024, "the sine and cosine of a quarter of pi");
        assert!(apart(log2(0, Wide::integer(10).times_power_of_two(-3)).add(Wide::integer(3)), LOG2_10) <= 1024, "log2 10");
        assert!(apart(LOG2_10.multiply(LOG10_2), one) <= 1024, "log2 10 times log10 2");
        assert!(apart(LN2.multiply(LOG2_E), one) <= 1024, "ln 2 times log2 e");
        let half = one.times_power_of_two(-1);
        let (sine, cosine) = sin_cos(half);
        assert!(apart(atan(sine.divide(cosine)), half) <= 1024, "the arctangent of the tangent of a half");
    }
}
