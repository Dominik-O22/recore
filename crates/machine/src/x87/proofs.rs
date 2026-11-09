//! Kani proofs that `fast` gives the bits `compute_exact` gives wherever it answers. `compute`
//! trusts `fast` when it answers, so a wrong answer here is a wrong float in lifted code and in
//! recore's emulator. Each proof covers every sign, exponent, operand width and control word of
//! one operation into one width of result. Significands are every bit pattern too, except where
//! the solver does not finish at full width: FMult and FDiv are proved on operands of at most 8
//! and 4 significant bits, and again on any first operand with a power of two second.
//! `.claude/skills/verify-x87-fast-path/SKILL.md` says how to run them and read a failure.

use super::*;

/// Every bit of an operand's significand.
const ALL: u32 = 64;

/// The widths of the floats x87 operations read and write.
const FLOATS: [usize; 3] = [4, 8, 10];

/// A float operand of `size` bytes, any bit pattern except that its significand has at most
/// `kept` significant bits, counting the integer bit; the rest are zero. A solver cannot prove
/// two full-width multipliers or dividers equal in useful time, so the arithmetic proofs bound
/// this.
fn float(size: usize, kept: u32) -> u128 {
    let fraction: u32 = match size {
        4 => 23,
        8 => 52,
        _ => 63,
    };
    let cleared = (1u128 << fraction.saturating_sub(kept - 1)) - 1;
    kani::any::<u128>() & mask(size) & !cleared
}

/// The property for one operation with operands and result of the widths given: on every input
/// `compute` hands to the x87 code, `fast` either declines or gives the exact path's bits. The
/// widths are constants, as they are in p-code, so that the solver never meets the error paths
/// that format a message.
fn agrees(code: Code, size: usize, widths: &[usize], kept: [u32; 2]) {
    let operands: Vec<(u128, usize)> = widths
        .iter()
        .zip(kept)
        .map(|(&width, kept)| (if code == Code::Int2Float { kani::any::<u128>() & mask(width) } else { float(width, kept) }, width))
        .collect();
    if !applies(code, size, &operands) {
        return;
    }
    // `fast` divides before it declines a zero divisor, and zero by zero is a NaN, which Kani
    // reports as a failure. It declines every zero divisor, so leaving out zero by zero loses no
    // case it answers.
    let zero = |(bits, width): (u128, usize)| bits & !(1 << (8 * width - 1)) == 0;
    kani::assume(!(code == Code::FDiv && zero(operands[0]) && zero(operands[1])));
    let control = Control::from_word(u128::from(kani::any::<u16>()));
    if let Some(bits) = fast(code, size, &operands, control) {
        // Unsatisfiable where `fast` declines every case, which proofs.sh reports.
        kani::cover!(true, "fast answers");
        // Kani reports the message's text alone; a replayed counterexample prints the case.
        let exact = compute_exact(code, size, &operands, control);
        assert!(exact == Ok(bits), "fast gives {bits:#x}, the exact path {exact:x?}, for {code:?} into {size} bytes of {operands:x?} under {control:?}");
    }
}

/// `agrees` for a result of `size` bytes and every width of operand that `code` takes.
fn every_operand(code: Code, size: usize, kept: [u32; 2]) {
    use Code::*;
    if code == Int2Float {
        // An integer of any width p-code converts, up to the 10-byte one held as a float.
        for from in [1, 2, 4, 8, 10] {
            agrees(code, size, &[from], kept);
        }
    } else if matches!(code, FAdd | FSub | FMult | FDiv | FEqual | FNotEqual | FLess | FLessEqual) {
        for a in FLOATS {
            for b in FLOATS {
                agrees(code, size, &[a, b], kept);
            }
        }
    } else {
        for a in FLOATS {
            agrees(code, size, &[a], kept);
        }
    }
}

/// A module of proofs per operation, a proof per width of result, so that a failure names both
/// and the solver works on one width at a time. A comparison writes one byte, `to_1`; the others
/// a float, `to_4`, `to_8` and `to_10`.
macro_rules! proofs {
    (compare $name:ident: $code:ident, $kept:expr;) => {
        mod $name {
            use super::*;

            #[kani::proof]
            pub(super) fn to_1() {
                every_operand(Code::$code, 1, $kept);
            }
        }
    };
    (float $name:ident: $code:ident, $kept:expr;) => {
        mod $name {
            use super::*;

            #[kani::proof]
            pub(super) fn to_4() {
                every_operand(Code::$code, 4, $kept);
            }

            #[kani::proof]
            pub(super) fn to_8() {
                every_operand(Code::$code, 8, $kept);
            }

            #[kani::proof]
            pub(super) fn to_10() {
                every_operand(Code::$code, 10, $kept);
            }
        }
    };
    ($($kind:ident $name:ident: $code:ident, $kept:expr;)*) => {
        $(proofs! { $kind $name: $code, $kept; })*
    };
}

// Every float operation `applies` sends here but FSqrt, so a fast path added for one is checked
// too. Kani 0.68 models `f64::sqrt` with the wrong bits: it gives 1.5 * 2^648 a root the processor
// does not, so a proof of FSqrt would fail on the model; the native test covers it.
proofs! {
    float add: FAdd, [ALL, ALL];
    float sub: FSub, [ALL, ALL];
    float mult: FMult, [8, 8];
    float mult_by_power: FMult, [ALL, 1];
    float div: FDiv, [4, 4];
    float div_by_power: FDiv, [ALL, 1];
    compare equal: FEqual, [ALL, ALL];
    compare not_equal: FNotEqual, [ALL, ALL];
    compare less: FLess, [ALL, ALL];
    compare less_equal: FLessEqual, [ALL, ALL];
    compare nan: FNan, [ALL, ALL];
    float neg: FNeg, [ALL, ALL];
    float abs: FAbs, [ALL, ALL];
    float int2float: Int2Float, [ALL, ALL];
    float float2float: Float2Float, [ALL, ALL];
    float trunc: Trunc, [ALL, ALL];
    float ceil: Ceil, [ALL, ALL];
    float floor: Floor, [ALL, ALL];
    float round: Round, [ALL, ALL];
}
