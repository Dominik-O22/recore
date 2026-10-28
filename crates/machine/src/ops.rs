//! The integer and float operations of Ghidra's p-code. recore's emulator and lifted code both
//! compute them here, so lifted code computes what the emulator does.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Code {
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
    /// The operation p-code names `name`, as Ghidra prints it.
    pub fn parse(name: &str) -> Option<Code> {
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

pub fn mask(size: usize) -> u128 {
    if size >= 16 { u128::MAX } else { (1u128 << (8 * size)) - 1 }
}

pub fn signed(value: u128, size: usize) -> i128 {
    if size == 0 {
        return 0;
    }
    let spare = 128u32.saturating_sub(8 * size as u32);
    ((value << spare) as i128) >> spare
}

/// Whether the signed `value` fits `size` bytes.
pub fn fits(value: i128, size: usize) -> bool {
    size >= 16 || signed(value as u128 & mask(size), size) == value
}

/// The lowest signed integer of `size` bytes.
pub fn signed_min(size: usize) -> i128 {
    if size >= 16 { i128::MIN } else { -(1i128 << (8 * size - 1)) }
}

/// A float cut toward zero to a signed integer of `size` bytes. Out of range or not a number,
/// ARM saturates and gives zero for not a number, and x86 gives the lowest integer.
pub fn float_to_int(value: f64, size: usize, arm: bool) -> u128 {
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

pub fn float(value: u128, size: usize) -> Result<f64, String> {
    match size {
        4 => Ok(f64::from(f32::from_bits(value as u32))),
        8 => Ok(f64::from_bits(value as u64)),
        _ => Err(format!("floating point of {size} bytes is not run")),
    }
}

pub fn float_bits(value: f64, size: usize) -> Result<u128, String> {
    match size {
        4 => Ok(u128::from((value as f32).to_bits())),
        8 => Ok(u128::from(value.to_bits())),
        _ => Err(format!("floating point of {size} bytes is not run")),
    }
}


/// The result of an operation that computes a value from its inputs, each as its bits and its
/// size in bytes, in a place `size` bytes wide.
pub fn compute(code: Code, size: usize, inputs: &[(u128, usize)], arm: bool) -> Result<u128, String> {
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
