//! The MMX, SSE and SSSE3/SSE4.1 integer instructions that the x86 processor specification leaves
//! as named processor operations instead of p-code. Most take the destination's old value first,
//! then the source, then any immediate: `dest = name(dest, src, imm)`. `phminposuw` takes only
//! its source, and `pblendvb` takes `XMM0` last. The destination's
//! size says whether the registers are MMX (8 bytes) or XMM (16 bytes). A register is a row of
//! lanes, and lane 0 is its lowest bits.
//!
//! Not here: the string compares (`pcmpestri` and its kin), `maskmovdqu`, which writes memory,
//! and the VEX forms, which the specification names apart (`vpshufb_avx` and so on).

use super::{mask, signed};

/// One of the operations, resolved from its name when the instruction is lifted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    /// Lane by lane, with lanes of `width` bytes.
    Lanes(Lane, usize),
    /// `pmaddwd`: products of signed words, summed in pairs into doublewords.
    MaddWords,
    /// `pmaddubsw`: products of the destination's unsigned bytes and the source's signed bytes,
    /// summed in pairs into words with saturation.
    MaddBytes,
    /// `pmuldq`: signed products of the even doublewords, as quadwords.
    MulEven,
    /// `psadbw`: the sum of the bytes' absolute differences in each quadword.
    SumOfDifferences,
    /// `mpsadbw`: eight sums of absolute differences over sliding blocks of four bytes.
    SlidingDifferences,
    /// Halves the lanes of `width` bytes, the destination's into the low half: signed, or with
    /// `unsigned` into the unsigned range.
    Pack { width: usize, unsigned: bool },
    /// Word shifts by the low quadword of the source or an immediate.
    ShiftWords { arithmetic: bool },
    ShuffleWords(Half),
    ShuffleBytes,
    BlendWords,
    BlendBytes,
    /// Pairs of adjacent lanes added or subtracted, the destination's into the low half.
    Horizontal { width: usize, subtract: bool, saturate: bool },
    /// The top bit of each lane of `width` bytes of the source.
    MoveMask(usize),
    MinPosition,
    /// The low lanes of the source extended from `from` bytes to `to`.
    Widen { from: usize, to: usize, signed: bool },
    /// The source as it is: `lddqu` and `movntdqa`, and `movdq2q` into a smaller register.
    Move,
}

/// What an operation does to a pair of lanes, the destination's and the source's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lane {
    AddSigned,
    AddUnsigned,
    SubSigned,
    SubUnsigned,
    MulHigh,
    MulHighUnsigned,
    MulHighRounded,
    MulLow,
    /// The source's absolute value.
    Abs,
    /// The destination negated, kept or cleared as the source is negative, positive or zero.
    Sign,
}

/// Which words `pshuflw`, `pshufhw` and `pshufw` reorder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Half {
    Low,
    High,
    /// All four words of an MMX register.
    Whole,
}

impl Op {
    /// The operation the specification calls `name`, if it is one of these.
    pub fn parse(name: &str) -> Option<Op> {
        use Lane::*;
        let width = |letter: u8| match letter {
            b'b' => Some(1),
            b'w' => Some(2),
            b'd' => Some(4),
            b'q' => Some(8),
            _ => None,
        };
        // The lane width is the last letter of most names.
        let last = width(*name.as_bytes().last()?);
        Some(match name {
            "paddsb" | "paddsw" => Op::Lanes(AddSigned, last?),
            "paddusb" | "paddusw" => Op::Lanes(AddUnsigned, last?),
            "psubsb" | "psubsw" => Op::Lanes(SubSigned, last?),
            "psubusb" | "psubusw" => Op::Lanes(SubUnsigned, last?),
            "pmulhw" => Op::Lanes(MulHigh, 2),
            "pmulhuw" => Op::Lanes(MulHighUnsigned, 2),
            "pmulhrsw" => Op::Lanes(MulHighRounded, 2),
            "pmulld" => Op::Lanes(MulLow, 4),
            "pabsb" | "pabsw" | "pabsd" => Op::Lanes(Abs, last?),
            "psignb" | "psignw" | "psignd" => Op::Lanes(Sign, last?),
            "pmaddwd" => Op::MaddWords,
            "pmaddubsw" => Op::MaddBytes,
            "pmuldq" => Op::MulEven,
            "psadbw" => Op::SumOfDifferences,
            "mpsadbw" => Op::SlidingDifferences,
            "packsswb" => Op::Pack { width: 2, unsigned: false },
            "packssdw" => Op::Pack { width: 4, unsigned: false },
            "packusdw" => Op::Pack { width: 4, unsigned: true },
            "psllw" => Op::ShiftWords { arithmetic: false },
            "psraw" => Op::ShiftWords { arithmetic: true },
            "pshuflw" => Op::ShuffleWords(Half::Low),
            "pshufhw" => Op::ShuffleWords(Half::High),
            "pshufw" => Op::ShuffleWords(Half::Whole),
            "pshufb" => Op::ShuffleBytes,
            "pblendw" => Op::BlendWords,
            "pblendvb" => Op::BlendBytes,
            "phaddw" | "phaddd" => Op::Horizontal { width: last?, subtract: false, saturate: false },
            "phsubw" | "phsubd" => Op::Horizontal { width: last?, subtract: true, saturate: false },
            "phaddsw" => Op::Horizontal { width: 2, subtract: false, saturate: true },
            "phsubsw" => Op::Horizontal { width: 2, subtract: true, saturate: true },
            "movmskps" => Op::MoveMask(4),
            "movmskpd" => Op::MoveMask(8),
            "phminposuw" => Op::MinPosition,
            "lddqu" | "movntdqa" | "movdq2q" => Op::Move,
            _ => {
                let rest = name.strip_prefix("pmovsx").map(|rest| (rest, true)).or_else(|| name.strip_prefix("pmovzx").map(|rest| (rest, false)));
                let (&[from, to], signed) = rest.map(|(rest, signed)| (rest.as_bytes(), signed))? else { return None };
                Op::Widen { from: width(from)?, to: width(to)?, signed }
            }
        })
    }

    /// What the operation leaves in a destination of `size` bytes, given the values of its
    /// inputs in the order the specification passes them.
    pub fn run(self, size: usize, inputs: &[u128]) -> u128 {
        let arg = |index: usize| inputs.get(index).copied().unwrap_or(0);
        let (dest, src, third) = (arg(0), arg(1), arg(2));
        let result = match self {
            Op::Lanes(Lane::Abs, width) => lanewise(size, width, src, 0, |a, _| sext(a, width).unsigned_abs()),
            Op::Lanes(lane, width) => lanewise(size, width, dest, src, |a, b| match lane {
                Lane::AddSigned => saturate(sext(a, width) + sext(b, width), width),
                Lane::SubSigned => saturate(sext(a, width) - sext(b, width), width),
                Lane::AddUnsigned => (a + b).min(mask(width)),
                Lane::SubUnsigned => a.saturating_sub(b),
                Lane::MulHigh => ((sext(a, 2) * sext(b, 2)) >> 16) as u128,
                Lane::MulHighUnsigned => (a * b) >> 16,
                Lane::MulHighRounded => ((((sext(a, 2) * sext(b, 2)) >> 14) + 1) >> 1) as u128,
                Lane::MulLow => a * b,
                Lane::Sign => match sext(b, width).signum() {
                    -1 => a.wrapping_neg(),
                    0 => 0,
                    _ => a,
                },
                Lane::Abs => unreachable!("the absolute value reads only the source"),
            }),
            Op::MaddWords => join(4, (0..size / 4).map(|lane| pair(dest, src, lane, 2, |a, b| sext(a, 2) * sext(b, 2)) as u128)),
            Op::MaddBytes => join(2, (0..size / 2).map(|lane| saturate(pair(dest, src, lane, 1, |a, b| a as i128 * sext(b, 1)), 2))),
            Op::MulEven => join(8, (0..size / 8).map(|lane| (sext(lane_of(dest, 4, lane * 2), 4) * sext(lane_of(src, 4, lane * 2), 4)) as u128)),
            Op::SumOfDifferences => join(8, (0..size / 8).map(|lane| (0..8).map(|byte| lane_of(dest, 1, lane * 8 + byte).abs_diff(lane_of(src, 1, lane * 8 + byte))).sum())),
            Op::SlidingDifferences => {
                let (from_dest, from_src) = ((third >> 2 & 1) as usize * 4, (third & 3) as usize * 4);
                join(2, (0..8).map(|lane| (0..4).map(|byte| lane_of(dest, 1, from_dest + lane + byte).abs_diff(lane_of(src, 1, from_src + byte))).sum()))
            }
            Op::Pack { width, unsigned } => {
                let per = size / width;
                let narrow = |value: u128| if unsigned { sext(value, width).clamp(0, mask(width / 2) as i128) as u128 } else { saturate(sext(value, width), width / 2) };
                join(width / 2, (0..per * 2).map(|lane| narrow(lane_of(if lane < per { dest } else { src }, width, lane % per))))
            }
            Op::ShiftWords { arithmetic } => {
                // The count is the low quadword of a register or memory source.
                let count = src & mask(8);
                lanewise(size, 2, dest, 0, |a, _| match (arithmetic, count > 15) {
                    (false, true) => 0,
                    (false, false) => a << count,
                    (true, _) => (sext(a, 2) >> count.min(15)) as u128,
                })
            }
            Op::ShuffleWords(Half::Low) => shuffle_words(src, 0, third) | src & !mask(8),
            Op::ShuffleWords(Half::High) => shuffle_words(src, 4, third) << 64 | src & mask(8),
            Op::ShuffleWords(Half::Whole) => shuffle_words(src, 0, third),
            Op::ShuffleBytes => join(1, (0..size).map(|lane| {
                let pick = lane_of(src, 1, lane);
                if pick & 0x80 != 0 { 0 } else { lane_of(dest, 1, pick as usize % size) }
            })),
            Op::BlendWords => join(2, (0..size / 2).map(|lane| lane_of(if third >> (lane % 8) & 1 == 1 { src } else { dest }, 2, lane))),
            Op::BlendBytes => join(1, (0..size).map(|lane| lane_of(if lane_of(third, 1, lane) & 0x80 != 0 { src } else { dest }, 1, lane))),
            Op::Horizontal { width, subtract, saturate: saturating } => {
                let per = size / width / 2;
                join(width, (0..per * 2).map(|lane| {
                    let from = if lane < per { dest } else { src };
                    let (a, b) = (sext(lane_of(from, width, lane % per * 2), width), sext(lane_of(from, width, lane % per * 2 + 1), width));
                    let value = if subtract { a - b } else { a + b };
                    if saturating { saturate(value, width) } else { value as u128 }
                }))
            }
            Op::MoveMask(width) => (0..16 / width).fold(0, |bits, lane| bits | (lane_of(src, width, lane) >> (width * 8 - 1)) << lane),
            Op::MinPosition => {
                let (index, min) = (0..8).map(|lane| (lane, lane_of(dest, 2, lane))).min_by_key(|&(_, value)| value).unwrap_or_default();
                min | (index as u128) << 16
            }
            Op::Widen { from, to, signed } => join(to, (0..size / to).map(|lane| {
                let value = lane_of(src, from, lane);
                if signed { sext(value, from) as u128 } else { value }
            })),
            Op::Move => src,
        };
        result & mask(size)
    }
}

/// The lane of `width` bytes at `index` in `value`.
fn lane_of(value: u128, width: usize, index: usize) -> u128 {
    value >> (index * width * 8) & mask(width)
}

/// Lanes of `width` bytes, lowest first, as one value. Each lane is cut to its width.
fn join(width: usize, lanes: impl Iterator<Item = u128>) -> u128 {
    lanes.enumerate().fold(0, |value, (index, lane)| value | (lane & mask(width)) << (index * width * 8))
}

/// `f` applied to each pair of lanes of `width` bytes of `a` and `b`.
fn lanewise(size: usize, width: usize, a: u128, b: u128, f: impl Fn(u128, u128) -> u128) -> u128 {
    join(width, (0..size / width).map(|lane| f(lane_of(a, width, lane), lane_of(b, width, lane))))
}

/// The sum of `f` over the two lanes of `width` bytes that make up the wider lane `lane`.
fn pair(a: u128, b: u128, lane: usize, width: usize, f: impl Fn(u128, u128) -> i128) -> i128 {
    (0..2).map(|half| f(lane_of(a, width, lane * 2 + half), lane_of(b, width, lane * 2 + half))).sum()
}

/// The four words of `value` from word `from` on, reordered as `imm` picks them two bits each.
fn shuffle_words(value: u128, from: usize, imm: u128) -> u128 {
    join(2, (0..4).map(|lane| lane_of(value, 2, from + (imm >> (lane * 2) & 3) as usize)))
}

fn sext(value: u128, width: usize) -> i128 {
    signed(value, width)
}

/// The nearest value a signed lane of `width` bytes holds to `value`.
fn saturate(value: i128, width: usize) -> u128 {
    let bits = width as u32 * 8;
    value.clamp(-(1 << (bits - 1)), (1 << (bits - 1)) - 1) as u128
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(name: &str, size: usize, inputs: &[u128]) -> u128 {
        Op::parse(name).unwrap_or_else(|| panic!("{name} is not parsed")).run(size, inputs)
    }

    #[test]
    fn names_resolve_to_their_operations() {
        assert_eq!(Op::parse("psubusb"), Some(Op::Lanes(Lane::SubUnsigned, 1)));
        assert_eq!(Op::parse("pmovsxwq"), Some(Op::Widen { from: 2, to: 8, signed: true }));
        for other in ["pmovsx", "pmovzxb", "pmovsxbwq", "cpuid", "vpshufb_avx", ""] {
            assert_eq!(Op::parse(other), None, "{other}");
        }
    }

    #[test]
    fn word_shuffles_fill_the_other_half_from_the_source() {
        // What MSVC's memset does to spread a byte: every word becomes word 0.
        assert_eq!(run("pshuflw", 16, &[0, 0x4444_3333_2222_1111, 0]), 0x1111_1111_1111_1111);
        assert_eq!(run("pshufhw", 16, &[0, 0x9999_8888_7777_6666_4444_3333_2222_1111, 0x1b]), 0x6666_7777_8888_9999_4444_3333_2222_1111);
    }

    #[test]
    fn word_shifts_count_by_the_low_quadword() {
        assert_eq!(run("psllw", 8, &[0x0001_8001, 4]), 0x0010_0010);
        assert_eq!(run("psllw", 16, &[0x0001, 4 | 1 << 64]), 0x0010);
        assert_eq!(run("psraw", 16, &[0x8000, 40]), 0xffff);
    }

    #[test]
    fn the_minimum_word_is_read_from_the_only_input() {
        assert_eq!(run("phminposuw", 16, &[0x0009_0008_0007_0003_0004_0005_0006_0007]), 0x4_0003);
    }

    /// Every operation against the processor this runs on, on values from a fixed generator
    /// that favours the lane limits, with the inputs laid out as the specification passes them.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn operations_match_the_processor() {
        if !is_x86_feature_detected!("ssse3") || !is_x86_feature_detected!("sse4.1") {
            return;
        }
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut half = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..2000 {
            let mut next = || {
                let (a, b) = (half(), half());
                // Lanes of 0, -1, the signed limits and random bits, a byte at a time.
                let pick = |seed: u64, byte: u32| match seed >> (byte * 3) & 7 {
                    0 => 0x00u8,
                    1 => 0xff,
                    2 => 0x7f,
                    3 => 0x80,
                    _ => (seed >> byte) as u8 ^ (seed >> 40) as u8,
                };
                u128::from_le_bytes(std::array::from_fn(|byte| pick(if byte < 8 { a } else { b }, byte as u32 % 8 * 2)))
            };
            let (a, b, c) = (next(), next(), next());
            // A shift count with bits above the low quadword, which the processor ignores.
            let count = (b as u8 % 20) as u128 | (c & !mask(8));
            unsafe { against_the_processor(a, b, c, count) };
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "ssse3,sse4.1")]
    unsafe fn against_the_processor(a: u128, b: u128, c: u128, count: u128) {
        use std::arch::x86_64::*;
        let m = |value: u128| unsafe { std::mem::transmute::<u128, __m128i>(value) };
        let v = |value: __m128i| unsafe { std::mem::transmute::<__m128i, u128>(value) };
        let check = |name: &str, inputs: &[u128], expected: u128| assert_eq!(run(name, 16, inputs), expected, "{name} of {inputs:x?}");
        let (ma, mb, mc) = (m(a), m(b), m(c));
        check("paddsb", &[a, b], v(_mm_adds_epi8(ma, mb)));
        check("paddsw", &[a, b], v(_mm_adds_epi16(ma, mb)));
        check("psubsb", &[a, b], v(_mm_subs_epi8(ma, mb)));
        check("psubsw", &[a, b], v(_mm_subs_epi16(ma, mb)));
        check("paddusb", &[a, b], v(_mm_adds_epu8(ma, mb)));
        check("paddusw", &[a, b], v(_mm_adds_epu16(ma, mb)));
        check("psubusb", &[a, b], v(_mm_subs_epu8(ma, mb)));
        check("psubusw", &[a, b], v(_mm_subs_epu16(ma, mb)));
        check("pmulhw", &[a, b], v(_mm_mulhi_epi16(ma, mb)));
        check("pmulhuw", &[a, b], v(_mm_mulhi_epu16(ma, mb)));
        check("pmulhrsw", &[a, b], v(_mm_mulhrs_epi16(ma, mb)));
        check("pmulld", &[a, b], v(_mm_mullo_epi32(ma, mb)));
        check("pmuldq", &[a, b], v(_mm_mul_epi32(ma, mb)));
        check("pmaddwd", &[a, b], v(_mm_madd_epi16(ma, mb)));
        check("pmaddubsw", &[a, b], v(_mm_maddubs_epi16(ma, mb)));
        check("psadbw", &[a, b], v(_mm_sad_epu8(ma, mb)));
        check("packsswb", &[a, b], v(_mm_packs_epi16(ma, mb)));
        check("packssdw", &[a, b], v(_mm_packs_epi32(ma, mb)));
        check("packusdw", &[a, b], v(_mm_packus_epi32(ma, mb)));
        check("psllw", &[a, count], v(_mm_sll_epi16(ma, m(count))));
        check("psraw", &[a, count], v(_mm_sra_epi16(ma, m(count))));
        check("pabsb", &[0, b], v(_mm_abs_epi8(mb)));
        check("pabsw", &[0, b], v(_mm_abs_epi16(mb)));
        check("pabsd", &[0, b], v(_mm_abs_epi32(mb)));
        check("psignb", &[a, b], v(_mm_sign_epi8(ma, mb)));
        check("psignw", &[a, b], v(_mm_sign_epi16(ma, mb)));
        check("psignd", &[a, b], v(_mm_sign_epi32(ma, mb)));
        check("phaddw", &[a, b], v(_mm_hadd_epi16(ma, mb)));
        check("phaddd", &[a, b], v(_mm_hadd_epi32(ma, mb)));
        check("phaddsw", &[a, b], v(_mm_hadds_epi16(ma, mb)));
        check("phsubw", &[a, b], v(_mm_hsub_epi16(ma, mb)));
        check("phsubd", &[a, b], v(_mm_hsub_epi32(ma, mb)));
        check("phsubsw", &[a, b], v(_mm_hsubs_epi16(ma, mb)));
        check("pshufb", &[a, b], v(_mm_shuffle_epi8(ma, mb)));
        check("pblendvb", &[a, b, c], v(_mm_blendv_epi8(ma, mb, mc)));
        check("phminposuw", &[a], v(_mm_minpos_epu16(ma)));
        for (name, widened) in [
            ("pmovsxbw", _mm_cvtepi8_epi16(ma)),
            ("pmovsxbd", _mm_cvtepi8_epi32(ma)),
            ("pmovsxbq", _mm_cvtepi8_epi64(ma)),
            ("pmovsxwd", _mm_cvtepi16_epi32(ma)),
            ("pmovsxwq", _mm_cvtepi16_epi64(ma)),
            ("pmovsxdq", _mm_cvtepi32_epi64(ma)),
            ("pmovzxbw", _mm_cvtepu8_epi16(ma)),
            ("pmovzxbd", _mm_cvtepu8_epi32(ma)),
            ("pmovzxbq", _mm_cvtepu8_epi64(ma)),
            ("pmovzxwd", _mm_cvtepu16_epi32(ma)),
            ("pmovzxwq", _mm_cvtepu16_epi64(ma)),
            ("pmovzxdq", _mm_cvtepu32_epi64(ma)),
        ] {
            check(name, &[0, a], v(widened));
        }
        assert_eq!(run("movmskps", 4, &[0, a]), _mm_movemask_ps(unsafe { std::mem::transmute::<u128, __m128>(a) }) as u128);
        assert_eq!(run("movmskpd", 4, &[0, a]), _mm_movemask_pd(unsafe { std::mem::transmute::<u128, __m128d>(a) }) as u128);
        // The immediate picks among separate instructions, so a spread of them is tried.
        macro_rules! by_immediate {
            ($($imm:literal),*) => {$(
                check("pshuflw", &[0, a, $imm], v(_mm_shufflelo_epi16::<$imm>(ma)));
                check("pshufhw", &[0, a, $imm], v(_mm_shufflehi_epi16::<$imm>(ma)));
                check("pblendw", &[a, b, $imm], v(_mm_blend_epi16::<$imm>(ma, mb)));
                check("mpsadbw", &[a, b, $imm & 7], v(_mm_mpsadbw_epu8::<{ $imm & 7 }>(ma, mb)));
            )*};
        }
        by_immediate!(0x00, 0x1b, 0x4e, 0x93, 0xa5, 0xe4, 0xff);
    }
}
