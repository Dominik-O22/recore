//! Checks `run` against machines that are not its interpreter. C functions are built for each
//! machine recore reads and run two ways over generated inputs, by the oracle and by something
//! else, and the answers are compared. A rewrite of firmware is scored against the oracle, so
//! this is what says the oracle can be trusted.
//!
//! The something else is this machine for x86-64. The same C built for AArch64, x86-32 and
//! Thumb is compared against the x86-64 result, since the C means the same on all of them. Float
//! functions built for the x87 are run by this machine as a 32-bit program, and the oracle is
//! compared with the 80 bits the processor leaves in ST0. An 8051 program runs in µCsim, a
//! simulator of the chip, and the oracle is compared with what it leaves in memory.
//!
//! It builds with gcc, a gcc that can build 32-bit programs, clang, rust-lld and sdcc and needs
//! `s51` from the sdcc package, so it is ignored by default. Run it after a change to the
//! interpreter, the shim or a specification:
//!
//!     cargo test --release -p recore-mcp --test oracle -- --ignored
//!
//! What C leaves undefined has no answer to compare with, so this does not judge it: dividing
//! by zero, a quotient too large for its register, and the registers a function reads without
//! setting. The tests in `session.rs` pin what the oracle does there.

mod common;

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::io::Write as _;
use std::process::{Command, Stdio};
use std::time::Duration;

use common::{Client, edits_dir};
use serde_json::json;

/// Inputs tried on each function.
const CASES: usize = 200;

/// A generator of inputs that is the same on every run.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ty {
    U8,
    I16,
    I32,
    U32,
    I64,
    U64,
    F32,
    F64,
}

/// A value of a type: an integer, sign-extended or not as its type has it, or the bits of a float.
#[derive(Clone, Copy, Debug)]
enum Input {
    Int(i64),
    Float(u64),
}

impl Ty {
    fn c(self) -> &'static str {
        match self {
            Ty::U8 => "uint8_t",
            Ty::I16 => "int16_t",
            Ty::I32 => "int32_t",
            Ty::U32 => "uint32_t",
            Ty::I64 => "int64_t",
            Ty::U64 => "uint64_t",
            Ty::F32 => "float",
            Ty::F64 => "double",
        }
    }

    fn bits(self) -> u32 {
        match self {
            Ty::U8 => 8,
            Ty::I16 => 16,
            Ty::I32 | Ty::U32 | Ty::F32 => 32,
            Ty::I64 | Ty::U64 | Ty::F64 => 64,
        }
    }

    fn is_float(self) -> bool {
        matches!(self, Ty::F32 | Ty::F64)
    }

    /// A value to try: the edges of the type, or a number in `range` when the function takes
    /// only some, or a random one.
    fn generate(self, rng: &mut Rng, range: Option<(i64, i64)>) -> Input {
        if self.is_float() {
            let negative = rng.below(2) == 1;
            let edges = [0.0, 1.0, 0.5, 3.0e9, 1.0e10, 123456.789];
            let magnitude = if rng.below(4) == 0 { edges[rng.below(edges.len() as u64) as usize] } else { rng.next() as f64 / u64::MAX as f64 * 2f64.powi(rng.below(60) as i32 - 30) };
            let value = if negative { -magnitude } else { magnitude };
            return Input::Float(if self == Ty::F32 { u64::from((value as f32).to_bits()) } else { value.to_bits() });
        }
        if let Some((low, high)) = range {
            return Input::Int(low + rng.below((high - low + 1) as u64) as i64);
        }
        let (low, high): (i64, i64) = match self {
            Ty::U8 => (0, 0xff),
            Ty::I16 => (i64::from(i16::MIN), i64::from(i16::MAX)),
            Ty::I32 => (i64::from(i32::MIN), i64::from(i32::MAX)),
            Ty::U32 => (0, i64::from(u32::MAX)),
            _ => (i64::MIN, i64::MAX),
        };
        let random = if self.bits() == 64 { rng.next() as i64 } else { low + rng.below((high - low + 1) as u64) as i64 };
        Input::Int(match rng.below(6) {
            0 => low,
            1 => high,
            2 => 0,
            3 => 1,
            _ => random,
        })
    }
}

#[derive(Clone, Copy)]
struct Param {
    ty: Ty,
    /// The only values the function takes.
    range: Option<(i64, i64)>,
}

const fn any(ty: Ty) -> Param {
    Param { ty, range: None }
}

const fn within(ty: Ty, low: i64, high: i64) -> Param {
    Param { ty, range: Some((low, high)) }
}

/// What a machine needs to have to run a function.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Needs {
    Everything,
    /// 64-bit registers, for a function that takes or gives 64 bits.
    Wide,
    /// Floats, which x86-64 and AArch64 take in registers.
    Floats,
    /// The MMX, SSE, SSSE3 and SSE4.1 integer instructions, which only x86 has.
    Vectors,
}

struct Function {
    name: &'static str,
    params: &'static [Param],
    ret: Ty,
    needs: Needs,
}

use Needs::{Everything, Floats, Vectors, Wide};
use Ty::{F32, F64, I16, I32, I64, U8, U32, U64};

const FUNCTIONS: &[Function] = &[
    Function { name: "mix", params: &[any(U32), any(U32), any(U32)], ret: U32, needs: Everything },
    Function { name: "narrow", params: &[any(U8), any(I16)], ret: U8, needs: Everything },
    Function { name: "collatz", params: &[within(I32, 1, 5000)], ret: I32, needs: Everything },
    Function { name: "divide", params: &[any(I32), any(I32)], ret: I32, needs: Everything },
    Function { name: "modulo", params: &[any(I32), any(I32)], ret: I32, needs: Everything },
    Function { name: "classify", params: &[within(I32, -3, 9)], ret: I32, needs: Everything },
    Function { name: "weigh", params: &[any(I32), any(I32), any(I32), any(I32), any(I32), any(I32), any(I32), any(I32)], ret: I32, needs: Everything },
    Function { name: "bits", params: &[any(U32)], ret: U32, needs: Everything },
    Function { name: "clamp", params: &[any(I32), any(I32), any(I32)], ret: I32, needs: Everything },
    Function { name: "rotl", params: &[any(U32), any(U32)], ret: U32, needs: Everything },
    Function { name: "addcheck", params: &[any(I32), any(I32)], ret: I32, needs: Everything },
    Function { name: "subcheck", params: &[any(I32), any(I32)], ret: I32, needs: Everything },
    Function { name: "mulcheck", params: &[any(I32), any(I32)], ret: I32, needs: Everything },
    Function { name: "uaddcheck", params: &[any(U32), any(U32)], ret: U32, needs: Everything },
    Function { name: "addcheck64", params: &[any(I64), any(I64)], ret: I64, needs: Wide },
    Function { name: "mulcheck64", params: &[any(I64), any(I64)], ret: I64, needs: Wide },
    Function { name: "smix", params: &[any(I64), any(I64), any(I32)], ret: I64, needs: Wide },
    Function { name: "mulhi", params: &[any(U64), any(U64)], ret: U64, needs: Wide },
    Function { name: "dmix", params: &[any(F64), any(F64)], ret: F64, needs: Floats },
    Function { name: "ftoi", params: &[any(F64)], ret: I32, needs: Floats },
    Function { name: "itof", params: &[any(I32)], ret: F64, needs: Floats },
    Function { name: "fmixf", params: &[any(F32), any(F32)], ret: F32, needs: Floats },
    Function { name: "saturating", params: &[any(U32), any(U32), any(U32)], ret: U32, needs: Vectors },
    Function { name: "multiplying", params: &[any(U32), any(U32), any(U32)], ret: U32, needs: Vectors },
    Function { name: "packing", params: &[any(U32), any(U32), any(U32)], ret: U32, needs: Vectors },
    Function { name: "shifting", params: &[any(U32), any(U32), any(U32)], ret: U32, needs: Vectors },
    Function { name: "shuffling", params: &[any(U32), any(U32), any(U32)], ret: U32, needs: Vectors },
    Function { name: "masking", params: &[any(U32), any(U32), any(U32)], ret: U32, needs: Vectors },
    Function { name: "ssse3", params: &[any(U32), any(U32), any(U32)], ret: U32, needs: Vectors },
    Function { name: "sse41", params: &[any(U32), any(U32), any(U32)], ret: U32, needs: Vectors },
    Function { name: "mmx", params: &[any(U32), any(U32), any(U32)], ret: U32, needs: Vectors },
];

/// Every operation is on unsigned numbers or cannot overflow, so the C means one thing on every
/// machine and under every compiler.
const SOURCE: &str = r#"
#include <stdint.h>

uint32_t mix(uint32_t a, uint32_t b, uint32_t c) {
    uint32_t x = a * 2654435761u ^ (b << (c & 31)) ^ (b >> ((c >> 5) & 31));
    x ^= (x >> 15) | (c << 3);
    return x + (a % (b | 1)) - b / ((c & 7) + 1);
}

uint8_t narrow(uint8_t a, int16_t b) { return (uint8_t)((a * b) >> 3) ^ (int8_t)a; }

int32_t collatz(int32_t n) {
    int32_t steps = 0;
    while (n != 1) {
        n = n & 1 ? 3 * n + 1 : n / 2;
        steps++;
    }
    return steps;
}

int32_t divide(int32_t a, int32_t b) {
    if (b == 0 || (b == -1 && a == INT32_MIN)) return 0;
    return a / b;
}

int32_t modulo(int32_t a, int32_t b) {
    if (b == 0 || (b == -1 && a == INT32_MIN)) return 0;
    return a % b;
}

int32_t classify(int32_t c) {
    switch (c) {
    case 0: return 10;
    case 1: return 21;
    case 2: return 35;
    case 3: return 48;
    case 4: return 52;
    case 5: return 67;
    default: return -1;
    }
}

int32_t weigh(int32_t a, int32_t b, int32_t c, int32_t d, int32_t e, int32_t f, int32_t g, int32_t h) {
    return (int32_t)((uint32_t)a + 2u * (uint32_t)b + 3u * (uint32_t)c + 4u * (uint32_t)d + 5u * (uint32_t)e + 6u * (uint32_t)f + 7u * (uint32_t)g + 8u * (uint32_t)h);
}

uint32_t bits(uint32_t x) { return (uint32_t)__builtin_popcount(x) * 33u + (uint32_t)__builtin_clz(x | 1); }

int32_t clamp(int32_t x, int32_t low, int32_t high) { return x < low ? low : x > high ? high : x; }

uint32_t rotl(uint32_t x, uint32_t n) {
    n &= 31;
    return n ? (x << n) | (x >> (32 - n)) : x;
}

// The overflow and carry flags, which a comparison alone seldom reads.
int32_t addcheck(int32_t a, int32_t b) { int32_t r; return __builtin_add_overflow(a, b, &r) ? -1 : r; }
int32_t subcheck(int32_t a, int32_t b) { int32_t r; return __builtin_sub_overflow(a, b, &r) ? -1 : r; }
int32_t mulcheck(int32_t a, int32_t b) { int32_t r; return __builtin_mul_overflow(a, b, &r) ? -1 : r; }
uint32_t uaddcheck(uint32_t a, uint32_t b) { uint32_t r; return __builtin_add_overflow(a, b, &r) ? 0 : r | 1; }

#ifdef WIDE
int64_t addcheck64(int64_t a, int64_t b) { int64_t r; return __builtin_add_overflow(a, b, &r) ? -1 : r; }
int64_t mulcheck64(int64_t a, int64_t b) { int64_t r; return __builtin_mul_overflow(a, b, &r) ? -1 : r; }

int64_t smix(int64_t a, int64_t b, int32_t c) {
    int64_t r = (int64_t)((uint64_t)a >> (c & 63)) + (int64_t)((uint64_t)b << (c & 15));
    if (a < b) r ^= (int64_t)((uint64_t)a * (uint64_t)b);
    return (r / ((b & 0xff) | 1)) % 1000003 + (a > 0 ? __builtin_popcountll(a) : __builtin_clzll(a | 1));
}

uint64_t mulhi(uint64_t a, uint64_t b) { return (uint64_t)(((unsigned __int128)a * b) >> 64); }
#endif

#ifdef FLOATS
double dmix(double a, double b) { return a * b + a / (b == 0.0 ? 1.0 : b) - __builtin_sqrt(a < 0 ? -a : a); }
// Out of range the conversion is undefined, and x86 and AArch64 give different integers.
int32_t ftoi(double d) { return d >= 2147483647.0 ? INT32_MAX : d <= -2147483648.0 ? INT32_MIN : (int32_t)d; }
double itof(int32_t i) { return (double)i * 0.5; }
float fmixf(float a, float b) { return a * b - a / (b == 0.0f ? 1.0f : b); }
#endif

#ifdef VECTORS
#include <immintrin.h>

// The instruction sets go on the functions, so that nothing else in the file is built with them.
#define VECTOR __attribute__((target("sse2,ssse3,sse4.1")))

// Three words spread over a register so that its lanes differ and some sit at their limits.
// The helpers are built apart, with SSE2 alone, so that the compiler moves values in and out of
// the registers with plain moves and not with SSE4.1 inserts that are not the instructions under
// test.
#define PLAIN __attribute__((noinline, target("sse2")))

PLAIN static __m128i spread(uint32_t a, uint32_t b, uint32_t c) {
    uint32_t w[4] = { a + c, c ^ 0x80007fffu, b * 2654435761u, a ^ (b << 16) };
    return _mm_loadu_si128((const __m128i *)w);
}

PLAIN static uint32_t fold(__m128i v) {
    uint32_t w[4];
    _mm_storeu_si128((__m128i *)w, v);
    return ((w[0] * 2654435761u ^ w[1]) * 2246822519u ^ w[2]) * 3266489917u ^ w[3];
}

VECTOR uint32_t saturating(uint32_t a, uint32_t b, uint32_t c) {
    __m128i x = spread(a, b, c), y = spread(c, a, b);
    return fold(_mm_adds_epi8(x, y)) ^ fold(_mm_adds_epu16(x, y)) * 3 ^ fold(_mm_subs_epi16(x, y)) * 5 ^ fold(_mm_subs_epu8(x, y)) * 7;
}

VECTOR uint32_t multiplying(uint32_t a, uint32_t b, uint32_t c) {
    __m128i x = spread(a, b, c), y = spread(b, c, a);
    return fold(_mm_mulhi_epi16(x, y)) ^ fold(_mm_mulhi_epu16(x, y)) * 3 ^ fold(_mm_madd_epi16(x, y)) * 5 ^ fold(_mm_sad_epu8(x, y)) * 7;
}

VECTOR uint32_t packing(uint32_t a, uint32_t b, uint32_t c) {
    __m128i x = spread(a, b, c), y = spread(c, b, a);
    return fold(_mm_packs_epi16(x, y)) ^ fold(_mm_packs_epi32(x, y)) * 3;
}

// The count's high quadword is not zero, and the processor reads only the low one.
VECTOR uint32_t shifting(uint32_t a, uint32_t b, uint32_t c) {
    __m128i x = spread(a, b, c), count = _mm_unpacklo_epi64(_mm_cvtsi32_si128((int)(c % 20)), spread(b, a, c));
    return fold(_mm_sll_epi16(x, count)) ^ fold(_mm_sra_epi16(x, count)) * 3 ^ fold(_mm_slli_epi16(x, 3)) * 5 ^ fold(_mm_srai_epi16(x, 5)) * 7;
}

VECTOR uint32_t shuffling(uint32_t a, uint32_t b, uint32_t c) {
    __m128i x = spread(a, b, c);
    return fold(_mm_shufflelo_epi16(x, 0)) ^ fold(_mm_shufflelo_epi16(x, 0x1b)) * 3 ^ fold(_mm_shufflehi_epi16(x, 0x4e)) * 5;
}

VECTOR uint32_t masking(uint32_t a, uint32_t b, uint32_t c) {
    __m128i x = spread(a, b, c);
    return (uint32_t)_mm_movemask_ps(_mm_castsi128_ps(x)) | (uint32_t)_mm_movemask_pd(_mm_castsi128_pd(x)) << 4;
}

VECTOR uint32_t ssse3(uint32_t a, uint32_t b, uint32_t c) {
    __m128i x = spread(a, b, c), y = spread(b, a, c);
    return fold(_mm_shuffle_epi8(x, y)) ^ fold(_mm_abs_epi8(y)) * 3 ^ fold(_mm_sign_epi16(x, y)) * 5 ^ fold(_mm_hadd_epi16(x, y)) * 7
        ^ fold(_mm_hadds_epi16(x, y)) * 11 ^ fold(_mm_hsub_epi32(x, y)) * 13 ^ fold(_mm_maddubs_epi16(x, y)) * 17 ^ fold(_mm_mulhrs_epi16(x, y)) * 19;
}

VECTOR uint32_t sse41(uint32_t a, uint32_t b, uint32_t c) {
    __m128i x = spread(a, b, c), y = spread(c, a, b);
    return fold(_mm_mullo_epi32(x, y)) ^ fold(_mm_mul_epi32(x, y)) * 3 ^ fold(_mm_packus_epi32(x, y)) * 5 ^ fold(_mm_minpos_epu16(x)) * 7
        ^ fold(_mm_cvtepi8_epi16(x)) * 11 ^ fold(_mm_cvtepu16_epi32(y)) * 13 ^ fold(_mm_blend_epi16(x, y, 0xa5)) * 17
        ^ fold(_mm_blendv_epi8(x, y, spread(b, c, a))) * 19 ^ fold(_mm_mpsadbw_epu8(x, y, 5)) * 23;
}

VECTOR uint32_t mmx(uint32_t a, uint32_t b, uint32_t c) {
    __m64 x = _mm_set_pi32((int)(a ^ 0x80007fffu), (int)b), y = _mm_set_pi32((int)c, (int)(a * 2654435761u));
    __m64 r = _mm_xor_si64(_mm_adds_pi16(x, y), _mm_shuffle_pi16(x, 0x1b));
    uint32_t low = (uint32_t)_mm_cvtsi64_si32(r), high = (uint32_t)_mm_cvtsi64_si32(_mm_srli_si64(r, 32));
    _mm_empty();
    return low * 2654435761u ^ high;
}
#endif
"#;

/// Float functions for the x87, built by gcc for 32-bit x86 with `-mfpmath=387`. They round
/// through the control word, compare with `FNSTSW` or `FCOMI`, and give a `float` and a `double`
/// back in ST0.
const X87_FUNCTIONS: &[Function] = &[
    Function { name: "xmix", params: &[any(F64), any(F64)], ret: F64, needs: Floats },
    Function { name: "xmixf", params: &[any(F32), any(F32)], ret: F32, needs: Floats },
    Function { name: "xsqrtf", params: &[any(F32)], ret: F32, needs: Floats },
    Function { name: "xftoi", params: &[any(F64)], ret: I32, needs: Floats },
    Function { name: "xftoll", params: &[any(F64)], ret: I64, needs: Floats },
    Function { name: "xitof", params: &[any(I32)], ret: F64, needs: Floats },
    Function { name: "xlltof", params: &[any(I64)], ret: F64, needs: Floats },
    Function { name: "xcmp", params: &[any(F64), any(F64)], ret: I32, needs: Floats },
    Function { name: "xpoly", params: &[any(F64), any(I32)], ret: F64, needs: Floats },
    Function { name: "xmean", params: &[any(F32), any(F64), any(I32), any(F32)], ret: F32, needs: Floats },
];

const X87_SOURCE: &str = r#"
#include <stdint.h>

double xmix(double a, double b) { return a * b + a / (b == 0.0 ? 1.0 : b) - __builtin_sqrt(a < 0 ? -a : a); }
float xmixf(float a, float b) { return a * b - a / (b == 0.0f ? 1.0f : b); }
float xsqrtf(float a) { return __builtin_sqrtf(a < 0 ? -a : a) * 0.75f; }
int32_t xftoi(double d) { return (int32_t)d; }
int64_t xftoll(double d) { return (int64_t)d; }
double xitof(int32_t i) { return (double)i * 0.5; }
double xlltof(int64_t i) { return (double)i / 3.0; }
int32_t xcmp(double a, double b) { return a < b ? 1 : a == b ? 2 : a > b ? 3 : 4; }

double xpoly(double x, int32_t n) {
    double s = 0;
    for (int32_t i = 0; i < (n & 7); i++) s = s * x + (i & 1 ? -1.5 : 2.25);
    return s < -1.0 ? -s : s > 1e6 ? 1e6 : s;
}

float xmean(float a, double b, int32_t n, float c) {
    double m = (a + b + c) / 3;
    return n > 0 && m > n ? (float)n : (float)m;
}
"#;

/// Functions of the C library on the x87, built with `-funsafe-math-optimizations`, which has
/// gcc compute `exp`, `log`, `sin`, `atan2`, `fmod` and the rest with the x87's own instructions.
/// `pow` is glibc's for 32-bit x86, written for the x87 and taken from its `libm.a`.
const X87_MATH: &[Function] = &[
    Function { name: "xpow", params: &[any(F64), any(F64)], ret: F64, needs: Floats },
    Function { name: "xexp", params: &[any(F64)], ret: F64, needs: Floats },
    Function { name: "xlog", params: &[any(F64)], ret: F64, needs: Floats },
    Function { name: "xlog1p", params: &[any(F64)], ret: F64, needs: Floats },
    Function { name: "xsin", params: &[any(F64)], ret: F64, needs: Floats },
    Function { name: "xtrig", params: &[any(F64)], ret: F64, needs: Floats },
    Function { name: "xatan2", params: &[any(F64), any(F64)], ret: F64, needs: Floats },
    Function { name: "xfmod", params: &[any(F64), any(F64)], ret: F64, needs: Floats },
    Function { name: "xfmodw", params: &[any(F64), any(F64)], ret: F64, needs: Floats },
    Function { name: "xremainder", params: &[any(F64), any(F64)], ret: F64, needs: Floats },
    Function { name: "xconstants", params: &[any(F64), any(I32)], ret: F64, needs: Floats },
];

const X87_MATH_SOURCE: &str = r#"
#include <math.h>
#include <stdint.h>

double xpow(double a, double b) { return pow(a, b); }
double xexp(double a) { return exp(a); }
double xlog(double a) { return log(a); }
double xlog1p(double a) { return log1p(a); }
double xsin(double a) { return sin(a); }
double xtrig(double a) { return tan(a) + cos(a) * sin(a); }
double xatan2(double a, double b) { return atan2(a, b); }
double xfmod(double a, double b) { return fmod(a, b); }
// A dividend so far above the divisor that FPREM takes it off in parts.
double xfmodw(double a, double b) { return fmod(a * 0x1p300, b); }
double xremainder(double a, double b) { return remainder(a, b); }
double xconstants(double a, int32_t n) { return ldexp(a * 3.14159265358979323846264338327950288L + 0.693147180559945309417232121458176568L, n & 63); }
"#;

/// The inputs of one function and what the machine it ran on gave.
struct Case {
    function: &'static Function,
    args: Vec<Input>,
    expected: u64,
}

fn literal(ty: Ty, value: Input) -> String {
    match value {
        Input::Int(i64::MIN) => format!("({})(-9223372036854775807LL-1)", ty.c()),
        Input::Int(int) => format!("({}){int}LL", ty.c()),
        Input::Float(bits) if ty == Ty::F32 => format!("single({bits:#x}u)"),
        Input::Float(bits) => format!("double_({bits:#x}ull)"),
    }
}

/// A C program that calls the functions on the cases and prints what each gave.
fn driver(cases: &[Case]) -> String {
    let mut c = String::from(
        "#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n\
         static double double_(uint64_t b) { double x; memcpy(&x, &b, 8); return x; }\n\
         static float single(uint32_t b) { float x; memcpy(&x, &b, 4); return x; }\n\
         static uint64_t bits_of_double(double x) { uint64_t b; memcpy(&b, &x, 8); return b; }\n\
         static uint64_t bits_of_single(float x) { uint32_t b; memcpy(&b, &x, 4); return b; }\n",
    );
    for function in FUNCTIONS {
        let params: Vec<&str> = function.params.iter().map(|param| param.ty.c()).collect();
        writeln!(c, "{} {}({});", function.ret.c(), function.name, params.join(", ")).unwrap();
    }
    c.push_str("int main(void) {\n");
    for (index, case) in cases.iter().enumerate() {
        let args: Vec<String> = case.function.params.iter().zip(&case.args).map(|(param, &value)| literal(param.ty, value)).collect();
        let call = format!("{}({})", case.function.name, args.join(", "));
        let shown = match case.function.ret {
            F64 => format!("bits_of_double({call})"),
            F32 => format!("bits_of_single({call})"),
            _ => format!("(unsigned long long)({call})"),
        };
        writeln!(c, "    printf(\"{index} %llu\\n\", (unsigned long long)({shown}));").unwrap();
    }
    c.push_str("    return 0;\n}\n");
    c
}

/// Runs a program and gives what it printed. A program that fails fails the test with its
/// messages.
fn command(program: impl AsRef<std::ffi::OsStr>, args: &[&str]) -> String {
    let program = program.as_ref();
    let output = Command::new(program).args(args).output().unwrap_or_else(|error| panic!("cannot run {program:?}: {error}"));
    assert!(output.status.success(), "{program:?} {args:?} failed:\n{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn on_path(tool: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|path| std::env::split_paths(&path).any(|dir| dir.join(tool).is_file()))
}

/// Where rustc keeps the linker it ships.
fn rust_lld() -> PathBuf {
    let sysroot = command("rustc", &["--print", "sysroot"]);
    let host = command("rustc", &["-vV"]).lines().find_map(|line| line.strip_prefix("host: ").map(String::from)).unwrap();
    Path::new(sysroot.trim()).join("lib/rustlib").join(host).join("bin/rust-lld")
}

/// A test that was asked for must not pass because there is nothing to compare with.
fn require(tools: &[&str]) {
    let missing: Vec<&&str> = tools.iter().filter(|tool| !on_path(tool)).collect();
    assert!(missing.is_empty(), "this test needs {missing:?} on the path");
    assert!(rust_lld().is_file(), "this test needs rust-lld, which rustup ships with the toolchain");
}

fn path(path: &Path) -> &str {
    path.to_str().unwrap()
}

/// A machine to run the functions on, and how to ask the oracle for one of them.
struct Machine {
    name: &'static str,
    /// The image the oracle loads.
    image: PathBuf,
    /// Where each function is, for an image that has no names; else the name is its place.
    addresses: BTreeMap<String, u64>,
    /// The register a result of up to a word comes back in.
    result: &'static str,
    wide: bool,
    /// The register a float result comes back in, where floats are asked for.
    floats: Option<&'static str>,
    vectors: bool,
}

impl Machine {
    fn runs(&self, function: &Function) -> bool {
        match function.needs {
            Everything => true,
            Wide => self.wide,
            Floats => self.floats.is_some(),
            Vectors => self.vectors,
        }
    }
}

fn native(dir: &Path, source: &Path) -> Machine {
    let image = dir.join("native.so");
    command("gcc", &["-O2", "-fPIC", "-shared", "-fno-math-errno", "-DWIDE", "-DFLOATS", "-DVECTORS", "-o", path(&image), path(source)]);
    Machine { name: "x86-64", image, addresses: BTreeMap::new(), result: "RAX", wide: true, floats: Some("XMM0"), vectors: true }
}

fn shared(dir: &Path, source: &Path, name: &'static str, target: &str, linker_machine: &[&str], result: &'static str, wide: bool, floats: Option<&'static str>, vectors: bool) -> Machine {
    let object = dir.join(format!("{name}.o"));
    let image = dir.join(format!("{name}.so"));
    let target = format!("--target={target}");
    let mut compile = vec![target.as_str(), "-O2", "-fPIC", "-ffreestanding", "-fno-math-errno", "-c", path(source), "-o", path(&object)];
    if wide {
        compile.push("-DWIDE");
    }
    if floats.is_some() {
        compile.push("-DFLOATS");
    }
    if vectors {
        compile.push("-DVECTORS");
    }
    command("clang", &compile);
    let mut link = vec!["-flavor", "gnu", "-shared"];
    link.extend(linker_machine);
    link.extend(["-o", path(&image), path(&object)]);
    command(rust_lld(), &link);
    Machine { name, image, addresses: BTreeMap::new(), result, wide, floats, vectors }
}

/// A Cortex-M3 image of flash at 0, with the layout file that names it.
fn thumb(dir: &Path, source: &Path) -> Machine {
    let start = dir.join("thumb-start.c");
    std::fs::write(&start, "__attribute__((used, section(\".vectors\"))) const unsigned vectors[] = {0x20001000, 1};\nvoid reset(void) { for (;;) {} }\n").unwrap();
    let script = dir.join("thumb.ld");
    std::fs::write(&script, "SECTIONS { .text 0 : { KEEP(*(.vectors)) *(.text*) *(.rodata*) } .bss 0x20000000 : { *(.bss*) } /DISCARD/ : { *(.ARM.exidx*) } }\n").unwrap();
    let mut objects = Vec::new();
    for file in [source, &start] {
        let object = file.with_extension("thumb.o");
        command("clang", &["--target=thumbv7m-none-eabi", "-mcpu=cortex-m3", "-O2", "-ffreestanding", "-fno-unwind-tables", "-c", path(file), "-o", path(&object)]);
        objects.push(object);
    }
    let elf = dir.join("thumb.elf");
    let mut link = vec!["-flavor", "gnu", "-e", "reset", "-T", path(&script), "-o", path(&elf)];
    link.extend(objects.iter().map(|object| path(object)));
    command(rust_lld(), &link);
    let bin = dir.join("thumb.bin");
    command("llvm-objcopy", &["-O", "binary", path(&elf), path(&bin)]);
    let image = dir.join("thumb.toml");
    let length = std::fs::metadata(&bin).unwrap().len();
    std::fs::write(&image, format!("machine = \"cortex-m\"\n[[region]]\nfile = \"thumb.bin\"\noffset = 0\nlength = {length}\naddress = 0\nexecutable = true\n")).unwrap();
    // A Thumb function's address has the bit that says so set.
    let addresses = command("nm", &[path(&elf)])
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let (address, kind, name) = (fields.next()?, fields.next()?, fields.next()?);
            (kind == "T").then(|| (name.to_string(), u64::from_str_radix(address, 16).unwrap() & !1))
        })
        .collect();
    Machine { name: "thumb", image, addresses, result: "r0", wide: false, floats: None, vectors: false }
}

/// The first value a register has in an answer of `run`, as the bits it printed.
fn register(answer: &str, name: &str) -> u128 {
    let at = answer.find(&format!("{name} = 0x")).unwrap_or_else(|| panic!("no {name} in\n{answer}")) + name.len() + 5;
    let digits: String = answer[at..].chars().take_while(char::is_ascii_hexdigit).collect();
    u128::from_str_radix(&digits, 16).unwrap()
}

fn same(ret: Ty, expected: u64, got: u64) -> bool {
    let mask = if ret.bits() == 64 { u64::MAX } else { (1 << ret.bits()) - 1 };
    match ret {
        F64 => expected == got || (f64::from_bits(expected).is_nan() && f64::from_bits(got).is_nan()),
        F32 => expected & mask == got & mask || (f32::from_bits(expected as u32).is_nan() && f32::from_bits(got as u32).is_nan()),
        _ => expected & mask == got & mask,
    }
}

/// Asks the oracle for one case on one machine.
fn ask(client: &mut Client, machine: &Machine, case: &Case) -> u64 {
    let function = case.function;
    let mut args = Vec::new();
    let set: Vec<String> = Vec::new();
    for (param, &value) in function.params.iter().zip(&case.args) {
        match value {
            Input::Int(int) if param.ty == U64 => args.push(json!(int as u64)),
            Input::Int(int) => args.push(json!(int)),
            Input::Float(bits) => args.push(json!(float_arg(param.ty, bits))),
        }
    }
    let place = machine.addresses.get(function.name).map_or_else(|| function.name.to_string(), |address| format!("{address:#x}"));
    let float = machine.floats.unwrap_or("none");
    let read: Vec<&str> = if function.ret.is_float() { vec![float] } else { vec![] };
    let answer = client.tool("run", json!({ "path": machine.image, "function": place, "args": args, "set": set, "read": read })).unwrap_or_else(|error| panic!("{} {}: {error}", machine.name, function.name));
    assert!(answer.contains(" returned "), "{} {} {:?}: {answer}", machine.name, function.name, case.args);
    register(&answer, if function.ret.is_float() { float } else { machine.result }) as u64
}

/// A float argument as `run` takes one, in the fewest digits that read back as it.
fn float_arg(ty: Ty, bits: u64) -> String {
    if ty == F32 { format!("f32:{:?}", f32::from_bits(bits as u32)) } else { format!("f64:{:?}", f64::from_bits(bits)) }
}

#[test]
#[ignore = "builds for four machines: cargo test --release -p recore-mcp --test oracle -- --ignored"]
fn the_oracle_agrees_with_the_machines() {
    require(&["gcc", "clang", "nm", "llvm-objcopy"]);
    let dir = edits_dir();
    std::fs::create_dir_all(&dir).unwrap();
    let source = dir.join("functions.c");
    std::fs::write(&source, SOURCE).unwrap();

    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let mut cases: Vec<Case> = FUNCTIONS
        .iter()
        .flat_map(|function| (0..CASES).map(|_| (function, function.params.iter().map(|param| param.ty.generate(&mut rng, param.range)).collect::<Vec<_>>())).collect::<Vec<_>>())
        .map(|(function, args)| Case { function, args, expected: 0 })
        .collect();

    // What the C gives on this machine, from the functions built apart from the program that
    // calls them so that the compiler cannot see through the call.
    let reference = dir.join("reference");
    command("gcc", &["-O2", "-c", "-fno-math-errno", "-DWIDE", "-DFLOATS", "-DVECTORS", "-o", path(&dir.join("functions.o")), path(&source)]);
    std::fs::write(dir.join("driver.c"), driver(&cases)).unwrap();
    command("gcc", &["-O0", "-o", path(&reference), path(&dir.join("driver.c")), path(&dir.join("functions.o"))]);
    for line in command(&reference, &[]).lines() {
        let (index, value) = line.split_once(' ').unwrap();
        cases[index.parse::<usize>().unwrap()].expected = value.parse().unwrap();
    }

    let machines = [
        native(&dir, &source),
        shared(&dir, &source, "aarch64", "aarch64-linux-gnu", &[], "x0", true, Some("d0"), false),
        shared(&dir, &source, "x86-32", "i686-linux-gnu", &["-m", "elf_i386"], "EAX", false, None, true),
        thumb(&dir, &source),
    ];
    let mut client = Client::start();
    let mut mismatches = Vec::new();
    let mut compared = 0;
    for machine in &machines {
        for case in cases.iter().filter(|case| machine.runs(case.function)) {
            let got = ask(&mut client, machine, case);
            compared += 1;
            if !same(case.function.ret, case.expected, got) {
                mismatches.push(format!("{} {}{:?}: the machine gave {:#x}, the oracle {got:#x}", machine.name, case.function.name, case.args, case.expected));
            }
        }
    }
    drop(client);
    std::fs::remove_dir_all(&dir).unwrap();
    assert!(compared > 4000, "only {compared} cases were compared");
    assert!(mismatches.is_empty(), "{} of {compared} cases differ, the first:\n{}", mismatches.len(), mismatches.iter().take(10).cloned().collect::<Vec<_>>().join("\n"));
}

/// A C program for 32-bit x86 that calls the x87 functions on the cases and prints what each
/// gave: an integer, or all 80 bits a float function leaves in ST0, read by declaring it to
/// return a `long double`, which comes back in ST0 too.
fn x87_driver(cases: &[Case]) -> String {
    let mut c = String::from(
        "#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n\
         static double double_(uint64_t b) { double x; memcpy(&x, &b, 8); return x; }\n\
         static float single(uint32_t b) { float x; memcpy(&x, &b, 4); return x; }\n\
         static void extended(int i, long double x) { uint64_t low; uint16_t high; memcpy(&low, &x, 8); memcpy(&high, (char *)&x + 8, 2); printf(\"%d %04x%016llx\\n\", i, high, (unsigned long long)low); }\n",
    );
    for function in X87_FUNCTIONS.iter().chain(X87_MATH) {
        let params: Vec<&str> = function.params.iter().map(|param| param.ty.c()).collect();
        let ret = if function.ret.is_float() { "long double" } else { function.ret.c() };
        writeln!(c, "{ret} {}_raw({}) __asm__(\"{}\");", function.name, params.join(", "), function.name).unwrap();
    }
    c.push_str("int main(void) {\n");
    for (index, case) in cases.iter().enumerate() {
        let args: Vec<String> = case.function.params.iter().zip(&case.args).map(|(param, &value)| literal(param.ty, value)).collect();
        let call = format!("{}_raw({})", case.function.name, args.join(", "));
        if case.function.ret.is_float() {
            writeln!(c, "    extended({index}, {call});").unwrap();
        } else {
            writeln!(c, "    printf(\"{index} %llx\\n\", (unsigned long long)({call}));").unwrap();
        }
    }
    c.push_str("    return 0;\n}\n");
    c
}

/// How far apart two extended floats of the same sign are, in units in the last place of the
/// 64-bit significand. The format writes its integer bit, so the count goes by value and not by
/// the bits: a normal number's exponent field counts from 1.
fn ulps(a: u128, b: u128) -> u128 {
    let magnitude = |bits: u128| match bits >> 64 & 0x7fff {
        0 => bits & u128::from(u64::MAX),
        exponent => (exponent - 1) << 63 | bits & ((1 << 63) - 1),
    };
    if a >> 79 != b >> 79 { u128::MAX } else { magnitude(a).abs_diff(magnitude(b)) }
}

#[test]
#[ignore = "needs a gcc that builds 32-bit programs: cargo test --release -p recore-mcp --test oracle -- --ignored"]
fn the_oracle_agrees_with_the_x87() {
    require(&["gcc"]);
    let dir = edits_dir();
    std::fs::create_dir_all(&dir).unwrap();
    let source = dir.join("x87.c");
    std::fs::write(&source, X87_SOURCE).unwrap();
    let math_source = dir.join("x87-math.c");
    std::fs::write(&math_source, X87_MATH_SOURCE).unwrap();
    // glibc's pow for the x87, under the name a caller uses.
    let libm = command("gcc", &["-m32", "-print-file-name=libm.a"]);
    assert!(Path::new(libm.trim()).is_file(), "this test needs glibc's 32-bit libm.a, which gcc does not find");
    let pow = dir.join("pow.o");
    command("ar", &["x", "--output", path(&dir), libm.trim(), "e_pow.o"]);
    command("objcopy", &["--redefine-sym", "__ieee754_pow=pow", path(&dir.join("e_pow.o")), path(&pow)]);
    let mut rng = Rng(0x0123_4567_89ab_cdef);
    let mut cases: Vec<Case> = Vec::new();
    for function in X87_FUNCTIONS.iter().chain(X87_MATH) {
        for _ in 0..CASES {
            let mut args: Vec<Input> = function.params.iter().map(|param| param.ty.generate(&mut rng, param.range)).collect();
            // A not-a-number now and then, and a second operand equal to the first.
            for (param, arg) in function.params.iter().zip(&mut args) {
                if param.ty.is_float() && rng.below(12) == 0 {
                    *arg = Input::Float(if param.ty == F32 { u64::from(f32::NAN.to_bits()) } else { f64::NAN.to_bits() });
                }
            }
            if function.params.len() == 2 && function.params[0].ty == function.params[1].ty && rng.below(8) == 0 {
                args[1] = args[0];
            }
            cases.push(Case { function, args, expected: 0 });
        }
    }
    // A Pentium has no FCOMI, so gcc compares with FNSTSW AX as MSVC does, and a Pentium Pro does.
    let mut compared = 0;
    let mut mismatches = Vec::new();
    // For each function: the cases compared, those that differ, and by how much at most.
    let mut tally: BTreeMap<&str, (usize, usize, u128)> = BTreeMap::new();
    let mut client = Client::start();
    for march in ["pentium", "pentiumpro"] {
        let object = dir.join(format!("x87-{march}.o"));
        let math_object = dir.join(format!("x87-math-{march}.o"));
        let image = dir.join(format!("x87-{march}.so"));
        let reference = dir.join(format!("x87-{march}"));
        let flags = ["-m32", "-O2", "-fPIC", "-mfpmath=387", "-fno-math-errno"];
        let march_flag = format!("-march={march}");
        command("gcc", &[&flags[..], &[march_flag.as_str(), "-c", path(&source), "-o", path(&object)]].concat());
        command("gcc", &[&flags[..], &[march_flag.as_str(), "-funsafe-math-optimizations", "-fno-stack-protector", "-c", path(&math_source), "-o", path(&math_object)]].concat());
        // Bound to the image's own pow, which a call reaches directly and not through an import.
        command("gcc", &["-m32", "-shared", "-nostdlib", "-Wl,-Bsymbolic", "-o", path(&image), path(&object), path(&math_object), path(&pow)]);
        std::fs::write(dir.join("x87-driver.c"), x87_driver(&cases)).unwrap();
        command("gcc", &["-m32", "-O0", "-o", path(&reference), path(&dir.join("x87-driver.c")), path(&object), path(&math_object), path(&pow), "-lm"]);
        let expected: Vec<u128> = command(&reference, &[]).lines().map(|line| u128::from_str_radix(line.split_once(' ').unwrap().1, 16).unwrap()).collect();
        for (case, &want) in cases.iter().zip(&expected) {
            let function = case.function;
            // A 64-bit integer takes two slots of the stack, the low half first.
            let args: Vec<serde_json::Value> = function.params.iter().zip(&case.args).flat_map(|(param, &value)| match value {
                Input::Int(int) if param.ty == I64 => vec![json!(int as u32), json!((int >> 32) as u32)],
                Input::Int(int) => vec![json!(int)],
                Input::Float(bits) => vec![json!(float_arg(param.ty, bits))],
            }).collect();
            let answer = client.tool("run", json!({ "path": image, "function": function.name, "args": args, "read": ["ST0", "EDX"] })).unwrap();
            assert!(answer.contains(" returned "), "{march} {} {:?}: {answer}", function.name, case.args);
            let got = match function.ret {
                F32 | F64 => register(&answer, "ST0"),
                I64 => register(&answer, "EDX") << 32 | register(&answer, "EAX"),
                _ => register(&answer, "EAX"),
            };
            compared += 1;
            let entry = tally.entry(function.name).or_default();
            entry.0 += 1;
            let mask = if function.ret.is_float() { (1 << 80) - 1 } else { (1 << function.ret.bits()) - 1 };
            if got & mask == want & mask {
                continue;
            }
            let units = if function.ret.is_float() { ulps(got, want) } else { u128::MAX };
            entry.1 += 1;
            entry.2 = entry.2.max(units);
            // The x87's transcendental instructions are not rounded correctly, and the oracle's
            // are, so a function that gives one back as it is may be a unit apart.
            let library = X87_MATH.iter().any(|math| math.name == function.name);
            if !library || units > 1 {
                mismatches.push(format!("{march} {}{:?}: the processor gave {want:#x}, the oracle {got:#x}", function.name, case.args));
            }
        }
    }
    drop(client);
    std::fs::remove_dir_all(&dir).unwrap();
    for (name, (tried, apart, largest)) in &tally {
        eprintln!("{name}: {apart} of {tried} differ in ST0, by {largest} units in the last place at most");
    }
    assert!(compared >= 2 * (X87_FUNCTIONS.len() + X87_MATH.len()) * CASES, "only {compared} cases were compared");
    assert!(mismatches.is_empty(), "{} of {compared} cases differ, the first:\n{}", mismatches.len(), mismatches.iter().take(10).cloned().collect::<Vec<_>>().join("\n"));
}

/// Inputs of the 8051 program, which it runs every function on.
const INPUTS: usize = 40;

/// Each function runs on each input, and the program leaves the answers in external memory for
/// the simulator to dump. `h8` and `h16` expect their caller to have picked a register bank, as
/// SDCC's own caller does, and call another function in the first.
fn program_8051(inputs: &[u16]) -> String {
    let table: Vec<String> = inputs.iter().map(|input| format!("{input:#x}")).collect();
    format!(
        r#"
#define N {INPUTS}
__code const unsigned int inputs[N] = {{{table}}};
unsigned char f8(unsigned char x) {{ return (unsigned char)((x * 37) ^ (x >> 3)) + (x & 0x0f) - (x / 7); }}
unsigned int f16(unsigned int x) {{ return (x * 37u) ^ (x >> 3) ^ (x << 5) ^ (x / 7u) ^ (x % 251u); }}
int s16(int x) {{ return (x / 7) + (x % 13) - (x >> 2) + (x * 3); }}
unsigned long f32(unsigned long x) {{ return (x * 2654435761ul) ^ (x >> 7) ^ (x << 3); }}
unsigned char inner(unsigned char x) {{ return (unsigned char)(x * 7 + (x >> 2)); }}
unsigned char h8(unsigned char x) __using(1) {{ unsigned char a = inner(x); return a ^ (x * 5); }}
unsigned int h16(unsigned int x) __using(2) {{ unsigned int a = x * 3u; a ^= x >> 2; return a + (x % 13u); }}
__xdata unsigned char o8[N], p8[N], done;
__xdata unsigned int o16[N], os16[N], p16[N];
__xdata unsigned long o32[N];
void main(void) {{
    for (unsigned char i = 0; i < N; i++) {{
        o8[i] = f8((unsigned char)inputs[i]);
        o16[i] = f16(inputs[i]);
        os16[i] = s16((int)inputs[i]);
        o32[i] = f32(((unsigned long)inputs[i] << 16) | inputs[N - 1 - i]);
        p8[i] = h8((unsigned char)inputs[i]);
        p16[i] = h16(inputs[i]);
    }}
    done = 1;
    for (;;) ;
}}
"#,
        table = table.join(",")
    )
}

/// The external memory of the program after it has run in µCsim, which runs on its own once
/// started. The program sets `done` when it has finished, and the dump is asked for again after
/// a longer wait if it has not.
fn simulate(ihx: &Path, done: usize) -> Vec<u8> {
    for wait in [1, 3, 9] {
        let mut simulator = Command::new("s51").args(["-g", "-t", "8051", path(ihx)]).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap();
        std::thread::sleep(Duration::from_secs(wait));
        writeln!(simulator.stdin.as_mut().unwrap(), "dump xram 0 0x400\nquit").unwrap();
        let output = simulator.wait_with_output().unwrap();
        let size = 0x400;
        let mut memory = vec![0u8; size];
        for line in String::from_utf8_lossy(&output.stdout).lines().filter(|line| line.starts_with("0x")) {
            let mut fields = line.split_whitespace();
            let row = usize::from_str_radix(fields.next().unwrap().trim_start_matches("0x"), 16).unwrap();
            // The row after the last asked for is dumped as well.
            for (offset, byte) in fields.take(8).enumerate().filter(|(offset, _)| row + offset < size) {
                memory[row + offset] = u8::from_str_radix(byte, 16).unwrap();
            }
        }
        if memory[done] == 1 {
            return memory;
        }
    }
    panic!("the simulator did not finish the program");
}

/// The address of each global of the program that the linker's map lists.
fn symbols(map: &str) -> BTreeMap<String, usize> {
    map.lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let (kind, address, name) = (fields.next()?, fields.next()?, fields.next()?);
            (matches!(kind, "C:" | "D:") && name.starts_with('_')).then(|| (name[1..].to_string(), usize::from_str_radix(address, 16).unwrap()))
        })
        .collect()
}

#[test]
#[ignore = "needs sdcc and s51: cargo test --release -p recore-mcp --test oracle -- --ignored"]
fn the_oracle_agrees_with_the_8051_simulator() {
    require(&["sdcc", "s51", "llvm-objcopy"]);
    let dir = edits_dir();
    std::fs::create_dir_all(&dir).unwrap();
    let mut rng = Rng(0x2545_f491_4f6c_dd1d);
    let edges = [0u16, 1, 2, 0xff, 0x100, 0x7fff, 0x8000, 0xffff];
    let inputs: Vec<u16> = (0..INPUTS).map(|index| edges.get(index).copied().unwrap_or_else(|| rng.next() as u16)).collect();
    std::fs::write(dir.join("program.c"), program_8051(&inputs)).unwrap();
    let ihx = dir.join("program.ihx");
    command("sdcc", &["-mmcs51", "--model-small", "-o", path(&ihx), path(&dir.join("program.c"))]);
    let bin = dir.join("program.bin");
    command("llvm-objcopy", &["-I", "ihex", "-O", "binary", path(&ihx), path(&bin)]);
    let length = std::fs::metadata(&bin).unwrap().len();
    let image = dir.join("program.toml");
    std::fs::write(&image, format!("machine = \"8051\"\ncompiler = \"sdcc\"\nentry = [0]\n[[region]]\nfile = \"program.bin\"\noffset = 0\nlength = {length}\naddress = 0\nexecutable = true\n")).unwrap();

    let symbols = symbols(&std::fs::read_to_string(dir.join("program.map")).unwrap());
    let memory = simulate(&ihx, symbols["done"]);
    let words = |name: &str, bytes: usize| -> Vec<u64> { (0..INPUTS).map(|index| (0..bytes).fold(0, |word, byte| word | u64::from(memory[symbols[name] + index * bytes + byte]) << (8 * byte))).collect() };
    let (o8, p8, o16, os16, p16, o32) = (words("o8", 1), words("p8", 1), words("o16", 2), words("os16", 2), words("p16", 2), words("o32", 4));

    let mut client = Client::start();
    let mut ask = |function: &str, set: Vec<String>| client.tool("run", json!({ "path": image, "function": format!("{:#x}", symbols[function]), "set": set })).unwrap();
    let mut mismatches = Vec::new();
    for (index, &input) in inputs.iter().enumerate() {
        let (low, high) = (input & 0xff, input >> 8);
        let wide = (u32::from(input) << 16) | u32::from(inputs[INPUTS - 1 - index]);
        let mut check = |what: &str, got: u128, want: u64| {
            if got != u128::from(want) {
                mismatches.push(format!("{what}({input:#x}): the simulator gave {want:#x}, the oracle {got:#x}"));
            }
        };
        let answer = ask("f8", vec![format!("DPL={low}")]);
        check("f8", register(&answer, "DPL"), o8[index]);
        let answer = ask("f16", vec![format!("DPL={low}"), format!("DPH={high}")]);
        check("f16", register(&answer, "DPH") << 8 | register(&answer, "DPL"), o16[index]);
        let answer = ask("s16", vec![format!("DPL={low}"), format!("DPH={high}")]);
        check("s16", register(&answer, "DPH") << 8 | register(&answer, "DPL"), os16[index]);
        let answer = ask("f32", vec![format!("DPL={}", wide & 0xff), format!("DPH={}", wide >> 8 & 0xff), format!("B={}", wide >> 16 & 0xff), format!("ACC={}", wide >> 24)]);
        check("f32", register(&answer, "ACC") << 24 | register(&answer, "B") << 16 | register(&answer, "DPH") << 8 | register(&answer, "DPL"), o32[index]);
        // These expect the register bank their caller picks.
        let answer = ask("h8", vec![format!("DPL={low}"), "RS0=1".into()]);
        check("h8", register(&answer, "DPL"), p8[index]);
        let answer = ask("h16", vec![format!("DPL={low}"), format!("DPH={high}"), "RS1=1".into()]);
        check("h16", register(&answer, "DPH") << 8 | register(&answer, "DPL"), p16[index]);
    }
    drop(client);
    std::fs::remove_dir_all(&dir).unwrap();
    assert!(mismatches.is_empty(), "{} of {} cases differ, the first:\n{}", mismatches.len(), 6 * INPUTS, mismatches.iter().take(10).cloned().collect::<Vec<_>>().join("\n"));
}
